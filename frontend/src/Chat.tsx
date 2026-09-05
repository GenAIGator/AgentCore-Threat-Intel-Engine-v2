/**
 * Chat component for the Threat Intelligence Engine.
 *
 * Sends freeform text to AgentCore /invocations — the agent retrieves
 * relevant threat-profile shards then generates a grounded, cited answer.
 * Handles SSE streaming of the generated answer plus the HITL profile-
 * enrichment approval flow.
 *
 * SSE events handled (Req 3.5, 5.2):
 *   {content}                        -> append to the current assistant message
 *   {done: true}                     -> terminal, stop streaming
 *   {pending_approval, interrupts}   -> render an approval message (HITL)
 *   {error}                          -> surface the error inline
 *
 * The HITL resume (Req 5.6) is a synchronous POST (not SSE) to the same
 * /invocations endpoint.
 *
 * Domain quick-prompts (task 11.3): grouped starter prompts (by country,
 *   threat type, purple-team, plus an enrichment example) are defined in
 *   `QUICK_PROMPT_GROUPS` and rendered in the empty state.
 */

import { useState, useRef, useEffect } from 'react';
import { getAccessToken, getUser } from './auth';
import MarkdownMessage from './MarkdownMessage';

/**
 * The enrichment draft context carried by a HITL interrupt.
 *
 * This is the `reason` payload the backend `enrich_profile` tool passes to
 * `tool_context.interrupt(reason=...)`. Because the stream branch maps
 * `interrupt.reason` onto the SSE event's `prompt` field, the same shape can
 * arrive under `interrupt.prompt` (as an object) OR `interrupt.reason` — we
 * read it defensively (see `extractEnrichment`).
 *
 * The approval card renders these fields (Req 5.2, 8.1) and `handleApproval`
 * echoes them back on the resume POST so the backend's orphaned-interrupt
 * fallback (task 9.4, Req 5.7) can complete the write if the agent was
 * recycled.
 */
interface EnrichmentPayload {
  action?: string;
  profile_id?: string;
  shard_id?: string;
  proposed_content?: string;
  current_content?: string;
  sources?: string[];
  // A human-readable fallback string some payloads carry.
  reason?: string;
}

/**
 * A HITL interrupt raised by the backend `enrich_profile` tool.
 *
 * `prompt` is the interrupt REASON payload the backend maps onto the SSE
 * event (an object shaped like {@link EnrichmentPayload}), though it may also
 * arrive as a plain string. `reason` is the same payload under the alternate
 * key. Both are read defensively by {@link extractEnrichment}.
 */
interface Interrupt {
  interrupt_id: string;
  prompt?: string | EnrichmentPayload;
  action?: string;
  reason?: EnrichmentPayload;
}

interface Message {
  role: 'user' | 'assistant' | 'approval';
  content: string;
  interrupts?: Interrupt[];
  // The rich enrichment payload extracted from the interrupt, stored so the
  // approval card can render it AND handleApproval can echo it back.
  enrichment?: EnrichmentPayload;
  resolved?: boolean;
}

/**
 * Extract the rich enrichment payload from an interrupt, defensively.
 *
 * The backend stream branch maps the tool's `interrupt.reason` object onto
 * the SSE event's `prompt` field, so the payload can arrive as:
 *   - `interrupt.prompt` as an object (the common stream case), or
 *   - `interrupt.reason` as an object, or
 *   - `interrupt.prompt` as a plain string (only a human-readable message).
 * This returns whichever object shape is found, or an empty object.
 */
function extractEnrichment(interrupt: Interrupt | undefined): EnrichmentPayload {
  if (!interrupt) return {};
  if (interrupt.prompt && typeof interrupt.prompt === 'object') {
    return interrupt.prompt;
  }
  if (interrupt.reason && typeof interrupt.reason === 'object') {
    return interrupt.reason;
  }
  return {};
}

/**
 * A short human-readable summary line for the approval card header.
 * Prefers an explicit `reason` string, else falls back to a plain-string
 * `prompt`, else a generic message.
 */
function approvalSummary(interrupt: Interrupt | undefined, enrichment: EnrichmentPayload): string {
  if (enrichment.reason) return enrichment.reason;
  if (interrupt && typeof interrupt.prompt === 'string' && interrupt.prompt) {
    return interrupt.prompt;
  }
  return 'The agent proposes an enrichment to a threat profile. Review the change below.';
}

const AGENTCORE_ENDPOINT = import.meta.env.VITE_AGENTCORE_ENDPOINT;

// Sentinel the backend appends after wiping memory (clear_all_memory). When present in a
// response the frontend strips it, shows the cleaned message, and auto-starts a fresh
// session so the wiped conversation id is not reused.
const NEW_SESSION_SENTINEL = '__NEW_SESSION_REQUIRED__';

// Storage key for the per-user/per-browser session id (threat-intel specific).
const SESSION_STORAGE_KEY = 'threat_intel_session_id';

// --- Domain quick-prompts (task 11.3) ----------------------------------
// Curated threat-intelligence starter prompts, grouped by domain and adapted
// from the v1 threat-intel engine's demo prompts. Clicking a prompt just
// populates the input via setInput (Req 8.1, 8.2); grouping mirrors the
// spec's "by country, threat type, purple-team" call-outs (Req 8.3), plus an
// enrichment example that exercises the HITL flow (Req 5.2, 5.6).
interface QuickPromptGroup {
  label: string;
  prompts: string[];
}

const QUICK_PROMPT_GROUPS: QuickPromptGroup[] = [
  {
    label: 'By country / attribution',
    prompts: [
      'Which threat actors are attributed to Russia?',
      'Show me Chinese state-sponsored actors and their cloud TTPs',
      'List North Korean actors and their financial-theft tactics',
    ],
  },
  {
    label: 'By threat type',
    prompts: [
      'Compare ransomware-as-a-service groups like ALPHV/BlackCat and 8base',
      'What actors focus on identity and SaaS attacks?',
      'Show detection guidance for cloud credential theft',
    ],
  },
  {
    label: 'Purple team',
    prompts: [
      'Design a purple-team exercise for APT29',
      'Give me tabletop scenarios for a ransomware intrusion',
      'Map Sandworm TTPs to MITRE ATT&CK for a detection lab',
    ],
  },
  {
    label: 'Enrich a profile',
    prompts: [
      "Enrich 0ktapus's detection profile with recent reporting",
    ],
  },
];
// -----------------------------------------------------------------------

/**
 * Generate a stable session ID per user per browser.
 * Persists in localStorage so memory carries across page refreshes.
 */
function getSessionId(): string {
  let id = localStorage.getItem(SESSION_STORAGE_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(SESSION_STORAGE_KEY, id);
  }
  return id;
}

function newSession(): string {
  const id = crypto.randomUUID();
  localStorage.setItem(SESSION_STORAGE_KEY, id);
  return id;
}

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  // Transient "working, up to 60 seconds" notice shown ONLY while the enrich_profile
  // tool is in flight (the window between the model's lead-in and the approval card).
  // Set from the backend's {tool_running, notice} SSE frame and cleared as soon as any
  // subsequent content delta / approval / done / error arrives (see sendMessage).
  const [toolRunningNotice, setToolRunningNotice] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // --- Streaming coalescing buffer (smoothness) ---------------------------
  // SSE content deltas can be very granular (token-by-token), so instead of a
  // setMessages per delta we accumulate deltas in `pendingDeltaRef` and flush
  // them into ONE state update roughly every 30ms. This avoids visibly
  // rendering individual characters and cuts re-renders, without adding
  // noticeable latency. The buffer is flushed on every terminal path (approval,
  // error, done, stream end, finally) so nothing is ever left unrendered.
  const pendingDeltaRef = useRef('');
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Append any buffered delta text to the current (last) assistant message in a
  // single state update, then clear the buffer and timer.
  function flushPendingDelta() {
    if (flushTimerRef.current !== null) {
      clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
    const pending = pendingDeltaRef.current;
    if (!pending) return;
    pendingDeltaRef.current = '';
    setMessages(prev => {
      const updated = [...prev];
      const last = updated[updated.length - 1];
      if (last && last.role === 'assistant') {
        updated[updated.length - 1] = { ...last, content: last.content + pending };
      }
      return updated;
    });
  }

  function handleNewSession() {
    newSession();
    setMessages([]);
  }

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  /**
   * Handle HITL approval: send the analyst's decision to the backend via a
   * synchronous resume POST (Req 5.6). Only an explicit approval sends "yes";
   * everything else denies.
   *
   * The resume body carries {responses:[{interrupt_id, response}], action,
   * user_email, session_id}. For the enrichment flow the action is "enrich".
   *
   * The body ALSO echoes the enrichment payload fields (profile_id, shard_id,
   * proposed_content, sources) at top level so the backend orphaned-interrupt
   * fallback (task 9.4, Req 5.7) can complete the terminal write directly if
   * the agent that raised the interrupt was recycled.
   */
  async function handleApproval(
    interrupts: Interrupt[],
    approved: boolean,
    messageIndex: number,
    enrichment: EnrichmentPayload = {},
  ) {
    const token = await getAccessToken();
    if (!token) return;

    const user = await getUser();
    const userEmail = user?.profile?.email ?? '';
    const sessionId = getSessionId();

    // Mark the approval message as resolved
    setMessages(prev => {
      const updated = [...prev];
      updated[messageIndex] = { ...updated[messageIndex], resolved: true };
      return updated;
    });

    setIsLoading(true);
    // Add placeholder for agent response after approval
    setMessages(prev => [...prev, { role: 'assistant', content: '' }]);

    // Resume goes through the same /invocations endpoint (AgentCore only exposes this path).
    const resumeUrl = AGENTCORE_ENDPOINT;

    try {
      const response = await fetch(resumeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
          'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
        },
        body: JSON.stringify({
          responses: interrupts.map(intr => ({
            interrupt_id: intr.interrupt_id,
            response: approved ? 'yes' : 'no',
          })),
          action: interrupts[0]?.action || enrichment.action || 'enrich',
          user_email: userEmail,
          session_id: sessionId,
          // Echo the enrichment payload at top level so the backend's
          // orphaned-interrupt fallback (Req 5.7) can complete the write if
          // the agent was recycled. Omit fields that are absent so we never
          // send empty values (the fallback only writes a complete payload).
          ...(enrichment.profile_id ? { profile_id: enrichment.profile_id } : {}),
          ...(enrichment.shard_id ? { shard_id: enrichment.shard_id } : {}),
          ...(enrichment.proposed_content ? { proposed_content: enrichment.proposed_content } : {}),
          ...(enrichment.sources && enrichment.sources.length > 0 ? { sources: enrichment.sources } : {}),
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      if (data.status === 'success') {
        // The backend signals a memory wipe with the __NEW_SESSION_REQUIRED__ sentinel
        // (e.g. after clear_all_memory). Strip it from the displayed text, show the
        // cleaned message, then auto-start a fresh session so the wiped conversation id
        // is not reused.
        const responseText: string = typeof data.response === 'string' ? data.response : '';
        if (responseText.includes(NEW_SESSION_SENTINEL)) {
          const cleaned = responseText.replace(NEW_SESSION_SENTINEL, '').trim();
          setMessages(prev => {
            const updated = [...prev];
            updated[updated.length - 1] = {
              role: 'assistant',
              content: `${cleaned}\n\nStarting a fresh session...`,
            };
            return updated;
          });
          setTimeout(() => {
            newSession();
            setMessages([]);
          }, 2000);
        } else {
          setMessages(prev => {
            const updated = [...prev];
            updated[updated.length - 1] = { role: 'assistant', content: responseText };
            return updated;
          });
        }
      } else if (data.status === 'error') {
        setMessages(prev => {
          const updated = [...prev];
          updated[updated.length - 1] = { role: 'assistant', content: `[Error: ${data.error}]` };
          return updated;
        });
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setMessages(prev => {
        const updated = [...prev];
        updated[updated.length - 1] = { role: 'assistant', content: `[Error: ${errorMsg}]` };
        return updated;
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function sendMessage(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setIsLoading(true);
    // Clear any lingering "working" notice from a prior turn before starting.
    setToolRunningNotice(null);

    // Add placeholder assistant message
    setMessages(prev => [...prev, { role: 'assistant', content: '' }]);

    try {
      const token = await getAccessToken();
      if (!token) {
        setMessages(prev => {
          const updated = [...prev];
          updated[updated.length - 1] = { role: 'assistant', content: '[Error: Not authenticated. Please log in again.]' };
          return updated;
        });
        setIsLoading(false);
        return;
      }

      // Get user email and session ID
      const user = await getUser();
      const userEmail = user?.profile?.email ?? '';
      const sessionId = getSessionId();

      const response = await fetch(AGENTCORE_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
          'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
        },
        body: JSON.stringify({
          prompt: userMessage,
          user_email: userEmail,
          session_id: sessionId,
          stream: true,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Read SSE stream
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) throw new Error('No response body');

      let buffer = '';
      // Track whether the streamed answer carried the memory-wipe sentinel so we can
      // strip it and auto-start a fresh session once the stream completes.
      let newSessionRequired = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const jsonStr = line.substring(6).trim();
          if (!jsonStr) continue;

          try {
            const event = JSON.parse(jsonStr);

            if (event.tool_running) {
              // The enrich_profile tool started running: show the transient "working,
              // up to 60 seconds" notice. The backend only emits this for
              // enrich_profile, so no client-side filtering is needed.
              const notice: string =
                typeof event.notice === 'string' && event.notice
                  ? event.notice
                  : 'Working — this can take up to 60 seconds.';
              setToolRunningNotice(notice);
            } else if (event.content) {
              // Streamed answer token(s): append to the current assistant message. If a
              // delta carries the memory-wipe sentinel, note it and strip it from the
              // displayed text so the raw token never shows.
              // A content delta means the model is producing output again, so the
              // "working" notice is no longer relevant — clear it.
              setToolRunningNotice(null);
              const delta: string = event.content;
              if (delta.includes(NEW_SESSION_SENTINEL)) {
                newSessionRequired = true;
              }
              const cleanedDelta = delta.replace(NEW_SESSION_SENTINEL, '');
              // Buffer the delta and flush on a ~30ms timer (see flushPendingDelta)
              // rather than updating state per token, for smoother streaming.
              pendingDeltaRef.current += cleanedDelta;
              if (flushTimerRef.current === null) {
                flushTimerRef.current = setTimeout(flushPendingDelta, 30);
              }
            } else if (event.done) {
              // Terminal event: flush any buffered text, then stop processing
              // further lines cleanly (the loop ends when the reader is done).
              flushPendingDelta();
              setToolRunningNotice(null);
              continue;
            } else if (event.pending_approval && event.interrupts) {
              // Flush buffered text first so an in-flight delta can't clobber the
              // approval message we're about to swap in.
              flushPendingDelta();
              // Approval card is about to render — clear the "working" notice so it
              // does not linger alongside the card.
              setToolRunningNotice(null);
              // HITL interrupt: replace the empty assistant placeholder with an
              // approval message. Extract the rich enrichment payload (defensively
              // from prompt-as-object or reason) so the card can render it and
              // handleApproval can echo it back for the orphaned-interrupt fallback.
              const first: Interrupt | undefined = event.interrupts[0];
              const enrichment = extractEnrichment(first);
              const content = approvalSummary(first, enrichment);
              setMessages(prev => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  role: 'approval',
                  content,
                  interrupts: event.interrupts,
                  enrichment,
                  resolved: false,
                };
                return updated;
              });
            } else if (event.error) {
              // Flush buffered text first so it isn't lost/clobbered by the error swap.
              flushPendingDelta();
              setToolRunningNotice(null);
              setMessages(prev => {
                const updated = [...prev];
                const last = updated[updated.length - 1];
                if (last && last.role === 'assistant') {
                  updated[updated.length - 1] = { ...last, content: `[Error: ${event.error}]` };
                }
                return updated;
              });
            }
          } catch {
            // Skip malformed JSON
          }
        }
      }

      // Stream finished — flush any buffered delta so the full answer is present
      // before the memory-wipe/new-session handling reads the accumulated content.
      flushPendingDelta();

      // The streamed answer wiped memory: append a note and auto-start a fresh session
      // so the wiped conversation id is not reused.
      if (newSessionRequired) {
        setMessages(prev => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = {
              ...last,
              content: `${last.content.trim()}\n\nStarting a fresh session...`,
            };
          }
          return updated;
        });
        setTimeout(() => {
          newSession();
          setMessages([]);
        }, 2000);
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      // Drop any buffered delta and cancel a pending flush so it can't append
      // stale text after the error message is swapped in.
      pendingDeltaRef.current = '';
      if (flushTimerRef.current !== null) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
      setMessages(prev => {
        const updated = [...prev];
        updated[updated.length - 1] = { role: 'assistant', content: `[Error: ${errorMsg}]` };
        return updated;
      });
    } finally {
      setIsLoading(false);
      // Ensure the transient "working" notice never lingers past the stream.
      setToolRunningNotice(null);
      // Defensively clear any leaked flush timer.
      if (flushTimerRef.current !== null) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
    }
  }

  /**
   * Render the HITL enrichment approval CARD (Req 5.2, 8.1).
   *
   * Shows which shard is being updated (profile_id / shard_id), the PROPOSED
   * new content, the current content for comparison when available, and the
   * WEB SOURCES as links. Approve / Reject are wired to `handleApproval`,
   * which echoes the enrichment payload back on the resume POST so the
   * backend orphaned-interrupt fallback can complete the write (Req 5.6, 5.7).
   */
  function renderApproval(msg: Message, i: number) {
    const enrichment = msg.enrichment ?? {};
    const sources = enrichment.sources ?? [];

    // The approval card serves three HITL actions (enrich / create / clear); the
    // heading and target line adapt to which one raised the interrupt. create_profile
    // has no shard_id (it builds a whole new profile), so it must NOT render the
    // enrichment-flavored "Updating shard: <id> / (unknown shard)" line.
    const action = enrichment.action ?? 'enrich';
    const heading =
      action === 'create_profile'
        ? 'Proposed new profile — approval required'
        : action === 'clear_memory'
          ? 'Clear all memory — approval required'
          : 'Proposed profile enrichment — approval required';

    // For create, show the new ProfileId being created (no shard). For enrich, show
    // the profile/shard being updated. For clear_memory, no target line.
    const targetLabel = action === 'create_profile' ? 'Creating profile' : 'Updating shard';
    const target =
      action === 'create_profile'
        ? enrichment.profile_id ?? null
        : enrichment.profile_id || enrichment.shard_id
          ? `${enrichment.profile_id ?? '(unknown profile)'} / ${enrichment.shard_id ?? '(unknown shard)'}`
          : null;

    return (
      <div key={i} style={styles.approvalMsg}>
        <div style={styles.approvalIcon}>&#9888;</div>
        <div style={styles.approvalContent}>
          <p style={styles.approvalText}>{heading}</p>
          <p style={styles.approvalSummary}>{String(msg.content)}</p>

          {target && (
            <div style={styles.approvalField}>
              <span style={styles.approvalLabel}>{targetLabel}</span>
              <code style={styles.approvalTarget}>{target}</code>
            </div>
          )}

          {enrichment.proposed_content && (
            <div style={styles.approvalField}>
              <span style={styles.approvalLabel}>Proposed new content</span>
              <div style={styles.proposedBox}>{enrichment.proposed_content}</div>
            </div>
          )}

          {enrichment.current_content && (
            <details style={styles.approvalField}>
              <summary style={styles.approvalLabel}>Current content (for comparison)</summary>
              <div style={styles.currentBox}>{enrichment.current_content}</div>
            </details>
          )}

          {sources.length > 0 && (
            <div style={styles.approvalField}>
              <span style={styles.approvalLabel}>Web sources</span>
              <ul style={styles.sourceList}>
                {sources.map((src, si) => (
                  <li key={si} style={styles.sourceItem}>
                    <a href={src} target="_blank" rel="noopener noreferrer" style={styles.sourceLink}>
                      {src}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!msg.resolved ? (
            <div style={styles.approvalButtons}>
              <button
                onClick={() => handleApproval(msg.interrupts!, true, i, enrichment)}
                style={styles.approveButton}
                disabled={isLoading}
              >
                Approve
              </button>
              <button
                onClick={() => handleApproval(msg.interrupts!, false, i, enrichment)}
                style={styles.denyButton}
                disabled={isLoading}
              >
                Reject
              </button>
            </div>
          ) : (
            <p style={styles.resolvedText}>Responded</p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {/* Header with New Session / Clear Memory */}
      {messages.length > 0 && (
        <div style={styles.header}>
          <button
            onClick={() => {
              if (!isLoading) {
                setInput('clear all memory');
                setTimeout(() => {
                  const form = document.querySelector('form');
                  if (form) form.requestSubmit();
                }, 50);
              }
            }}
            style={styles.clearMemoryButton}
            title="Clear all memory (requires confirmation)"
            disabled={isLoading}
          >
            Clear Memory
          </button>
          <button onClick={handleNewSession} style={styles.newSessionButton} title="Start a new conversation session">
            New Session
          </button>
        </div>
      )}

      {/* Messages */}
      <div style={styles.messages}>
        {messages.length === 0 && (
          <div style={styles.empty}>
            <p style={styles.emptyTitle}>What would you like to investigate?</p>
            {/* Domain quick-prompts (task 11.3): grouped by country, threat
                type, purple-team, plus an enrichment example. Clicking one
                just populates the input (Req 8.1, 8.2). */}
            <div style={styles.suggestionGroups}>
              {QUICK_PROMPT_GROUPS.map(group => (
                <div key={group.label} style={styles.suggestionGroup}>
                  <span style={styles.suggestionGroupLabel}>{group.label}</span>
                  <div style={styles.suggestions}>
                    {group.prompts.map(prompt => (
                      <button key={prompt} onClick={() => setInput(prompt)} style={styles.suggestion}>
                        {prompt}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        {messages.map((msg, i) => {
          if (msg.role === 'approval') {
            return renderApproval(msg, i);
          }

          if (msg.role === 'assistant') {
            // Assistant answers render as GitHub-Flavored Markdown (streamed or
            // post-approval). The empty+loading case keeps the "Researching..."
            // hint. User messages stay plain text (below).
            return (
              <div key={i} style={styles.assistantMsg}>
                <strong>Analyst:</strong>
                {msg.content === '' ? (
                  isLoading && <span style={styles.loadingText}> Researching...</span>
                ) : (
                  <MarkdownMessage content={msg.content} />
                )}
              </div>
            );
          }

          return (
            <div key={i} style={styles.userMsg}>
              <strong>You:</strong>{' '}
              <span style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</span>
            </div>
          );
        })}
        {toolRunningNotice && isLoading && (
          <p style={styles.waitNotice}>{'\u23F3'} {toolRunningNotice}</p>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div style={styles.bottomBar}>
        <form onSubmit={sendMessage} style={styles.form}>
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="e.g. Profile the threat actor 0ktapus"
            disabled={isLoading}
            style={styles.input}
          />
          <button type="submit" disabled={isLoading || !input.trim()} style={styles.button}>
            {isLoading ? '...' : 'Ask'}
          </button>
        </form>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    flex: 1,
    minHeight: 0,
    maxWidth: '800px',
    margin: '0 auto',
    padding: '0.5rem 1rem',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    overflow: 'hidden',
    width: '100%',
  },
  header: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '0.5rem',
    padding: '0.25rem 0',
    flexShrink: 0,
  },
  messages: {
    flex: 1,
    overflowY: 'auto',
    padding: '1rem 0',
  },
  empty: {
    textAlign: 'center',
    marginTop: '3rem',
  },
  emptyTitle: {
    color: '#888',
    fontSize: '1.1rem',
    marginBottom: '1.5rem',
  },
  suggestionGroups: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem',
    alignItems: 'center',
  },
  suggestionGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    alignItems: 'center',
    width: '100%',
  },
  suggestionGroupLabel: {
    fontSize: '0.7rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    fontWeight: 700,
    color: '#90a4ae',
  },
  suggestions: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    alignItems: 'center',
  },
  suggestion: {
    padding: '0.6rem 1.2rem',
    fontSize: '0.9rem',
    background: '#f0f7ff',
    border: '1px solid #bbdefb',
    borderRadius: '20px',
    cursor: 'pointer',
    color: '#1565c0',
  },
  userMsg: {
    padding: '0.75rem 1rem',
    margin: '0.5rem 0',
    borderRadius: '8px',
    background: '#e3f2fd',
  },
  assistantMsg: {
    padding: '0.75rem 1rem',
    margin: '0.5rem 0',
    borderRadius: '8px',
    background: '#f5f5f5',
  },
  approvalMsg: {
    display: 'flex',
    gap: '0.75rem',
    padding: '1rem',
    margin: '0.5rem 0',
    borderRadius: '8px',
    background: '#fff3e0',
    border: '1px solid #ffcc80',
  },
  approvalIcon: {
    fontSize: '1.5rem',
    lineHeight: '1',
  },
  approvalContent: {
    flex: 1,
  },
  approvalText: {
    margin: '0 0 0.5rem 0',
    fontWeight: 600,
    color: '#e65100',
  },
  approvalSummary: {
    margin: '0 0 0.75rem 0',
    fontSize: '0.9rem',
    color: '#5d4037',
    whiteSpace: 'pre-wrap',
  },
  approvalField: {
    marginBottom: '0.75rem',
  },
  approvalLabel: {
    display: 'block',
    fontSize: '0.7rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    fontWeight: 700,
    color: '#a1611a',
    marginBottom: '0.25rem',
    cursor: 'default',
  },
  approvalTarget: {
    fontSize: '0.85rem',
    background: '#ffe0b2',
    padding: '0.15rem 0.4rem',
    borderRadius: '4px',
    color: '#5d4037',
  },
  proposedBox: {
    padding: '0.6rem 0.75rem',
    background: '#ffffff',
    border: '1px solid #c8e6c9',
    borderLeft: '3px solid #66bb6a',
    borderRadius: '6px',
    fontSize: '0.85rem',
    color: '#2e2e2e',
    whiteSpace: 'pre-wrap',
    maxHeight: '18rem',
    overflowY: 'auto',
  },
  currentBox: {
    marginTop: '0.4rem',
    padding: '0.6rem 0.75rem',
    background: '#fafafa',
    border: '1px solid #e0e0e0',
    borderRadius: '6px',
    fontSize: '0.8rem',
    color: '#616161',
    whiteSpace: 'pre-wrap',
    maxHeight: '14rem',
    overflowY: 'auto',
  },
  sourceList: {
    margin: 0,
    paddingLeft: '1.1rem',
  },
  sourceItem: {
    fontSize: '0.82rem',
    marginBottom: '0.2rem',
    wordBreak: 'break-all',
  },
  sourceLink: {
    color: '#1565c0',
    textDecoration: 'underline',
  },
  approvalButtons: {
    display: 'flex',
    gap: '0.5rem',
  },
  approveButton: {
    padding: '0.4rem 1rem',
    fontSize: '0.9rem',
    background: '#c8e6c9',
    border: '1px solid #81c784',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: 600,
    color: '#2e7d32',
  },
  denyButton: {
    padding: '0.4rem 1rem',
    fontSize: '0.9rem',
    background: '#ffcdd2',
    border: '1px solid #e57373',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: 600,
    color: '#c62828',
  },
  resolvedText: {
    margin: 0,
    fontSize: '0.85rem',
    color: '#888',
    fontStyle: 'italic',
  },
  loadingText: {
    color: '#888',
    fontStyle: 'italic',
  },
  waitNotice: {
    margin: '0.5rem 0',
    padding: '0.5rem 0.75rem',
    color: '#a1611a',
    fontStyle: 'italic',
    fontSize: '0.85rem',
    background: '#fff8e1',
    border: '1px solid #ffe0b2',
    borderRadius: '6px',
  },
  bottomBar: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'center',
    padding: '0.75rem 0',
    borderTop: '1px solid #eee',
    flexShrink: 0,
  },
  form: {
    display: 'flex',
    gap: '0.5rem',
    flex: 1,
  },
  input: {
    flex: 1,
    padding: '0.75rem',
    fontSize: '1rem',
    border: '1px solid #ddd',
    borderRadius: '8px',
    outline: 'none',
  },
  button: {
    padding: '0.75rem 1.5rem',
    fontSize: '1rem',
    background: '#1976d2',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
  },
  newSessionButton: {
    padding: '0.3rem 0.6rem',
    fontSize: '0.75rem',
    background: 'transparent',
    color: '#1565c0',
    border: '1px solid #90caf9',
    borderRadius: '4px',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  clearMemoryButton: {
    padding: '0.3rem 0.6rem',
    fontSize: '0.75rem',
    background: 'transparent',
    color: '#d32f2f',
    border: '1px solid #ffcdd2',
    borderRadius: '4px',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
};

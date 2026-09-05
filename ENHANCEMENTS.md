# Enhancements over v1 (agentcore-threat-intel-engine)

v2 is a rebuild of v1 that keeps the same defensive threat-intel mission — actor research,
purple-team exercise design, and incident attribution — but changes the retrieval store,
modernizes the stack, and layers on several new capabilities. This document is the
consolidated **"what improved and why"** narrative, gathering both the initial rebuild
changes and the feature work added afterward into one place.

For the side-by-side quick reference, see the "What's different from v1" table in
[`README.md`](./README.md). For the deep architectural rationale and trade-offs behind each
decision, see [`DECISIONS.md`](./DECISIONS.md). This doc sits between the two: per-feature,
with source pointers.

Enhancements are grouped by theme: retrieval, agent/tools, new capabilities, frontend/backend,
ops/tooling, and data model.

## Retrieval

### 1. RAG store: DynamoDB vector search (was: Bedrock Knowledge Base on S3 Vectors)

- **What changed.** Each threat-profile shard is a DynamoDB item carrying its own 1024-dim
  Titan v2 embedding. Retrieval is a custom embed-query step followed by `SearchVectors` over
  a vector index (COSINE, no HASH key, with `FileType`/`Country` inline filters).
- **Why it's an improvement.** A single store holds operational data *and* vectors, metadata
  filters are first-class, and the HITL enrichment flow gets a clean in-place re-embed path.
  (Honestly: for this mostly-static corpus, S3 Vectors is likely the better *production*
  choice — see [`DECISIONS.md`](./DECISIONS.md) ADR-1. DynamoDB vector search here is a
  deliberate learning choice.)
- **Where it lives.** `agent/src/tools/retrieval_tools.py`, `agent/src/ddb.py`,
  `agent/src/embeddings.py`, `cfn/template.yaml` (vector index), `loader/`.

## Agent & tools

### 2. Agentic retrieve-then-generate with Strands (was: hand-rolled retrieve-then-generate)

- **What changed.** A Strands agent orchestrates tool use — `retrieve_profiles`, `WebSearch`,
  `enrich_profile`, `clear_all_memory`, `current_time` — with Claude Sonnet 4.6.
- **Why it's an improvement.** The model decides when and how to retrieve and can chain
  multiple retrievals per query; tool contracts are cleaner; the result is a reusable
  production pattern (see [`DECISIONS.md`](./DECISIONS.md) ADR-4).
- **Where it lives.** `agent/src/agentcore_app.py` (agent factory + system prompt),
  `agent/src/tools/`.

## New capabilities

### 3. Managed Web Search via MCP gateway (NEW in v2)

- **What changed.** An AgentCore managed Web Search connector is exposed to the agent as an
  MCP tool through a Gateway (web-search only, no Lambda targets).
- **Why it's an improvement.** The agent can supplement the static KB with current or
  breaking info, while the system prompt keeps retrieve-then-generate primary and attributes
  web sources distinctly from KB citations.
- **Where it lives.** `cfn/template.yaml` (WebSearchGateway + WebSearchTarget),
  `agent/src/agentcore_app.py` (MCP client wiring).

### 4. Human-in-the-loop profile enrichment (NEW in v2)

- **What changed.** An `enrich_profile` tool researches an actor, drafts a full shard
  replacement, and pauses on a HITL interrupt for analyst Approve/Reject before writing back
  and re-embedding in place with provenance.
- **Why it's an improvement.** No unreviewed writes reach the knowledge base, and the design
  keeps one authoritative shard per `file_type` (see [`DECISIONS.md`](./DECISIONS.md) ADR-6).
- **Where it lives.** `agent/src/tools/enrich_tools.py`, `agent/src/agentcore_app.py`
  (interrupt/resume), `frontend/src/Chat.tsx` (approval card).

### 5. Human-in-the-loop Clear Memory (NEW in v2)

- **What changed.** A `clear_all_memory` tool wipes ALL analyst memory — short-term
  conversation history plus long-term facts/preferences — gated behind a HITL approval
  interrupt. After a wipe the backend appends a `__NEW_SESSION_REQUIRED__` sentinel; the
  frontend strips it, shows the cleaned message, and auto-starts a fresh session so the wiped
  conversation id is not reused.
- **Why it's an improvement.** It gives the analyst an explicit, reviewable "forget
  everything" control, routed as its own tool distinct from `enrich_profile`.
- **Where it lives.** `agent/src/tools/memory_tools.py` (`clear_all_memory`),
  `agent/src/agentcore_app.py` (tool registration + system-prompt routing),
  `frontend/src/Chat.tsx` (sentinel handling + fresh session).

### 6. Enrichment wait-notice (NEW in v2)

- **What changed.** When the `enrich_profile` tool starts, the backend emits a single SSE
  frame `{"tool_running": "enrich_profile", "notice": ...}`; the frontend shows a transient
  "working, up to ~60 seconds" ⏳ indicator during the window between the model's lead-in text
  and the approval card appearing, cleared as soon as any subsequent content delta / approval
  / done / error arrives.
- **Why it's an improvement.** Enrichment takes noticeably longer than normal streaming (web
  research + draft) and the stream goes quiet; without a cue, users think it stalled. The
  notice is scoped to ONLY the enrich tool (deterministic detection of the tool-use start),
  not a blind timer.
- **Where it lives.** `agent/src/agentcore_app.py` (SSE `tool_running` frame),
  `frontend/src/Chat.tsx` (`toolRunningNotice` state + indicator).

### 7. Autonomous new-profile creation (two-runtime, HITL) (NEW in v2)

- **What changed.** A `create_profile` HITL tool on the main agent lets an analyst ADD a
  brand-new threat actor. It first runs a **variation-aware duplicate check** (normalized
  id/name/alias match plus a semantic vector-similarity check) so an actor that already
  exists — even under a different name variation — never triggers a build; if it is genuinely
  new, the analyst approves the *create*, and the main agent then **fire-and-forget invokes a
  separate autonomous "builder" AgentCore Runtime**. The builder researches and generates all
  12 profile sections (web-search MCP via the gateway), grades each against per-section
  quality minimums (regenerating thin sections), embeds them (Titan v2), and writes the whole
  profile in one `BatchWriteItem`. It runs in the background (nobody waits); the analyst
  rechecks by searching for the actor. Failures alert an operator via SNS (out-of-band).
- **Why it's an improvement.** v1 had no way to add actors. A second runtime is the right fit
  because building a full profile is minutes of agentic web research — too long to block the
  chat turn — and AgentCore async sessions cover it (hours, not the 15-min synchronous
  request timeout). The dedup gate avoids duplicates/wasted research; the quality gate
  substitutes for a second human review (there is only one approval, for the create itself).
  See [`docs/CREATE_PROFILE_DESIGN.md`](./docs/CREATE_PROFILE_DESIGN.md).
- **Where it lives.** `agent/src/tools/create_tools.py` (HITL tool + fire-and-forget launch),
  `agent/src/profile_dedup.py` (variation-aware dedup), `builder/` (the autonomous builder
  runtime: `builder_app.py`, `sections.py`, `quality_gate.py`, `section_generator.py`,
  `profile_writer.py`, OTEL `Dockerfile`), `cfn/template.yaml` (builder runtime/role, SNS
  topic, invoke permission), `deploy.sh` (second image build).

## Frontend & backend

### 8. Hosted web tier: React SPA + Cognito auth + CloudFront (was: local Streamlit, no auth, no hosting)

- **What changed.** A React 18 + Vite SPA with SSE streaming and the HITL approval UI. Two
  pieces are **entirely new to v2**, not just a framework swap:
  - **Auth.** Cognito OIDC issues a JWT that authorizes calls to the agent runtime
    (admin-created users; self-registration disabled). v1 had *no auth at all* — it ran as a
    local Streamlit app that talked directly to the runtime, auto-discovering the runtime ARN
    from CloudFormation outputs.
  - **Hosting.** The SPA is served from **S3 + CloudFront**. v1 had *no web hosting* — the UI
    lived on your laptop via `streamlit run`, with no CloudFront distribution and no S3 site.
- **Why it's an improvement.** A real, hosted single-page app with proper sign-in and
  streaming UX; it doubles as a reusable production reference. The whole client/edge/auth tier
  (SPA → S3 + CloudFront → Cognito OIDC/JWT → agent runtime) is a v2 addition.
- **Where it lives.** `frontend/`, `cfn/template.yaml` (Cognito user pool + app client, S3
  bucket, CloudFront distribution + OAC).

### 9. FastAPI + Strands backend on AgentCore Runtime (was: stdlib HTTP handler)

- **What changed.** A single `/invocations` endpoint (SSE for generation, synchronous POST for
  HITL resume) plus `/ping`, served by uvicorn on ARM64 AgentCore Runtime.
- **Why it's an improvement.** A clean streaming + interrupt/resume contract on a single
  endpoint (see [`DECISIONS.md`](./DECISIONS.md) ADR-5).
- **Where it lives.** `agent/src/agentcore_app.py`, `agent/Dockerfile`.

### 10. Markdown rendering of streamed answers (NEW in v2)

- **What changed.** Assistant responses render as GitHub-Flavored Markdown
  (`react-markdown` + `remark-gfm`) instead of plain text — headings, bold/italics, nested
  lists, tables, blockquotes, links, inline code, and fenced code blocks. Rendering happens
  *while* the SSE stream is still arriving: incoming deltas are coalesced in a ~30 ms buffer
  and flushed as one state update (smoother than token-by-token, no added latency), and the
  accumulated text is re-rendered through the Markdown component on each flush. The buffer is
  flushed on every terminal path (approval, error, done, stream end) so nothing is left
  unrendered, and incomplete markdown mid-stream (an unclosed `**`, a half-written table or
  code fence) renders best-effort and resolves as more text arrives without layout jumping.
- **Why it's an improvement.** Long, structured RAG answers (actor overviews, TTP tables,
  MITRE mappings, detection code) are far easier to scan than a wall of plain text. Styling is
  scoped so it matches the existing theme without leaking into the rest of the inline-styled
  UI; user messages and the HITL approval card stay as-is, and all SSE/HITL/auth behavior is
  preserved.
- **Where it lives.** `frontend/src/MarkdownMessage.tsx` (reusable renderer + safe links),
  `frontend/src/markdown.css` (scoped `.md` styles), `frontend/src/Chat.tsx` (assistant render
  + streaming coalescing buffer).

## Ops & tooling

### 11. Observability via ADOT / OpenTelemetry (NEW in v2)

- **What changed.** The agent runs under `opentelemetry-instrument` (AWS Distro for
  OpenTelemetry); `deploy.sh` enables CloudWatch Transaction Search (account-wide) with 100%
  X-Ray indexing. Tool calls like `retrieve_profiles` surface as trace spans. It uses unified
  telemetry (spans in the agent's own runtime log group).
- **Why it's an improvement.** You can confirm the agent actually used RAG (via
  `retrieve_profiles` spans) and debug tool/latency behavior. See the README "Observability"
  section for the CLI/console verification steps.
- **Where it lives.** `agent/Dockerfile` (ADOT distro/configurator + `opentelemetry-instrument`
  CMD), `deploy.sh` (Transaction Search enablement), `cfn/template.yaml` (runtime-role
  permissions), [`README.md`](./README.md) (verification).

### 12. Build-speed: buildx ECR registry cache (NEW in v2 tooling)

- **What changed.** `deploy.sh` builds the ARM64 image with `docker buildx` using a
  `:buildcache` registry cache in ECR (auto-creating a docker-container builder when needed)
  and preflights the build path. It also adds a `SKIP_LOAD=1` guard to skip the idempotent
  corpus re-embed on redeploys.
- **Why it's an improvement.** The slow `uv sync` layer (ARM64 deps cross-compiling under
  QEMU on x86) is cached across machines/checkouts, and redeploys avoid re-embedding ~1707
  shards.
- **Where it lives.** `deploy.sh`, `agent/Dockerfile`.

## Data model

### 13. One embedding per shard, composite key `(ProfileId, ShardId)` with first-class metadata (was: metadata in S3 Vectors only)

- **What changed.** Each `file_type` shard is its own DynamoDB item/embedding; `FileType` and
  `Country` are queryable attributes and inline filters.
- **Why it's an improvement.** Retrieval precision (a detection query matches the detection
  shard), plus direct operational access (Query a whole actor, GetItem a single shard). See
  [`DECISIONS.md`](./DECISIONS.md) ADR-2/ADR-3.
- **Where it lives.** `loader/content.py`, `loader/load_profiles.py`, `cfn/template.yaml`.

## See also

- [`README.md`](./README.md) — quick reference table + Observability verification steps.
- [`DECISIONS.md`](./DECISIONS.md) — ADRs with the deep rationale and trade-offs.
- v1 (`agentcore-threat-intel-engine`) — the original build this project rebuilds on.

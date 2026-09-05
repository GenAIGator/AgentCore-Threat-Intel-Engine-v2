# Design — Create New Threat-Actor Profile (two-runtime, HITL + autonomous builder)

Status: design (pre-implementation). Companion to [`DECISIONS.md`](../DECISIONS.md) and
[`ENHANCEMENTS.md`](../ENHANCEMENTS.md).

## Goal

Let an analyst ask the agent to **add a brand-new threat actor** to the knowledge base.
Creation must produce a **complete** profile — all 12 shard sections, researched and
written to the same quality bar as the existing seed corpus — not a rushed, shallow stub.
Adding a profile is a **human-in-the-loop (HITL)** action: the analyst approves the
*create*, then a background worker researches, generates, embeds, and writes all sections.

## Why two runtimes (not one, not three, not Step Functions)

- **Interactive agent (existing runtime)** stays fast and user-facing. Generating 12
  researched sections can take minutes; blocking the chat turn on it is bad UX and risks
  the synchronous request timeout (15 min).
- **Builder agent (new runtime)** runs the slow work **autonomously, fire-and-forget**.
  It is a Strands agent — the natural executor for "use the web-search MCP tool + generate"
  — so it reuses the same MCP/gateway machinery the main agent already has, instead of
  hand-rolling an MCP client inside a Lambda.
- **No Step Functions:** the job is one bounded unit (~5 min, well under AgentCore's async
  session budget of up to 8h on microVMs), not a long fan-out/retry-heavy pipeline. SFN
  would be ceremony for no payoff.
- **No supervisor / third runtime:** there is one interactive agent and one background
  worker. Nothing to coordinate. The main agent's fire-and-forget invoke IS the handoff.
- **AgentCore async, not synchronous:** the builder is invoked as an async/long-running
  session (not a synchronous request), so it is bound by the multi-hour session budget,
  NOT the 15-minute synchronous request timeout. While actively working it reports
  `HealthyBusy` and is not idle-terminated.

## Architecture

```
User: "add threat actor X"
  Main agent — create_profile tool (HITL):
    1. DEDUP CHECK (fast, synchronous, user-visible)
         - normalized id/name/alias match against existing profiles
         - semantic vector-similarity check (embed proposed name+intent, SearchVectors)
         - if exists / likely-duplicate  -> STOP, tell user (route to enrich instead).
           NO research loop runs.
    2. HITL interrupt: "Create a new profile for <X> (all 12 sections)? [Approve/Reject]"
       (nothing is invoked while pending)
    3. On approve -> fire-and-forget ASYNC invoke of the Builder runtime, return "started"
       On reject  -> nothing happens
  Main agent: "Creation started. It takes a few minutes; search for <X> shortly."

  Builder runtime (autonomous, async session, OTEL-instrumented):
    - re-run the dedup check (defense in depth; never trust the caller)
    - for each of the 12 sections:
         web-search research (managed connector via AgentCore Gateway MCP)
         generate section text (uses the per-file_type EXAMPLE as a template)
         QUALITY GATE: length/field-count vs per-section minimums -> regenerate if thin
    - embed all 12 (Titan v2, 1024-d)
    - BatchWriteItem all 12 shards + metadata + provenance (one final write)
    - on any unrecoverable failure -> publish to SNS (out-of-band alert; user not notified)
```

## Trust model (decided)

- **One approval, for the create itself.** The analyst approves *that a profile will be
  created*, not each generated section. There is **no second HITL** on the generated text.
- The **quality gate** substitutes for human review of the content — it must be strict.
- The user cannot edit generated content, and does not get an in-band success/failure
  signal. Discovery is "search for the actor and see if it's there." Failures are handled
  out-of-band via **SNS** (operator alert), not surfaced to the user.

## The 12 sections (canonical)

Derived from `loader/content.py` `CONTENT_BUILDERS` — every new profile MUST have all 12:

`core_identity`, `core_description`, `summary`, `tactics_ttp`, `tactics_mitre`,
`detection`, `response`, `purple_team`, `tabletop`, `ai_tooling`, `cloud_general`,
`cloud_aws`.

Each section's generated JSON must carry the same fields the corresponding
`_content_*` builder reads (e.g. `core_identity` -> aliases/category/target_sectors/
target_regions; `tactics_mitre` -> mitre_tactics + mitre_techniques[{id,name}]; etc.), so
that `derive_content` and `derive_metadata` produce corpus-consistent Content + metadata.

## Dedup / existence check (variation-aware — required)

Runs BEFORE any research. Two tiers; either tier tripping = treat as duplicate:

1. **Normalized exact-ish match.** Normalize the proposed id, name, and any provided
   aliases (lowercase; strip punctuation, whitespace, and common suffixes like "group",
   "APT", "team"; collapse separators). Compare against the normalized `ProfileId`,
   `Name`, and `Aliases` of existing profiles. Catches "0ktapus" vs "Oktapus" vs
   "0ktapus group", "ALPHV" vs "ALPHV/BlackCat", etc.
2. **Semantic similarity.** Embed the proposed name + short intent and run `SearchVectors`
   (reuse `retrieve_profiles` plumbing). If the top match's COSINE distance is within a
   duplicate threshold (tighter than the retrieval relevance threshold), surface the
   likely-existing actor and STOP rather than silently creating a near-duplicate.

On a hit, the tool returns a clear message naming the existing profile and suggesting
`enrich_profile` instead — no builder invoke, no research.

## Quality gate + example

- **Per-section minimums** derived empirically from the existing `threat-profiles/` corpus
  (measure current section content lengths / field counts, set thresholds from those) so
  "on par with existing profiles" is defensible, not arbitrary.
- Each section prompt includes a **worked EXAMPLE** for that `file_type` (a real shard
  shape from the corpus) so the model matches structure and depth.
- A generated section failing its minimum is **regenerated** (bounded retries) before the
  profile is assembled. If a section can't pass after retries, the build fails cleanly
  (SNS) rather than writing a thin profile.

## Observability (OTEL / ADOT) — required for the new runtime

The builder runtime is instrumented exactly like the main agent:
- `opentelemetry-instrument` wraps the entrypoint; `OTEL_PYTHON_DISTRO=aws_distro` +
  `OTEL_PYTHON_CONFIGURATOR=aws_configurator` (platform injects endpoint/protocol/resource
  attrs — do NOT hardcode them).
- Unified telemetry: spans land in the builder's own runtime log group. Section research /
  generation / write show up as spans, verifiable with the same approach as
  `scripts/verify_otel_rag.py`.

## Authentication between the runtimes

There are two DISTINCT auth models, and the builder is NOT reached the way the browser
reaches the main agent:

- **Browser → main agent = Cognito JWT (OIDC).** The main runtime has a
  `CustomJWTAuthorizer` (Cognito user pool) in the CFN, so a human must present a valid
  access token. This is the interactive, user-facing door.
- **Main agent → builder = IAM / SigV4 (machine-to-machine).** The builder runtime has
  **no `AuthorizerConfiguration`** — it is authorized purely by AWS IAM. There is no JWT,
  no token to pass, and no human involved on this hop.

How the main agent authenticates the invoke, concretely:
1. The main agent runs under its own execution role (`AgentCoreRole`); AgentCore injects
   that role's temporary credentials into the container.
2. `launch_builder` calls `boto3` `invoke_agent_runtime(...)`, which **SigV4-signs** the
   request with those role credentials automatically (no secret is handled in code).
3. The builder has no JWT authorizer, so AgentCore authorizes by IAM: it checks that the
   calling principal holds `bedrock-agentcore:InvokeAgentRuntime` on the builder's ARN.
4. That exact grant is the `InvokeBuilderRuntime` statement on `AgentCoreRole` in the CFN,
   scoped to the builder runtime ARN (least privilege — only the main agent's role can
   invoke it).

Notes:
- The builder's `NetworkMode` is `PUBLIC`, but "public network" ≠ "public auth": PUBLIC
  only grants internet egress (needed for Bedrock + web search). Invoking the builder is
  still gated entirely by IAM, so it is not callable from the frontend or the public
  internet — only by principals in the account holding the explicit grant.
- The builder does not touch AgentCore Memory and has no Cognito relationship; it is a
  stateless internal worker.

## Infrastructure added

- **Builder ECR repo** + **Builder AgentCore Runtime** (own container image, OTEL env).
- **Builder IAM role:** Bedrock invoke (Claude + Titan), AgentCore Gateway invoke
  (web-search MCP), DynamoDB write (`BatchWriteItem`/`Query`/`GetItem` on the table),
  SNS publish.
- **SNS topic** for builder failure alerts (operator-subscribed).
- **Main runtime role** gains permission to async-invoke the builder runtime
  (`bedrock-agentcore:InvokeAgentRuntime`).
- Builder runtime ARN + SNS topic ARN wired into the main agent's env (for the tool) and
  the builder's env, via CFN outputs / parameters.

## Failure handling

- Builder wraps the whole build in a top-level try/except -> SNS publish with the actor id
  and error. Optionally also set the runtime/Lambda-style async failure destination as a
  backstop.
- **Atomic-ish write:** all 12 sections are embedded and written in ONE final
  `BatchWriteItem` pass. A mid-build failure therefore writes NOTHING (no half-profiles).

## Explicitly out of scope

- Editing generated content / second HITL review.
- In-band progress or completion status to the user (no status shard, no polling).
- Bulk/multi-profile creation (would justify revisiting Step Functions or Streams->Lambda
  auto-embed per DECISIONS.md ADR-2/ADR-7).

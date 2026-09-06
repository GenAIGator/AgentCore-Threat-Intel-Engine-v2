# Architecture Decisions — Threat Intelligence Engine v2

This records the key decisions and trade-offs. The headline one — the RAG store — includes
an explicit demo-vs-production analysis, per the project's learning goal.

## ADR-1: Use DynamoDB vector search as the RAG store (demo choice)

**Decision.** Store each threat-profile shard as a DynamoDB item with its own embedding and
retrieve via `SearchVectors`, instead of v1's Bedrock Knowledge Base on S3 Vectors.

**Why (for this project).**
- The explicit goal is to **learn DynamoDB vector search**.
- One store for operational data *and* vectors: the same item you `GetItem`/`Query` for the
  HITL flow is the one that gets searched — no separate ingestion copy to keep in sync.
- Metadata becomes first-class DynamoDB attributes usable as `INLINE_FILTER`s and for direct
  queries.
- The HITL "update a profile and re-embed in place" story is clean: `UpdateItem` the shard,
  overwrite `Embedding`, and the index re-derives asynchronously.

### Would this be the right production choice?

**For this corpus — probably not.** These ~1630 shards are small, mostly static, and
read-heavy. That profile fits the **S3 Vectors + managed Bedrock KB** sweet spot: cheaper
storage for cold vectors, and AWS owns chunking, embedding, ingestion, and retrieval. v1's
design is the more sensible production baseline for this exact data.

**DynamoDB vector search wins in production when:**
- Vectors live alongside **hot operational data** you already read/write per item
  (per-user/tenant records, agent memory, product catalogs with live inventory).
- You need **single-digit-ms** ANN co-located with those items and a single write path.
- You want **per-tenant isolation** via a HASH key, or **scale-to-zero** for bursty traffic.
- You're already all-in on DynamoDB operationally and want to avoid a second datastore.

**S3 Vectors (+ managed KB) wins when:**
- The corpus is **large and mostly cold**; storage cost dominates.
- You want **managed RAG** (ingestion jobs, chunking, retrieval) with minimal code.
- The data is document-like and updated in batches rather than per-item.

**Net:** great learning vehicle here; for a real deployment of *this* knowledge base, prefer
S3 Vectors. The app is structured so retrieval is isolated behind `retrieve_profiles`, so the
store could be swapped with limited blast radius.

## ADR-2: One embedding per shard, composite key `(ProfileId, ShardId)`

**Decision.** Each `file_type` shard is its own DynamoDB item and its own embedding; the
actor id is the partition key (`ProfileId`) and the shard/`file_type` is the sort key
(`ShardId`). Actor/section identity lives in first-class item **attributes**
(`ProfileId`, `Name`, `FileType`, `ShardId`) — separate from the embedded `Content` — so
every item self-identifies at retrieval time regardless of what its text says.

### Why

- **Retrieval precision.** A query about detection matches the detection shard, not a
  diluted per-actor blob. (v1 already embeds per-shard: the corpus is pre-chunked into
  one file per `file_type`, i.e. the file *is* the chunk.)
- **Operational access.** `Query(ProfileId)` fetches a whole actor for the enrich flow;
  `GetItem(ProfileId, ShardId)` targets one shard to update.
- **Titan token limits.** Avoids truncating a concatenated per-actor document before it's
  embedded.

**Trade-off.** More items (~1,630 seed shards) and more embedding calls at load time.
Acceptable for a one-time seed; the production alternative (DynamoDB Streams → Lambda
auto-embed) is documented but not built.

### Chunking — current approach and a known limitation

Today each shard is embedded as a single fixed, non-split chunk — one `file_type` shard →
one `Content` string → one embedding. This is inherited from v1's S3 Vectors design,
which pre-chunked the corpus into per-`file_type` files (the file is the chunk). It works
well for the **seed** corpus because those shards were authored to a bounded size
(~500 characters each).

That assumption breaks down for the **richer, generated** content v2 now produces:
`enrich_profile` rewrites a shard from web research, and `create_profile` generates all
12 sections from scratch. A generated section can be far longer than a hand-authored seed
shard (observed: ~6,000–6,500 characters vs. ~500), so embedding it as one chunk risks:

- **Diluted embeddings** — a single vector averaged over a long, multi-topic section
  retrieves less precisely than several focused vectors would; and
- **Token-limit pressure** — a long enough section approaches Titan's input limit, where
  content would be truncated before it's embedded.

### Recommended evolution (not yet built)

Move from fixed whole-shard chunks to a **size-aware splitting strategy for large
shards**: split an over-length section into multiple sub-chunks, embed each, and store
them as sibling items under the same `ProfileId`, extending `ShardId` with a zero-padded
suffix (`detection#01`, `detection#02`, …).

**How to split (dispatch by field shape):**

- **List / dict fields** (most sections — e.g. `detection_opportunities`, `tooling`,
  `common_tactics`) — split on field / list-item boundaries, packing whole items to a
  target size (~1,000–1,500 characters). Never cut a list item; no overlap needed.
- **Free-text prose fields** (only `description`, `summary`) — split on sentence
  boundaries with a small (~1 sentence) overlap so a fact spanning a boundary isn't lost.

**Example layout:**

```
ProfileId   ShardId          FileType      Content (embedded)
team_pcp    detection#01     detection     <sub-topic 1, ~1,200 ch>
team_pcp    detection#02     detection     <sub-topic 2, ~1,200 ch>
team_pcp    detection#03     detection     <sub-topic 3, ~1,200 ch>
```

Notes:

- **`FileType` stays the bare section name** (`detection`) on every sub-chunk, so the
  existing `FileType` inline filter still scopes a whole section without change.
- **Zero-pad the suffix** (`#01`, not `#1`) so sort order stays correct past nine
  sub-chunks.
- **Reuse the existing `derive_content` formatter** on each sub-shard so sub-chunk text
  is formatted identically to today's shards (stable, idempotent embeddings).

**Optional — per-section summary chunk.** A short summary of the section MAY also be
embedded as `detection#00` (uniformly suffixed, ahead of the detail chunks). It serves
high-level queries ("what is this actor's detection posture?") while the `#01…#NN` chunks
serve specific ones — a lightweight two-tier (overview vs. detail) retrieval layer. This
is optional; the core decision above works without it.

**Considered lighter alternative — summary-embed.** Instead of splitting, embed a concise
generated summary as `Content` and keep the full section text in a **non-embedded**
`Body` attribute for display. This fixes the dilution problem with no split/reassembly
machinery, at the cost of matching on the summary rather than the exact sentence. For a
small, mostly-static corpus this may be the better ROI; sub-chunk splitting is warranted
when paragraph-level retrieval precision is needed.

### Impact on retrieval

- **Query path: unchanged.** Retrieval already spans all shards (no HASH key, ADR-3) and
  ranks by distance, so multiple sub-chunks per section slot in with no change to the
  `SearchVectors` call, index, or inline filters.
- **Presentation: a small change.** Project `ShardId` and group multiple sub-chunk hits
  under one `ProfileId / FileType` heading so the model sees one coherent section rather
  than scattered `detection#01`, `detection#02` entries. Optionally, if any sub-chunk of a
  section ranks, expand to the full section via
  `Query(ProfileId, begins_with(ShardId, "detection"))` — precise matching, complete
  context ("small-to-big" retrieval).
- **Association is preserved for free.** Each sub-chunk is still its own item carrying
  `ProfileId` / `Name` / `FileType`, so a hit always knows which actor and section it
  belongs to — the split never risks losing attribution.

**Ownership.** The `enrich_profile` / `create_profile` writers own the split-and-embed
step; the loader/seed path is unaffected (seed shards stay seed-sized and need no
splitting).

### No infrastructure change required

All of the above stays within the current `(ProfileId, ShardId)` table and the existing
`FileType` inline filter — no CloudFormation or vector-index change is needed for either
the sub-chunk or summary-embed approach.

## ADR-3: No HASH key on the vector index

**Decision.** The vector index has no HASH key; `FileType` and `Country` are `INLINE_FILTER`s.

**Why.** Retrieval must range over the entire corpus. A HASH key forces every `SearchVectors`
call to a single partition value (learned in `demo/`), which would prevent cross-actor search.
Inline filters give optional scoping ("detection shards for Chinese actors") without
fragmenting the space. If per-tenant isolation were a hard requirement, a HASH key would be
the right call — but it isn't here.

## ADR-4: Full-stack AgentCore pattern (SPA + FastAPI/Strands runtime)

**Decision.** React/Vite SPA + FastAPI/Strands on AgentCore Runtime, Cognito OIDC +
`CustomJWTAuthorizer`, AgentCore Memory, single `/invocations` endpoint.

**Why.** This pattern solves streaming, tool-use, auth, and HITL cleanly and is meant to
double as a reusable production reference, so the app can focus on its domain and the
retrieval store rather than re-solving the plumbing.

## ADR-5: SSE for generation, synchronous POST for HITL resume

**Decision.** Stream generated answers over SSE; handle the approve/reject resume as a plain
synchronous JSON request/response.

**Why.** `stream_agent_response` yields `{"content":...}` chunks and ends with
`{"pending_approval":...}` on interrupt; the resume POST carries `responses:[...]` and is
handled synchronously via `agent.invoke_async([{interruptResponse:...}])`. Keeping the resume
synchronous simplifies the request/response contract for a discrete approve/reject decision.

## ADR-6: HITL enrichment updates the shard in place (write + re-embed)

**Decision.** On approval, overwrite the existing shard's `Content`, regenerate `Embedding`,
and set provenance (`Source="web-enrichment"`, `SourceUrl`, `LastUpdated`, `UpdatedBy`).

**Why.** Chosen over appending a new enrichment shard for simplicity and because a single
authoritative shard per `file_type` keeps retrieval clean. **Trade-off:** the prior content is
overwritten (no built-in version history) — `RawJson`/provenance give partial traceability;
full versioning is a possible enhancement.

## ADR-7: Local loader run by `deploy.sh`; `us-east-1` region guard

**Decision.** A local Python loader embeds and writes all shards, invoked as a step in
`deploy.sh`. The script hard-fails if the region isn't `us-east-1`.

**Why.** A simple, inspectable seed suits a learning starter better than a Streams+Lambda
pipeline (which is documented as the production path). The region guard prevents a confusing
partial deploy, since the managed Web Search connector requires `us-east-1`.

## Operational notes (DynamoDB vector search — learned in `demo/`)

Carried forward so implementers don't rediscover them:
- **Response shape:** `SearchVectors` returns `SearchResults` (list of `{Item, Score}`),
  **not** `Items`.
- **`SearchVector`** is a plain list `[{"N":...}, ...]`, not `L`-wrapped.
- **COSINE `Score` is a distance:** lower = more similar; results ascend down the ranked list.
- **Backfill/eventual consistency:** after the index is `ACTIVE`, the search endpoint can lag
  and backfill can take time even for few items — retry `SearchVectors` until the first success.
- **CloudFormation:** `SearchSchema` entries use `SearchSchemaElementType`, not `KeyType`;
  cfn-lint may flag the new `VectorIndexes` property until its spec updates.
- **SDK:** needs boto3 with `search_vectors` (>= 1.43.88); run inside the project venv.

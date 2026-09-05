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

**Decision.** Each `file_type` shard is its own item and its own embedding; the actor id is
the partition key and the shard/`file_type` is the sort key.

**Why.**
- **Retrieval precision:** a query about detection matches the `detection` shard, not a
  diluted per-actor blob. (v1 already embeds per-shard via `ChunkingStrategy: NONE`.)
- **Operational access:** `Query(ProfileId)` fetches a whole actor for the enrich flow;
  `GetItem(ProfileId, ShardId)` targets one shard to update.
- **Titan token limits:** avoids truncating a concatenated per-actor document.

**Trade-off:** more items (~1630) and more embedding calls at load time. Acceptable for a
one-time seed; the production alternative (Streams→Lambda auto-embed) is documented but not built.

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

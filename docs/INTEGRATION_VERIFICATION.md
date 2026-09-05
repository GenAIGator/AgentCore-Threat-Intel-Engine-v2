# Integration Verification Runbook

Post-deploy verification for **Threat Intelligence Engine v2** (spec task 14). Run this
after `deploy.sh` completes to confirm the retrieval path, ranking quality, loader
idempotency, and the enrichment write-back all work end to end against the live stack.

The recommended flow is: **deploy a small subset first → verify → run the HITL flow →
load the full corpus → re-verify.** Verifying against a 25-item subset gives fast
feedback and cheap embeddings before committing to the full ~1630-shard load.

> These steps require a **live, deployed stack** and **valid AWS credentials** in
> `us-east-1`. The offline unit tests in `scripts/tests/test_integration_verify.py`
> cover the script's pure logic (ranking assertion, PASS/FAIL summary, warm-up retry)
> without AWS.

---

## Prerequisites

- The stack is deployed (`./deploy.sh`) and its DynamoDB vector table exists.
- AWS credentials for the deployment account are active, region **`us-east-1`**.
- `uv` is installed (the script runs under the `agent/` uv project so `boto3`, the
  agent helpers, and the loader resolve).

Resolve the deployed resource names from the CloudFormation stack outputs:

```bash
STACK_NAME=ThreatIntelEngineV2Stack
export AWS_REGION=us-east-1
export DDB_TABLE_NAME=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --region "$AWS_REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='TableName'].OutputValue" --output text)
export DDB_VECTOR_INDEX=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --region "$AWS_REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='VectorIndexName'].OutputValue" --output text)
```

The script reads these env vars (matching `agent/src/config.py`):

| Env var            | Purpose                                  | Default              |
| ------------------ | ---------------------------------------- | -------------------- |
| `AWS_REGION`       | Region (must be `us-east-1`)             | `us-east-1`          |
| `DDB_TABLE_NAME`   | Base table                               | `ThreatProfilesV2`   |
| `DDB_VECTOR_INDEX` | Vector index                             | `profile-embeddings` |
| `EMBEDDING_MODEL`  | Titan model (keep in sync with the load) | Titan v2             |

---

## Step 1 — Deploy a subset (`LOAD_LIMIT`)

`deploy.sh` honors `LOAD_LIMIT`, which maps to the loader's `--limit` flag, so it
ingests only the first N shards. Deploy with a small subset first:

```bash
LOAD_LIMIT=25 ./deploy.sh
```

This provisions the full stack but seeds only 25 shards — enough to exercise search and
ranking quickly. (Note: with only 25 shards the specific known-query actors may not be
present; either bump `LOAD_LIMIT` or expect the ranking check to be validated fully on
the full-corpus pass in Step 5.)

## Step 2 — Wait for the index and verify

A freshly created DynamoDB vector index re-derives from the base-table writes and is
briefly unqueryable (Req 2.5). The verification script polls `SearchVectors` until the
first success before running any other check, so you can run it immediately:

```bash
uv run --project agent python scripts/integration_verify.py \
  --skip-idempotency \
  --readiness-timeout 600
```

What it checks:

- **`index_ready`** — retries `SearchVectors` (embedding a probe query via Titan),
  backing off on the warm-up `ValidationException`, until the first success or timeout
  (Req 2.5).
- **`semantic_ranking`** — runs the known queries and asserts the expected `ProfileId`
  appears in the top-K (Req 3.1):
  - "Okta phishing kit …" → `0ktapus`
  - "Russian ransomware-as-a-service group known as BlackCat" → `alphv_blackcat`

The script prints a per-check `PASS`/`FAIL`/`SKIP` summary and **exits non-zero** if any
executed check fails, so it can gate a pipeline.

To also verify the enrichment write-back at the DynamoDB layer (mutates a shard, then
restores it):

```bash
uv run --project agent python scripts/integration_verify.py \
  --skip-idempotency \
  --check-enrichment \
  --enrich-profile-id 0ktapus \
  --enrich-shard-id summary
```

## Step 3 — Run the enrich HITL flow end to end (manual, via the runtime)

The DynamoDB-level write-back check above covers the *terminal* half of enrichment. The
full human-in-the-loop round-trip goes through the deployed AgentCore Runtime and needs
a signed request (SigV4 or a Cognito JWT), so it is a **manual** step (Req 5.4):

1. Open the deployed frontend (the CloudFront URL printed by `deploy.sh`) and sign in
   via Cognito.
2. Ask the agent to enrich an existing profile, e.g.
   *"Research the latest on ALPHV/BlackCat and update its summary shard."*
   The agent retrieves the current shard, does web research, drafts an update, and the
   stream ends with a `pending_approval` frame carrying the proposed change + sources.
3. The frontend renders the approval card. Click **Approve**. This sends the synchronous
   resume `POST` to `/invocations`:

   ```json
   {
     "responses": [{ "interrupt_id": "<id>", "response": "yes" }],
     "action": "enrich",
     "session_id": "<session>"
   }
   ```

   (Reject sends `"response": "no"` and writes nothing — Req 5.5.)
4. On approval, the shard is updated in place, re-embedded, and stamped with
   `Source="web-enrichment"` provenance.
5. Re-query the same actor in the chat and confirm the updated content is retrievable
   (the vector index re-derives the new embedding asynchronously, so allow a short lag).

Equivalent scripted round-trip against the runtime endpoint (advanced; requires a valid
bearer token) — the endpoint URL is printed by `deploy.sh` as `AgentCore:`:

```bash
# 1) Kick off the enrichment (streams to a pending_approval frame carrying interrupt_id)
curl -N -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"prompt":"Update the summary shard for alphv_blackcat from recent reporting.",
       "session_id":"verify-hitl-1","stream":true}' \
  "$AGENTCORE_ENDPOINT"

# 2) Approve (synchronous resume — not SSE)
curl -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d '{"responses":[{"interrupt_id":"<id-from-step-1>","response":"yes"}],
       "action":"enrich","session_id":"verify-hitl-1"}' \
  "$AGENTCORE_ENDPOINT"
```

## Step 4 — Load the full corpus

Re-run the deploy without `LOAD_LIMIT` (the stack is already up, so this mainly re-runs
the loader against the full ~1630 shards), or run the loader directly:

```bash
# Option A: re-run deploy with no subset limit
./deploy.sh

# Option B: run the loader directly against the deployed table
uv run --project loader python loader/load_profiles.py --table "$DDB_TABLE_NAME"
```

## Step 5 — Re-verify (full corpus, including idempotency)

Now run every check, including the loader idempotency re-run (loads twice, asserts a
stable item count — Req 1.6):

```bash
uv run --project agent python scripts/integration_verify.py \
  --check-enrichment
```

Expected `PASS` for `index_ready`, `semantic_ranking`, `idempotency`, and
`enrichment_writeback`. A non-zero exit indicates at least one executed check failed;
read the summary block for the offending check and detail.

> `--idempotency-limit N` restricts the idempotency re-run to N shards — handy if you
> want a fast idempotency spot-check without re-loading the full corpus twice.

---

## What the script verifies vs. what is manual

| Concern                              | Requirement | How                                                        |
| ------------------------------------ | ----------- | ---------------------------------------------------------- |
| Index becomes queryable (warm-up)    | 2.5         | `check_index_ready` — poll/retry `SearchVectors`           |
| Semantic ranking on known queries    | 3.1         | `check_semantic_ranking` — expected `ProfileId` in top-K   |
| Loader idempotency (stable count)    | 1.6         | `check_idempotency` → loader `verify_idempotency`          |
| Enrichment write-back retrievable    | 5.4         | `check_enrichment_writeback` (DynamoDB-level)              |
| Full HITL interrupt → approve → save | 5.4         | **Manual** via the runtime `/invocations` (Step 3)         |

The manual runtime round-trip is separated out because it requires a signed request
against the deployed AgentCore Runtime (SigV4/JWT), which the offline/CLI tooling here
does not perform.

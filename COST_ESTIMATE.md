# Cost Estimate — Threat Intelligence Engine v2

> **⚠️ These figures are ROUGH APPROXIMATIONS and will vary — often significantly —
> with your usage, region, traffic, model choice, and current AWS pricing.** They are
> here to build intuition about *what drives cost*, not to predict your bill. Always check
> the linked AWS pricing pages for authoritative, current rates, and use the
> [AWS Pricing Calculator](https://calculator.aws/) and **AWS Cost Explorer / Budgets** on
> your own account for real numbers. Nothing here is a quote or a guarantee.

This stack is a **demo / learning** deployment. Most services are usage-based, so an idle
stack costs far less than one under active use. The dominant cost drivers are the two
**AgentCore runtimes**, **Amazon Bedrock** model calls, and **CloudWatch/X-Ray Transaction
Search** (configured here at **100% trace indexing**, which is deliberately not the cheap
default — see below).

## How each service bills (the model matters more than the number)

| Service | What you pay for | Rough driver | Notes |
|---|---|---|---|
| **Bedrock AgentCore Runtime** (×2: agent + builder) | Compute while a session is active (CPU/GB-seconds) | Time spent handling requests / running builds | The builder runs minutes per profile creation; the agent bills while answering. Idle ≈ no compute charge. [pricing](https://aws.amazon.com/bedrock/agentcore/pricing/) |
| **Bedrock — Claude Sonnet** (generation) | Per input + output **token** | Answer length × traffic; builder generates 12 sections per new profile (token-heavy) | Biggest variable cost under active use. [pricing](https://aws.amazon.com/bedrock/pricing/) |
| **Bedrock — Titan Text Embeddings v2** | Per input **token** embedded | Query embeddings + shard embeddings (seed load ≈ 1707 shards once; each new profile = 12) | Cheap per call vs. Claude, but the one-time corpus load embeds the whole corpus. |
| **AgentCore Gateway + managed Web Search** | Per gateway request / search | How often the agent (and builder) search the web | Builder web-researches each section, so a profile build = many searches. |
| **AgentCore Memory** | Stored records + retrieval | Conversation history + learned facts per analyst | Small for a demo. |
| **DynamoDB** (`PAY_PER_REQUEST` + vector index) | Per read/write request + storage + vector index | Retrieval reads, writes on enrich/create, vector storage | On-demand: no idle capacity charge; you pay per request. Vector index adds storage/query cost. [pricing](https://aws.amazon.com/dynamodb/pricing/on-demand/) |
| **CloudWatch + X-Ray Transaction Search** | Ingested spans/logs + **indexed traces** | **100% trace indexing** is set by `deploy.sh` | AWS indexes the first 1% free; **100% indexing can add meaningful cost under load.** Lower it (e.g. 5%) to save — see below. [CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/) |
| **Amazon S3 + CloudFront** (frontend hosting) | Storage + requests + egress | SPA is tiny; egress scales with visitors | Negligible for a demo. |
| **Amazon Cognito** | Monthly active users | Number of analysts signing in | Free tier covers small demos. |
| **Amazon ECR** | Image storage + data transfer | Two repos (agent + builder) + `:buildcache` | A few GB; small monthly storage cost. |
| **Amazon SNS** (build-failure alerts) | Per notification | Only on builder failures | Effectively $0 in normal use. |

## Rough scenarios (illustrative only — NOT a quote)

These assume **us-east-1**, on-demand pricing, and are deliberately order-of-magnitude.
Your actual cost depends on real token counts, request volume, and current rates.

- **Idle stack (deployed, no traffic):** small, mostly fixed — DynamoDB/vector storage,
  ECR image storage, Memory storage, minimal CloudWatch. Runtimes idle ≈ no compute charge.
  Think "a few dollars a month," but confirm on your account.
- **Light demo use (a handful of queries + a few enrichments per day):** dominated by
  Bedrock tokens + a little runtime compute + trace indexing. Modest.
- **Creating a new profile (per build):** the builder spins up, does ~12 rounds of web
  search + Claude generation + embeddings, then writes. This is the most token- and
  search-intensive single action — each build is a discrete, noticeable cost. Avoid
  creating profiles in a loop for testing.
- **100% X-Ray indexing under sustained traffic:** the line item most likely to surprise
  you if the stack gets heavy use, because it indexes *every* trace.

## Biggest cost drivers (watch these)

1. **Bedrock Claude tokens** — scale with answer length and traffic; profile creation is
   especially token-heavy (12 sections, with retries on thin sections).
2. **100% X-Ray trace indexing** — great for a demo (see every trace), but
   `deploy.sh` sets `DesiredSamplingPercentage: 100`. Under load this is a real cost.
3. **Two AgentCore runtimes** — the builder is separate compute; it only bills while
   building, but each build is minutes of active session.
4. **The one-time corpus load** — embeds ~1707 shards. It now **auto-skips when the table
   already has data** (see `deploy.sh`), so you pay this once, not on every redeploy.

## How to keep costs down

- **Don't reload the corpus needlessly.** `deploy.sh` auto-skips the load when the table
  already has data; only `FORCE_LOAD=1` re-embeds everything.
- **Lower trace indexing.** In `deploy.sh`, change the X-Ray indexing rule
  `DesiredSamplingPercentage` from `100` to something like `5` to cut Transaction Search
  cost while still sampling traces.
- **Tear the stack down when not in use.** Deleting the CloudFormation stack removes the
  recurring costs (runtimes, DynamoDB, hosting). Re-deploy when needed.
- **Set an AWS Budget / alert** so you're notified before a surprise.
- **Avoid loops that create profiles or hammer the agent** during testing — each is a
  distinct Bedrock + web-search cost.
- **Consider the S3 Vectors alternative** for a real deployment of this corpus — see
  [`DECISIONS.md`](./DECISIONS.md) ADR-1; it can be more cost-effective for a large,
  mostly-cold corpus.

## Authoritative sources

- [AWS Pricing Calculator](https://calculator.aws/)
- [Bedrock AgentCore pricing](https://aws.amazon.com/bedrock/agentcore/pricing/)
- [Amazon Bedrock pricing](https://aws.amazon.com/bedrock/pricing/)
- [DynamoDB on-demand pricing](https://aws.amazon.com/dynamodb/pricing/on-demand/)
- [CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/) (Transaction Search / trace indexing)
- [CloudFront pricing](https://aws.amazon.com/cloudfront/pricing/) · [S3 pricing](https://aws.amazon.com/s3/pricing/) · [Cognito pricing](https://aws.amazon.com/cognito/pricing/) · [ECR pricing](https://aws.amazon.com/ecr/pricing/)

_Content compiled from AWS's public pricing model; specific rates change over time and were
not copied verbatim. Verify current pricing before relying on any figure here._

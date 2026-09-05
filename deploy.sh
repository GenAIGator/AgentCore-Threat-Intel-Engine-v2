#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""

# -------------------------------------------------------------------
# deploy.sh — Threat Intelligence Engine v2 one-command deploy
#
# Builds/pushes the ARM64 agent image, deploys the CloudFormation
# stack (DynamoDB vector table, AgentCore Runtime/Memory/Gateway,
# Cognito, S3+CloudFront hosting), loads the threat-profile corpus,
# and builds/publishes the frontend.
#
# Reads configuration from agent/.env (if present) and environment
# variables. Fails fast on any step (set -e).
#
# REGION GUARD: This deployment MUST run in us-east-1. The AgentCore
# managed Web Search connector is only available there. The guard
# below runs before any AWS mutation and before any credential call.
# -------------------------------------------------------------------

# --- Resolve paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # v2 app root (this dir)
AGENT_DIR="$SCRIPT_DIR/agent"
LOADER_DIR="$SCRIPT_DIR/loader"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
CFN_DIR="$SCRIPT_DIR/cfn"
ENV_FILE="$AGENT_DIR/.env"

# --- Load agent/.env if present ---
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# --- Resolve region (env vars, then aws configure, default us-east-1) ---
AWS_REGION="${CDK_DEFAULT_REGION:-${AWS_DEFAULT_REGION:-${AWS_REGION:-$(aws configure get region 2>/dev/null || echo "us-east-1")}}}"

# --- REGION GUARD (Req 9.1) ---
# Must be the FIRST actionable step, before any AWS mutation or
# credential lookup (aws sts), so it is testable offline.
if [[ "$AWS_REGION" != "us-east-1" ]]; then
  echo "ERROR: Threat Intelligence Engine v2 must be deployed in us-east-1." >&2
  echo "       Resolved region is '$AWS_REGION'." >&2
  echo "" >&2
  echo "       The AgentCore managed Web Search connector (used by the agent's" >&2
  echo "       web-search tool) is only available in us-east-1. Deploying to any" >&2
  echo "       other region would produce a stack whose web search cannot function." >&2
  echo "" >&2
  echo "       Set your region to us-east-1 and retry, e.g.:" >&2
  echo "         export AWS_REGION=us-east-1" >&2
  echo "         aws configure set region us-east-1" >&2
  exit 1
fi

# --- Configuration (from env vars, resolved after the region guard) ---
AWS_ACCOUNT_ID="${CDK_DEFAULT_ACCOUNT:-${AWS_DEFAULT_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}}"
STACK_NAME="${STACK_NAME:-ThreatIntelEngineV2Stack}"
BEDROCK_MODEL_ID="${BEDROCK_MODEL_ID:-us.anthropic.claude-sonnet-4-6}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"

ECR_REPO_NAME="$(echo "$STACK_NAME" | tr '[:upper:]' '[:lower:]')-agent"  # lowercase stack name
BUILDER_ECR_REPO_NAME="$(echo "$STACK_NAME" | tr '[:upper:]' '[:lower:]')-builder"

# Immutable image tag per build — NEVER ':latest' (a mutable tag makes deployments
# non-reproducible and lets a later push silently change what a stack "is" running).
# Prefer the git short SHA (traceable to a commit); mark a dirty tree; fall back to a
# UTC timestamp outside a git checkout. The CloudFormation stack is still deployed by
# immutable DIGEST (repo@sha256:...), so this tag is primarily a human-readable handle
# and a stable buildx cache key. Override with IMAGE_TAG=... if desired.
if [[ -z "${IMAGE_TAG:-}" ]]; then
  _git_sha="$(git -C "$SCRIPT_DIR" rev-parse --short=12 HEAD 2>/dev/null || true)"
  if [[ -n "$_git_sha" ]]; then
    if ! git -C "$SCRIPT_DIR" diff --quiet 2>/dev/null || \
       ! git -C "$SCRIPT_DIR" diff --cached --quiet 2>/dev/null; then
      _git_sha="${_git_sha}-dirty"
    fi
    IMAGE_TAG="git-${_git_sha}"
  else
    IMAGE_TAG="ts-$(date -u +%Y%m%d%H%M%S)"
  fi
fi
if [[ "$IMAGE_TAG" == "latest" ]]; then
  echo "ERROR: refusing to use the mutable ':latest' image tag. Unset IMAGE_TAG or set" >&2
  echo "       it to an immutable value (e.g. a git sha or timestamp)." >&2
  exit 1
fi
ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME:$IMAGE_TAG"
BUILDER_ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$BUILDER_ECR_REPO_NAME:$IMAGE_TAG"

echo "============================================================"
echo " Threat Intelligence Engine v2 — Deployment"
echo "============================================================"
echo " Stack:    $STACK_NAME"
echo " Account:  $AWS_ACCOUNT_ID"
echo " Region:   $AWS_REGION"
echo " Model:    $BEDROCK_MODEL_ID"
echo " Img tag:  $IMAGE_TAG (immutable; deployed by digest)"
echo " ECR:      $ECR_URI"
echo " Builder:  $BUILDER_ECR_URI"
echo "============================================================"
echo ""

# --- Preflight: Docker build path check ---
# Step 3 prefers `docker buildx` (with an ECR registry cache for the slow uv
# layer) and falls back to a plain `docker build` + `docker push` when buildx
# is unavailable. Surface which path will run up front, using the same
# predicates Step 3 uses so the messages stay consistent with what actually
# runs. Plain `docker` is required either way, so a missing docker fails fast.
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed, but is required to build the agent image." >&2
  echo "       Install from https://docs.docker.com/get-docker/ and retry." >&2
  exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
  BUILDX_AVAILABLE=0
  BUILDX_CACHE=0
  echo "WARN: docker buildx not available; Step 3 will use the slower plain" >&2
  echo "      'docker build' path WITHOUT the ECR registry cache." >&2
  echo "      The agent image targets linux/arm64. If you are on x86_64," >&2
  echo "      install QEMU emulation first:" >&2
  echo "        docker run --rm --privileged multiarch/qemu-user-static --reset -p yes" >&2
else
  BUILDX_AVAILABLE=1
  # Registry cache export requires the docker-container (or remote) buildx
  # driver; the default `docker` driver cannot export a registry cache. Inspect
  # the active builder's driver so Step 3 only passes --cache-to/--cache-from
  # when it will actually work.
  driver="$(docker buildx inspect 2>/dev/null | awk -F': *' '/^Driver:/{print $2; exit}')"
  if [[ -z "$driver" ]]; then
    driver="$(docker buildx inspect --bootstrap 2>/dev/null | awk -F': *' '/^Driver:/{print $2; exit}')"
  fi
  if [[ "$driver" == "docker-container" || "$driver" == "remote" ]]; then
    BUILDX_CACHE=1
    echo "[OK] docker buildx available with cache-capable driver ($driver); Step 3 will use the ECR registry cache"
  elif docker buildx create --name tie-cache-builder --driver docker-container --use >/dev/null 2>&1 || docker buildx use tie-cache-builder >/dev/null 2>&1; then
    # The active builder uses the default `docker` driver, which can't export a
    # registry cache. Create/select a docker-container builder once; this
    # switches the global active builder for the rest of the script (fine).
    BUILDX_CACHE=1
    echo "[OK] created/selected buildx builder 'tie-cache-builder' (docker-container); Step 3 will use the ECR registry cache"
  else
    BUILDX_CACHE=0
    echo "WARN: docker buildx is present, but the active 'docker' driver can't export" >&2
    echo "      a registry cache and a docker-container builder couldn't be created." >&2
    echo "      Step 3 will build with buildx WITHOUT the ECR registry cache." >&2
  fi
fi
echo ""

# --- Step: enable CloudWatch Transaction Search (AgentCore observability) ---
# One-time, account-wide setup so agent tool calls (e.g. retrieve_profiles)
# surface as trace spans in CloudWatch -> GenAI Observability. This is an
# enhancement, not a hard requirement: each call is guarded so an already-enabled
# account or missing permissions won't abort the deploy (set -euo pipefail stays
# intact because every optional call is wrapped in `|| echo ... >&2`).
echo "Enabling CloudWatch Transaction Search (AgentCore observability)..."

# X-Ray needs permission to write spans into the CloudWatch Logs groups that back
# Transaction Search. Build the resource policy with the real account id/region
# (the policy doc is otherwise single-quoted, so interpolate via a heredoc).
POLICY_DOC=$(cat <<JSON
{"Version":"2012-10-17","Statement":[{"Sid":"TransactionSearchXRayAccess","Effect":"Allow","Principal":{"Service":"xray.amazonaws.com"},"Action":"logs:PutLogEvents","Resource":["arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:aws/spans:*","arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:/aws/application-signals/data:*"],"Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:xray:${AWS_REGION}:${AWS_ACCOUNT_ID}:*"},"StringEquals":{"aws:SourceAccount":"${AWS_ACCOUNT_ID}"}}}]}
JSON
)
aws logs put-resource-policy \
  --policy-name ThreatIntelXRayTransactionSearch \
  --region "$AWS_REGION" \
  --policy-document "$POLICY_DOC" \
  || echo "WARN: could not put X-Ray resource policy (may already exist / insufficient perms); continuing." >&2

# Route X-Ray trace segments to CloudWatch Logs (the Transaction Search backend).
# This is idempotent: once set, re-running errors with "already set to CloudWatchLogs".
# Check the current destination first so a re-deploy prints a clean "already enabled"
# note instead of a scary error+WARN.
_xray_dest="$(aws xray get-trace-segment-destination --region "$AWS_REGION" \
  --query Destination --output text 2>/dev/null || echo "")"
if [[ "$_xray_dest" == "CloudWatchLogs" ]]; then
  echo "[OK] X-Ray trace segment destination already set to CloudWatchLogs."
else
  aws xray update-trace-segment-destination --destination CloudWatchLogs --region "$AWS_REGION" \
    || echo "WARN: could not set X-Ray trace segment destination; continuing." >&2
fi

# Index 100% of traces so nothing is missed in the demo. NOTE: AWS indexes the
# first 1% free; 100% indexing can incur additional cost. Lower this (e.g. 5) to
# keep it cheaper if needed.
aws xray update-indexing-rule --name "Default" --region "$AWS_REGION" \
  --rule '{"Probabilistic":{"DesiredSamplingPercentage":100}}' \
  || echo "WARN: could not set X-Ray indexing rule; continuing." >&2

echo "NOTE: After first enablement, spans can take ~10 minutes to appear."
echo "      View them at CloudWatch -> GenAI Observability."
echo ""

# --- Step: build/push ARM64 images + cloudformation deploy (task 13.2) ---
# Two images are built: the main agent (context: agent/) and the autonomous
# profile-builder (context: the v2 ROOT, because builder/Dockerfile COPYs shared
# modules from agent/src and loader/). Each gets its own ECR repo + buildcache tag.

# --- Step 1: Create ECR repositories if they don't exist ---
echo "------------------------------------------------------------"
echo " Step 1/4: Ensuring ECR repositories exist..."
echo "           agent:   $ECR_REPO_NAME"
echo "           builder: $BUILDER_ECR_REPO_NAME"
echo "------------------------------------------------------------"
for _repo in "$ECR_REPO_NAME" "$BUILDER_ECR_REPO_NAME"; do
  # NOTE: repos are left tag-MUTABLE on purpose. We do NOT set IMMUTABLE tag mutability
  # because the buildx registry cache rewrites the ':buildcache' tag on every build, which
  # IMMUTABLE would reject (breaking the build cache). The "no mutable :latest" policy is
  # instead enforced by (a) using a unique per-build tag (never ':latest') and (b) deploying
  # by immutable digest (repo@sha256:...), so a given stack always runs an exact image.
  aws ecr describe-repositories --repository-names "$_repo" --region "$AWS_REGION" 2>/dev/null || \
    aws ecr create-repository \
      --repository-name "$_repo" \
      --region "$AWS_REGION" \
      --image-scanning-configuration scanOnPush=true >/dev/null
done

# --- Step 2: Authenticate Docker with ECR ---
echo "------------------------------------------------------------"
echo " Step 2/4: Authenticating Docker with ECR..."
echo "------------------------------------------------------------"
aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

# --- Step 3: Build and push the ARM64 container images ---
# AgentCore Runtime only supports ARM64; both Dockerfiles enforce it too.
#
# The slow part of every build is the Dockerfile's `uv sync` layer: the ARM64
# deps (strands/bedrock-agentcore/botocore/...) cross-compile under QEMU on x86
# hosts (~5-10 min). To avoid paying that on every clean checkout/machine, we push
# a BuildKit registry cache to ECR (:buildcache, per repo) and pull it back on the
# next build via buildx --cache-from/--cache-to. BuildKit is required for both the
# registry cache and the Dockerfile's `--mount=type=cache` uv cache.
export DOCKER_BUILDKIT=1
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/arm64}"

# build_and_push <image_tag_uri> <repo_name> <context_dir> [dockerfile]
# Uses the same buildx-cache / buildx / plain-build fallback the preflight resolved
# (BUILDX_CACHE / BUILDX_AVAILABLE), so both images share one code path.
build_and_push() {
  local image_uri="$1" repo_name="$2" context="$3" dockerfile="${4:-}"
  local buildcache_ref="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$repo_name:buildcache"
  local file_args=()
  if [[ -n "$dockerfile" ]]; then
    file_args=(-f "$dockerfile")
  fi

  if [[ "${BUILDX_CACHE:-0}" == "1" ]]; then
    echo "--- Building $repo_name ($DOCKER_PLATFORM) [buildx registry cache]"
    echo "    context: $context   cache: $buildcache_ref"
    docker buildx build \
      --platform "$DOCKER_PLATFORM" \
      --cache-from "type=registry,ref=$buildcache_ref" \
      --cache-to "type=registry,ref=$buildcache_ref,mode=max" \
      "${file_args[@]+"${file_args[@]}"}" \
      -t "$image_uri" \
      --push \
      "$context"
  elif [[ "${BUILDX_AVAILABLE:-0}" == "1" ]]; then
    echo "--- Building $repo_name ($DOCKER_PLATFORM) [buildx, no registry cache]"
    echo "    context: $context"
    docker buildx build \
      --platform "$DOCKER_PLATFORM" \
      "${file_args[@]+"${file_args[@]}"}" \
      -t "$image_uri" \
      --push \
      "$context"
  else
    echo "--- Building $repo_name ($DOCKER_PLATFORM) [plain build]"
    echo "    context: $context"
    docker build --platform "$DOCKER_PLATFORM" "${file_args[@]+"${file_args[@]}"}" -t "$image_uri" "$context"
    echo "--- Pushing image to ECR: $image_uri"
    docker push "$image_uri"
  fi
}

# resolve_digest_uri <repo_name> -> prints the immutable repo@sha256:... reference
resolve_digest_uri() {
  local repo_name="$1"
  local digest
  digest=$(aws ecr describe-images \
    --repository-name "$repo_name" \
    --region "$AWS_REGION" \
    --image-ids imageTag="$IMAGE_TAG" \
    --query 'imageDetails[0].imageDigest' \
    --output text)
  echo "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$repo_name@$digest"
}

echo "------------------------------------------------------------"
echo " Step 3/4: Building agent + builder images ($DOCKER_PLATFORM)..."
echo "------------------------------------------------------------"
# Agent image: context is agent/ (its Dockerfile is self-contained).
build_and_push "$ECR_URI" "$ECR_REPO_NAME" "$AGENT_DIR"
# Builder image: context MUST be the v2 root so builder/Dockerfile can COPY the
# shared modules from agent/src and loader/. Its Dockerfile is passed explicitly.
build_and_push "$BUILDER_ECR_URI" "$BUILDER_ECR_REPO_NAME" "$SCRIPT_DIR" "$SCRIPT_DIR/builder/Dockerfile"

# Resolve immutable digest references for both images.
CONTAINER_IMAGE_URI="$(resolve_digest_uri "$ECR_REPO_NAME")"
BUILDER_IMAGE_URI="$(resolve_digest_uri "$BUILDER_ECR_REPO_NAME")"
echo "--- Agent image URI:   $CONTAINER_IMAGE_URI"
echo "--- Builder image URI: $BUILDER_IMAGE_URI"

# --- Step 4: Deploy the CloudFormation stack (Req 9.2) ---
# The template also exposes TableName/VectorIndexName/Dimensions/DistanceFunction,
# but those carry defaults, so only the required overrides are passed here.
echo "------------------------------------------------------------"
echo " Step 4/4: Deploying CloudFormation stack '$STACK_NAME'..."
echo "------------------------------------------------------------"
aws cloudformation deploy \
  --template-file "$CFN_DIR/template.yaml" \
  --stack-name "$STACK_NAME" \
  --parameter-overrides \
    ContainerImageUri="$CONTAINER_IMAGE_URI" \
    BuilderImageUri="$BUILDER_IMAGE_URI" \
    BedrockModelId="$BEDROCK_MODEL_ID" \
    AdminEmail="$ADMIN_EMAIL" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$AWS_REGION" \
  --no-fail-on-empty-changeset

echo ""
echo "=== Infrastructure deployed ==="
echo ""

# --- Step: run loader/load_profiles.py (task 13.3) ---
# The corpus MUST be ingested before the deployment is marked complete (Req 9.3),
# so this runs after `cloudformation deploy` and fails the whole script (set -e) if
# the loader errors out.

# Read a single stack Output value by OutputKey (empty string if the key is absent).
get_output() {
  aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='${1}'].OutputValue" \
    --output text
}

# Resolve the created table + vector index from the stack outputs (not the defaults),
# so the loader always writes to exactly what CloudFormation provisioned.
TABLE_NAME="$(get_output "TableName")"
VECTOR_INDEX="$(get_output "VectorIndexName")"

if [[ -z "$TABLE_NAME" || "$TABLE_NAME" == "None" ]]; then
  echo "ERROR: could not resolve the DynamoDB table name from stack '$STACK_NAME' outputs (TableName)." >&2
  echo "       Was the CloudFormation deploy step successful?" >&2
  exit 1
fi

# --- Load-skip logic (protects existing data) ---
# The loader upserts every seed shard by (ProfileId, ShardId) with PutRequest, which
# OVERWRITES whatever is there — including human enrichments (Source="web-enrichment")
# and agent-created profiles. So on a redeploy we must NOT blindly reload:
#
#   * SKIP_LOAD=1  -> always skip (explicit).
#   * otherwise, if the table ALREADY has items -> auto-skip to protect existing data,
#     UNLESS FORCE_LOAD=1 is set (explicit opt-in to (re)seed the corpus).
#   * empty table + not skipped -> load (first deploy / fresh table).
#
# This makes "forgot the flag on a redeploy" safe: an already-populated table is left
# untouched by default. TABLE_NAME was resolved above (outside this guard) because the
# frontend steps and the final banner still need it.
_is_truthy() {
  case "$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes | y) return 0 ;;
    *) return 1 ;;
  esac
}

# Is the table already populated? We only need "empty vs non-empty", so scan a single
# server-side page with a small --limit and read its Count. IMPORTANT: use the server-side
# --limit (NOT the CLI's client-side --max-items, which combined with --select COUNT can
# yield a bogus/zero Count and cause the load to run over existing data). Any item on the
# first scanned page means the table has data. Failure (missing table / no perms) yields
# 0 so a genuinely fresh first deploy still loads.
EXISTING_ITEM_COUNT="$(aws dynamodb scan --table-name "$TABLE_NAME" --select COUNT \
  --region "$AWS_REGION" --limit 100 --query 'Count' --output text --no-paginate 2>/dev/null || echo 0)"
if ! [[ "$EXISTING_ITEM_COUNT" =~ ^[0-9]+$ ]]; then
  EXISTING_ITEM_COUNT=0
fi

if _is_truthy "${SKIP_LOAD:-}"; then
  echo "Skipping threat-profile corpus load (SKIP_LOAD=$SKIP_LOAD)."
  echo ""
elif [[ "$EXISTING_ITEM_COUNT" -gt 0 ]] && ! _is_truthy "${FORCE_LOAD:-}"; then
  echo "------------------------------------------------------------"
  echo " Skipping corpus load: table '$TABLE_NAME' already has data."
  echo "   Auto-skip protects human enrichments and agent-created profiles from being"
  echo "   overwritten by a re-seed. To force a (re)load of the seed corpus anyway,"
  echo "   re-run with FORCE_LOAD=1 (this WILL overwrite seed shards, reverting any"
  echo "   enrichments made to them)."
  echo "------------------------------------------------------------"
  echo ""
else
  echo "------------------------------------------------------------"
  if [[ "$EXISTING_ITEM_COUNT" -gt 0 ]]; then
    echo " Data load: FORCE_LOAD set — (re)seeding corpus over existing data (task 13.3)"
    echo " WARNING: this overwrites seed shards; enrichments to them will be reverted."
  else
    echo " Data load: ingesting threat-profile corpus (task 13.3)"
  fi
  echo "------------------------------------------------------------"
  echo " Table:        $TABLE_NAME"
  echo " Vector index: ${VECTOR_INDEX:-<default>}"
  echo " Loader:       $LOADER_DIR/load_profiles.py"
  if [[ -n "${LOAD_LIMIT:-}" ]]; then
    echo " Limit:        $LOAD_LIMIT (subset load)"
  fi
  if [[ -n "${THREAT_PROFILES_DIR:-}" ]]; then
    echo " Profiles dir: $THREAT_PROFILES_DIR"
  fi
  echo "------------------------------------------------------------"

  # Build the loader's optional CLI overrides. --table always wins over env; LOAD_LIMIT
  # maps to --limit (subset loads for task 14 integration verification); THREAT_PROFILES_DIR
  # maps to --profiles-dir when the corpus lives outside the loader's default location.
  LOADER_ARGS=(--table "$TABLE_NAME")
  if [[ -n "${LOAD_LIMIT:-}" ]]; then
    LOADER_ARGS+=(--limit "$LOAD_LIMIT")
  fi
  if [[ -n "${THREAT_PROFILES_DIR:-}" ]]; then
    LOADER_ARGS+=(--profiles-dir "$THREAT_PROFILES_DIR")
  fi

  # The loader reads DDB_TABLE_NAME / AWS_REGION / EMBEDDING_MODEL / EMBEDDING_DIMENSIONS
  # from the environment; keep them consistent with the stack so seed embeddings match the
  # query embeddings the agent produces. --table above overrides DDB_TABLE_NAME regardless.
  export DDB_TABLE_NAME="$TABLE_NAME"
  export AWS_REGION="$AWS_REGION"
  export EMBEDDING_MODEL="${EMBEDDING_MODEL:-amazon.titan-embed-text-v2:0}"
  export EMBEDDING_DIMENSIONS="${EMBEDDING_DIMENSIONS:-1024}"
  if [[ -n "${THREAT_PROFILES_DIR:-}" ]]; then
    export THREAT_PROFILES_DIR
  fi

  # Prefer uv (the loader is a uv project: loader/pyproject.toml exists) so the boto3
  # dependency resolves in an isolated env; fall back to python3 if uv is unavailable.
  if command -v uv >/dev/null 2>&1 && [[ -f "$LOADER_DIR/pyproject.toml" ]]; then
    uv run --project "$LOADER_DIR" python "$LOADER_DIR/load_profiles.py" "${LOADER_ARGS[@]}"
  else
    python3 "$LOADER_DIR/load_profiles.py" "${LOADER_ARGS[@]}"
  fi

  echo ""
  echo "=== Threat-profile corpus ingested into '$TABLE_NAME' ==="
  echo ""
fi

# --- Step: build frontend, upload to S3, invalidate CloudFront, print outputs (task 13.4) ---
# Publishes the SPA and reports the deployment. Reuses the get_output() helper defined
# in the data-load step (13.3). set -e ensures any failing command aborts the whole
# script, so no step below silently swallows an error (Req 9.5).

# --- Resolve the remaining stack outputs (TABLE_NAME was resolved in 13.3) ---
RUNTIME_ARN="$(get_output "RuntimeArn")"
USER_POOL_ID="$(get_output "UserPoolId")"
CLIENT_ID="$(get_output "UserPoolClientId")"
COGNITO_DOMAIN="$(get_output "CognitoDomain")"
CF_DOMAIN="$(get_output "CloudFrontDomain")"
CF_DIST_ID="$(get_output "CloudFrontDistributionId")"
S3_BUCKET="$(get_output "FrontendBucketName")"
MEMORY_ID="$(get_output "MemoryId")"
GATEWAY_URL="$(get_output "GatewayUrl")"

# Guard the outputs the frontend publish path depends on; fail fast (Req 9.5) with a
# clear message rather than writing a broken .env or syncing to an empty bucket name.
for _pair in \
  "RuntimeArn:$RUNTIME_ARN" \
  "UserPoolId:$USER_POOL_ID" \
  "UserPoolClientId:$CLIENT_ID" \
  "CognitoDomain:$COGNITO_DOMAIN" \
  "CloudFrontDomain:$CF_DOMAIN" \
  "CloudFrontDistributionId:$CF_DIST_ID" \
  "FrontendBucketName:$S3_BUCKET"; do
  _key="${_pair%%:*}"
  _val="${_pair#*:}"
  if [[ -z "$_val" || "$_val" == "None" ]]; then
    echo "ERROR: could not resolve required stack output '$_key' from '$STACK_NAME'." >&2
    echo "       Was the CloudFormation deploy step successful?" >&2
    exit 1
  fi
done

# --- Update the Cognito app client callback/logout URLs with the CloudFront domain ---
# Keep the localhost URLs (local dev) alongside the deployed CloudFront ones.
echo "------------------------------------------------------------"
echo " Frontend publish (task 13.4)"
echo "------------------------------------------------------------"
echo "--- Updating Cognito app-client callback/logout URLs..."

CALLBACK_URL="https://${CF_DOMAIN}/callback"
LOGOUT_URL="https://${CF_DOMAIN}"

aws cognito-idp update-user-pool-client \
  --user-pool-id "$USER_POOL_ID" \
  --client-id "$CLIENT_ID" \
  --explicit-auth-flows "ALLOW_USER_SRP_AUTH" "ALLOW_REFRESH_TOKEN_AUTH" "ALLOW_USER_PASSWORD_AUTH" \
  --callback-urls "[\"${CALLBACK_URL}\",\"http://localhost:5173/callback\"]" \
  --logout-urls "[\"${LOGOUT_URL}\",\"http://localhost:5173\"]" \
  --allowed-o-auth-flows "code" \
  --allowed-o-auth-flows-user-pool-client \
  --allowed-o-auth-scopes "openid" "email" "profile" \
  --supported-identity-providers "COGNITO" \
  --region "$AWS_REGION"

echo "[OK] Callback URL registered: $CALLBACK_URL"

# --- Construct the AgentCore invoke endpoint (URL-encode the runtime ARN) ---
ENCODED_ARN=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${RUNTIME_ARN}', safe=''))")
AGENTCORE_ENDPOINT="https://bedrock-agentcore.${AWS_REGION}.amazonaws.com/runtimes/${ENCODED_ARN}/invocations?qualifier=DEFAULT"

# --- Write frontend/.env from the resolved outputs (matches frontend/src/vite-env.d.ts) ---
cat > "$FRONTEND_DIR/.env" <<EOF
VITE_AGENTCORE_ENDPOINT=${AGENTCORE_ENDPOINT}
VITE_COGNITO_DOMAIN=${COGNITO_DOMAIN}.auth.${AWS_REGION}.amazoncognito.com
VITE_COGNITO_CLIENT_ID=${CLIENT_ID}
VITE_COGNITO_REDIRECT_URI=https://${CF_DOMAIN}/callback
VITE_COGNITO_USER_POOL_ID=${USER_POOL_ID}
EOF
echo "[OK] frontend/.env written"

# --- Build the SPA and publish it to the frontend bucket ---
echo "--- Building frontend ($FRONTEND_DIR)..."
cd "$FRONTEND_DIR"
npm install
npm run build
cd "$SCRIPT_DIR"

echo "--- Uploading frontend to S3 (s3://${S3_BUCKET})..."
aws s3 sync "$FRONTEND_DIR/dist" "s3://${S3_BUCKET}" --delete --region "$AWS_REGION"

echo "--- Invalidating CloudFront distribution ($CF_DIST_ID)..."
aws cloudfront create-invalidation \
  --distribution-id "$CF_DIST_ID" \
  --paths "/*" --output text

# --- Final banner: frontend URL + key resource identifiers (Req 9.4) ---
echo ""
echo "============================================================"
echo " Deployment Complete!"
echo "============================================================"
echo ""
echo " Frontend:   https://${CF_DOMAIN}"
echo " AgentCore:  ${AGENTCORE_ENDPOINT}"
echo " Cognito:    https://${COGNITO_DOMAIN}.auth.${AWS_REGION}.amazoncognito.com"
echo ""
echo " User Pool:  ${USER_POOL_ID}"
echo " Client ID:  ${CLIENT_ID}"
echo " Runtime:    ${RUNTIME_ARN}"
echo " Memory:     ${MEMORY_ID}"
echo " Gateway:    ${GATEWAY_URL}"
echo " Table:      ${TABLE_NAME}"
echo ""
if [[ -n "$ADMIN_EMAIL" ]]; then
  echo " Admin user: ${ADMIN_EMAIL} (check email for a temporary password)"
fi
echo "============================================================"

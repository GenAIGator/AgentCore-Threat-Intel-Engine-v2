# Autonomous profile-builder runtime image (ARM64 — AgentCore Runtime is ARM64-only).
#
# BUILD CONTEXT: this Dockerfile expects the build context to be the v2 APP ROOT
# (agentcore-threat-intel-engine-v2/), NOT builder/, because it vendors a few shared
# modules from sibling packages:
#   * builder/src/*                    — the builder's own code
#   * agent/src/{profile_dedup,ddb,embeddings}.py — reused dedup + Titan + SearchVectors
#   * loader/content.py                — reused Content/metadata derivation
# All of these resolve against the builder's own config.py (same env-var names), so the
# vendored agent modules use the builder's configuration at import time.
#
# deploy.sh builds this with:  docker build -f builder/Dockerfile <v2-root>
FROM --platform=linux/arm64 python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

WORKDIR /app

COPY builder/pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project --no-editable

# Builder source first, then vendor the shared modules alongside it on PYTHONPATH.
COPY builder/src/ ./src/
COPY agent/src/profile_dedup.py agent/src/ddb.py agent/src/embeddings.py ./src/
COPY loader/content.py ./src/

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app

ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH="/app/src"

USER appuser

ENV LOG_LEVEL=INFO

# ADOT auto-instrumentation. We ONLY select the ADOT distro/configurator and let the
# AgentCore Runtime platform own the OTLP export destination, protocol, AND resource
# attributes (it injects them at container start). Do NOT hardcode
# OTEL_EXPORTER_OTLP_PROTOCOL / OTEL_RESOURCE_ATTRIBUTES — that conflicts with the
# platform-injected values and causes span-export 400s.
ENV OTEL_PYTHON_DISTRO=aws_distro
ENV OTEL_PYTHON_CONFIGURATOR=aws_configurator

# Do NOT capture full GenAI message content (prompts/completions) in spans/logs. Each
# generated profile section is large, and capturing the full model input+output made
# single OTLP records exceed CloudWatch's 1 MB limit ("Upload too large ... exceeds
# 1048576"), so those telemetry batches were dropped. Traces still carry the useful
# metadata (tool names, token counts, latency, section names); only the bulky message
# bodies are omitted. Both the modern enum var and the older boolean are set because
# different ADOT versions honor different ones.
ENV OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=NO_CONTENT
ENV OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT=false

# Bound the size of EACH span independently of GenAI content capture. Even with message
# bodies omitted, individual span attributes (tool args/results, prompts echoed as
# attributes) can be large; these standard OTEL SDK limits truncate any single attribute
# value and cap attribute counts, keeping every span small. This further reduces the
# oversized-record "Failed to export span batch code: 400" noise. Values are generous
# enough to preserve useful metadata (technique IDs, section names, token counts).
ENV OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT=4096
ENV OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT=4096
ENV OTEL_ATTRIBUTE_COUNT_LIMIT=64
ENV OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT=64
# Export fewer spans per OTLP POST so a single batch is far less likely to exceed the
# collector's per-request size limit (default batch size is 512).
ENV OTEL_BSP_MAX_EXPORT_BATCH_SIZE=32

EXPOSE 8080

CMD ["opentelemetry-instrument", "uvicorn", "builder_app:app", "--host", "0.0.0.0", "--port", "8080"]

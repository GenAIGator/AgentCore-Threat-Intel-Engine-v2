FROM --platform=linux/arm64 python:3.12-slim

# uv pinned to the 0.11.x line (satisfies pyproject [tool.uv] required-version >=0.11.0).
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml ./
# The `uv sync` layer is the slow one (ARM64 deps cross-compile under QEMU on
# x86). Two things keep it fast + lean:
#   * --mount=type=cache,target=/root/.cache/uv — persists uv's download/build
#     cache. deploy.sh runs buildx with --cache-to/--cache-from a registry
#     cache in ECR (:buildcache), which exports this mount so the layer is
#     reused across clean checkouts and other machines.
#   * --no-dev — keeps dev deps (pytest/ruff/mypy/black/boto3-stubs) out of the
#     image. uv resolves wheels, so no build-essential/source builds are needed.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project --no-editable

COPY src/ ./src/

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app

ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH="/app/src"

USER appuser

ENV LOG_LEVEL=INFO

# ADOT auto-instrumentation config. `opentelemetry-instrument` (from
# aws-opentelemetry-distro, installed via pyproject) wraps uvicorn below to emit
# traces/spans for Strands + Bedrock + boto3 tool calls. We ONLY select the ADOT
# distro/configurator here and let the AgentCore Runtime platform own the export
# destination, protocol, AND resource attributes: at container start it injects
# the OTLP endpoint, OTLP protocol, and resource attributes (service.name,
# aws.log.group.names, cloud.resource_id, etc.). We therefore do NOT set
# OTEL_EXPORTER_OTLP_PROTOCOL / OTEL_RESOURCE_ATTRIBUTES /
# OTEL_EXPORTER_OTLP_LOGS_HEADERS / log-group envs here — hardcoding them would
# conflict with the platform-injected values (a common cause of span-export 400s)
# and those are only relevant for non-runtime-hosted agents.
ENV OTEL_PYTHON_DISTRO=aws_distro
ENV OTEL_PYTHON_CONFIGURATOR=aws_configurator

# Do NOT capture full GenAI message content (prompts/completions) in spans/logs. The
# agent's spans otherwise embed the entire system prompt + retrieved context + memory
# blob, which can make single OTLP records exceed CloudWatch's 1 MB limit and get
# dropped. Traces keep the useful metadata (tool names like retrieve_profiles, token
# counts, latency); only the bulky message bodies are omitted. Both the modern enum var
# and the older boolean are set because different ADOT versions honor different ones.
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

CMD ["opentelemetry-instrument", "uvicorn", "agentcore_app:app", "--host", "0.0.0.0", "--port", "8080"]

"""Autonomous profile-builder AgentCore Runtime entrypoint.

Invoked fire-and-forget by the main agent's ``create_profile`` tool (see
``docs/CREATE_PROFILE_DESIGN.md``). Given a create payload, it runs to completion on its
own — nobody is waiting — and:

1. re-runs the duplicate check (defense in depth; never trust the caller),
2. for each of the 12 canonical sections: web-researches + generates the JSON fields,
   grades them against the per-section quality minimums, and regenerates thin sections
   up to ``SECTION_MAX_RETRIES`` times,
3. embeds all 12 derived Content strings (Titan v2) and writes the whole profile in one
   ``BatchWriteItem`` pass (atomic-ish: a failure before the write lands nothing),
4. on any unrecoverable failure, publishes an alert to SNS (out-of-band; the user is not
   notified in-band).

The runtime is OTEL/ADOT-instrumented via the Dockerfile (``opentelemetry-instrument`` +
``OTEL_PYTHON_DISTRO=aws_distro`` / ``OTEL_PYTHON_CONFIGURATOR=aws_configurator``); the
platform injects the OTLP export destination, so section research/generation/write appear
as spans in the builder's own runtime log group.

The pure orchestration (looping sections, applying the gate, assembling items) is
factored into :func:`build_profile_sections` / :func:`assemble_items` so it is
unit-testable with a fake generator + fake content-deriver and no AWS/model access.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections.abc import Callable
from typing import Any

import boto3
from fastapi import FastAPI, Request

from config import (
    AGENTCORE_GATEWAY_URL,
    AWS_REGION,
    FAILURE_SNS_TOPIC_ARN,
    MODEL_ID,
    SECTION_MAX_RETRIES,
)
from content import derive_content
from profile_dedup import check_duplicate
from profile_writer import build_item, build_shard, write_items
from quality_gate import SectionVerdict, evaluate_section
from section_generator import generate_section_fields
from sections import SECTION_SPECS, SectionSpec

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))
logger = logging.getLogger("builder.app")

app = FastAPI(title="Threat Intelligence Engine v2 — Profile Builder")

# --- Async background-build lifecycle ------------------------------------------------
# AgentCore keeps a runtime session alive based on the /ping health status: a session
# reporting "HealthyBusy" survives past the 15-min idle timeout, while an idle "Healthy"
# session is reclaimed. Because a profile build runs in a BACKGROUND thread after the
# /invocations handler has already returned, we must report "HealthyBusy" for as long as
# any build is in flight — otherwise the platform could terminate the container mid-build.
# _ACTIVE_BUILDS is a simple in-flight counter guarded by a lock; /ping reports busy when
# it is > 0. (See AWS "Handle asynchronous and long running agents".)
_ACTIVE_BUILDS = 0
_ACTIVE_BUILDS_LOCK = threading.Lock()


def _begin_build() -> None:
    global _ACTIVE_BUILDS
    with _ACTIVE_BUILDS_LOCK:
        _ACTIVE_BUILDS += 1


def _end_build() -> None:
    global _ACTIVE_BUILDS
    with _ACTIVE_BUILDS_LOCK:
        _ACTIVE_BUILDS = max(0, _ACTIVE_BUILDS - 1)


def _builds_in_flight() -> int:
    with _ACTIVE_BUILDS_LOCK:
        return _ACTIVE_BUILDS


# --- Pure orchestration (unit-testable) -----------------------------------------------


def build_one_section(
    generate: Callable[[SectionSpec], dict[str, Any]],
    content_deriver: Callable[[dict[str, Any]], str],
    spec: SectionSpec,
    profile_name: str,
    max_retries: int,
) -> tuple[dict[str, Any], SectionVerdict]:
    """Generate one section, grading + regenerating until it passes or retries run out.

    Args:
        generate: Callable that produces a section's ``fields`` given its :class:`SectionSpec`
            (the builder binds this to the model-backed generator).
        content_deriver: Turns a shard dict into its embedded Content (the loader's
            ``derive_content``), used by the quality gate to measure real length.
        spec: The section being built.
        profile_name: Actor display name.
        max_retries: Additional attempts after the first if the gate fails.

    Returns:
        ``(best_fields, best_verdict)`` — the best attempt seen (passing if any attempt
        passed, else the last). The caller decides whether a non-passing section fails
        the whole build.
    """
    best_fields: dict[str, Any] = {}
    best_verdict: SectionVerdict | None = None
    for attempt in range(max_retries + 1):
        fields = generate(spec)
        verdict = evaluate_section(
            spec.file_type, fields, spec, content_deriver, profile_name=profile_name
        )
        if best_verdict is None or (verdict.passed and not best_verdict.passed):
            best_fields, best_verdict = fields, verdict
        if verdict.passed:
            logger.info("Section %s passed on attempt %d", spec.file_type, attempt + 1)
            return fields, verdict
        logger.warning(
            "Section %s failed gate on attempt %d: %s",
            spec.file_type,
            attempt + 1,
            "; ".join(verdict.reasons),
        )
    assert best_verdict is not None
    return best_fields, best_verdict


def build_profile_sections(
    generate: Callable[[SectionSpec], dict[str, Any]],
    content_deriver: Callable[[dict[str, Any]], str],
    profile_name: str,
    max_retries: int,
    specs: tuple[SectionSpec, ...] = SECTION_SPECS,
) -> tuple[dict[str, dict[str, Any]], list[SectionVerdict]]:
    """Build all sections; return ``(fields_by_type, verdicts)``.

    Every section in ``specs`` is attempted. The caller inspects the verdicts to decide
    whether the profile is complete enough to write (all sections must pass — the profile
    MUST have all 12 fully-populated sections).
    """
    fields_by_type: dict[str, dict[str, Any]] = {}
    verdicts: list[SectionVerdict] = []
    for spec in specs:
        fields, verdict = build_one_section(
            generate, content_deriver, spec, profile_name, max_retries
        )
        fields_by_type[spec.file_type] = fields
        verdicts.append(verdict)
    return fields_by_type, verdicts


def assemble_items(
    profile_id: str,
    name: str,
    attribution: dict[str, Any] | None,
    fields_by_type: dict[str, dict[str, Any]],
    updated_by: str,
    item_builder: Callable[..., dict[str, dict[str, Any]]] = build_item,
    shard_builder: Callable[..., dict[str, Any]] = build_shard,
) -> list[dict[str, dict[str, Any]]]:
    """Assemble the DynamoDB items for every section (embeds via ``item_builder``).

    ``item_builder``/``shard_builder`` are injectable so tests can assemble items without
    calling Bedrock (the real defaults embed via Titan).
    """
    items: list[dict[str, dict[str, Any]]] = []
    for spec in SECTION_SPECS:
        fields = fields_by_type.get(spec.file_type, {})
        shard = shard_builder(profile_id, name, spec.file_type, fields, attribution)
        items.append(item_builder(shard, updated_by=updated_by))
    return items


# --- AWS-touching pieces --------------------------------------------------------------


def _publish_failure(profile_id: str, name: str, error: str) -> None:
    """Publish a builder-failure alert to SNS (best-effort; never raises)."""
    topic = (FAILURE_SNS_TOPIC_ARN or "").strip()
    if not topic:
        logger.error(
            "Build failed for %s but no FAILURE_SNS_TOPIC_ARN is set: %s", profile_id, error
        )
        return
    try:
        boto3.client("sns", region_name=AWS_REGION).publish(
            TopicArn=topic,
            Subject=f"[ThreatIntel] Profile build failed: {profile_id}"[:100],
            Message=(
                f"Building the '{name}' profile (ProfileId='{profile_id}') failed.\n\n"
                f"Error: {error}\n\nNo profile was written."
            ),
        )
    except Exception as sns_error:  # pragma: no cover - best-effort alerting
        logger.error("Failed to publish failure to SNS: %s", sns_error)


def _make_agent() -> Any:
    """Construct the web-researching Strands agent (with web-search MCP when configured)."""
    from strands import Agent

    tools: list[Any] = []
    mcp_client = None
    if AGENTCORE_GATEWAY_URL:
        import mcp_proxy_for_aws.client as aws_mcp  # type: ignore[import-untyped]
        from strands.tools.mcp import MCPClient

        mcp_client = MCPClient(
            lambda: aws_mcp.aws_iam_streamablehttp_client(
                endpoint=AGENTCORE_GATEWAY_URL,
                aws_region=AWS_REGION,
                aws_service="bedrock-agentcore",
            )
        )
        tools.append(mcp_client)

    agent = Agent(
        model=MODEL_ID,
        tools=tools,
        system_prompt=(
            "You are a threat-intelligence research assistant building a knowledge-base "
            "profile section. Research the actor with the web search tool and return only "
            "the requested JSON. Be factual and specific; never fabricate."
        ),
    )
    # Return the agent only. The MCPClient (if any) is already registered in the agent's
    # tools; Strands manages its session when the agent runs, so callers must NOT enter it
    # as a context manager themselves (that double-starts it).
    return agent


def run_build(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a full profile build from a create payload. Never raises (alerts on failure).

    Returns a small status dict (the invoker is fire-and-forget and ignores it, but it is
    useful in logs/tests).
    """
    profile_id = str(payload.get("profile_id", "")).strip()
    name = str(payload.get("name", "")).strip()
    intent = str(payload.get("intent", "")).strip()
    attribution = payload.get("attribution") or {}
    aliases = payload.get("aliases") or []
    requested_by = str(payload.get("requested_by", "")).strip()

    if not profile_id or not name:
        logger.error("Builder invoked without profile_id/name: %r", payload)
        return {"status": "error", "error": "missing profile_id/name"}

    logger.info("Builder starting for ProfileId=%s name=%s", profile_id, name)

    try:
        # 1. Defense-in-depth dedup re-check.
        verdict = check_duplicate(
            profile_id, proposed_name=name, proposed_aliases=aliases, intent=intent
        )
        if verdict.is_duplicate:
            logger.warning(
                "Builder aborting: %s already exists (%s -> %s); no write.",
                profile_id,
                verdict.reason,
                verdict.existing_profile_id,
            )
            return {"status": "skipped", "reason": "duplicate"}

        # 2. Build all sections with a web-search-capable agent.
        # The MCPClient is passed in the agent's tools (see _make_agent); Strands manages
        # the client session lifecycle itself when the agent runs — exactly like the main
        # agent (agentcore_app.py). Do NOT wrap this in `with mcp_client:`: that
        # double-starts the session and raises MCPClientInitializationError
        # ("the client session is currently running").
        agent = _make_agent()

        def _generate(spec: SectionSpec) -> dict[str, Any]:
            return generate_section_fields(agent, name, intent, attribution, spec)

        fields_by_type, verdicts = build_profile_sections(
            _generate, derive_content, name, SECTION_MAX_RETRIES
        )

        failed = [v for v in verdicts if not v.passed]
        if failed:
            detail = "; ".join(f"{v.file_type}: {'/'.join(v.reasons)}" for v in failed)
            raise RuntimeError(f"{len(failed)} section(s) failed the quality gate: {detail}")

        # 3. Embed + atomic write.
        items = assemble_items(profile_id, name, attribution, fields_by_type, requested_by)
        written = write_items(items)
        logger.info("Builder completed for ProfileId=%s (%d shards written)", profile_id, written)
        return {"status": "success", "profile_id": profile_id, "written": written}

    except Exception as error:  # noqa: BLE001 - top-level guard: alert, never crash silently
        logger.error("Builder failed for ProfileId=%s: %s", profile_id, error, exc_info=True)
        _publish_failure(profile_id, name, str(error))
        return {"status": "error", "error": str(error)}


@app.post("/invocations")
async def invocations(request: Request) -> dict[str, Any]:
    """AgentCore entrypoint — accept the build and run it in the BACKGROUND, return now.

    IMPORTANT: ``bedrock-agentcore invoke_agent_runtime`` is a streaming request/response
    call — the CALLER (the main agent's create_profile tool) stays connected until this
    handler responds. If we ran the whole ~minutes-long build here before returning, the
    caller (and the chat UI's approval POST) would block the entire time.

    So this handler must return IMMEDIATELY. We schedule the blocking ``run_build`` on a
    background thread (it does boto3 + model calls, so it must not run on the event loop)
    and respond right away with ``{"status": "accepted"}``. The container stays alive for
    the session, so the background build completes on its own; the analyst rechecks by
    searching for the actor. run_build has its own top-level try/except -> SNS, so a
    background failure is alerted, never lost.
    """
    body = await request.json()
    # The payload may arrive directly or nested under a conventional key.
    payload = body if "profile_id" in body else body.get("payload", body)

    profile_id = str(payload.get("profile_id", "")).strip()

    # Mark busy BEFORE returning so /ping reports HealthyBusy immediately (no race where
    # the platform sees an idle session between our response and the thread starting).
    _begin_build()

    def _run_and_release(p: dict[str, Any]) -> None:
        try:
            run_build(p)  # has its own try/except -> SNS on failure
        finally:
            _end_build()

    asyncio.get_running_loop().run_in_executor(None, _run_and_release, payload)
    logger.info(
        "Accepted build for ProfileId=%s; running in background.", profile_id or "<unknown>"
    )
    return {"status": "accepted", "profile_id": profile_id}


@app.get("/ping")
async def ping() -> dict[str, str]:
    """AgentCore Runtime health check / session-lifecycle signal.

    Reports "HealthyBusy" while one or more profile builds are running in background
    threads so the platform keeps the session alive past the idle timeout; "Healthy" when
    idle so an unused session can be reclaimed normally.
    """
    return {"status": "HealthyBusy" if _builds_in_flight() > 0 else "Healthy"}

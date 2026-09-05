"""HITL tool to create a NEW threat-actor profile (fire-and-forget to the builder runtime).

This module exposes :func:`create_profile`, the Strands ``@tool(context=True)`` the agent
calls when the analyst asks to ADD a brand-new threat actor to the knowledge base. Unlike
``enrich_profile`` (which UPDATES one existing shard), this creates a whole new profile —
all 12 sections — by handing the work to the autonomous **builder** AgentCore Runtime.

Flow (see ``docs/CREATE_PROFILE_DESIGN.md``):

1. **Dedup check FIRST** (before any approval or research) via
   :func:`profile_dedup.check_duplicate` — normalized id/name/alias match plus a semantic
   vector-similarity check. If the actor already exists, even under a name variation, the
   tool STOPS and routes the analyst to ``enrich_profile``; nothing is invoked.
2. **HITL interrupt** — the analyst approves creating the profile. Nothing is invoked while
   approval is pending. The interrupt name prefix ``create_profile`` drives the frontend
   ``action`` (via ``interrupt.name.split("-")[0]``) and the orphaned-interrupt fallback.
3. **On approval** — :func:`launch_builder` fire-and-forget async-invokes the builder
   runtime and returns immediately. The build (research + generate 12 sections + embed +
   write) runs autonomously; the analyst rechecks by searching for the actor later.

:func:`launch_builder` is a standalone helper (not a tool) so the ``/invocations``
orphaned-interrupt fallback can launch the builder directly from the echoed payload if the
agent that raised the interrupt was recycled, and so it can be unit-tested against a fake
``bedrock-agentcore`` client without live AWS access.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from strands import tool

from config import AWS_REGION, BUILDER_RUNTIME_ARN
from profile_dedup import check_duplicate

logger = logging.getLogger(__name__)

# ``invoke_agent_runtime`` is a streaming request/response call: boto3 holds the
# connection open until the builder's ``/invocations`` handler responds. The builder
# handler returns ``{"status": "accepted"}`` almost immediately when the container is
# WARM, but a COLD start (image pull + boot) can take longer than boto3's default 60s
# read timeout — which previously surfaced as a ``ReadTimeoutError`` and a profile that
# never got built. We therefore (1) fire the invoke on a background daemon thread so the
# chat turn never blocks on it, and (2) give that background client a long read timeout
# so cold-start latency doesn't abort the call. See ``docs/CREATE_PROFILE_DESIGN.md``.
_BUILDER_INVOKE_CONFIG = BotoConfig(
    connect_timeout=10,
    read_timeout=900,  # absorb builder cold start; the thread is detached from the chat turn
    retries={"max_attempts": 2, "mode": "standard"},
)

# The most recently started background invoke thread. Tests join this to assert on the
# (detached) invoke; production code never reads it.
_LAST_INVOKE_THREAD: threading.Thread | None = None


def launch_builder(
    profile_id: str,
    name: str,
    intent: str,
    attribution: dict[str, Any] | None = None,
    aliases: list[str] | None = None,
    requested_by: str = "",
    client: Any = None,
) -> str:
    """Fire-and-forget async-invoke the builder runtime to create the profile.

    This is a plain function (NOT a tool) so the orphaned-interrupt fallback can reuse it
    and it can be unit-tested with a fake client. It assumes the dedup check passed and
    human approval was granted; callers own those gates.

    The builder runtime is invoked with ``InvokeAgentRuntime`` using a fresh
    ``runtimeSessionId`` so the build runs as its own asynchronous session (bound by the
    multi-hour session budget, not the 15-minute synchronous request timeout). We do NOT
    await or read the response stream — the call returns as soon as the invocation is
    accepted.

    Args:
        profile_id: The normalized ``ProfileId`` for the new actor.
        name: The actor display name.
        intent: A short description of the actor to steer research.
        attribution: Optional ``{"country": ..., "region": ...}`` hints.
        aliases: Optional known aliases.
        requested_by: The analyst email, recorded as provenance by the builder.
        client: Optional ``bedrock-agentcore`` client (injected for tests).

    Returns:
        A human-readable "creation started" confirmation.

    Raises:
        RuntimeError: If the builder runtime ARN is not configured.
        ClientError, BotoCoreError: If the invoke call itself is rejected.
    """
    runtime_arn = (BUILDER_RUNTIME_ARN or "").strip()
    if not runtime_arn:
        raise RuntimeError("Profile builder runtime is not configured (BUILDER_RUNTIME_ARN).")

    if client is None:  # pragma: no cover - exercised only with AWS creds
        client = boto3.client(
            "bedrock-agentcore", region_name=AWS_REGION, config=_BUILDER_INVOKE_CONFIG
        )

    payload = {
        "action": "create_profile",
        "profile_id": profile_id,
        "name": name,
        "intent": intent,
        "attribution": attribution or {},
        "aliases": aliases or [],
        "requested_by": requested_by,
    }

    # A fresh session id keeps the build isolated from the interactive chat session.
    # AgentCore requires runtimeSessionId to be 33-256 chars, so use two full uuid4 hex
    # strings (64 chars) — always long enough regardless of profile_id length. (A short
    # id like "team_pcp" made the previous "build-<id>-<12hex>" form too short, which the
    # platform rejected with a session-id validation error.)
    builder_session_id = f"build-{uuid.uuid4().hex}{uuid.uuid4().hex}"

    def _invoke() -> None:
        # Runs on a detached daemon thread: the chat turn has already returned, so a slow
        # (cold-start) builder response can never block the user. The builder's own
        # top-level try/except -> SNS covers failures once it starts; this guard only
        # covers the invoke call itself (e.g. the runtime never accepting the request).
        try:
            client.invoke_agent_runtime(
                agentRuntimeArn=runtime_arn,
                runtimeSessionId=builder_session_id,
                payload=json.dumps(payload).encode("utf-8"),
            )
            logger.info(
                "[create_profile] builder invoke accepted for ProfileId=%s session=%s",
                profile_id,
                builder_session_id,
            )
        except (BotoCoreError, ClientError) as invoke_error:
            # A ReadTimeout here is NOT necessarily fatal: the builder handler may still
            # have received the payload and be building in the background. But a hard
            # rejection (auth, validation, throttling) means nothing was launched. Log
            # loudly either way so the failure is visible in the runtime log group.
            logger.error(
                "[create_profile] background builder invoke failed for ProfileId=%s "
                "session=%s: %s",
                profile_id,
                builder_session_id,
                invoke_error,
                exc_info=True,
            )

    thread = threading.Thread(
        target=_invoke, name=f"builder-invoke-{profile_id}", daemon=True
    )
    thread.start()
    # Expose the most recently launched invoke thread so tests can join it
    # deterministically (the thread is otherwise detached from the caller).
    global _LAST_INVOKE_THREAD
    _LAST_INVOKE_THREAD = thread

    logger.info(
        "[create_profile] launched builder (async) for ProfileId=%s session=%s",
        profile_id,
        builder_session_id,
    )
    return (
        f"Creation of the '{name}' profile (ProfileId='{profile_id}') has started. "
        "Building and researching all sections takes a few minutes and runs in the "
        "background — search for the actor shortly and it should appear. You will not get "
        "a live progress update here."
    )


@tool(context=True)
def create_profile(
    tool_context: Any,
    profile_id: str,
    name: str,
    intent: str,
    country: str | None = None,
    region: str | None = None,
    aliases: list[str] | None = None,
    user_email: str = "",
) -> str:
    """Create a NEW threat-actor profile, gated by human approval (HITL).

    Call this tool ONLY when the analyst asks to ADD, CREATE, or REGISTER a threat actor
    that is NOT already in the knowledge base. This does NOT update existing profiles — for
    that use ``enrich_profile``. On approval it hands the work to an autonomous builder that
    researches and writes ALL sections; it does not return the finished profile inline.

    Provide a concise ``profile_id`` (lowercase, underscore-separated, e.g. ``volt_typhoon``),
    the display ``name``, a one or two sentence ``intent`` describing the actor (used to steer
    research and the duplicate check), and any known ``country``/``region``/``aliases``.

    The tool FIRST checks whether the actor already exists — including under a slightly
    different name variation — and if so it STOPS and tells you to use ``enrich_profile``
    instead, without doing any research. If it is genuinely new, it interrupts for your
    approval; nothing is created while approval is pending. On approval the build starts in
    the background and this returns immediately.

    Args:
        profile_id: Proposed new ``ProfileId`` (normalized, e.g. ``volt_typhoon``).
        name: Actor display name.
        intent: Short description of the actor (steers research + dedup).
        country: Optional attributed country.
        region: Optional attributed region.
        aliases: Optional known aliases.
        user_email: The analyst's email (recorded as provenance).

    Returns:
        A "creation started" confirmation, a "already exists — use enrich_profile" message
        when a duplicate is detected, a cancellation message on rejection, or an error.
    """
    normalized_id = (profile_id or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not normalized_id or not (name or "").strip():
        return "A new profile needs at least a profile_id and a name."

    # 1. Dedup check FIRST — never research/approve a profile that already exists (even
    # under a name variation). This calls DynamoDB (scan + semantic search) directly.
    try:
        verdict = check_duplicate(
            normalized_id,
            proposed_name=name,
            proposed_aliases=aliases,
            intent=intent,
        )
    except (BotoCoreError, ClientError) as error:
        logger.error("[create_profile] dedup check failed: %s", error, exc_info=True)
        return f"Could not verify whether '{name}' already exists: {error}. No profile was created."

    if verdict.is_duplicate:
        logger.info(
            "[create_profile] duplicate (%s) for proposed=%s -> existing=%s",
            verdict.reason,
            normalized_id,
            verdict.existing_profile_id,
        )
        return verdict.detail

    attribution: dict[str, Any] = {}
    if country and country.strip():
        attribution["country"] = country.strip()
    if region and region.strip():
        attribution["region"] = region.strip()
    clean_aliases = [a for a in (aliases or []) if isinstance(a, str) and a.strip()]

    # 2. HITL interrupt — approve creating the profile. Nothing is launched while pending.
    # The "create_profile" name prefix drives the frontend action; the reason payload is
    # echoed back so the orphaned-interrupt fallback can launch the builder if the agent
    # was recycled.
    approval = tool_context.interrupt(
        f"create_profile-{normalized_id}",
        reason={
            "reason": (
                f"Create a NEW threat-actor profile for '{name}' (ProfileId='{normalized_id}'). "
                "All sections will be researched and generated automatically in the "
                "background. This adds a new profile to the knowledge base."
            ),
            "action": "create_profile",
            "profile_id": normalized_id,
            "name": name,
            "intent": intent,
            "attribution": attribution,
            "aliases": clean_aliases,
            "user_email": user_email,
        },
    )

    if not isinstance(approval, str) or approval.strip().lower() != "yes":
        logger.info("[create_profile] rejected for ProfileId=%s; nothing launched.", normalized_id)
        return f"Creation cancelled. No profile for '{name}' was created."

    # 3. Approved — fire-and-forget launch the builder.
    try:
        return launch_builder(
            profile_id=normalized_id,
            name=name,
            intent=intent,
            attribution=attribution,
            aliases=clean_aliases,
            requested_by=user_email,
        )
    except RuntimeError as error:
        logger.error("[create_profile] builder not configured: %s", error)
        return f"Approval was granted, but profile creation is not available: {error}"
    except (BotoCoreError, ClientError) as error:
        logger.error("[create_profile] failed to launch builder: %s", error, exc_info=True)
        return (
            f"Approval was granted, but starting the build for '{name}' failed: {error}. "
            "No profile was created; please try again."
        )

"""HITL-protected destructive memory tool for the Threat Intelligence Engine v2.

This module exposes :func:`clear_all_memory`, the Strands ``@tool(context=True)`` the
agent calls to erase EVERYTHING it remembers about the analyst — short-term conversation
history (STM events) plus long-term memory records (LTM: learned facts, analyst
preferences, and rolling session summaries). It is gated by explicit human approval:
nothing is deleted until the analyst approves the interrupt (Requirement 5-style HITL).

The v2 AgentCore Memory namespaces this tool deletes from mirror the strategies declared
on the ``AWS::BedrockAgentCore::Memory`` resource (``cfn/template.yaml``) and the agent's
retrieval config (``agentcore_app.get_session_manager``):

* Semantic facts    → ``/threat-intel/facts/{actorId}``   (per-analyst learned facts)
* User preferences  → ``/users/preferences/{actorId}``    (per-analyst preferences)
* Session summaries  → ``/summaries/{sessionId}``          (session-scoped, NOT actor-scoped)

``actorId`` is derived from the analyst's email exactly as the session manager derives it
(``@`` → ``-at-``, ``.`` → ``-``, empty → ``anonymous``), reusing
:func:`agentcore_app.sanitize_actor_id` so the namespaces line up with what was written.

The terminal deletion is factored into the standalone :func:`clear_memory` helper (not a
tool) so it can be reused by the ``/invocations`` orphaned-interrupt fallback and
unit-tested against a fake ``bedrock-agentcore`` client without live AWS access.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from strands import tool

from config import AGENTCORE_MEMORY_ID, AWS_REGION

logger = logging.getLogger(__name__)

# Sentinel appended to a successful clear so the frontend can auto-start a fresh session
# (the underlying conversation history has been wiped, so continuing the old session id
# would be misleading). The frontend strips this token before displaying the message.
NEW_SESSION_SENTINEL = "__NEW_SESSION_REQUIRED__"


def _sanitize_actor_id(user_email: str) -> str:
    """Derive the AgentCore ``actor_id`` from a user's email.

    Reuses :func:`agentcore_app.sanitize_actor_id` when importable so the namespaces this
    tool deletes from match exactly what the session manager wrote. Falls back to an
    inline replication (``@`` → ``-at-``, ``.`` → ``-``, empty → ``anonymous``) if the
    import is unavailable (e.g. isolated unit test import order).

    Args:
        user_email: The authenticated analyst's email, when known.

    Returns:
        A sanitized actor id safe to pass to AgentCore Memory namespaces.
    """
    try:
        from agentcore_app import sanitize_actor_id

        return sanitize_actor_id(user_email)
    except Exception:  # pragma: no cover - defensive fallback if import order differs
        return (user_email or "anonymous").replace("@", "-at-").replace(".", "-")


def _delete_ltm_records(client: Any, memory_id: str, namespace: str) -> tuple[int, str | None]:
    """Delete every long-term-memory record in a single namespace.

    Lists the records in ``namespace`` and issues a ``delete_memory_record`` for each one
    that carries a ``memoryRecordId``. Handles both response shapes AgentCore may return
    (``memoryRecordSummaries`` or ``memoryRecords``).

    Args:
        client: The ``bedrock-agentcore`` boto3 client.
        memory_id: The configured AgentCore Memory id.
        namespace: The fully-qualified namespace to clear (e.g.
            ``/threat-intel/facts/a-at-b-com``).

    Returns:
        A ``(deleted_count, error_message)`` tuple. ``error_message`` is ``None`` on
        success, or a ``"{namespace}: {error}"`` string when the list/delete failed so
        the caller can collect per-namespace errors without aborting the whole clear.
    """
    deleted = 0
    try:
        response = client.list_memory_records(memoryId=memory_id, namespace=namespace)
        records = response.get("memoryRecordSummaries", response.get("memoryRecords", []))
        for record in records:
            record_id = record.get("memoryRecordId")
            if record_id:
                client.delete_memory_record(memoryId=memory_id, memoryRecordId=record_id)
                deleted += 1
    except ClientError as error:
        return deleted, f"{namespace}: {error}"
    return deleted, None


def clear_memory(session_id: str, user_email: str) -> str:
    """Erase all STM events and LTM records for the analyst (terminal deletion).

    This is a plain function (NOT a tool) so it can be reused by the ``/invocations``
    orphaned-interrupt fallback and unit-tested against a fake client. It assumes human
    approval has already been granted; callers own the HITL gate.

    The clear runs in three parts against the v2 AgentCore Memory namespaces:

    1. STM events: ``list_events(memoryId, sessionId, actorId)`` then ``delete_event`` for
       every returned ``eventId`` — wiping the current session's conversation history.
    2. LTM facts + preferences: ``list_memory_records`` + ``delete_memory_record`` for the
       actor-scoped ``/threat-intel/facts/{actorId}`` and ``/users/preferences/{actorId}``
       namespaces.
    3. LTM summaries: the same list/delete against the SESSION-scoped
       ``/summaries/{sessionId}`` namespace (summaries are keyed by session id, not
       actor id).

    Per-namespace failures are collected rather than aborting: if some deletes succeed the
    partial progress is reported; only a total failure surfaces as an error message.

    Args:
        session_id: The current AgentCore runtime session id (STM + summary key).
        user_email: The analyst's email; source of the sanitized ``actorId``.

    Returns:
        A confirmation string ending in :data:`NEW_SESSION_SENTINEL` on success, or a
        clear error message when memory is not configured or the deletion fails.
    """
    memory_id = (AGENTCORE_MEMORY_ID or "").strip()
    if not memory_id:
        return "Error: Memory is not configured on this agent."

    actor_id = _sanitize_actor_id(user_email)

    try:
        client = boto3.client("bedrock-agentcore", region_name=AWS_REGION)
        total_deleted = 0
        errors: list[str] = []

        # 1. Delete STM events for the current session.
        try:
            events_resp = client.list_events(
                memoryId=memory_id,
                sessionId=session_id,
                actorId=actor_id,
            )
            events = events_resp.get("events", [])
            for event in events:
                event_id = event.get("eventId")
                if event_id:
                    client.delete_event(
                        memoryId=memory_id,
                        sessionId=session_id,
                        eventId=event_id,
                    )
            logger.info(f"Deleted {len(events)} STM events for session={session_id[:20]}")
        except ClientError as error:
            errors.append(f"STM events: {error}")

        # 2 + 3. Delete LTM records from the v2 namespaces. Facts and preferences are
        # actor-scoped; summaries are SESSION-scoped in v2 (uses session_id, not actor_id).
        namespaces = [
            f"/threat-intel/facts/{actor_id}",
            f"/users/preferences/{actor_id}",
            f"/summaries/{session_id}",
        ]
        for namespace in namespaces:
            deleted, error = _delete_ltm_records(client, memory_id, namespace)
            total_deleted += deleted
            if error:
                errors.append(error)

        if errors and total_deleted == 0:
            return f"Error clearing memory records: {'; '.join(errors)}"

        logger.info(
            f"Memory cleared: session + {total_deleted} LTM records for user={user_email}"
        )
        return (
            f"All memory cleared. Deleted conversation history and {total_deleted} stored "
            f"facts/preferences/summaries. {NEW_SESSION_SENTINEL}"
        )

    except (BotoCoreError, ClientError) as error:
        logger.error(f"Failed to clear memory: {error}", exc_info=True)
        return f"Error clearing memory: {type(error).__name__}: {error}"
    except Exception as error:  # pragma: no cover - defensive catch-all
        logger.error(f"Unexpected error clearing memory: {error}", exc_info=True)
        return f"Unexpected error clearing memory: {type(error).__name__}: {error}"


@tool(context=True)
def clear_all_memory(tool_context: Any, session_id: str, user_email: str) -> str:
    """Clear ALL memory for the analyst, gated by human approval (destructive, HITL).

    Call this tool ONLY when the analyst explicitly asks to clear, delete, reset, or wipe
    ALL memory / chat history, or asks the agent to "forget everything". This permanently
    erases short-term conversation history (STM), learned facts, analyst preferences, and
    session summaries (LTM). It cannot be undone. Do not confuse it with ``enrich_profile``
    (which UPDATES a knowledge-base shard — a different operation entirely).

    The tool interrupts FIRST for approval and writes nothing while approval is pending.
    The interrupt key is ``clear_memory-{user_email}`` — the ``clear_memory`` prefix is
    load-bearing: the stream branch derives the frontend ``action`` from
    ``interrupt.name.split("-")[0]``, so this yields ``action="clear_memory"``. The
    ``reason`` payload carries ``action``/``session_id``/``user_email`` so the
    orphaned-interrupt fallback can reconstruct the deletion if the agent was recycled.

    On approval (``"yes"``) the terminal deletion runs via :func:`clear_memory`; on any
    other response nothing is deleted (Requirement 5-style HITL gate).

    Args:
        session_id: The current AgentCore runtime session id.
        user_email: The analyst's email address.

    Returns:
        The clear-memory confirmation (ending in the new-session sentinel), a cancellation
        message on rejection, or an error message on failure.
    """
    # Always interrupt — every call requires confirmation. The "clear_memory" prefix
    # drives the frontend action, and the extra reason fields let the orphaned fallback
    # reconstruct the deletion.
    approval = tool_context.interrupt(
        f"clear_memory-{user_email}",
        reason={
            "reason": (
                "The agent wants to erase ALL memory — conversation history, learned "
                "facts, and preferences. This cannot be undone."
            ),
            "action": "clear_memory",
            "session_id": session_id,
            "user_email": user_email,
        },
    )

    if not isinstance(approval, str) or approval.strip().lower() != "yes":
        logger.info("Clear-memory rejected; no deletion performed.")
        return "Operation cancelled. Your memory is unchanged."

    return clear_memory(session_id, user_email)

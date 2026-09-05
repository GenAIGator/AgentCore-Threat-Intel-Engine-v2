"""Human-in-the-loop profile-enrichment tool for the Threat Intelligence Engine v2.

This module exposes :func:`enrich_profile`, the Strands ``@tool(context=True)`` the
agent calls to apply a web-research-derived update to an *existing* threat-profile
shard, gated by explicit human approval (Requirement 5). The agent is expected to have
already retrieved the current shard(s) and searched the web; it passes a drafted
``proposed_content`` plus the web ``sources`` into this tool, which then:

1. Loads the current shard with ``GetItem(ProfileId, ShardId)`` for context and
   validation. Enrichment *updates* existing shards, so a missing shard is reported and
   no new shard is created (Requirement 5.4).
2. Raises a HITL interrupt via ``tool_context.interrupt`` surfacing the proposed change
   and its sources to the frontend, and writes nothing while approval is pending
   (Requirements 5.2, 5.3).
3. On approval (``"yes"``) performs the in-place ``UpdateItem`` — overwriting
   ``Content``, regenerating the ``Embedding``, and updating provenance metadata
   (``Source="web-enrichment"``, ``SourceUrl``, ``LastUpdated``, ``UpdatedBy``) — and
   confirms the write (Requirements 5.4, 6.2). On rejection it discards the draft and
   makes no change (Requirement 5.5).

The terminal write is factored into the standalone :func:`apply_enrichment` helper so
it can be reused by the orphaned-interrupt fallback (task 9.4) and unit-tested against a
fake DynamoDB client without live AWS access.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from strands import tool

from config import DDB_TABLE_NAME
from ddb import dynamodb_client
from embeddings import embed_text

logger = logging.getLogger(__name__)

# Provenance marker written to enriched shards (Requirement 6.2). Seed items use
# ``"seed"``; every human-approved web enrichment is stamped with this value so the
# origin of a shard's current content is auditable.
ENRICHMENT_SOURCE = "web-enrichment"

# Fallback ``UpdatedBy`` when the analyst's email is not available from the tool
# context. The write is still attributable to the enrichment flow rather than an
# unknown actor.
DEFAULT_UPDATED_BY = ENRICHMENT_SOURCE

# How many characters of the current shard content to surface in the interrupt payload
# so the analyst can compare the proposal against the existing text without shipping an
# arbitrarily large shard to the frontend.
CURRENT_CONTENT_PREVIEW_CHARS = 2000


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string for ``LastUpdated``."""
    return datetime.now(UTC).isoformat()


def _vector_list_attr(vector: list[float]) -> dict[str, Any]:
    """Wrap an embedding as a DynamoDB list-of-number attribute for ``UpdateItem``.

    Unlike the ``SearchVectors`` ``SearchVector`` parameter (a *bare* list built by
    :func:`ddb.to_vector_attr`), a stored ``Embedding`` attribute is a normal list
    attribute and must be wrapped as ``{"L": [{"N": "..."}, ...]}``. Each component is
    serialized via ``str`` so full float precision is preserved.

    Args:
        vector: The embedding to store, as a list of floats.

    Returns:
        The embedding as a ``{"L": [...]}`` DynamoDB ``AttributeValue``.
    """
    return {"L": [{"N": str(component)} for component in vector]}


def _source_url(sources: list[str] | None) -> str | None:
    """Derive the ``SourceUrl`` provenance value from the web sources.

    The first source is treated as the primary citation; any remaining sources are
    joined with spaces so all references are retained in the single provenance field.
    Blank/whitespace-only entries are ignored. Returns ``None`` when there are no
    usable sources, so the caller can omit the attribute rather than store an empty
    value (Requirement 6.4).

    Args:
        sources: The web source URLs the agent used to draft the update, if any.

    Returns:
        The joined source URL string, or ``None`` when no usable source is present.
    """
    if not sources:
        return None
    cleaned = [source.strip() for source in sources if source and source.strip()]
    if not cleaned:
        return None
    return " ".join(cleaned)


def apply_enrichment(
    profile_id: str,
    shard_id: str,
    proposed_content: str,
    sources: list[str] | None,
    updated_by: str,
) -> str:
    """Apply an approved enrichment to an existing shard in place (Requirements 5.4, 6.2).

    Performs a single ``UpdateItem`` on ``(ProfileId, ShardId)`` that overwrites
    ``Content`` with ``proposed_content``, regenerates ``Embedding`` from that content
    via :func:`embeddings.embed_text`, and stamps provenance metadata: ``Source`` is set
    to ``"web-enrichment"``, ``SourceUrl`` to the joined web sources (omitted when
    absent), ``LastUpdated`` to the current ISO-8601 timestamp, and ``UpdatedBy`` to the
    supplied analyst identity. The vector index re-derives the new embedding from this
    base-table write asynchronously (eventual consistency).

    This is a plain function (not a tool) so it can be reused by the orphaned-interrupt
    fallback (task 9.4) and unit-tested against a fake client. It assumes approval has
    already been granted; callers own the HITL gate.

    Args:
        profile_id: The actor id (partition key) of the shard to update.
        shard_id: The shard ``file_type`` (sort key) of the shard to update.
        proposed_content: The approved replacement text for ``Content``.
        sources: The web source URLs backing the enrichment, if any.
        updated_by: The analyst email (or a fallback marker) recorded in ``UpdatedBy``.

    Returns:
        A human-readable confirmation string describing the applied write.

    Raises:
        ClientError, BotoCoreError: If the ``UpdateItem`` call fails. Callers translate
            these into a graceful message.
    """
    embedding = embed_text(proposed_content)
    last_updated = _now_iso()

    set_clauses = [
        "#content = :content",
        "#embedding = :embedding",
        "#source = :source",
        "#last_updated = :last_updated",
        "#updated_by = :updated_by",
    ]
    names = {
        "#content": "Content",
        "#embedding": "Embedding",
        "#source": "Source",
        "#last_updated": "LastUpdated",
        "#updated_by": "UpdatedBy",
    }
    values: dict[str, Any] = {
        ":content": {"S": proposed_content},
        ":embedding": _vector_list_attr(embedding),
        ":source": {"S": ENRICHMENT_SOURCE},
        ":last_updated": {"S": last_updated},
        ":updated_by": {"S": updated_by},
    }

    source_url = _source_url(sources)
    if source_url is not None:
        set_clauses.append("#source_url = :source_url")
        names["#source_url"] = "SourceUrl"
        values[":source_url"] = {"S": source_url}

    dynamodb_client().update_item(
        TableName=DDB_TABLE_NAME,
        Key={"ProfileId": {"S": profile_id}, "ShardId": {"S": shard_id}},
        UpdateExpression="SET " + ", ".join(set_clauses),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    logger.info(
        "Applied enrichment to ProfileId=%s ShardId=%s by=%s", profile_id, shard_id, updated_by
    )
    citation = f" Source: {source_url}." if source_url else ""
    provenance = (
        f"(Source={ENRICHMENT_SOURCE}, UpdatedBy={updated_by}, LastUpdated={last_updated})"
    )
    return (
        f"Enrichment applied. Updated the '{shard_id}' shard of '{profile_id}' in place, "
        f"regenerated its embedding, and stamped provenance {provenance}.{citation}"
    )


def _get_shard(profile_id: str, shard_id: str) -> dict[str, Any] | None:
    """Load a single shard by key, returning its ``AttributeValue`` map or ``None``.

    Args:
        profile_id: The actor id (partition key).
        shard_id: The shard ``file_type`` (sort key).

    Returns:
        The raw DynamoDB item map when the shard exists, else ``None``.
    """
    response = dynamodb_client().get_item(
        TableName=DDB_TABLE_NAME,
        Key={"ProfileId": {"S": profile_id}, "ShardId": {"S": shard_id}},
    )
    return response.get("Item")


def _current_content_preview(item: dict[str, Any]) -> str:
    """Extract a truncated preview of a shard's current ``Content`` for the interrupt.

    Args:
        item: The raw DynamoDB item map of the current shard.

    Returns:
        The current ``Content`` string truncated to
        :data:`CURRENT_CONTENT_PREVIEW_CHARS`, or an empty string when absent.
    """
    content_attr = item.get("Content")
    current = content_attr.get("S", "") if isinstance(content_attr, dict) else ""
    if len(current) > CURRENT_CONTENT_PREVIEW_CHARS:
        return current[:CURRENT_CONTENT_PREVIEW_CHARS] + "…"
    return current


def _resolve_updated_by(tool_context: Any, updated_by: str | None) -> str:
    """Best-effort resolution of the analyst identity recorded in ``UpdatedBy``.

    Prefers an explicitly-passed ``updated_by``; otherwise probes the tool context for a
    user email defensively (its shape varies across Strands versions), falling back to
    :data:`DEFAULT_UPDATED_BY` so provenance is always populated.

    Args:
        tool_context: The Strands tool context passed to the ``@tool(context=True)``.
        updated_by: An optional explicit analyst identity.

    Returns:
        The resolved identity string, never empty.
    """
    if updated_by and updated_by.strip():
        return updated_by.strip()

    for attr in ("user_email", "email", "actor_id", "user_id"):
        try:
            value = getattr(tool_context, attr, None)
        except Exception:  # pragma: no cover - defensive: context shape varies
            value = None
        if isinstance(value, str) and value.strip():
            return value.strip()

    return DEFAULT_UPDATED_BY


@tool(context=True)
def enrich_profile(
    tool_context: Any,
    profile_id: str,
    shard_id: str,
    proposed_content: str,
    sources: list[str] | None = None,
    updated_by: str | None = None,
) -> str:
    """Enrich an existing threat-profile shard, gated by human approval (Requirement 5).

    Call this tool ONLY to update an existing profile shard with web-research-derived
    content. First retrieve the current shard(s) for the ``ProfileId`` and search the
    web, then pass the drafted ``proposed_content`` and the ``sources`` you used. This
    tool loads the current shard for context, then pauses for the analyst to approve or
    reject the change — it never writes directly and never writes while approval is
    pending (Requirements 5.2, 5.3). Profile-update requests MUST route through this
    tool so the human-in-the-loop interrupt fires.

    On approval the existing shard is overwritten in place, re-embedded, and stamped with
    web-enrichment provenance (Requirements 5.4, 6.2); on rejection nothing changes
    (Requirement 5.5). If the shard does not exist, no shard is created and a clear
    message is returned (Requirement 5.4).

    Args:
        profile_id: The actor id (partition key) of the shard to enrich, e.g. ``"apt29"``.
        shard_id: The shard ``file_type`` (sort key) to enrich, e.g. ``"detection"``.
        proposed_content: The drafted replacement text for the shard's ``Content``.
        sources: The web source URLs used to draft the update, for analyst review and
            provenance.
        updated_by: Optional analyst identity to record; inferred from context or a
            fallback marker when omitted.

    Returns:
        A confirmation of the applied write, a cancellation message on rejection, a
        missing-shard message, or an error message on failure.
    """
    if not proposed_content or not proposed_content.strip():
        return "No proposed content was provided, so there is nothing to enrich."

    try:
        current_item = _get_shard(profile_id, shard_id)
    except (BotoCoreError, ClientError) as error:
        logger.error("Failed to load shard for enrichment: %s", error, exc_info=True)
        return f"Error loading the '{shard_id}' shard of '{profile_id}': {error}"

    if current_item is None:
        return (
            f"No existing '{shard_id}' shard found for profile '{profile_id}'. "
            "Enrichment only updates existing shards, so no new shard was created. "
            "Verify the ProfileId and ShardId, or load the profile first."
        )

    clean_sources = [source for source in (sources or []) if source and source.strip()]

    # Pause for human approval. No write happens on this side of the interrupt
    # (Requirement 5.3); the frontend renders the proposal + sources (Requirement 5.2).
    approval = tool_context.interrupt(
        f"enrich-{profile_id}-{shard_id}",
        reason={
            "action": "enrich",
            "profile_id": profile_id,
            "shard_id": shard_id,
            "proposed_content": proposed_content,
            "sources": clean_sources,
            "current_content": _current_content_preview(current_item),
        },
    )

    if not isinstance(approval, str) or approval.strip().lower() != "yes":
        logger.info(
            "Enrichment rejected for ProfileId=%s ShardId=%s (no write)", profile_id, shard_id
        )
        return (
            f"Enrichment cancelled. The '{shard_id}' shard of '{profile_id}' is unchanged; "
            "no update was written."
        )

    resolved_updated_by = _resolve_updated_by(tool_context, updated_by)
    try:
        return apply_enrichment(
            profile_id=profile_id,
            shard_id=shard_id,
            proposed_content=proposed_content,
            sources=clean_sources,
            updated_by=resolved_updated_by,
        )
    except (BotoCoreError, ClientError) as error:
        logger.error("Failed to apply enrichment: %s", error, exc_info=True)
        return (
            f"Approval was granted, but writing the '{shard_id}' shard of '{profile_id}' failed: "
            f"{error}. No partial change was applied."
        )

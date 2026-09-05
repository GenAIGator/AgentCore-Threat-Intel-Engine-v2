"""Semantic retrieval tool for the Threat Intelligence Engine v2 agent.

This module exposes :func:`retrieve_profiles`, the Strands ``@tool`` the agent calls
to ground its answers in the DynamoDB vector store (Requirement 2). Given a natural
language query it:

1. Embeds the query with Titan v2 (1024-dim) via :func:`embeddings.embed_text`
   (Requirement 2.1).
2. Calls the DynamoDB ``SearchVectors`` API for the Top K nearest shards, clamping
   ``top_k`` to ``[1, 100]`` (default 10, max 100 — Requirement 2.2).
3. Optionally constrains the search with ``INLINE_FILTER`` equality on ``FileType``
   and/or ``Country`` via a ``SearchConditionExpression`` (Requirement 2.3).
4. Retries a warm-up ``ValidationException`` (the index re-derives from base-table
   writes and is briefly unqueryable right after creation — Requirement 2.5).
5. Parses ``SearchResults`` and drops matches whose COSINE distance exceeds a
   configurable relevance threshold — lower distance means more similar — returning an
   empty-context indicator when nothing qualifies (Requirement 2.6).
6. Renders the survivors as a compact, citation-tagged context block (``ProfileId``,
   ``Name``, ``FileType`` per result) for the generating model (Requirement 2.4).

The pure request/response shaping — filter-expression construction and threshold
filtering — is factored into the standalone helpers :func:`build_search_condition` and
:func:`filter_by_threshold` so they can be unit-tested without AWS access (task 6.2).
"""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError
from strands import tool

from config import DDB_TABLE_NAME, DDB_VECTOR_INDEX
from ddb import dynamodb_client, from_search_results, to_vector_attr
from embeddings import embed_text

# Top K bounds (Requirement 2.2): default 10, never below 1 or above the API max 100.
DEFAULT_TOP_K = 10
MIN_TOP_K = 1
MAX_TOP_K = 100

# Relevance threshold (Requirement 2.6). COSINE distance in [0, 2]; lower = more
# similar. Matches at or below this distance are kept; anything greater is dropped as
# a low-quality match. Tuned conservatively so unrelated shards are excluded while
# genuine topical matches survive.
DEFAULT_RELEVANCE_THRESHOLD = 0.6

# Warm-up retry policy (Requirement 2.5): a freshly created index can reject the first
# few searches with a ValidationException while it backfills from the base table.
WARMUP_MAX_RETRIES = 5
WARMUP_BASE_DELAY_SECONDS = 1.0

# Returned when no shard clears the relevance threshold, so the agent can fall back to
# web search or state its limits rather than answering from low-quality matches.
EMPTY_CONTEXT = "NO_RELEVANT_CONTEXT"


def build_search_condition(
    file_type: str | None = None,
    country: str | None = None,
) -> dict[str, Any]:
    """Build the ``INLINE_FILTER`` clause for a ``SearchVectors`` request.

    Constructs an equality-only ``SearchConditionExpression`` (the sole operator the
    inline-filter index supports today) over the optional ``FileType`` and ``Country``
    constraints, together with the matching ``ExpressionAttributeNames`` and
    ``ExpressionAttributeValues`` (Requirement 2.3). Attribute *names* are aliased with
    ``#``-placeholders so they never collide with DynamoDB reserved words, and values
    are typed as ``S`` strings.

    When both constraints are given they are combined with ``AND``; when neither is
    given an empty dict is returned so the caller can search the whole corpus without a
    condition expression.

    Args:
        file_type: Optional ``FileType`` (shard type, e.g. ``"detection"``) to require.
        country: Optional ``Country`` (e.g. ``"China"``) to require.

    Returns:
        A dict ready to merge into the ``search_vectors`` request. Either empty (no
        filters) or carrying ``SearchConditionExpression``, ``ExpressionAttributeNames``
        and ``ExpressionAttributeValues``.
    """
    clauses: list[str] = []
    names: dict[str, str] = {}
    values: dict[str, dict[str, str]] = {}

    if file_type:
        clauses.append("#ft = :ft")
        names["#ft"] = "FileType"
        values[":ft"] = {"S": file_type}
    if country:
        clauses.append("#co = :co")
        names["#co"] = "Country"
        values[":co"] = {"S": country}

    if not clauses:
        return {}

    return {
        "SearchConditionExpression": " AND ".join(clauses),
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
    }


def filter_by_threshold(
    results: list[dict[str, Any]],
    threshold: float = DEFAULT_RELEVANCE_THRESHOLD,
) -> list[dict[str, Any]]:
    """Drop matches whose COSINE distance exceeds ``threshold`` (Requirement 2.6).

    The index ranks by COSINE distance where a *lower* score means *more* similar, so a
    result qualifies when its ``Score`` is less than or equal to ``threshold``. Results
    with a missing/non-numeric ``Score`` are treated as failing the threshold and
    dropped, since they cannot be judged relevant. Input order is preserved, so callers
    that pass already-ranked ``SearchResults`` keep the best matches first.

    Args:
        results: Parsed results from :func:`ddb.from_search_results`, each a dict with a
            numeric ``Score`` (COSINE distance).
        threshold: The maximum distance to keep. Defaults to
            :data:`DEFAULT_RELEVANCE_THRESHOLD`.

    Returns:
        The subset of ``results`` at or below ``threshold``, in the original order.
    """
    kept: list[dict[str, Any]] = []
    for result in results:
        score = result.get("Score")
        if isinstance(score, (int, float)) and not isinstance(score, bool) and score <= threshold:
            kept.append(result)
    return kept


def _is_warmup_validation_error(error: ClientError) -> bool:
    """Return whether ``error`` is a retryable index warm-up ``ValidationException``."""
    return error.response.get("Error", {}).get("Code") == "ValidationException"


def _search_vectors_with_retry(request: dict[str, Any]) -> dict[str, Any]:
    """Call ``search_vectors``, retrying a warm-up ``ValidationException``.

    A vector index re-derives from base-table writes and can reject searches with a
    ``ValidationException`` for a short window right after creation (Requirement 2.5).
    This retries such errors with linear backoff up to :data:`WARMUP_MAX_RETRIES`
    times; any non-``ValidationException`` ``ClientError`` is surfaced immediately, and
    the last warm-up error is re-raised if the budget is exhausted.

    Args:
        request: The fully built ``search_vectors`` keyword arguments.

    Returns:
        The raw ``search_vectors`` response.

    Raises:
        ClientError: A non-retryable error, or the final warm-up error after retries.
    """
    ddb = dynamodb_client()
    last_error: ClientError | None = None
    for attempt in range(WARMUP_MAX_RETRIES + 1):
        try:
            return ddb.search_vectors(**request)
        except ClientError as error:
            if not _is_warmup_validation_error(error):
                raise
            last_error = error
            if attempt < WARMUP_MAX_RETRIES:
                time.sleep(WARMUP_BASE_DELAY_SECONDS * (attempt + 1))
    assert last_error is not None  # loop only exits normally via return
    raise last_error


def _format_context(results: list[dict[str, Any]]) -> str:
    """Render qualifying results as a compact, citation-tagged context block.

    Each result becomes a ``[n]`` numbered entry carrying its citation metadata
    (``ProfileId``, ``Name``, ``FileType``) followed by the embedded ``Content``
    (Requirement 2.4), so the model can quote and attribute intelligence back to the
    contributing actor and shard.

    Args:
        results: The threshold-qualifying results to render.

    Returns:
        A newline-delimited context block; :data:`EMPTY_CONTEXT` when ``results`` is
        empty.
    """
    if not results:
        return EMPTY_CONTEXT

    blocks: list[str] = []
    for index, result in enumerate(results, start=1):
        name = result.get("Name") or "Unknown actor"
        profile_id = result.get("ProfileId") or "unknown"
        file_type = result.get("FileType") or "unknown"
        content = result.get("Content") or ""
        blocks.append(
            f"[{index}] Name={name} | ProfileId={profile_id} | FileType={file_type}\n"
            f"{content}"
        )
    return "\n\n".join(blocks)


@tool
def retrieve_profiles(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    file_type: str | None = None,
    country: str | None = None,
) -> str:
    """Retrieve the most relevant threat-profile shards for a query (Requirement 2).

    Embeds ``query`` with Titan v2 and runs a DynamoDB vector ``SearchVectors`` search
    over the whole corpus (the index has no HASH key), optionally scoped by ``FileType``
    and/or ``Country`` inline filters. Results are ranked by COSINE distance, filtered to
    those meeting the relevance threshold, and returned as a citation-tagged context
    block for grounding the generated answer. When nothing is relevant enough, returns a
    sentinel so the agent can fall back to web search or state its limits.

    Args:
        query: The analyst's natural-language question or search text.
        top_k: Maximum number of shards to retrieve. Clamped to ``[1, 100]``; defaults
            to 10.
        file_type: Optional shard-type filter (e.g. ``"detection"``, ``"ai_tooling"``).
        country: Optional actor-country filter (e.g. ``"China"``).

    Returns:
        A compact, citation-tagged context block (one ``[n]`` entry per qualifying
        shard with ``ProfileId``, ``Name``, ``FileType`` and ``Content``), or
        :data:`EMPTY_CONTEXT` when no shard clears the relevance threshold.
    """
    clamped_top_k = max(MIN_TOP_K, min(top_k, MAX_TOP_K))

    request: dict[str, Any] = {
        "TableName": DDB_TABLE_NAME,
        "IndexName": DDB_VECTOR_INDEX,
        "SearchVector": to_vector_attr(embed_text(query)),
        "TopK": clamped_top_k,
        "ProjectionExpression": "#pid, #nm, #ft, #ct",
        "ExpressionAttributeNames": {
            "#pid": "ProfileId",
            "#nm": "Name",
            "#ft": "FileType",
            "#ct": "Content",
        },
    }

    condition = build_search_condition(file_type=file_type, country=country)
    if condition:
        request["SearchConditionExpression"] = condition["SearchConditionExpression"]
        request["ExpressionAttributeNames"].update(condition["ExpressionAttributeNames"])
        request["ExpressionAttributeValues"] = condition["ExpressionAttributeValues"]

    response = _search_vectors_with_retry(request)
    results = from_search_results(response)
    relevant = filter_by_threshold(results)
    return _format_context(relevant)

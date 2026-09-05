"""DynamoDB clients and vector-search (de)serialization helpers for v2.

This module owns the low-level DynamoDB access used by the retrieval and enrichment
paths (Requirements 2.1, 2.4). It provides:

* :func:`dynamodb_client` — a cached low-level ``dynamodb`` client. The low-level
  client (not the resource) is required because ``SearchVectors`` and native
  ``AttributeValue`` I/O are only exposed there.
* :func:`to_vector_attr` — convert a Python ``list[float]`` embedding into the
  **plain list** of number ``AttributeValue``\\ s that the ``SearchVectors``
  ``SearchVector`` parameter expects, i.e. ``[{"N": "0.1"}, ...]`` — *not* the
  ``{"L": [...]}`` wrapper used elsewhere in the DynamoDB API.
* :func:`from_search_results` — parse a ``SearchVectors`` response, whose matches
  live under the ``SearchResults`` array (each element ``{"Item": {...},
  "Score": <distance>}``, *not* ``Items``), into a compact list of citation-ready
  dicts ``{ProfileId, Name, FileType, Content, Score}``.

Region and table/index names come from :mod:`config`, so callers do not repeat the
configuration lookups. The ``SearchVectors`` capability guard lives in
:mod:`embeddings` (:func:`embeddings.ensure_search_vectors_supported`); the client
factory here invokes it so a missing API fails fast with an actionable message.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any

import boto3

from config import AWS_REGION
from embeddings import ensure_search_vectors_supported

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_dynamodb import DynamoDBClient

# A single ``SearchVectors`` match, as returned under the ``SearchResults`` array.
SearchResult = dict[str, Any]


@lru_cache(maxsize=1)
def dynamodb_client() -> DynamoDBClient:
    """Return a cached low-level DynamoDB client for vector search and item I/O.

    The low-level client is required (rather than the boto3 resource) because the
    ``SearchVectors`` API and raw ``AttributeValue`` reads/writes are only available
    there. The client is validated once for ``search_vectors`` support so an
    unsupported boto3 fails fast with a clear message instead of an opaque
    ``AttributeError`` deep in a retrieval call.

    Returns:
        A low-level ``dynamodb`` client bound to :data:`config.AWS_REGION`.

    Raises:
        RuntimeError: If the installed boto3 lacks the ``search_vectors`` API.
    """
    client = boto3.client("dynamodb", region_name=AWS_REGION)
    ensure_search_vectors_supported(client)
    return client


def to_vector_attr(vector: list[float]) -> list[dict[str, str]]:
    """Convert an embedding into the plain-list ``SearchVector`` form.

    The ``SearchVectors`` ``SearchVector`` parameter takes a **bare list** of number
    ``AttributeValue``\\ s — ``[{"N": "0.1"}, {"N": "-0.2"}, ...]`` — and must *not*
    be wrapped in ``{"L": [...]}`` the way a stored list attribute would be. Passing
    the ``L`` wrapper causes a ``ValidationException``. Each component is serialized
    via ``str`` so the full float precision is preserved in the request.

    Args:
        vector: The query (or shard) embedding as a list of floats.

    Returns:
        The embedding as a list of ``{"N": "<value>"}`` attribute values, ready to
        pass directly as the ``SearchVector`` request parameter.

    Raises:
        ValueError: If ``vector`` is empty.
    """
    if not vector:
        raise ValueError("to_vector_attr requires a non-empty vector.")
    return [{"N": str(component)} for component in vector]


def _s(item: dict[str, Any], key: str) -> str | None:
    """Read a DynamoDB string (``S``) attribute from ``item``; ``None`` if absent."""
    value = item.get(key)
    if isinstance(value, dict) and "S" in value:
        return value["S"]
    return None


def from_search_results(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a ``SearchVectors`` response into citation-ready result dicts.

    ``SearchVectors`` returns its matches under the ``SearchResults`` key (note: not
    ``Items``); each entry is ``{"Item": {<AttributeValue map>}, "Score": <distance>}``
    where ``Score`` is the COSINE distance (lower means more similar). This function
    flattens each match into a compact dict carrying the citation metadata and the
    embedded text the model needs — ``ProfileId``, ``Name``, ``FileType``,
    ``Content`` — plus the raw ``Score`` so callers can rank and apply a relevance
    threshold (Requirements 2.2, 2.4, 2.6).

    Missing string attributes are returned as ``None`` rather than raising, so a
    projection that omits a field (or a shard lacking optional metadata) degrades
    gracefully. Entries without an ``Item`` are skipped.

    Args:
        response: The dict returned by ``dynamodb.search_vectors``.

    Returns:
        A list of ``{"ProfileId", "Name", "FileType", "Content", "Score"}`` dicts,
        preserving the order of ``SearchResults``.
    """
    results: list[dict[str, Any]] = []
    for match in response.get("SearchResults", []):
        item = match.get("Item")
        if not item:
            continue
        results.append(
            {
                "ProfileId": _s(item, "ProfileId"),
                "Name": _s(item, "Name"),
                "FileType": _s(item, "FileType"),
                "Content": _s(item, "Content"),
                "Score": match.get("Score"),
            }
        )
    return results

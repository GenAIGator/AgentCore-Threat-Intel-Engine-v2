"""Embed generated sections and write the complete profile to DynamoDB.

Mirrors the loader's item shape (``agentcore-threat-intel-engine-v2/loader/load_profiles.py``)
so a builder-created profile is indistinguishable from a seeded one, except provenance is
stamped ``Source="agent-created"`` / ``UpdatedBy=<requester>`` instead of ``"seed"``/``"loader"``.

The write is **atomic-ish**: all 12 sections are embedded, then written in one
``BatchWriteItem`` pass (chunked at 25, with unprocessed-item retry). A failure before the
write means nothing lands — no half-profiles.

``build_item`` assembles a single item from a section's generated ``fields`` using the
loader's own ``derive_content`` / ``derive_metadata`` (imported from the loader package,
which is on the builder image), so Content + metadata match the corpus exactly. The Titan
embed + DynamoDB serialization helpers are self-contained here (boto3 only), mirroring the
loader.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Any

import boto3

from config import (
    AWS_REGION,
    DDB_TABLE_NAME,
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
)

# The loader package (content.py) is copied onto the builder image so we reuse the exact
# Content/metadata derivation the seed corpus used.
from content import derive_content, derive_metadata

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_bedrock_runtime import BedrockRuntimeClient
    from mypy_boto3_dynamodb import DynamoDBClient

logger = logging.getLogger("builder.profile_writer")

_STRING_SET_ATTRS = frozenset({"Aliases", "Category"})
BATCH_SIZE = 25
MAX_UNPROCESSED_RETRIES = 8
_BACKOFF_BASE_SECONDS = 0.05
_BACKOFF_CAP_SECONDS = 5.0

CREATED_SOURCE = "agent-created"


@lru_cache(maxsize=1)
def _bedrock_client() -> BedrockRuntimeClient:
    return boto3.client("bedrock-runtime", region_name=AWS_REGION)


@lru_cache(maxsize=1)
def _ddb_client() -> DynamoDBClient:
    return boto3.client("dynamodb", region_name=AWS_REGION)


def embed_text(text: str) -> list[float]:
    """Embed ``text`` with Titan v2 (same request/response shape as loader + agent)."""
    if not text or not text.strip():
        raise ValueError("embed_text requires non-empty text.")
    body = json.dumps({"inputText": text, "dimensions": EMBEDDING_DIMENSIONS})
    response = _bedrock_client().invoke_model(modelId=EMBEDDING_MODEL, body=body)
    payload = json.loads(response["body"].read())
    embedding = payload["embedding"]
    if len(embedding) != EMBEDDING_DIMENSIONS:
        raise ValueError(
            f"Titan returned a {len(embedding)}-dim embedding but {EMBEDDING_DIMENSIONS} "
            "was requested."
        )
    return [float(v) for v in embedding]


def _to_ddb_number_list(vector: list[float]) -> dict[str, Any]:
    return {"L": [{"N": str(component)} for component in vector]}


def _metadata_to_attrs(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    attrs: dict[str, dict[str, Any]] = {}
    for key, value in metadata.items():
        if key in _STRING_SET_ATTRS:
            members = [str(m) for m in value if str(m).strip()]
            if members:
                attrs[key] = {"SS": members}
        elif isinstance(value, bool):
            attrs[key] = {"BOOL": value}
        else:
            attrs[key] = {"S": str(value)}
    return attrs


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def build_shard(
    profile_id: str,
    name: str,
    file_type: str,
    fields: dict[str, Any],
    attribution: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble the raw shard dict (loader input shape) for one section.

    Combines the actor identity (``id``, ``name``, ``attribution``) with the section's
    ``file_type`` and generated ``fields``. This is what ``derive_content`` /
    ``derive_metadata`` consume, and what is stored verbatim in ``RawJson``.
    """
    shard: dict[str, Any] = {
        "id": profile_id,
        "name": name,
        "file_type": file_type,
    }
    if attribution:
        shard["attribution"] = attribution
    shard.update(fields)
    return shard


def build_item(
    shard: dict[str, Any],
    *,
    updated_by: str,
) -> dict[str, dict[str, Any]]:
    """Build a DynamoDB item from a shard, embedding its derived Content.

    Uses the loader's ``derive_metadata``/``derive_content`` so keys, metadata, and the
    embedded text match the seed corpus. Stamps ``Source="agent-created"`` provenance.
    """
    metadata = derive_metadata(shard)
    if "ProfileId" not in metadata or "ShardId" not in metadata:
        raise ValueError("shard is missing a usable 'id' and/or 'file_type'.")
    content = derive_content(shard)
    embedding = embed_text(content)

    item: dict[str, dict[str, Any]] = _metadata_to_attrs(metadata)
    item["Content"] = {"S": content}
    item["Embedding"] = _to_ddb_number_list(embedding)
    item["RawJson"] = {"S": json.dumps(shard, sort_keys=True)}
    item["Source"] = {"S": CREATED_SOURCE}
    item["LastUpdated"] = {"S": _now_iso()}
    item["UpdatedBy"] = {"S": updated_by or CREATED_SOURCE}
    return item


def write_items(
    items: list[dict[str, dict[str, Any]]],
    client: DynamoDBClient | None = None,
) -> int:
    """BatchWriteItem all items (chunked at 25) with unprocessed-item retry.

    Returns the number of items submitted. Raises on a batch that cannot drain its
    unprocessed items within the retry budget (so the caller fails cleanly -> SNS).
    """
    ddb = client if client is not None else _ddb_client()
    written = 0
    for start in range(0, len(items), BATCH_SIZE):
        chunk = items[start : start + BATCH_SIZE]
        # RequestItems is a loosely-typed AttributeValue structure; keep it Any so the
        # UnprocessedItems re-submission (same shape) type-checks under strict mypy.
        request: dict[str, Any] = {
            DDB_TABLE_NAME: [{"PutRequest": {"Item": item}} for item in chunk]
        }
        attempt = 0
        while True:
            response = ddb.batch_write_item(RequestItems=request)
            unprocessed = response.get("UnprocessedItems", {})
            if not unprocessed:
                break
            attempt += 1
            if attempt > MAX_UNPROCESSED_RETRIES:
                raise RuntimeError(
                    f"BatchWriteItem left {len(unprocessed.get(DDB_TABLE_NAME, []))} "
                    f"unprocessed items after {MAX_UNPROCESSED_RETRIES} retries."
                )
            delay = min(_BACKOFF_BASE_SECONDS * (2**attempt), _BACKOFF_CAP_SECONDS)
            time.sleep(delay)
            request = dict(unprocessed)
        written += len(chunk)
    logger.info("Wrote %d profile shard items to %s", written, DDB_TABLE_NAME)
    return written

"""Ingestion loader: v1 threat-profile shards -> DynamoDB vector-store items.

This module walks the v1 threat-profile corpus (``threat-profiles/*.json``, ~1630 files,
one shard per file), turns each shard into a single DynamoDB item, and prepares those
items for the vector table ``ThreatProfilesV2`` (Requirement 1). For every shard it:

* derives the deterministic ``Content`` string and the promoted metadata attributes via
  :mod:`content` (task 3, Requirements 6.1, 6.4, 7.1);
* embeds ``Content`` with Amazon Titan Text Embeddings v2 (1024-dim) into an
  ``Embedding`` attribute stored as a list of numbers (Requirement 1.3);
* preserves the raw source JSON in ``RawJson`` for traceability (Requirement 7.3);
* stamps seed provenance ``Source="seed"``, ``LastUpdated`` (ISO-8601 now),
  ``UpdatedBy="loader"`` (Requirement 6.2).

Keys are ``ProfileId`` (partition, the actor ``id``) + ``ShardId`` (sort, the shard
``file_type``), per Requirement 1.2. Metadata list attributes (``Aliases``, ``Category``)
are written as DynamoDB string sets (``SS``) and ``AiConfirmed`` as a boolean (``BOOL``),
matching the data model in ``design.md``.

Per-file failures (unreadable/unparseable JSON, a shard missing its keys, or an embed
error) are logged with the offending path and skipped so a single bad file never aborts
the load; the run reports succeeded vs. failed counts at the end (Requirement 1.5).

**Task boundary.** Task 5.1 owns item *building*: this module exposes
:func:`iter_built_items` (a generator over ``(path, item)`` pairs, skipping failures) and
:func:`build_items` (materialize + counts). Task 5.2 adds the ``BatchWriteItem`` upsert
with unprocessed-item retry (:func:`write_items`, 25/batch, idempotent by
``(ProfileId, ShardId)``) and the :func:`run` orchestration that builds then writes and
reports succeeded/failed/written counts. Task 5.3 adds the ``--limit`` CLI
(:func:`main` / :func:`build_arg_parser`, also ``--profiles-dir`` / ``--table`` /
``--verify-idempotency``) and the run-twice idempotency check (:func:`count_table_items`
via a paginated COUNT scan, :func:`verify_idempotency` asserting a stable item count),
both wiring onto :func:`run`.

The loader is intentionally dependency-light (``boto3`` only): it reimplements a small
Titan embed helper here (mirroring ``agent/src/embeddings.py``'s request/response shape)
reading ``EMBEDDING_MODEL`` / ``EMBEDDING_DIMENSIONS`` / ``AWS_REGION`` from the
environment, rather than importing the agent package. Importing this module never touches
AWS; clients are created lazily on first embed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

import boto3

from content import derive_content, derive_metadata

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_bedrock_runtime import BedrockRuntimeClient
    from mypy_boto3_dynamodb import DynamoDBClient

logger = logging.getLogger("load_profiles")

# --- Configuration (env vars, mirroring agent/src/config.py defaults) ---------------
#
# The loader is a separate, boto3-only package, so it reads its own configuration from
# the environment rather than importing the agent's config module. Defaults match
# design.md / the agent so seed and query embeddings are generated identically.
DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
DEFAULT_EMBEDDING_DIMENSIONS = 1024
DEFAULT_TABLE_NAME = "ThreatProfilesV2"

# Default location of the v1 corpus, resolved relative to this file so the loader works
# from any CWD: ``agentcore-threat-intel-engine-v2/loader/`` -> repo root ->
# ``agentcore-threat-intel-engine/threat-profiles``. Overridable via THREAT_PROFILES_DIR.
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILES_DIR = _REPO_ROOT / "agentcore-threat-intel-engine" / "threat-profiles"

# Metadata attributes that hold a Python ``list[str]`` and must be written as a
# DynamoDB string set (``SS``); everything else promoted by derive_metadata is a scalar.
_STRING_SET_ATTRS = frozenset({"Aliases", "Category"})

# BatchWriteItem hard limit: DynamoDB accepts at most 25 write requests per call.
BATCH_SIZE = 25
# How many times to re-submit ``UnprocessedItems`` before giving up on a batch. Each
# retry waits an exponentially growing, capped delay so throttled writes eventually land.
MAX_UNPROCESSED_RETRIES = 8
# Exponential-backoff base / cap (seconds) between UnprocessedItems re-submissions.
_BACKOFF_BASE_SECONDS = 0.05
_BACKOFF_CAP_SECONDS = 5.0


def aws_region() -> str:
    return os.environ.get("AWS_REGION", DEFAULT_AWS_REGION).strip() or DEFAULT_AWS_REGION


def embedding_model() -> str:
    value = os.environ.get("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL).strip()
    return value or DEFAULT_EMBEDDING_MODEL


def embedding_dimensions() -> int:
    raw = os.environ.get("EMBEDDING_DIMENSIONS", "").strip()
    if not raw:
        return DEFAULT_EMBEDDING_DIMENSIONS
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(
            f"EMBEDDING_DIMENSIONS must be an integer, got {raw!r}"
        ) from exc


def table_name() -> str:
    return os.environ.get("DDB_TABLE_NAME", DEFAULT_TABLE_NAME).strip() or DEFAULT_TABLE_NAME


def profiles_dir() -> Path:
    """Resolve the threat-profiles source directory (env override or default)."""
    override = os.environ.get("THREAT_PROFILES_DIR", "").strip()
    return Path(override) if override else DEFAULT_PROFILES_DIR


# --- Titan embedding (self-contained; mirrors agent/src/embeddings.py) ---------------


@lru_cache(maxsize=1)
def _bedrock_client() -> BedrockRuntimeClient:
    """Return a cached Bedrock runtime client (created lazily on first embed)."""
    return boto3.client("bedrock-runtime", region_name=aws_region())


def embed_text(text: str) -> list[float]:
    """Embed ``text`` with Titan Text Embeddings v2 and return the vector.

    Uses the same request/response shape as ``agent/src/embeddings.py`` so seed vectors
    match query vectors: request body ``{"inputText": ..., "dimensions": N}`` against
    ``EMBEDDING_MODEL``; response carries the vector under ``embedding``. The result is a
    plain ``list[float]`` of length :func:`embedding_dimensions` (Requirement 1.3).

    Args:
        text: The non-empty text to embed.

    Returns:
        The embedding as a ``list[float]``.

    Raises:
        ValueError: If ``text`` is empty/whitespace-only, or the returned vector's
            dimensionality does not match the configured dimensions.
    """
    if not text or not text.strip():
        raise ValueError("embed_text requires non-empty text.")

    dimensions = embedding_dimensions()
    body = json.dumps({"inputText": text, "dimensions": dimensions})
    response = _bedrock_client().invoke_model(modelId=embedding_model(), body=body)
    payload = json.loads(response["body"].read())
    embedding = payload["embedding"]

    if len(embedding) != dimensions:
        raise ValueError(
            f"Titan returned a {len(embedding)}-dim embedding but {dimensions} was "
            "requested; check EMBEDDING_MODEL / EMBEDDING_DIMENSIONS and the vector "
            "index Dimensions."
        )

    return [float(value) for value in embedding]


# --- Item construction ---------------------------------------------------------------


def to_ddb_number_list(vector: list[float]) -> dict[str, Any]:
    """Serialize an embedding as a DynamoDB list-of-number (``L`` of ``N``) attribute.

    This is the *stored* form on the base-table item (``{"L": [{"N": "0.1"}, ...]}``),
    which the vector index reads to build the ANN structure — distinct from the plain,
    unwrapped list the ``SearchVectors`` request expects (see ``agent/src/ddb.py``
    ``to_vector_attr``). Components are stringified to preserve full float precision.

    Args:
        vector: The embedding as a list of floats.

    Returns:
        A DynamoDB ``AttributeValue`` of the form ``{"L": [{"N": "<value>"}, ...]}``.
    """
    return {"L": [{"N": str(component)} for component in vector]}


def metadata_to_attrs(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Serialize the native-Python metadata mapping into DynamoDB ``AttributeValue``\\ s.

    Applies the data-model types from ``design.md``: ``Aliases`` and ``Category`` become
    string sets (``SS``), ``AiConfirmed`` becomes a boolean (``BOOL``), and the remaining
    promoted fields (``ProfileId``, ``ShardId``, ``Name``, ``Country``, ``Region``,
    ``FileType``, ``CloudRelevance``) become strings (``S``). Because
    :func:`content.derive_metadata` already omits absent/empty fields (Requirement 6.4),
    no empty values are produced here.

    A string-set attribute whose list is empty is skipped (DynamoDB rejects empty sets);
    in practice derive_metadata never emits one.

    Args:
        metadata: The mapping returned by :func:`content.derive_metadata`.

    Returns:
        A mapping of attribute name to DynamoDB ``AttributeValue``.
    """
    attrs: dict[str, dict[str, Any]] = {}
    for key, value in metadata.items():
        if key in _STRING_SET_ATTRS:
            members = [str(member) for member in value if str(member).strip()]
            if members:
                attrs[key] = {"SS": members}
        elif isinstance(value, bool):
            attrs[key] = {"BOOL": value}
        else:
            attrs[key] = {"S": str(value)}
    return attrs


def _now_iso() -> str:
    """Current UTC time as an ISO-8601 string (Requirement 6.2)."""
    return datetime.now(UTC).isoformat()


def build_item(shard: dict[str, Any], *, raw_json: str) -> dict[str, dict[str, Any]]:
    """Build a single DynamoDB item (native ``AttributeValue`` map) from a shard.

    Assembles the full item for the base table (Requirements 1.2, 1.3, 1.4, 6.2, 7.3):

    * keys ``ProfileId`` (from ``id``) + ``ShardId`` (from ``file_type``);
    * promoted metadata attributes (``Name``, ``Aliases``, ``Country``, ``Region``,
      ``Category``, ``FileType``, ``CloudRelevance``, ``AiConfirmed``);
    * ``Content`` — the deterministic embedded text;
    * ``Embedding`` — the Titan v2 vector as a list of numbers;
    * ``RawJson`` — the original shard JSON, verbatim;
    * seed provenance ``Source="seed"``, ``LastUpdated`` (now), ``UpdatedBy="loader"``.

    Args:
        shard: The parsed shard JSON.
        raw_json: The original source JSON text for the shard (stored in ``RawJson``).

    Returns:
        The item as a mapping of attribute name to DynamoDB ``AttributeValue``, ready to
        pass to ``PutItem`` / ``BatchWriteItem``.

    Raises:
        ValueError: If the shard lacks a usable ``ProfileId``/``ShardId`` (missing ``id``
            or ``file_type``), or if the derived content cannot be embedded.
    """
    metadata = derive_metadata(shard)
    if "ProfileId" not in metadata or "ShardId" not in metadata:
        raise ValueError("shard is missing a usable 'id' and/or 'file_type' (keys required).")

    content = derive_content(shard)
    embedding = embed_text(content)

    item: dict[str, dict[str, Any]] = metadata_to_attrs(metadata)
    item["Content"] = {"S": content}
    item["Embedding"] = to_ddb_number_list(embedding)
    item["RawJson"] = {"S": raw_json}
    item["Source"] = {"S": "seed"}
    item["LastUpdated"] = {"S": _now_iso()}
    item["UpdatedBy"] = {"S": "loader"}
    return item


def iter_profile_files(directory: Path | None = None) -> list[Path]:
    """Return the sorted ``*.json`` shard files under ``directory`` (Requirement 1.1).

    Sorting gives a stable, reproducible processing order (useful for ``--limit`` subsets
    in task 5.3 and for deterministic logs).

    Args:
        directory: The threat-profiles directory; defaults to :func:`profiles_dir`.

    Returns:
        A sorted list of ``Path`` objects for every ``*.json`` file in the directory.

    Raises:
        FileNotFoundError: If the directory does not exist.
    """
    source = directory if directory is not None else profiles_dir()
    if not source.is_dir():
        raise FileNotFoundError(f"threat-profiles directory not found: {source}")
    return sorted(source.glob("*.json"))


def iter_built_items(
    directory: Path | None = None,
    *,
    limit: int | None = None,
) -> Iterator[tuple[Path, dict[str, dict[str, Any]]]]:
    """Yield ``(path, item)`` for each successfully built shard, skipping failures.

    Walks the corpus (Requirement 1.1), and for each file parses the JSON, derives
    content + metadata, embeds, and builds the item. Any per-file error — unreadable
    file, invalid JSON, a non-object payload, a shard missing its keys, or an embed
    failure — is logged with the offending path and the file is skipped, so one bad file
    never aborts the load (Requirement 1.5). Callers count what they consume; see
    :func:`build_items` for a materialized run with success/failure totals.

    Args:
        directory: The threat-profiles directory; defaults to :func:`profiles_dir`.
        limit: If set, stop after yielding this many items (subset loads for task 5.3).

    Yields:
        ``(path, item)`` tuples for each shard whose item was built successfully.
    """
    yielded = 0
    for path in iter_profile_files(directory):
        if limit is not None and yielded >= limit:
            return
        try:
            raw_json = path.read_text(encoding="utf-8")
            shard = json.loads(raw_json)
            if not isinstance(shard, dict):
                raise ValueError(f"expected a JSON object, got {type(shard).__name__}")
            item = build_item(shard, raw_json=raw_json)
        except Exception:  # noqa: BLE001 - per-file resilience (Requirement 1.5)
            logger.exception("skipping profile file (parse/embed failure): %s", path)
            continue
        yielded += 1
        yield path, item


@dataclass
class BuildResult:
    """Outcome of a build pass: the items and the succeeded/failed tallies."""

    items: list[dict[str, dict[str, Any]]] = field(default_factory=list)
    succeeded: int = 0
    failed: int = 0


def build_items(directory: Path | None = None, *, limit: int | None = None) -> BuildResult:
    """Materialize all built items and count successes vs. failures (Requirement 1.5).

    Convenience wrapper over :func:`iter_built_items` for callers (and tasks 5.2/5.3)
    that want the full list plus tallies. ``failed`` is derived by comparing the number
    of source files considered against the number of items built, so it captures every
    skipped file regardless of the failure cause.

    Args:
        directory: The threat-profiles directory; defaults to :func:`profiles_dir`.
        limit: If set, build at most this many items.

    Returns:
        A :class:`BuildResult` with the built ``items`` and ``succeeded`` / ``failed``
        counts.
    """
    source = directory if directory is not None else profiles_dir()
    files = iter_profile_files(source)
    considered = len(files) if limit is None else min(limit, len(files))

    items = [item for _path, item in iter_built_items(source, limit=limit)]
    succeeded = len(items)
    # With a limit, iter_built_items stops at ``limit`` successes and may not touch every
    # considered file; only count failures among the files actually consumed.
    failed = max(0, considered - succeeded) if limit is None else 0
    return BuildResult(items=items, succeeded=succeeded, failed=failed)


# --- Batch writing (task 5.2) --------------------------------------------------------


@lru_cache(maxsize=1)
def _dynamodb_client() -> DynamoDBClient:
    """Return a cached low-level DynamoDB client (created lazily on first write).

    Mirrors :func:`_bedrock_client`: the client is built on first use (never at import),
    with the region taken from ``AWS_REGION`` (:func:`aws_region`), so importing this
    module never touches AWS.
    """
    return boto3.client("dynamodb", region_name=aws_region())


def _chunk(
    items: Sequence[dict[str, dict[str, Any]]], size: int
) -> Iterator[list[dict[str, dict[str, Any]]]]:
    """Yield successive ``size``-length chunks of ``items`` (last may be shorter)."""
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


def _backoff_seconds(attempt: int) -> float:
    """Capped exponential backoff for retry ``attempt`` (0-indexed)."""
    delay = _BACKOFF_BASE_SECONDS * float(2**attempt)
    return delay if delay < _BACKOFF_CAP_SECONDS else _BACKOFF_CAP_SECONDS


def _item_key_repr(item: dict[str, dict[str, Any]]) -> str:
    """A ``ProfileId/ShardId`` label for logging a failed item (best-effort)."""
    profile = item.get("ProfileId", {}).get("S", "?")
    shard = item.get("ShardId", {}).get("S", "?")
    return f"{profile}/{shard}"


def _write_batch(
    client: DynamoDBClient,
    table: str,
    batch: list[dict[str, dict[str, Any]]],
) -> int:
    """Write one ``<=25``-item batch via ``BatchWriteItem``, retrying unprocessed items.

    Submits the batch as ``PutRequest`` entries (which overwrite by primary key, giving
    upsert-by-``(ProfileId, ShardId)`` semantics — Requirement 1.6). Any items DynamoDB
    returns in ``UnprocessedItems`` (throttling / capacity) are re-submitted with capped
    exponential backoff up to :data:`MAX_UNPROCESSED_RETRIES` times. Items still
    unprocessed after the retry budget are logged and counted as not written.

    Args:
        client: The low-level DynamoDB client.
        table: Target table name.
        batch: Up to :data:`BATCH_SIZE` built items.

    Returns:
        The number of items from this batch that were successfully written.
    """
    if not batch:
        return 0

    requests = [{"PutRequest": {"Item": item}} for item in batch]
    pending: dict[str, list[dict[str, Any]]] = {table: requests}
    total = len(batch)

    for attempt in range(MAX_UNPROCESSED_RETRIES + 1):
        response = client.batch_write_item(RequestItems=pending)
        unprocessed = response.get("UnprocessedItems") or {}
        remaining = unprocessed.get(table) or []
        if not remaining:
            return total
        if attempt < MAX_UNPROCESSED_RETRIES:
            logger.warning(
                "batch has %d unprocessed item(s); retry %d/%d after backoff",
                len(remaining),
                attempt + 1,
                MAX_UNPROCESSED_RETRIES,
            )
            time.sleep(_backoff_seconds(attempt))
        pending = {table: remaining}

    # Exhausted retries: whatever is still pending never landed.
    stuck = pending.get(table) or []
    for request in stuck:
        item = request.get("PutRequest", {}).get("Item", {})
        logger.error(
            "giving up on item after %d retries: %s",
            MAX_UNPROCESSED_RETRIES,
            _item_key_repr(item),
        )
    return total - len(stuck)


def write_items(items: list[dict[str, dict[str, Any]]], *, table: str | None = None) -> int:
    """Upsert built items into the table with ``BatchWriteItem`` (Requirements 1.2, 1.6).

    Chunks ``items`` into batches of :data:`BATCH_SIZE` (25, the DynamoDB per-call limit)
    and writes each batch as ``PutRequest`` entries. Because ``PutRequest`` overwrites by
    primary key, re-running the loader upserts by ``(ProfileId, ShardId)`` without
    creating duplicates (idempotency, Requirement 1.6). Each batch retries its
    ``UnprocessedItems`` with capped exponential backoff so throttled writes eventually
    succeed (:func:`_write_batch`).

    A batch that fails outright (an exception from ``BatchWriteItem``) is logged with the
    keys of its items and skipped so one bad batch does not abort the whole load
    (Requirement 1.5); its items are counted as failures via the returned total.

    Args:
        items: The built DynamoDB items to write.
        table: Target table name; defaults to :func:`table_name`.

    Returns:
        The number of items successfully written.
    """
    if not items:
        return 0

    target = table or table_name()
    client = _dynamodb_client()
    written = 0

    for batch in _chunk(items, BATCH_SIZE):
        try:
            written += _write_batch(client, target, batch)
        except Exception:  # noqa: BLE001 - per-batch resilience (Requirement 1.5)
            keys = ", ".join(_item_key_repr(item) for item in batch)
            logger.exception("batch write failed; skipping %d item(s): %s", len(batch), keys)

    return written


@dataclass
class LoadResult:
    """Outcome of a full load: build tallies plus how many items were written."""

    succeeded: int = 0
    failed: int = 0
    written: int = 0


def run(
    directory: Path | None = None,
    *,
    limit: int | None = None,
    table: str | None = None,
) -> LoadResult:
    """Build items from the corpus and upsert them, reporting succeeded/failed counts.

    Orchestrates the loader end to end (Requirement 1): build every item from
    ``threat-profiles/*.json`` (:func:`build_items`, which skips + counts unparseable /
    unembeddable files, Requirement 1.5), then upsert them via :func:`write_items`
    (BatchWriteItem, idempotent by ``(ProfileId, ShardId)``, Requirement 1.6). The final
    succeeded / failed / written tallies are logged at ``INFO`` (Requirement 1.5).

    The ``--limit`` CLI and the run-twice idempotency check (task 5.3) wire onto this
    function via :func:`main` / :func:`verify_idempotency`.

    Args:
        directory: The threat-profiles directory; defaults to :func:`profiles_dir`.
        limit: If set, build/write at most this many items (subset loads).
        table: Target table name; defaults to :func:`table_name`.

    Returns:
        A :class:`LoadResult` with ``succeeded`` / ``failed`` build counts and the number
        of items ``written`` to the table.
    """
    target = table or table_name()
    build = build_items(directory, limit=limit)
    written = write_items(build.items, table=target)
    logger.info(
        "load complete: succeeded=%d failed=%d written=%d (table=%s)",
        build.succeeded,
        build.failed,
        written,
        target,
    )
    return LoadResult(succeeded=build.succeeded, failed=build.failed, written=written)


# --- Idempotency verification + CLI (task 5.3) ---------------------------------------


def count_table_items(table: str | None = None) -> int:
    """Return the total number of items in ``table`` via a paginated COUNT scan.

    Uses ``Scan`` with ``Select="COUNT"`` (which returns only a ``Count`` per page, not
    item bodies) and follows ``LastEvaluatedKey`` until the table is fully paginated,
    summing each page's ``Count``. This gives the post-run item count used to verify
    idempotency (Requirement 1.6): because the loader upserts by ``(ProfileId, ShardId)``,
    re-running the same load must leave this count unchanged.

    Args:
        table: Table to count; defaults to :func:`table_name`.

    Returns:
        The total item count in the table.
    """
    target = table or table_name()
    client = _dynamodb_client()
    total = 0
    start_key: dict[str, Any] | None = None

    while True:
        kwargs: dict[str, Any] = {"TableName": target, "Select": "COUNT"}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        response = client.scan(**kwargs)
        total += int(response.get("Count", 0))
        start_key = response.get("LastEvaluatedKey")
        if not start_key:
            break

    return total


@dataclass
class IdempotencyResult:
    """Outcome of a run-twice idempotency check (Requirement 1.6)."""

    first: LoadResult
    second: LoadResult
    count_after_first: int
    count_after_second: int

    @property
    def stable(self) -> bool:
        """True when the table item count did not change between the two runs."""
        return self.count_after_first == self.count_after_second


def verify_idempotency(
    directory: Path | None = None,
    *,
    limit: int | None = None,
    table: str | None = None,
) -> IdempotencyResult:
    """Load the corpus twice and assert the table item count is stable (Requirement 1.6).

    Runs :func:`run` (build + upsert) twice against the same target, counting the table's
    items after each run via :func:`count_table_items`. Because writes are ``PutRequest``
    upserts keyed by ``(ProfileId, ShardId)``, the second run must not create duplicates,
    so the two post-run counts must be identical. The comparison result is exposed via
    :attr:`IdempotencyResult.stable` and logged at ``INFO`` (or ``ERROR`` if it drifted).

    Args:
        directory: The threat-profiles directory; defaults to :func:`profiles_dir`.
        limit: If set, load at most this many items on each run (subset loads).
        table: Target table name; defaults to :func:`table_name`.

    Returns:
        An :class:`IdempotencyResult` with both runs' tallies and the two item counts.
    """
    target = table or table_name()

    logger.info("idempotency check: run 1/2 (table=%s)", target)
    first = run(directory, limit=limit, table=target)
    count_after_first = count_table_items(target)

    logger.info("idempotency check: run 2/2 (table=%s)", target)
    second = run(directory, limit=limit, table=target)
    count_after_second = count_table_items(target)

    result = IdempotencyResult(
        first=first,
        second=second,
        count_after_first=count_after_first,
        count_after_second=count_after_second,
    )

    if result.stable:
        logger.info(
            "idempotency OK: item count stable at %d across both runs (table=%s)",
            count_after_first,
            target,
        )
    else:
        logger.error(
            "idempotency FAILED: item count changed %d -> %d between runs (table=%s)",
            count_after_first,
            count_after_second,
            target,
        )

    return result


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the ``load_profiles`` CLI argument parser (task 5.3).

    Exposes:

    * ``--limit N`` — load only the first ``N`` shards (subset loads for testing);
    * ``--profiles-dir PATH`` — override the threat-profiles source directory;
    * ``--table NAME`` — override the target DynamoDB table;
    * ``--verify-idempotency`` — run the load twice and assert a stable item count
      (Requirement 1.6).

    Returns:
        The configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="load_profiles",
        description=(
            "Ingest v1 threat-profile shards into the DynamoDB vector table. "
            "Use --limit for a subset and --verify-idempotency to load twice and "
            "confirm the item count is stable."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Load at most N shards (subset load for testing).",
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Override the threat-profiles source directory.",
    )
    parser.add_argument(
        "--table",
        default=None,
        metavar="NAME",
        help="Override the target DynamoDB table name.",
    )
    parser.add_argument(
        "--verify-idempotency",
        action="store_true",
        help="Run the load twice and assert the table item count is stable (Req 1.6).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint: parse flags, run the load (or the idempotency check), report.

    Configures ``INFO`` logging so the succeeded/failed/written tallies print, then wires
    the parsed flags to :func:`run` (or, with ``--verify-idempotency``, to
    :func:`verify_idempotency`). Returns a process exit code: ``0`` on success, ``1`` if
    the idempotency check found the item count drifted between the two runs.

    Args:
        argv: Argument vector to parse; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (``0`` success, ``1`` idempotency drift).
    """
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.verify_idempotency:
        result = verify_idempotency(
            args.profiles_dir, limit=args.limit, table=args.table
        )
        return 0 if result.stable else 1

    run(args.profiles_dir, limit=args.limit, table=args.table)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI dispatch
    raise SystemExit(main())

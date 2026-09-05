#!/usr/bin/env python3
"""Post-deploy integration verification for the Threat Intelligence Engine v2.

This script is run by an operator **against a live, deployed stack** to confirm the
end-to-end retrieval path works before declaring a deployment good (spec task 14). It
exercises the requirements that can only be checked against real infrastructure:

* **Index readiness (Req 2.5).** A freshly created DynamoDB vector index re-derives
  from base-table writes and briefly rejects ``SearchVectors`` with a warm-up
  ``ValidationException``. :func:`check_index_ready` embeds a probe query and retries
  ``SearchVectors`` with backoff until the first success (or a timeout).
* **Semantic ranking (Req 3.1, 2.x).** :func:`check_semantic_ranking` runs a handful of
  known queries whose top matches are well understood (e.g. "Okta phishing kit"
  -> ``0ktapus``; "Russian ransomware group" -> ``alphv_blackcat``) and asserts the
  expected ``ProfileId`` appears within the top-K results.
* **Idempotency (Req 1.6).** :func:`check_idempotency` re-runs the loader against the
  live table and confirms the item count is unchanged, reusing the loader's own
  ``count_table_items`` / ``verify_idempotency`` helpers.
* **Enrichment write-back (Req 5.4).** :func:`check_enrichment_writeback` applies an
  enrichment at the DynamoDB layer (reusing the agent's ``apply_enrichment``) against a
  throwaway probe shard and confirms the new content is retrievable, then restores the
  table. The full runtime HITL round-trip (interrupt -> approve via the resume POST)
  needs SigV4/JWT against a deployed runtime and is documented as a manual step in
  ``docs/INTEGRATION_VERIFICATION.md``.

The AWS-touching checks import the agent's retrieval helpers (``embeddings.embed_text``,
``ddb.to_vector_attr`` / ``ddb.from_search_results``) and the loader's idempotency
helpers so the verification uses exactly the same request/response shaping as production.
The **pure** logic — ranking assertion and the PASS/FAIL summary — is factored into
:func:`assert_expected_profile` and :class:`CheckReport` /
:func:`format_summary` so it can be unit-tested with a fake ``SearchVectors`` client and
no AWS access (see ``scripts/tests/test_integration_verify.py``).

Usage (against a deployed stack)::

    DDB_TABLE_NAME=ThreatProfilesV2 \\
    DDB_VECTOR_INDEX=profile-embeddings \\
    AWS_REGION=us-east-1 \\
    python scripts/integration_verify.py --skip-idempotency

Exit status is ``0`` when every executed check passes and non-zero otherwise, so it can
gate a deploy pipeline.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

# --- Make the agent and loader packages importable ------------------------------------
#
# The verification reuses production code rather than reimplementing it: the agent's
# Titan embed + SearchVectors (de)serialization helpers, and the loader's idempotency
# check. Both live in sibling directories, so put them on sys.path when this script runs
# as a program. Guarded imports below degrade gracefully if a dependency is missing so
# the pure helpers (and their unit tests) never require boto3 / strands to be installed.
_V2_ROOT = Path(__file__).resolve().parents[1]
_AGENT_SRC = _V2_ROOT / "agent" / "src"
_LOADER = _V2_ROOT / "loader"
for _p in (_AGENT_SRC, _LOADER):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# --- Known-query fixtures (Req 3.1) ---------------------------------------------------


@dataclass(frozen=True)
class KnownQuery:
    """A semantic-ranking probe: a natural-language query and its expected top match.

    Attributes:
        query: The analyst-style natural-language search text to embed and search.
        expected_profile_id: The ``ProfileId`` that should appear within the top-K
            results for this query. Chosen from actors present in the seed corpus whose
            top match for the query is well understood.
        description: A short human-readable label for the summary output.
    """

    query: str
    expected_profile_id: str
    description: str


# These ProfileIds exist in the v1 seed corpus (see
# agentcore-threat-intel-engine/threat-profiles/): 0ktapus is the Okta-targeting phishing
# campaign; alphv_blackcat is a Russia-attributed ransomware-as-a-service group.
DEFAULT_KNOWN_QUERIES: tuple[KnownQuery, ...] = (
    KnownQuery(
        query="Okta phishing kit that steals SaaS credentials via SMS",
        expected_profile_id="0ktapus",
        description="Okta phishing kit -> 0ktapus",
    ),
    KnownQuery(
        query="Russian ransomware-as-a-service group known as BlackCat",
        expected_profile_id="alphv_blackcat",
        description="Russian ransomware -> ALPHV/BlackCat",
    ),
)

# A probe query used only to warm up / poll the index (never asserted on).
READINESS_PROBE_QUERY = "threat actor tactics techniques and procedures"


# --- Pure helpers (unit-testable without AWS) -----------------------------------------


@dataclass
class CheckResult:
    """The outcome of one verification check.

    Attributes:
        name: Short check name (appears in the summary).
        passed: Whether the check succeeded.
        detail: A human-readable explanation of the result.
        skipped: When True the check did not run (e.g. disabled by a flag) and does not
            affect the overall pass/fail.
    """

    name: str
    passed: bool
    detail: str
    skipped: bool = False


@dataclass
class CheckReport:
    """Accumulates :class:`CheckResult`\\ s and reports overall pass/fail."""

    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> CheckResult:
        """Record ``result`` and return it (for convenient chaining/logging)."""
        self.results.append(result)
        return result

    @property
    def executed(self) -> list[CheckResult]:
        """Results for checks that actually ran (i.e. were not skipped)."""
        return [r for r in self.results if not r.skipped]

    @property
    def ok(self) -> bool:
        """True when every executed check passed (skipped checks are ignored)."""
        return all(r.passed for r in self.executed)


def assert_expected_profile(
    results: list[dict[str, Any]],
    expected_profile_id: str,
) -> tuple[bool, str]:
    """Check that ``expected_profile_id`` appears among parsed search ``results``.

    ``results`` is the output of :func:`ddb.from_search_results` — a ranked list of
    ``{ProfileId, Name, FileType, Content, Score}`` dicts, best match first. This is the
    pure core of the semantic-ranking assertion (Req 3.1): it does not call AWS, so it
    can be unit-tested with fabricated results.

    Args:
        results: Ranked, parsed ``SearchVectors`` results (best match first).
        expected_profile_id: The ``ProfileId`` expected to appear in the list.

    Returns:
        A ``(passed, detail)`` tuple. ``passed`` is True when the expected profile is
        present; ``detail`` names the rank on success or lists the observed profiles on
        failure.
    """
    profile_ids = [r.get("ProfileId") for r in results]
    if expected_profile_id in profile_ids:
        rank = profile_ids.index(expected_profile_id) + 1
        return True, f"found {expected_profile_id!r} at rank {rank}/{len(results)}"
    observed = ", ".join(str(pid) for pid in profile_ids[:10]) or "<no results>"
    return False, f"expected {expected_profile_id!r} not in top {len(results)}; got: {observed}"


def format_summary(report: CheckReport) -> str:
    """Render a per-check PASS/FAIL/SKIP summary block for the report.

    Produces a stable, greppable multi-line string (one line per check plus a final
    verdict), suitable for console output and for asserting in unit tests. Purely a
    function of the accumulated results — no AWS access.

    Args:
        report: The accumulated :class:`CheckReport`.

    Returns:
        The formatted summary text (no trailing newline).
    """
    lines = ["", "=" * 60, " Integration verification summary", "=" * 60]
    for result in report.results:
        if result.skipped:
            status = "SKIP"
        elif result.passed:
            status = "PASS"
        else:
            status = "FAIL"
        lines.append(f" [{status}] {result.name}: {result.detail}")
    lines.append("=" * 60)
    verdict = "ALL CHECKS PASSED" if report.ok else "ONE OR MORE CHECKS FAILED"
    lines.append(f" {verdict}")
    lines.append("=" * 60)
    return "\n".join(lines)


# --- SearchVectors client protocol (lets tests inject a fake) -------------------------


class SearchVectorsClient(Protocol):
    """The minimal DynamoDB client surface the AWS-touching checks depend on.

    Declaring it as a :class:`Protocol` lets the unit tests pass a fake client (raising
    a warm-up ``ValidationException`` a few times, then returning a canned
    ``SearchResults`` payload) without importing boto3.
    """

    def search_vectors(self, **kwargs: Any) -> dict[str, Any]: ...


# --- AWS-touching checks (run against the live stack) ---------------------------------


def _table_name() -> str:
    return os.environ.get("DDB_TABLE_NAME", "ThreatProfilesV2").strip() or "ThreatProfilesV2"


def _vector_index() -> str:
    return os.environ.get("DDB_VECTOR_INDEX", "profile-embeddings").strip() or "profile-embeddings"


def _search_once(
    client: SearchVectorsClient,
    *,
    table: str,
    index: str,
    query_vector: list[dict[str, str]],
    top_k: int,
) -> dict[str, Any]:
    """Issue a single ``SearchVectors`` call for a query vector (no retry).

    Kept separate from the retry loop so the readiness poll and the ranking checks share
    one request shape. The projection matches the retrieval tool so parsing via
    :func:`ddb.from_search_results` works identically.
    """
    return client.search_vectors(
        TableName=table,
        IndexName=index,
        SearchVector=query_vector,
        TopK=top_k,
        ProjectionExpression="#pid, #nm, #ft, #ct",
        ExpressionAttributeNames={
            "#pid": "ProfileId",
            "#nm": "Name",
            "#ft": "FileType",
            "#ct": "Content",
        },
    )


def check_index_ready(
    client: SearchVectorsClient,
    embed_fn: Any,
    to_vector_attr: Any,
    *,
    table: str,
    index: str,
    timeout_seconds: float = 300.0,
    poll_interval_seconds: float = 5.0,
    sleep: Any = time.sleep,
) -> CheckResult:
    """Poll ``SearchVectors`` until the index is queryable or a timeout elapses (Req 2.5).

    Embeds a fixed probe query once, then repeatedly issues ``SearchVectors`` until the
    first success. A warm-up ``ValidationException`` (the index still backfilling from
    base-table writes) is treated as "not ready yet" and retried after
    ``poll_interval_seconds``; any other error fails the check immediately. On the first
    successful response the check passes.

    Args:
        client: A DynamoDB client exposing ``search_vectors``.
        embed_fn: ``embeddings.embed_text`` (query -> ``list[float]``).
        to_vector_attr: ``ddb.to_vector_attr`` (vector -> plain ``SearchVector`` list).
        table: The base table name.
        index: The vector index name.
        timeout_seconds: Give up (fail) after this long without a success.
        poll_interval_seconds: Delay between attempts on a warm-up error.
        sleep: Injectable sleep (patched out in tests).

    Returns:
        A :class:`CheckResult` describing readiness and the number of attempts made.
    """
    # Import here so a missing botocore does not break importing this module (the pure
    # helpers and their tests must not require boto3).
    from botocore.exceptions import ClientError

    query_vector = to_vector_attr(embed_fn(READINESS_PROBE_QUERY))
    deadline = time.monotonic() + timeout_seconds
    attempts = 0

    while True:
        attempts += 1
        try:
            _search_once(client, table=table, index=index, query_vector=query_vector, top_k=1)
            return CheckResult(
                name="index_ready",
                passed=True,
                detail=f"SearchVectors succeeded after {attempts} attempt(s)",
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code != "ValidationException":
                return CheckResult(
                    name="index_ready",
                    passed=False,
                    detail=f"non-retryable {code} error after {attempts} attempt(s): {error}",
                )
            if time.monotonic() >= deadline:
                return CheckResult(
                    name="index_ready",
                    passed=False,
                    detail=(
                        f"index still warming up (ValidationException) after {attempts} "
                        f"attempt(s) / {timeout_seconds:.0f}s timeout"
                    ),
                )
            sleep(poll_interval_seconds)


def check_semantic_ranking(
    client: SearchVectorsClient,
    embed_fn: Any,
    to_vector_attr: Any,
    from_search_results: Any,
    *,
    table: str,
    index: str,
    known_queries: Sequence[KnownQuery] = DEFAULT_KNOWN_QUERIES,
    top_k: int = 10,
) -> CheckResult:
    """Assert each known query surfaces its expected ``ProfileId`` in the top-K (Req 3.1).

    For every :class:`KnownQuery` it embeds the query, runs ``SearchVectors`` for the
    top ``top_k`` shards, parses the response with :func:`ddb.from_search_results`, and
    checks the expected profile is present via :func:`assert_expected_profile`. The
    check passes only when *every* known query matches; the detail lists each query's
    result so a partial failure is easy to diagnose.

    Args:
        client: A DynamoDB client exposing ``search_vectors``.
        embed_fn: ``embeddings.embed_text``.
        to_vector_attr: ``ddb.to_vector_attr``.
        from_search_results: ``ddb.from_search_results``.
        table: The base table name.
        index: The vector index name.
        known_queries: The probes to run (defaults to :data:`DEFAULT_KNOWN_QUERIES`).
        top_k: How many results to request per query.

    Returns:
        A :class:`CheckResult` aggregating every known-query outcome.
    """
    outcomes: list[str] = []
    all_passed = True

    for known in known_queries:
        query_vector = to_vector_attr(embed_fn(known.query))
        response = _search_once(
            client, table=table, index=index, query_vector=query_vector, top_k=top_k
        )
        results = from_search_results(response)
        passed, detail = assert_expected_profile(results, known.expected_profile_id)
        all_passed = all_passed and passed
        marker = "ok" if passed else "MISS"
        outcomes.append(f"{known.description}: {marker} ({detail})")

    return CheckResult(
        name="semantic_ranking",
        passed=all_passed,
        detail="; ".join(outcomes),
    )


def check_idempotency(
    verify_idempotency: Any,
    *,
    table: str,
    limit: int | None,
) -> CheckResult:
    """Re-run the loader and confirm the live table item count is stable (Req 1.6).

    Delegates to the loader's own :func:`load_profiles.verify_idempotency`, which loads
    the corpus twice and compares the post-run item counts (upserts keyed by
    ``(ProfileId, ShardId)`` must not create duplicates). This mutates the live table
    (idempotent upserts only), so callers gate it behind a flag.

    Args:
        verify_idempotency: ``load_profiles.verify_idempotency``.
        table: The live table to load into.
        limit: Optional subset size (matches the deployed subset when re-verifying).

    Returns:
        A :class:`CheckResult` reporting whether the item count held steady.
    """
    result = verify_idempotency(limit=limit, table=table)
    if result.stable:
        detail = f"item count stable at {result.count_after_first} across two loads"
    else:
        detail = (
            f"item count drifted {result.count_after_first} -> {result.count_after_second} "
            "between loads"
        )
    return CheckResult(name="idempotency", passed=result.stable, detail=detail)


def check_enrichment_writeback(
    client: Any,
    embed_fn: Any,
    to_vector_attr: Any,
    from_search_results: Any,
    apply_enrichment: Any,
    *,
    table: str,
    index: str,
    profile_id: str,
    shard_id: str,
) -> CheckResult:
    """Apply a DynamoDB-level enrichment and confirm the new content is retrievable (Req 5.4).

    This scripts the *terminal* half of the HITL flow (the write-back that runs after an
    analyst approves) without the runtime interrupt/resume round-trip, which requires a
    signed request against a deployed runtime (documented as a manual step). It:

    1. Snapshots the target shard (``GetItem``) so it can be restored afterward.
    2. Calls the agent's :func:`enrich_tools.apply_enrichment` with a unique sentinel
       string, which overwrites ``Content``, regenerates ``Embedding``, and stamps
       ``Source="web-enrichment"`` provenance.
    3. Embeds the sentinel and searches the index; passes if the enriched shard's
       ``ProfileId`` surfaces (eventual consistency: the index re-derives asynchronously,
       so this may need the caller to allow warm-up time / retry).
    4. Restores the original shard so the verification leaves no residue.

    The check is best-effort about cleanup: if restore fails it is reported in the
    detail. Requires a real shard to exist at ``(profile_id, shard_id)``.

    Args:
        client: A DynamoDB client (``get_item`` / ``put_item`` / ``search_vectors``).
        embed_fn: ``embeddings.embed_text``.
        to_vector_attr: ``ddb.to_vector_attr``.
        from_search_results: ``ddb.from_search_results``.
        apply_enrichment: ``enrich_tools.apply_enrichment``.
        table: The base table name.
        index: The vector index name.
        profile_id: Target actor id to enrich (must exist).
        shard_id: Target shard file_type to enrich (must exist).

    Returns:
        A :class:`CheckResult` describing whether the enriched content became retrievable.
    """
    sentinel = f"INTEGRATION-VERIFY sentinel marker {int(time.time())}"
    proposed_content = (
        f"{sentinel}: verification enrichment for {profile_id}/{shard_id}. "
        "This is a temporary write applied by scripts/integration_verify.py and is "
        "restored immediately after the read-back check."
    )

    key = {"ProfileId": {"S": profile_id}, "ShardId": {"S": shard_id}}
    snapshot = client.get_item(TableName=table, Key=key).get("Item")
    if snapshot is None:
        return CheckResult(
            name="enrichment_writeback",
            passed=False,
            detail=f"target shard {profile_id}/{shard_id} not found; cannot verify write-back",
            skipped=False,
        )

    try:
        apply_enrichment(
            profile_id=profile_id,
            shard_id=shard_id,
            proposed_content=proposed_content,
            sources=["https://example.com/integration-verify"],
            updated_by="integration-verify",
        )
        # Read back via the vector index using the sentinel as the query.
        query_vector = to_vector_attr(embed_fn(sentinel))
        response = _search_once(
            client, table=table, index=index, query_vector=query_vector, top_k=10
        )
        results = from_search_results(response)
        passed, detail = assert_expected_profile(results, profile_id)
    finally:
        # Best-effort restore of the original shard.
        try:
            client.put_item(TableName=table, Item=snapshot)
            restore_note = "original shard restored"
        except Exception as restore_error:  # noqa: BLE001 - report, don't mask
            restore_note = f"WARNING: restore failed: {restore_error}"

    return CheckResult(
        name="enrichment_writeback",
        passed=passed,
        detail=f"{detail}; {restore_note}",
    )


# --- Orchestration --------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the ``integration_verify`` CLI parser."""
    parser = argparse.ArgumentParser(
        prog="integration_verify",
        description=(
            "Post-deploy integration verification for Threat Intelligence Engine v2. "
            "Polls index readiness, asserts semantic ranking on known queries, and "
            "(optionally) checks loader idempotency and enrichment write-back against "
            "the live stack. Exits non-zero if any executed check fails."
        ),
    )
    parser.add_argument(
        "--top-k", type=int, default=10, metavar="N", help="Top-K results per query (default 10)."
    )
    parser.add_argument(
        "--readiness-timeout",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="Max time to wait for the index to become queryable (default 300).",
    )
    parser.add_argument(
        "--skip-idempotency",
        action="store_true",
        help="Skip the loader idempotency re-run (it mutates the live table via upserts).",
    )
    parser.add_argument(
        "--idempotency-limit",
        type=int,
        default=None,
        metavar="N",
        help="Subset size for the idempotency re-run (match the deployed subset).",
    )
    parser.add_argument(
        "--check-enrichment",
        action="store_true",
        help="Also run the DynamoDB-level enrichment write-back check (mutates then restores).",
    )
    parser.add_argument(
        "--enrich-profile-id",
        default="0ktapus",
        metavar="ID",
        help="ProfileId to use for the enrichment write-back check (default 0ktapus).",
    )
    parser.add_argument(
        "--enrich-shard-id",
        default="summary",
        metavar="ID",
        help="ShardId (file_type) for the enrichment write-back check (default summary).",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    """Run the verification checks against the live stack and print a summary.

    Wires the CLI flags to the checks, importing the production helpers lazily so a
    missing boto3/strands surfaces as a clear message rather than an import error at
    module load. Returns a process exit code: ``0`` when every executed check passed,
    ``1`` otherwise (so it can gate a deploy pipeline).

    Args:
        argv: Argument vector; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code.
    """
    args = build_arg_parser().parse_args(argv)

    # Lazy imports of production code (need boto3 / strands installed + AWS creds).
    from ddb import dynamodb_client, from_search_results, to_vector_attr
    from embeddings import embed_text
    from load_profiles import verify_idempotency  # loader package
    from tools.enrich_tools import apply_enrichment

    table = _table_name()
    index = _vector_index()
    client = dynamodb_client()

    print(f"Verifying table={table!r} index={index!r} in region "
          f"{os.environ.get('AWS_REGION', 'us-east-1')!r}\n")

    report = CheckReport()

    # 1. Index readiness (Req 2.5) — always run; other checks need a queryable index.
    ready = report.add(
        check_index_ready(
            client,
            embed_text,
            to_vector_attr,
            table=table,
            index=index,
            timeout_seconds=args.readiness_timeout,
        )
    )
    print(f"[{'PASS' if ready.passed else 'FAIL'}] index_ready: {ready.detail}")

    if ready.passed:
        # 2. Semantic ranking (Req 3.1).
        ranking = report.add(
            check_semantic_ranking(
                client,
                embed_text,
                to_vector_attr,
                from_search_results,
                table=table,
                index=index,
                top_k=args.top_k,
            )
        )
        print(f"[{'PASS' if ranking.passed else 'FAIL'}] semantic_ranking: {ranking.detail}")

        # 4. Enrichment write-back (Req 5.4) — optional (mutates then restores).
        if args.check_enrichment:
            enrich = report.add(
                check_enrichment_writeback(
                    client,
                    embed_text,
                    to_vector_attr,
                    from_search_results,
                    apply_enrichment,
                    table=table,
                    index=index,
                    profile_id=args.enrich_profile_id,
                    shard_id=args.enrich_shard_id,
                )
            )
            print(f"[{'PASS' if enrich.passed else 'FAIL'}] enrichment_writeback: {enrich.detail}")
    else:
        # Downstream checks cannot run without a queryable index; mark them skipped.
        report.add(
            CheckResult("semantic_ranking", passed=False, detail="skipped: index not ready",
                        skipped=True)
        )

    # 3. Idempotency (Req 1.6) — independent of the vector index; optional.
    if args.skip_idempotency:
        report.add(
            CheckResult("idempotency", passed=False, detail="skipped by --skip-idempotency",
                        skipped=True)
        )
    else:
        idem = report.add(
            check_idempotency(verify_idempotency, table=table, limit=args.idempotency_limit)
        )
        print(f"[{'PASS' if idem.passed else 'FAIL'}] idempotency: {idem.detail}")

    print(format_summary(report))
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover - CLI dispatch
    raise SystemExit(run())

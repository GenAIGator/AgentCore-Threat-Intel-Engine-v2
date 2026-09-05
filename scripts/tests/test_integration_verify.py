"""Offline unit tests for :mod:`scripts.integration_verify`.

These tests exercise the parts of the verification script that do **not** require AWS,
using a fake ``SearchVectors`` client and stub embed/parse helpers:

- ``assert_expected_profile`` — the pure ranking assertion: present vs. absent profile,
  rank reporting, and empty-result handling (Req 3.1).
- ``format_summary`` / ``CheckReport`` — PASS/FAIL/SKIP rendering and the overall-ok
  rule that skipped checks do not affect the verdict.
- ``check_index_ready`` — the warm-up poll: retries a ``ValidationException`` a few times
  then passes on first success; fails fast on a non-``ValidationException`` error; times
  out if never ready (Req 2.5). ``sleep`` is injected as a no-op so the tests are fast.
- ``check_semantic_ranking`` — aggregates per-query outcomes and only passes when every
  known query surfaces its expected profile (Req 3.1).

The script adds ``agent/src`` and ``loader`` to ``sys.path`` at import time; boto3 is
imported lazily inside :func:`check_index_ready`, so the fake client here only needs a
``botocore``-style ``ClientError``, which we build with a real ``botocore`` if present or
a tiny stand-in otherwise.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Make the script importable as a top-level module (scripts/ is not a package).
_SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import integration_verify as iv  # noqa: I001  (must follow the sys.path setup above)


# --- Test doubles ---------------------------------------------------------------------


class _FakeClientError(Exception):
    """A minimal ``ClientError`` stand-in used when botocore is unavailable."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _client_error(code: str) -> Exception:
    """Build a botocore ``ClientError`` (or a close stand-in) with the given error code."""
    try:
        from botocore.exceptions import ClientError
    except ImportError:  # pragma: no cover - botocore should be present in the env
        return _FakeClientError(code)
    return ClientError({"Error": {"Code": code, "Message": code}}, "SearchVectors")


class FakeSearchClient:
    """A fake DynamoDB client whose ``search_vectors`` is scripted per test.

    Either raises ``fail_times`` warm-up ``ValidationException``\\ s before returning
    ``response``, or (when ``error_code`` is set) always raises that error code. Records
    how many times it was called.
    """

    def __init__(
        self,
        *,
        response: dict[str, Any] | None = None,
        fail_times: int = 0,
        error_code: str | None = None,
    ) -> None:
        self._response = response or {"SearchResults": []}
        self._fail_times = fail_times
        self._error_code = error_code
        self.calls = 0

    def search_vectors(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        if self._error_code is not None:
            raise _client_error(self._error_code)
        if self.calls <= self._fail_times:
            raise _client_error("ValidationException")
        return self._response


def _identity_embed(text: str) -> list[float]:
    """Stub embed: returns a fixed non-empty vector (content is irrelevant to the fake)."""
    return [0.1, 0.2, 0.3]


def _passthrough_to_vector_attr(vector: list[float]) -> list[dict[str, str]]:
    return [{"N": str(v)} for v in vector]


def _fake_from_search_results(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Minimal parser mirroring ddb.from_search_results for the fake response shape."""
    out: list[dict[str, Any]] = []
    for match in response.get("SearchResults", []):
        item = match.get("Item", {})
        out.append(
            {
                "ProfileId": item.get("ProfileId", {}).get("S"),
                "Name": item.get("Name", {}).get("S"),
                "FileType": item.get("FileType", {}).get("S"),
                "Content": item.get("Content", {}).get("S"),
                "Score": match.get("Score"),
            }
        )
    return out


def _results(*profile_ids: str) -> dict[str, Any]:
    """Build a fake SearchVectors response containing the given ProfileIds, in order."""
    return {
        "SearchResults": [
            {"Item": {"ProfileId": {"S": pid}, "Name": {"S": pid}}, "Score": 0.1 + i * 0.01}
            for i, pid in enumerate(profile_ids)
        ]
    }


# --- assert_expected_profile (Req 3.1) ------------------------------------------------


def test_assert_expected_profile_found_reports_rank() -> None:
    results = _fake_from_search_results(_results("0ktapus", "other"))
    passed, detail = iv.assert_expected_profile(results, "0ktapus")
    assert passed is True
    assert "rank 1/2" in detail


def test_assert_expected_profile_found_not_first() -> None:
    results = _fake_from_search_results(_results("other", "alphv_blackcat"))
    passed, detail = iv.assert_expected_profile(results, "alphv_blackcat")
    assert passed is True
    assert "rank 2/2" in detail


def test_assert_expected_profile_absent_lists_observed() -> None:
    results = _fake_from_search_results(_results("foo", "bar"))
    passed, detail = iv.assert_expected_profile(results, "0ktapus")
    assert passed is False
    assert "expected '0ktapus'" in detail
    assert "foo" in detail and "bar" in detail


def test_assert_expected_profile_empty_results() -> None:
    passed, detail = iv.assert_expected_profile([], "0ktapus")
    assert passed is False
    assert "<no results>" in detail


# --- CheckReport / format_summary -----------------------------------------------------


def test_report_ok_ignores_skipped() -> None:
    report = iv.CheckReport()
    report.add(iv.CheckResult("a", passed=True, detail="ok"))
    report.add(iv.CheckResult("b", passed=False, detail="skipped", skipped=True))
    assert report.ok is True
    assert len(report.executed) == 1


def test_report_ok_false_when_executed_check_fails() -> None:
    report = iv.CheckReport()
    report.add(iv.CheckResult("a", passed=True, detail="ok"))
    report.add(iv.CheckResult("b", passed=False, detail="boom"))
    assert report.ok is False


def test_format_summary_renders_status_labels_and_verdict() -> None:
    report = iv.CheckReport()
    report.add(iv.CheckResult("index_ready", passed=True, detail="1 attempt"))
    report.add(iv.CheckResult("semantic_ranking", passed=False, detail="miss"))
    report.add(iv.CheckResult("idempotency", passed=False, detail="disabled", skipped=True))
    summary = iv.format_summary(report)
    assert "[PASS] index_ready" in summary
    assert "[FAIL] semantic_ranking" in summary
    assert "[SKIP] idempotency" in summary
    assert "ONE OR MORE CHECKS FAILED" in summary


def test_format_summary_all_pass_verdict() -> None:
    report = iv.CheckReport()
    report.add(iv.CheckResult("index_ready", passed=True, detail="ok"))
    summary = iv.format_summary(report)
    assert "ALL CHECKS PASSED" in summary


# --- check_index_ready (Req 2.5) ------------------------------------------------------


def test_check_index_ready_retries_then_passes() -> None:
    client = FakeSearchClient(response=_results("x"), fail_times=3)
    slept: list[float] = []
    result = iv.check_index_ready(
        client,
        _identity_embed,
        _passthrough_to_vector_attr,
        table="T",
        index="I",
        poll_interval_seconds=0.0,
        sleep=slept.append,
    )
    assert result.passed is True
    assert client.calls == 4  # 3 warm-up failures + 1 success
    assert len(slept) == 3


def test_check_index_ready_fails_fast_on_other_error() -> None:
    client = FakeSearchClient(error_code="AccessDeniedException")
    result = iv.check_index_ready(
        client,
        _identity_embed,
        _passthrough_to_vector_attr,
        table="T",
        index="I",
        sleep=lambda _s: None,
    )
    assert result.passed is False
    assert "AccessDeniedException" in result.detail
    assert client.calls == 1


def test_check_index_ready_times_out() -> None:
    client = FakeSearchClient(error_code="ValidationException")
    result = iv.check_index_ready(
        client,
        _identity_embed,
        _passthrough_to_vector_attr,
        table="T",
        index="I",
        timeout_seconds=0.0,  # deadline already passed after the first failure
        sleep=lambda _s: None,
    )
    assert result.passed is False
    assert "warming up" in result.detail


# --- check_semantic_ranking (Req 3.1) -------------------------------------------------


def test_check_semantic_ranking_all_match() -> None:
    # The fake returns the same payload for every call; craft it to contain both
    # expected profiles so both known queries pass.
    client = FakeSearchClient(response=_results("0ktapus", "alphv_blackcat", "noise"))
    result = iv.check_semantic_ranking(
        client,
        _identity_embed,
        _passthrough_to_vector_attr,
        _fake_from_search_results,
        table="T",
        index="I",
    )
    assert result.passed is True
    assert "ok" in result.detail


def test_check_semantic_ranking_reports_miss() -> None:
    # Only 0ktapus present -> the ALPHV query misses, so the aggregate fails.
    client = FakeSearchClient(response=_results("0ktapus", "noise"))
    result = iv.check_semantic_ranking(
        client,
        _identity_embed,
        _passthrough_to_vector_attr,
        _fake_from_search_results,
        table="T",
        index="I",
    )
    assert result.passed is False
    assert "MISS" in result.detail


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))

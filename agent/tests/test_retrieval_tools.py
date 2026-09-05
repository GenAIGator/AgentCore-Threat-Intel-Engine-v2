"""Unit tests for :mod:`tools.retrieval_tools`.

These tests exercise the pure request/response shaping of the retrieval tool without
touching AWS, per task 6.2:

- ``build_search_condition`` — the ``INLINE_FILTER`` clause builder. We assert it emits
  nothing when unconstrained, an equality clause per constraint aliased with
  ``#``-placeholders, ``S``-typed values, and an ``AND``-joined expression when both
  ``file_type`` and ``country`` are supplied (Requirement 2.3).
- ``filter_by_threshold`` — the relevance gate. COSINE distance is lower-is-more-similar,
  so results at or below the threshold are kept and everything else (including
  missing/``None``/non-numeric/``bool`` scores) is dropped, preserving order and honoring
  boundary equality (Requirement 2.6).
- ``_format_context`` — the citation-tagged renderer. We assert the empty-context
  sentinel on no results and ``[n]`` blocks carrying ProfileId/Name/FileType/Content for
  populated results (Requirement 2.4).
- ``retrieve_profiles`` — Top K clamping to ``[1, 100]`` with a default of 10, verified by
  monkeypatching ``embed_text`` and the DynamoDB client (Requirement 2.2).
- ``_search_vectors_with_retry`` — the warm-up retry. A fake client raising a
  ``ValidationException`` a few times then succeeding must be retried and eventually
  return; a non-``ValidationException`` ``ClientError`` must propagate immediately
  (Requirement 2.5). ``time.sleep`` is patched out to keep the tests fast.
"""

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

import tools.retrieval_tools as rt

# --------------------------------------------------------------------------------------
# build_search_condition — INLINE_FILTER clause construction (Requirement 2.3)
# --------------------------------------------------------------------------------------


def test_build_search_condition_no_filters_returns_empty_dict() -> None:
    assert rt.build_search_condition() == {}
    assert rt.build_search_condition(file_type=None, country=None) == {}
    # Empty strings are falsy and treated as "no filter".
    assert rt.build_search_condition(file_type="", country="") == {}


def test_build_search_condition_file_type_only() -> None:
    condition = rt.build_search_condition(file_type="detection")

    assert condition == {
        "SearchConditionExpression": "#ft = :ft",
        "ExpressionAttributeNames": {"#ft": "FileType"},
        "ExpressionAttributeValues": {":ft": {"S": "detection"}},
    }
    # Value is S-typed, not any other AttributeValue type.
    assert set(condition["ExpressionAttributeValues"][":ft"].keys()) == {"S"}


def test_build_search_condition_country_only() -> None:
    condition = rt.build_search_condition(country="China")

    assert condition == {
        "SearchConditionExpression": "#co = :co",
        "ExpressionAttributeNames": {"#co": "Country"},
        "ExpressionAttributeValues": {":co": {"S": "China"}},
    }
    assert set(condition["ExpressionAttributeValues"][":co"].keys()) == {"S"}


def test_build_search_condition_both_combined_with_and() -> None:
    condition = rt.build_search_condition(file_type="ransomware", country="Russia")

    assert condition["SearchConditionExpression"] == "#ft = :ft AND #co = :co"
    assert condition["ExpressionAttributeNames"] == {
        "#ft": "FileType",
        "#co": "Country",
    }
    assert condition["ExpressionAttributeValues"] == {
        ":ft": {"S": "ransomware"},
        ":co": {"S": "Russia"},
    }


def test_build_search_condition_uses_placeholder_aliases_for_names() -> None:
    # Attribute names must be aliased (never inlined) so they can't collide with
    # DynamoDB reserved words.
    condition = rt.build_search_condition(file_type="detection", country="Iran")

    expr = condition["SearchConditionExpression"]
    assert "FileType" not in expr
    assert "Country" not in expr
    for placeholder in condition["ExpressionAttributeNames"]:
        assert placeholder.startswith("#")
    for placeholder in condition["ExpressionAttributeValues"]:
        assert placeholder.startswith(":")


# --------------------------------------------------------------------------------------
# filter_by_threshold — relevance gate (Requirement 2.6)
# --------------------------------------------------------------------------------------


def _r(profile_id: str, score: Any) -> dict[str, Any]:
    return {"ProfileId": profile_id, "Score": score}


def test_filter_by_threshold_keeps_scores_at_or_below_threshold() -> None:
    results = [_r("a", 0.1), _r("b", 0.5), _r("c", 0.6)]

    kept = rt.filter_by_threshold(results, threshold=0.6)

    assert [r["ProfileId"] for r in kept] == ["a", "b", "c"]


def test_filter_by_threshold_drops_scores_above_threshold() -> None:
    results = [_r("a", 0.1), _r("b", 0.61), _r("c", 1.5)]

    kept = rt.filter_by_threshold(results, threshold=0.6)

    assert [r["ProfileId"] for r in kept] == ["a"]


def test_filter_by_threshold_boundary_equality_is_kept() -> None:
    # Score exactly equal to the threshold qualifies (<=, not <).
    results = [_r("edge", 0.6)]

    assert rt.filter_by_threshold(results, threshold=0.6) == [_r("edge", 0.6)]


def test_filter_by_threshold_uses_default_threshold() -> None:
    assert rt.DEFAULT_RELEVANCE_THRESHOLD == 0.6
    results = [_r("keep", 0.6), _r("drop", 0.61)]

    kept = rt.filter_by_threshold(results)

    assert [r["ProfileId"] for r in kept] == ["keep"]


def test_filter_by_threshold_drops_missing_none_and_nonnumeric_scores() -> None:
    results = [
        {"ProfileId": "no-score-key"},  # missing Score
        _r("none-score", None),
        _r("string-score", "0.1"),
        _r("bool-score-true", True),  # bool must not count as numeric
        _r("bool-score-false", False),
        _r("valid", 0.2),
    ]

    kept = rt.filter_by_threshold(results, threshold=0.6)

    # Only the genuinely-numeric, in-range score survives; bools are excluded even
    # though False == 0 <= 0.6 numerically.
    assert [r["ProfileId"] for r in kept] == ["valid"]


def test_filter_by_threshold_accepts_integer_scores() -> None:
    results = [_r("zero", 0), _r("one", 1)]

    kept = rt.filter_by_threshold(results, threshold=0.6)

    assert [r["ProfileId"] for r in kept] == ["zero"]


def test_filter_by_threshold_preserves_order() -> None:
    results = [_r("c", 0.3), _r("a", 0.1), _r("b", 0.2)]

    kept = rt.filter_by_threshold(results, threshold=0.6)

    # Order is preserved exactly as given; the filter does not re-sort.
    assert [r["ProfileId"] for r in kept] == ["c", "a", "b"]


def test_filter_by_threshold_empty_input_returns_empty() -> None:
    assert rt.filter_by_threshold([]) == []


# --------------------------------------------------------------------------------------
# _format_context — citation-tagged rendering (Requirement 2.4)
# --------------------------------------------------------------------------------------


def test_format_context_empty_returns_sentinel() -> None:
    assert rt._format_context([]) == rt.EMPTY_CONTEXT
    assert rt.EMPTY_CONTEXT == "NO_RELEVANT_CONTEXT"


def test_format_context_renders_citation_block_for_single_result() -> None:
    results = [
        {
            "ProfileId": "0ktapus",
            "Name": "0ktapus",
            "FileType": "detection",
            "Content": "Phishing kit targeting Okta credentials.",
        }
    ]

    context = rt._format_context(results)

    assert context == (
        "[1] Name=0ktapus | ProfileId=0ktapus | FileType=detection\n"
        "Phishing kit targeting Okta credentials."
    )


def test_format_context_numbers_and_separates_multiple_results() -> None:
    results = [
        {
            "ProfileId": "0ktapus",
            "Name": "0ktapus",
            "FileType": "detection",
            "Content": "first",
        },
        {
            "ProfileId": "8base",
            "Name": "8Base",
            "FileType": "ransomware",
            "Content": "second",
        },
    ]

    context = rt._format_context(results)

    assert "[1] Name=0ktapus | ProfileId=0ktapus | FileType=detection" in context
    assert "[2] Name=8Base | ProfileId=8base | FileType=ransomware" in context
    # Blocks are separated by a blank line and content follows each header.
    assert "\n\n" in context
    assert context.index("[1]") < context.index("[2]")


def test_format_context_substitutes_placeholders_for_missing_fields() -> None:
    results = [{"ProfileId": None, "Name": None, "FileType": None, "Content": None}]

    context = rt._format_context(results)

    assert context == "[1] Name=Unknown actor | ProfileId=unknown | FileType=unknown\n"


# --------------------------------------------------------------------------------------
# Helpers for exercising retrieve_profiles / _search_vectors_with_retry
# --------------------------------------------------------------------------------------


def _validation_error() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ValidationException", "Message": "index warming up"}},
        "SearchVectors",
    )


def _other_client_error() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "no such table"}},
        "SearchVectors",
    )


class _FakeDdbClient:
    """Records search_vectors calls and returns/raises a scripted sequence."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def search_vectors(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        outcome = self._responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _call_retrieve(**kwargs: Any) -> str:
    """Invoke the (possibly @tool-wrapped) retrieve_profiles with plain kwargs."""
    func = getattr(rt.retrieve_profiles, "__wrapped__", None)
    if callable(func):
        return func(**kwargs)
    return rt.retrieve_profiles(**kwargs)


# --------------------------------------------------------------------------------------
# retrieve_profiles — Top K clamping (Requirement 2.2)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("requested_top_k", "expected_top_k"),
    [
        (None, 10),  # default
        (10, 10),
        (1, 1),
        (100, 100),
        (0, 1),  # below MIN clamps up to 1
        (-5, 1),  # negative clamps up to 1
        (101, 100),  # above MAX clamps down to 100
        (1000, 100),
    ],
)
def test_retrieve_profiles_clamps_top_k(
    monkeypatch: pytest.MonkeyPatch,
    requested_top_k: int | None,
    expected_top_k: int,
) -> None:
    fake = _FakeDdbClient([{"SearchResults": []}])
    monkeypatch.setattr(rt, "embed_text", lambda _query: [0.0] * 1024)
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    if requested_top_k is None:
        _call_retrieve(query="china apt")
    else:
        _call_retrieve(query="china apt", top_k=requested_top_k)

    assert len(fake.calls) == 1
    assert fake.calls[0]["TopK"] == expected_top_k


def test_retrieve_profiles_default_top_k_is_ten() -> None:
    assert rt.DEFAULT_TOP_K == 10
    assert rt.MIN_TOP_K == 1
    assert rt.MAX_TOP_K == 100


def test_retrieve_profiles_passes_inline_filter_into_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeDdbClient([{"SearchResults": []}])
    monkeypatch.setattr(rt, "embed_text", lambda _query: [0.0] * 1024)
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    _call_retrieve(query="q", file_type="detection", country="China")

    request = fake.calls[0]
    assert request["SearchConditionExpression"] == "#ft = :ft AND #co = :co"
    # The filter's names are merged onto the projection's names, and values are set.
    assert request["ExpressionAttributeNames"]["#ft"] == "FileType"
    assert request["ExpressionAttributeNames"]["#co"] == "Country"
    assert request["ExpressionAttributeValues"] == {
        ":ft": {"S": "detection"},
        ":co": {"S": "China"},
    }


def test_retrieve_profiles_omits_condition_when_unfiltered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeDdbClient([{"SearchResults": []}])
    monkeypatch.setattr(rt, "embed_text", lambda _query: [0.0] * 1024)
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    _call_retrieve(query="q")

    request = fake.calls[0]
    assert "SearchConditionExpression" not in request
    assert "ExpressionAttributeValues" not in request


def test_retrieve_profiles_returns_formatted_relevant_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = {
        "SearchResults": [
            {
                "Item": {
                    "ProfileId": {"S": "0ktapus"},
                    "Name": {"S": "0ktapus"},
                    "FileType": {"S": "detection"},
                    "Content": {"S": "relevant content"},
                },
                "Score": 0.1,
            },
            {
                "Item": {
                    "ProfileId": {"S": "far"},
                    "Name": {"S": "Far"},
                    "FileType": {"S": "summary"},
                    "Content": {"S": "irrelevant"},
                },
                "Score": 1.9,  # above threshold, dropped
            },
        ]
    }
    fake = _FakeDdbClient([response])
    monkeypatch.setattr(rt, "embed_text", lambda _query: [0.0] * 1024)
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    context = _call_retrieve(query="okta phishing")

    assert "0ktapus" in context
    assert "relevant content" in context
    assert "irrelevant" not in context  # dropped by the threshold filter


def test_retrieve_profiles_returns_sentinel_when_nothing_relevant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = {
        "SearchResults": [
            {
                "Item": {"ProfileId": {"S": "far"}, "Content": {"S": "x"}},
                "Score": 1.9,
            }
        ]
    }
    fake = _FakeDdbClient([response])
    monkeypatch.setattr(rt, "embed_text", lambda _query: [0.0] * 1024)
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    assert _call_retrieve(query="q") == rt.EMPTY_CONTEXT


# --------------------------------------------------------------------------------------
# _search_vectors_with_retry — warm-up retry (Requirement 2.5)
# --------------------------------------------------------------------------------------


def test_search_vectors_retries_validation_exception_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = {"SearchResults": []}
    fake = _FakeDdbClient([_validation_error(), _validation_error(), success])
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    sleeps: list[float] = []
    monkeypatch.setattr(rt.time, "sleep", lambda seconds: sleeps.append(seconds))

    result = rt._search_vectors_with_retry({"TableName": "t"})

    assert result is success
    assert len(fake.calls) == 3  # two failures + one success
    assert len(sleeps) == 2  # slept once before each retry


def test_search_vectors_non_validation_error_propagates_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeDdbClient([_other_client_error()])
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    slept: list[float] = []
    monkeypatch.setattr(rt.time, "sleep", lambda seconds: slept.append(seconds))

    with pytest.raises(ClientError) as excinfo:
        rt._search_vectors_with_retry({"TableName": "t"})

    assert excinfo.value.response["Error"]["Code"] == "ResourceNotFoundException"
    assert len(fake.calls) == 1  # no retry
    assert slept == []  # never backed off


def test_search_vectors_reraises_last_validation_error_after_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every attempt fails with a warm-up error; after the retry budget is exhausted the
    # final error is surfaced.
    attempts = rt.WARMUP_MAX_RETRIES + 1
    fake = _FakeDdbClient([_validation_error() for _ in range(attempts)])
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)
    monkeypatch.setattr(rt.time, "sleep", lambda _seconds: None)

    with pytest.raises(ClientError) as excinfo:
        rt._search_vectors_with_retry({"TableName": "t"})

    assert excinfo.value.response["Error"]["Code"] == "ValidationException"
    assert len(fake.calls) == attempts


def test_search_vectors_succeeds_on_first_try_without_sleeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = {"SearchResults": [{"Item": {}, "Score": 0.1}]}
    fake = _FakeDdbClient([success])
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)

    slept: list[float] = []
    monkeypatch.setattr(rt.time, "sleep", lambda seconds: slept.append(seconds))

    assert rt._search_vectors_with_retry({"TableName": "t"}) is success
    assert len(fake.calls) == 1
    assert slept == []

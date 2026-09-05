"""Unit tests for :mod:`ddb` (the vector-search request builder and response parser).

These tests exercise the pure (de)serialization helpers with fixture payloads and do
not touch AWS:

- ``to_vector_attr`` — the ``SearchVector`` request builder. We assert it emits the
  **plain list** ``[{"N": ...}]`` form (never the ``{"L": [...]}`` wrapper), preserves
  full float precision, and rejects an empty vector (Requirement 2.1).
- ``from_search_results`` — the ``SearchVectors`` response parser. We feed it fixture
  ``SearchResults`` payloads (each ``{"Item", "Score"}``) and assert it flattens each
  match to ``{ProfileId, Name, FileType, Content, Score}``, returns ``None`` for
  missing attributes, skips entries without an ``Item``, and preserves order
  (Requirement 2.4).
"""

from __future__ import annotations

from typing import Any

import pytest

import ddb

# --------------------------------------------------------------------------------------
# to_vector_attr — the SearchVector request builder
# --------------------------------------------------------------------------------------


def test_to_vector_attr_produces_plain_list_of_number_values() -> None:
    attr = ddb.to_vector_attr([0.1, -0.2, 0.3])

    # Plain list of {"N": ...} entries — NOT wrapped in {"L": [...]}.
    assert isinstance(attr, list)
    assert attr == [{"N": "0.1"}, {"N": "-0.2"}, {"N": "0.3"}]
    assert all(set(entry.keys()) == {"N"} for entry in attr)


def test_to_vector_attr_is_not_l_wrapped() -> None:
    attr = ddb.to_vector_attr([1.0, 2.0])

    # The bare-list form must not be the {"L": [...]} attribute wrapper used for
    # stored list attributes; passing that to SearchVector triggers a ValidationException.
    assert not (isinstance(attr, dict) and "L" in attr)
    assert isinstance(attr, list)


def test_to_vector_attr_preserves_precision() -> None:
    # Values that would lose precision if rounded/truncated. str() keeps full repr.
    vector = [0.123456789012345, -1.0000000001, 3.14159265358979]
    attr = ddb.to_vector_attr(vector)

    assert [entry["N"] for entry in attr] == [str(v) for v in vector]
    # Round-tripping the serialized strings recovers the original floats exactly.
    assert [float(entry["N"]) for entry in attr] == vector


def test_to_vector_attr_matches_length_of_input() -> None:
    vector = [float(i) for i in range(1024)]
    attr = ddb.to_vector_attr(vector)

    assert len(attr) == 1024


def test_to_vector_attr_rejects_empty_vector() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        ddb.to_vector_attr([])


# --------------------------------------------------------------------------------------
# from_search_results — the SearchVectors response parser
# --------------------------------------------------------------------------------------


def _item(
    *,
    profile_id: str | None = None,
    name: str | None = None,
    file_type: str | None = None,
    content: str | None = None,
) -> dict[str, Any]:
    """Build a DynamoDB AttributeValue item map, omitting attributes set to None."""
    item: dict[str, Any] = {}
    if profile_id is not None:
        item["ProfileId"] = {"S": profile_id}
    if name is not None:
        item["Name"] = {"S": name}
    if file_type is not None:
        item["FileType"] = {"S": file_type}
    if content is not None:
        item["Content"] = {"S": content}
    return item


def test_from_search_results_parses_full_fixture_payload() -> None:
    response = {
        "SearchResults": [
            {
                "Item": _item(
                    profile_id="0ktapus",
                    name="0ktapus",
                    file_type="detection",
                    content="Phishing kit targeting Okta credentials.",
                ),
                "Score": 0.12,
            },
            {
                "Item": _item(
                    profile_id="8base",
                    name="8Base",
                    file_type="ransomware",
                    content="Double-extortion ransomware operation.",
                ),
                "Score": 0.34,
            },
        ]
    }

    results = ddb.from_search_results(response)

    assert results == [
        {
            "ProfileId": "0ktapus",
            "Name": "0ktapus",
            "FileType": "detection",
            "Content": "Phishing kit targeting Okta credentials.",
            "Score": 0.12,
        },
        {
            "ProfileId": "8base",
            "Name": "8Base",
            "FileType": "ransomware",
            "Content": "Double-extortion ransomware operation.",
            "Score": 0.34,
        },
    ]


def test_from_search_results_reads_from_search_results_not_items() -> None:
    # A payload keyed on "Items" (the GetItem/Query shape) must NOT be parsed;
    # only the "SearchResults" array is authoritative for SearchVectors.
    response = {"Items": [{"Item": _item(profile_id="ignored"), "Score": 0.1}]}

    assert ddb.from_search_results(response) == []


def test_from_search_results_handles_missing_attributes_as_none() -> None:
    response = {
        "SearchResults": [
            {"Item": _item(profile_id="lazarus"), "Score": 0.05},
        ]
    }

    results = ddb.from_search_results(response)

    assert results == [
        {
            "ProfileId": "lazarus",
            "Name": None,
            "FileType": None,
            "Content": None,
            "Score": 0.05,
        }
    ]


def test_from_search_results_skips_entries_without_item() -> None:
    response = {
        "SearchResults": [
            {"Item": _item(profile_id="present"), "Score": 0.1},
            {"Score": 0.2},  # no Item key
            {"Item": {}, "Score": 0.3},  # empty Item map
            {"Item": None, "Score": 0.4},  # explicit null Item
        ]
    }

    results = ddb.from_search_results(response)

    assert [r["ProfileId"] for r in results] == ["present"]


def test_from_search_results_preserves_order() -> None:
    response = {
        "SearchResults": [
            {"Item": _item(profile_id="a"), "Score": 0.9},
            {"Item": _item(profile_id="b"), "Score": 0.1},
            {"Item": _item(profile_id="c"), "Score": 0.5},
        ]
    }

    results = ddb.from_search_results(response)

    # Order is preserved exactly as returned; the parser does not re-rank.
    assert [r["ProfileId"] for r in results] == ["a", "b", "c"]
    assert [r["Score"] for r in results] == [0.9, 0.1, 0.5]


def test_from_search_results_empty_response_returns_empty_list() -> None:
    assert ddb.from_search_results({}) == []
    assert ddb.from_search_results({"SearchResults": []}) == []


def test_from_search_results_preserves_score_none_when_absent() -> None:
    response = {"SearchResults": [{"Item": _item(profile_id="noscore")}]}

    results = ddb.from_search_results(response)

    assert results[0]["Score"] is None

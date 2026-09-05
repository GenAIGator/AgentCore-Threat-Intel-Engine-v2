"""Offline unit tests for the pure profile-dedup logic (no AWS access).

Exercises normalization, the two decision predicates, and :func:`check_duplicate`'s
composition with injected ``existing`` / ``nearest`` so neither the DynamoDB scan nor the
vector search is called.
"""

from __future__ import annotations

from profile_dedup import (
    DEFAULT_DUPLICATE_DISTANCE,
    ProfileIdentity,
    check_duplicate,
    is_normalized_duplicate,
    is_semantic_duplicate,
    normalize,
    normalized_set,
)

# --- normalize ------------------------------------------------------------------------


def test_normalize_basic_and_digits() -> None:
    assert normalize("0ktapus") == "0ktapus"
    assert normalize("  0ktapus  ") == "0ktapus"
    assert normalize("Qilin") == "qilin"


def test_normalize_strips_filler_tokens() -> None:
    assert normalize("0ktapus Group") == "0ktapus"
    assert normalize("Lazarus Group") == "lazarus"
    assert normalize("Sandworm Team") == "sandworm"


def test_normalize_collapses_separators() -> None:
    assert normalize("ALPHV/BlackCat") == "alphvblackcat"
    assert normalize("ALPHV-BlackCat") == "alphvblackcat"
    assert normalize("ALPHV BlackCat") == "alphvblackcat"


def test_normalize_empty() -> None:
    assert normalize("") == ""
    assert normalize(None) == ""
    assert normalize("The Group") == ""  # all filler


def test_normalized_set_handles_lists_and_blanks() -> None:
    keys = normalized_set("0ktapus", ["Scattered Spider", "Octo Tempest"], None, "")
    assert "0ktapus" in keys
    assert "scatteredspider" in keys
    assert "octotempest" in keys
    assert "" not in keys


# --- is_normalized_duplicate ----------------------------------------------------------


def _existing() -> list[ProfileIdentity]:
    return [
        ProfileIdentity(profile_id="0ktapus", name="0ktapus", aliases=("Scattered Spider",)),
        ProfileIdentity(profile_id="alphv_blackcat", name="ALPHV/BlackCat", aliases=("BlackCat",)),
        ProfileIdentity(profile_id="qilin", name="Qilin", aliases=()),
    ]


def test_normalized_duplicate_exact_id() -> None:
    match = is_normalized_duplicate("0ktapus", None, None, _existing())
    assert match is not None
    assert match.profile_id == "0ktapus"


def test_normalized_duplicate_name_variation() -> None:
    # "Oktapus group" should still collapse to match "0ktapus"? No — 0 vs O differ.
    # But "0ktapus Group" (filler) must match.
    match = is_normalized_duplicate("0ktapus Group", None, None, _existing())
    assert match is not None and match.profile_id == "0ktapus"


def test_normalized_duplicate_via_alias() -> None:
    # Proposing "Scattered Spider" as a new actor must hit 0ktapus via its alias.
    match = is_normalized_duplicate("scattered_spider", "Scattered Spider", None, _existing())
    assert match is not None and match.profile_id == "0ktapus"


def test_normalized_duplicate_separator_variation() -> None:
    match = is_normalized_duplicate("alphv-blackcat", "ALPHV BlackCat", None, _existing())
    assert match is not None and match.profile_id == "alphv_blackcat"


def test_normalized_no_match_for_genuinely_new() -> None:
    match = is_normalized_duplicate("volt_typhoon", "Volt Typhoon", None, _existing())
    assert match is None


# --- is_semantic_duplicate ------------------------------------------------------------


def test_semantic_duplicate_threshold() -> None:
    assert is_semantic_duplicate(0.05) is True
    assert is_semantic_duplicate(DEFAULT_DUPLICATE_DISTANCE) is True
    assert is_semantic_duplicate(DEFAULT_DUPLICATE_DISTANCE + 0.01) is False
    assert is_semantic_duplicate(0.6) is False
    assert is_semantic_duplicate(None) is False


# --- check_duplicate (composition, injected data) -------------------------------------


def test_check_duplicate_normalized_wins_first() -> None:
    verdict = check_duplicate(
        "0ktapus",
        proposed_name="0ktapus",
        existing=_existing(),
        nearest=(0.9, "unrelated", "Unrelated"),  # ignored — tier 1 trips first
    )
    assert verdict.is_duplicate is True
    assert verdict.reason == "normalized"
    assert verdict.existing_profile_id == "0ktapus"


def test_check_duplicate_semantic_when_no_normalized_match() -> None:
    verdict = check_duplicate(
        "octo_tempest_new",
        proposed_name="Octo Tempest",
        intent="Okta phishing social engineering crew",
        existing=[ProfileIdentity(profile_id="qilin", name="Qilin")],  # no normalized hit
        nearest=(0.10, "0ktapus", "0ktapus"),  # very close semantically
    )
    assert verdict.is_duplicate is True
    assert verdict.reason == "semantic"
    assert verdict.existing_profile_id == "0ktapus"
    assert verdict.distance == 0.10


def test_check_duplicate_clears_genuinely_new() -> None:
    verdict = check_duplicate(
        "volt_typhoon",
        proposed_name="Volt Typhoon",
        intent="Chinese state-sponsored living-off-the-land",
        existing=_existing(),
        nearest=(0.55, "qilin", "Qilin"),  # far enough
    )
    assert verdict.is_duplicate is False
    assert verdict.reason == ""
    assert verdict.distance == 0.55

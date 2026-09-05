"""Offline unit tests for the quality gate and section generator parsing (no AWS/model)."""

from __future__ import annotations

from typing import Any

from quality_gate import count_list_items, evaluate_section
from section_generator import build_section_prompt, extract_json_fields
from sections import SECTIONS_BY_TYPE


def _joined_deriver(shard: dict[str, Any]) -> str:
    """A trivial content deriver: concatenate all string/list values (approximates length)."""
    parts: list[str] = []
    for key, value in shard.items():
        if key in ("id", "name", "file_type", "attribution"):
            continue
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            for item in value:
                parts.append(str(item))
    return " ".join(parts)


# --- count_list_items -----------------------------------------------------------------


def test_count_list_items_counts_across_list_fields_and_ignores_blanks() -> None:
    spec = SECTIONS_BY_TYPE["tactics_ttp"]  # list_fields: common_tactics, common_initial_access
    fields = {
        "common_tactics": ["a", "b", "", "  "],  # 2 non-blank
        "common_initial_access": ["c", "d", "e"],  # 3
    }
    assert count_list_items(fields, spec) == 5


def test_count_list_items_counts_dicts() -> None:
    spec = SECTIONS_BY_TYPE["tactics_mitre"]
    fields = {
        "mitre_tactics": ["Initial Access", "Persistence"],
        "mitre_techniques": [{"id": "T1566", "name": "Phishing"}, {"id": "T1078", "name": "VA"}],
    }
    assert count_list_items(fields, spec) == 4


# --- evaluate_section -----------------------------------------------------------------


def test_evaluate_section_passes_when_deep_enough() -> None:
    spec = SECTIONS_BY_TYPE["detection"]  # min 4 items, min 200 chars
    long_items = [
        "Alert on impossible-travel sign-ins across the identity provider estate widely",
        "Monitor for repeated MFA push denials immediately followed by a single approval",
        "Detect help-desk-initiated MFA resets that occur outside approved change windows",
        "Flag new OAuth grants to unverified third-party applications on core SaaS tenants",
    ]
    verdict = evaluate_section(
        "detection", {"detection_opportunities": long_items}, spec, _joined_deriver
    )
    assert verdict.passed is True
    assert verdict.list_items == 4
    assert verdict.reasons == ()


def test_evaluate_section_fails_short_content() -> None:
    spec = SECTIONS_BY_TYPE["detection"]
    fields = {"detection_opportunities": ["a", "b", "c", "d"]}
    verdict = evaluate_section("detection", fields, spec, _joined_deriver)
    assert verdict.passed is False
    assert any("content too short" in r for r in verdict.reasons)


def test_evaluate_section_fails_too_few_items() -> None:
    spec = SECTIONS_BY_TYPE["tactics_ttp"]  # needs 6 items
    fields = {
        "common_tactics": ["one very long tactic description " * 5],
        "common_initial_access": [],
    }
    verdict = evaluate_section("tactics_ttp", fields, spec, _joined_deriver)
    assert verdict.passed is False
    assert any("too few list items" in r for r in verdict.reasons)


# --- section prompt + JSON extraction -------------------------------------------------


def test_build_section_prompt_mentions_actor_fields_and_example() -> None:
    spec = SECTIONS_BY_TYPE["core_identity"]
    prompt = build_section_prompt("Volt Typhoon", "China LOTL actor", {"country": "China"}, spec)
    assert "Volt Typhoon" in prompt
    assert "core_identity" in prompt
    assert "aliases" in prompt  # field list
    assert "China" in prompt  # attribution line
    assert "JSON object" in prompt


def test_extract_json_fields_from_fenced_block() -> None:
    text = 'Here you go:\n```json\n{"aliases": ["X", "Y"], "category": ["cybercrime"]}\n```\nDone.'
    fields = extract_json_fields(text)
    assert fields == {"aliases": ["X", "Y"], "category": ["cybercrime"]}


def test_extract_json_fields_from_bare_object() -> None:
    text = 'prefix {"summary": ["a concise summary"]} suffix'
    assert extract_json_fields(text) == {"summary": ["a concise summary"]}


def test_extract_json_fields_returns_empty_on_garbage() -> None:
    assert extract_json_fields("no json here at all") == {}
    assert extract_json_fields("") == {}

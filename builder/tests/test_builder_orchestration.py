"""Offline unit tests for builder_app's pure orchestration (no AWS/model)."""

from __future__ import annotations

from typing import Any

import builder_app as ba
from sections import SECTION_FILE_TYPES, SECTIONS_BY_TYPE, SectionSpec


def _deriver(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in shard.items():
        if key in ("id", "name", "file_type", "attribution"):
            continue
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(i) for i in value)
    return " ".join(parts)


def _rich_fields(spec: SectionSpec) -> dict[str, Any]:
    """Generate fields guaranteed to pass the gate for any spec (many long items)."""
    fields: dict[str, Any] = {}
    for name in spec.json_fields:
        if name in spec.list_fields:
            fields[name] = [
                f"A sufficiently long and specific detail item number {i} for {name} here"
                for i in range(spec.min_list_items + 2)
            ]
        elif name in ("ai_confirmed", "ai_suspected"):
            fields[name] = False
        else:
            fields[name] = {"note": "x"}
    return fields


# --- build_one_section: retry-until-pass ----------------------------------------------


def test_build_one_section_retries_until_pass() -> None:
    spec = SECTIONS_BY_TYPE["detection"]
    calls = {"n": 0}

    def generate(_s: SectionSpec) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] < 2:
            return {"detection_opportunities": ["too", "few"]}  # fails gate
        return _rich_fields(spec)

    fields, verdict = ba.build_one_section(generate, _deriver, spec, "Actor", max_retries=2)
    assert verdict.passed is True
    assert calls["n"] == 2  # failed once, passed on the second


def test_build_one_section_returns_best_when_never_passes() -> None:
    spec = SECTIONS_BY_TYPE["detection"]

    def generate(_s: SectionSpec) -> dict[str, Any]:
        return {"detection_opportunities": ["short"]}  # always fails

    fields, verdict = ba.build_one_section(generate, _deriver, spec, "Actor", max_retries=2)
    assert verdict.passed is False


# --- build_profile_sections: all 12 attempted -----------------------------------------


def test_build_profile_sections_covers_all_twelve() -> None:
    def generate(spec: SectionSpec) -> dict[str, Any]:
        return _rich_fields(spec)

    fields_by_type, verdicts = ba.build_profile_sections(generate, _deriver, "Actor", max_retries=0)
    assert set(fields_by_type) == set(SECTION_FILE_TYPES)
    assert len(verdicts) == 12
    assert all(v.passed for v in verdicts)


# --- assemble_items: one item per section, via injected builders ----------------------


def test_assemble_items_builds_one_per_section() -> None:
    fields_by_type = {ft: {} for ft in SECTION_FILE_TYPES}

    def fake_shard_builder(
        pid: str, name: str, ft: str, fields: dict[str, Any], attr: Any
    ) -> dict[str, Any]:
        return {"id": pid, "name": name, "file_type": ft}

    def fake_item_builder(shard: dict[str, Any], *, updated_by: str) -> dict[str, dict[str, Any]]:
        return {
            "ProfileId": {"S": shard["id"]},
            "ShardId": {"S": shard["file_type"]},
            "UpdatedBy": {"S": updated_by},
        }

    items = ba.assemble_items(
        "volt_typhoon", "Volt Typhoon", {"country": "China"}, fields_by_type, "a@b.com",
        item_builder=fake_item_builder, shard_builder=fake_shard_builder,
    )
    assert len(items) == 12
    shard_ids = {i["ShardId"]["S"] for i in items}
    assert shard_ids == set(SECTION_FILE_TYPES)
    assert all(i["UpdatedBy"]["S"] == "a@b.com" for i in items)

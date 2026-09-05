"""Unit tests for :mod:`content` (deterministic ``Content`` + metadata derivation).

These tests exercise the pure transformation of a v1 threat-profile shard into the
embedded ``Content`` string and the promoted DynamoDB metadata attributes. No AWS or
embedding calls are involved.

Coverage (Requirements 6.1, 6.4, 7.1, 7.2, 7.3):

- One self-contained fixture shard per ``file_type``. The v1 corpus has 12 shard types
  (``summary``, ``core_description``, ``core_identity``, ``tactics_ttp``,
  ``tactics_mitre``, ``tabletop``, ``response``, ``purple_team``, ``detection``,
  ``ai_tooling``, ``cloud_general``, ``cloud_aws``); all are exercised.
- ``derive_content`` produces the stable ``"{Name} ({file_type}):"`` prefix and folds in
  each type's meaningful fields (Requirements 7.1). ``tactics_mitre`` renders technique
  entries as ``"T####: name"`` pairs.
- ``derive_content`` is deterministic: two calls on the same shard are byte-identical.
- ``derive_metadata`` promotes the declared attributes (Requirement 6.1) and OMITS any
  field absent from the source shard (Requirement 6.4).
- The DEFAULT fallback handles an unknown ``file_type``.
- Truncated source text (v1's mid-word S3-Vectors cap) is stored verbatim (Requirement
  7.2).
"""

from __future__ import annotations

from typing import Any

import pytest

import content

# --------------------------------------------------------------------------------------
# Self-contained fixtures — one shard per file_type.
#
# Shapes mirror the real v1 corpus (see agentcore-threat-intel-engine/threat-profiles/)
# but use small, hand-written values so each assertion is exact. The shared identity
# block (id/name/attribution) is attached to every shard by _shard().
# --------------------------------------------------------------------------------------

_ATTRIBUTION = {"country": "Testland", "region": "Test Region"}


def _shard(file_type: str, **fields: Any) -> dict[str, Any]:
    """Build a shard with the shared identity block plus type-specific fields."""
    return {
        "id": "testactor",
        "name": "Test Actor",
        "attribution": dict(_ATTRIBUTION),
        "file_type": file_type,
        **fields,
    }


SUMMARY = _shard(
    "summary",
    summary="A concise SaaS identity theft campaign summary.",
)

CORE_DESCRIPTION = _shard(
    "core_description",
    description="A large-scale phishing and identity-theft campaign.",
    strategic_objectives=["Credential theft", "MFA bypass"],
    operating_characteristics={"stealth_level": "very_high", "noise_level": "low"},
)

CORE_IDENTITY = _shard(
    "core_identity",
    aliases=["Test Campaign", "Test Cluster"],
    category=["Financially Motivated Cybercrime", "Credential Theft"],
    target_sectors=["Technology", "Financial services"],
    target_regions=["North America", "Europe"],
)

TACTICS_TTP = _shard(
    "tactics_ttp",
    common_tactics=["Adversary-in-the-middle phishing", "Session token theft"],
    common_initial_access=["Phishing links", "Smishing"],
)

TACTICS_MITRE = _shard(
    "tactics_mitre",
    mitre_tactics=["Initial Access", "Credential Access"],
    mitre_techniques=[
        {"id": "T1566", "name": "Phishing"},
        {"id": "T1078", "name": "Valid Accounts"},
        {"id": "T1528", "name": "Steal Application Access Token"},
    ],
)

TABLETOP = _shard(
    "tabletop",
    tabletop_use_cases=["Identity-compromise exercise", "BEC response drill"],
    simulator_injects=["Help-desk impersonation call", "MFA fatigue prompt"],
)

RESPONSE = _shard(
    "response",
    investigation_questions=["Which accounts were accessed?", "Any mailbox rules added?"],
    containment=["Revoke sessions", "Reset credentials"],
)

PURPLE_TEAM = _shard(
    "purple_team",
    purple_team=["Simulate AiTM phishing", "Emulate token replay"],
    difficulty=["moderate"],
)

DETECTION = _shard(
    "detection",
    detection_opportunities=[
        "Unexpected logins from unusual geographies",
        "Suspicious OAuth grants",
    ],
)

AI_TOOLING = _shard(
    "ai_tooling",
    tooling=["AiTM phishing kits", "Reverse proxy harvesting"],
    behaviors=["SaaS identity theft focus", "AiTM credential capture"],
    ai_tactics=["Improved phishing lures", "Better help-desk impersonation"],
    ai_confirmed=False,
    ai_suspected=True,
)

CLOUD_GENERAL = _shard(
    "cloud_general",
    cloud_relevance="critical",
    cloud_why=["Fundamentally a cloud identity attack", "SaaS identities grant access"],
    saas_targets=["Okta", "Microsoft 365"],
)

CLOUD_AWS = _shard(
    "cloud_aws",
    aws_relevance="moderate_to_high",
    aws_paths=["Compromise of federated AWS access", "Access to IAM roles"],
    aws_targets=["Federated IAM access paths", "S3 buckets"],
)

# Every mapped file_type paired with its fixture, for parametric coverage.
ALL_FIXTURES: dict[str, dict[str, Any]] = {
    "summary": SUMMARY,
    "core_description": CORE_DESCRIPTION,
    "core_identity": CORE_IDENTITY,
    "tactics_ttp": TACTICS_TTP,
    "tactics_mitre": TACTICS_MITRE,
    "tabletop": TABLETOP,
    "response": RESPONSE,
    "purple_team": PURPLE_TEAM,
    "detection": DETECTION,
    "ai_tooling": AI_TOOLING,
    "cloud_general": CLOUD_GENERAL,
    "cloud_aws": CLOUD_AWS,
}


# --------------------------------------------------------------------------------------
# derive_content — prefix + meaningful fields, per file_type (Requirement 7.1)
# --------------------------------------------------------------------------------------


def test_all_twelve_file_types_have_a_builder() -> None:
    # Guard: every fixture type is explicitly mapped (not silently using DEFAULT).
    assert set(ALL_FIXTURES) == set(content.CONTENT_BUILDERS)
    assert len(ALL_FIXTURES) == 12


@pytest.mark.parametrize("file_type", list(ALL_FIXTURES))
def test_content_has_name_and_file_type_prefix(file_type: str) -> None:
    result = content.derive_content(ALL_FIXTURES[file_type])
    assert result.startswith(f"Test Actor ({file_type}):")


@pytest.mark.parametrize("file_type", list(ALL_FIXTURES))
def test_content_is_deterministic(file_type: str) -> None:
    shard = ALL_FIXTURES[file_type]
    assert content.derive_content(shard) == content.derive_content(shard)


def test_content_summary_includes_summary_text() -> None:
    result = content.derive_content(SUMMARY)
    assert result == "Test Actor (summary): A concise SaaS identity theft campaign summary."


def test_content_core_description_includes_objectives_and_characteristics() -> None:
    result = content.derive_content(CORE_DESCRIPTION)
    assert "A large-scale phishing and identity-theft campaign." in result
    assert "Strategic objectives: Credential theft; MFA bypass." in result
    assert "Operating characteristics: stealth_level: very_high; noise_level: low." in result


def test_content_core_identity_includes_aliases_category_sectors_regions() -> None:
    result = content.derive_content(CORE_IDENTITY)
    assert "Aliases: Test Campaign, Test Cluster." in result
    assert "Category: Financially Motivated Cybercrime, Credential Theft." in result
    assert "Target sectors: Technology, Financial services." in result
    assert "Target regions: North America, Europe." in result


def test_content_tactics_ttp_includes_tactics_and_initial_access() -> None:
    result = content.derive_content(TACTICS_TTP)
    assert "Common tactics: Adversary-in-the-middle phishing; Session token theft." in result
    assert "Common initial access: Phishing links; Smishing." in result


def test_content_tactics_mitre_renders_technique_id_name_pairs() -> None:
    result = content.derive_content(TACTICS_MITRE)
    assert "MITRE tactics: Initial Access, Credential Access." in result
    # Techniques render as "T####: name" pairs joined by "; ".
    assert (
        "MITRE techniques: T1566: Phishing; T1078: Valid Accounts; "
        "T1528: Steal Application Access Token." in result
    )


def test_content_tabletop_includes_use_cases_and_injects() -> None:
    result = content.derive_content(TABLETOP)
    assert "Tabletop use cases: Identity-compromise exercise; BEC response drill." in result
    assert "Simulator injects: Help-desk impersonation call; MFA fatigue prompt." in result


def test_content_response_includes_questions_and_containment() -> None:
    result = content.derive_content(RESPONSE)
    assert (
        "Investigation questions: Which accounts were accessed?; "
        "Any mailbox rules added?." in result
    )
    assert "Containment: Revoke sessions; Reset credentials." in result


def test_content_purple_team_includes_exercises_and_difficulty() -> None:
    result = content.derive_content(PURPLE_TEAM)
    assert "Purple team exercises: Simulate AiTM phishing; Emulate token replay." in result
    assert "Difficulty: moderate." in result


def test_content_detection_includes_opportunities() -> None:
    result = content.derive_content(DETECTION)
    assert (
        "Detection opportunities: Unexpected logins from unusual geographies; "
        "Suspicious OAuth grants." in result
    )


def test_content_ai_tooling_includes_tooling_behaviors_tactics_and_flags() -> None:
    result = content.derive_content(AI_TOOLING)
    assert "Tooling: AiTM phishing kits, Reverse proxy harvesting." in result
    assert "Behaviors: SaaS identity theft focus; AiTM credential capture." in result
    assert "AI tactics: Improved phishing lures; Better help-desk impersonation." in result
    assert "AI confirmed: false." in result
    assert "AI suspected: true." in result


def test_content_cloud_general_includes_relevance_why_saas() -> None:
    result = content.derive_content(CLOUD_GENERAL)
    assert "Cloud relevance: critical." in result
    assert (
        "Why cloud matters: Fundamentally a cloud identity attack; "
        "SaaS identities grant access." in result
    )
    assert "SaaS targets: Okta, Microsoft 365." in result


def test_content_cloud_aws_includes_relevance_paths_targets() -> None:
    result = content.derive_content(CLOUD_AWS)
    assert "AWS relevance: moderate_to_high." in result
    assert "AWS attack paths: Compromise of federated AWS access; Access to IAM roles." in result
    assert "AWS targets: Federated IAM access paths, S3 buckets." in result


# --------------------------------------------------------------------------------------
# derive_content — DEFAULT fallback for unknown file_type
# --------------------------------------------------------------------------------------


def test_content_default_fallback_for_unknown_file_type() -> None:
    shard = _shard(
        "some_new_type",
        notes=["First note", "Second note"],
        headline="A single headline string",
    )
    result = content.derive_content(shard)

    assert result.startswith("Test Actor (some_new_type):")
    # Non-structural string/list fields are flattened with an underscore-to-space label.
    assert "notes: First note; Second note." in result
    assert "headline: A single headline string." in result


def test_content_default_skips_structural_fields() -> None:
    shard = _shard("mystery", details=["Only this should render"])
    result = content.derive_content(shard)

    # id / attribution / file_type must not leak into the DEFAULT body.
    assert "testactor" not in result
    assert "Testland" not in result
    assert "details: Only this should render." in result


def test_content_missing_file_type_uses_default_and_bare_prefix() -> None:
    shard = {"id": "x", "name": "No Type Actor", "field": "value"}
    result = content.derive_content(shard)

    # No file_type → prefix has no parenthetical.
    assert result.startswith("No Type Actor:")
    assert "field: value." in result


def test_content_empty_body_returns_prefix_only() -> None:
    shard = _shard("summary")  # no summary field present
    result = content.derive_content(shard)

    assert result == "Test Actor (summary):"


# --------------------------------------------------------------------------------------
# Requirement 7.2 — truncated text stored verbatim (no cleanup / re-truncation)
# --------------------------------------------------------------------------------------


def test_truncated_text_is_stored_verbatim() -> None:
    # Mid-word truncation from v1's S3-Vectors metadata cap must survive untouched.
    shard = _shard(
        "cloud_aws",
        aws_relevance="moderate_to_high",
        aws_paths=[
            "Compromise of federated AWS access through SSO identity thef",
            "Access to IAM roles through stolen enterprise identity sessi",
        ],
    )
    result = content.derive_content(shard)

    assert "identity thef" in result
    assert "identity sessi" in result
    # The mangled fragments are not repaired or dropped.
    assert "identity theft" not in result


# --------------------------------------------------------------------------------------
# derive_metadata — promotes declared attributes (Requirement 6.1)
# --------------------------------------------------------------------------------------


def test_metadata_promotes_core_identity_attributes() -> None:
    metadata = content.derive_metadata(CORE_IDENTITY)

    assert metadata["ProfileId"] == "testactor"
    assert metadata["ShardId"] == "core_identity"
    assert metadata["FileType"] == "core_identity"
    assert metadata["Name"] == "Test Actor"
    assert metadata["Aliases"] == ["Test Campaign", "Test Cluster"]
    assert metadata["Country"] == "Testland"
    assert metadata["Region"] == "Test Region"
    assert metadata["Category"] == ["Financially Motivated Cybercrime", "Credential Theft"]


def test_metadata_promotes_cloud_relevance() -> None:
    metadata = content.derive_metadata(CLOUD_GENERAL)
    assert metadata["CloudRelevance"] == "critical"


def test_metadata_promotes_ai_confirmed_bool() -> None:
    metadata = content.derive_metadata(AI_TOOLING)
    # Present and boolean-typed → promoted (even though the value is False).
    assert metadata["AiConfirmed"] is False


@pytest.mark.parametrize("file_type", list(ALL_FIXTURES))
def test_metadata_always_promotes_identity_keys(file_type: str) -> None:
    # Every shard carries id/name/attribution/file_type, so these are always present.
    metadata = content.derive_metadata(ALL_FIXTURES[file_type])
    assert metadata["ProfileId"] == "testactor"
    assert metadata["ShardId"] == file_type
    assert metadata["FileType"] == file_type
    assert metadata["Name"] == "Test Actor"
    assert metadata["Country"] == "Testland"
    assert metadata["Region"] == "Test Region"


# --------------------------------------------------------------------------------------
# derive_metadata — omits absent fields (Requirement 6.4)
# --------------------------------------------------------------------------------------


def test_metadata_omits_absent_fields() -> None:
    # A summary shard carries no aliases/category/cloud_relevance/ai_confirmed.
    metadata = content.derive_metadata(SUMMARY)

    assert "Aliases" not in metadata
    assert "Category" not in metadata
    assert "CloudRelevance" not in metadata
    assert "AiConfirmed" not in metadata


def test_metadata_omits_country_and_region_when_attribution_absent() -> None:
    shard = {"id": "x", "name": "Y", "file_type": "summary", "summary": "text"}
    metadata = content.derive_metadata(shard)

    assert "Country" not in metadata
    assert "Region" not in metadata
    # But the always-present keys are still there.
    assert metadata["ProfileId"] == "x"
    assert metadata["Name"] == "Y"


def test_metadata_omits_empty_string_fields() -> None:
    # Blank / whitespace-only values are treated as absent, not stored empty.
    shard = _shard("core_identity", aliases=["", "   "], category=[])
    metadata = content.derive_metadata(shard)

    assert "Aliases" not in metadata
    assert "Category" not in metadata


def test_metadata_omits_ai_confirmed_when_not_boolean() -> None:
    # Only a real bool is promoted; a stray string must be omitted, not coerced.
    shard = _shard("ai_tooling", ai_confirmed="false")
    metadata = content.derive_metadata(shard)

    assert "AiConfirmed" not in metadata

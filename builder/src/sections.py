"""Canonical section definitions for building a NEW threat-actor profile.

A complete profile has all 12 shard ``file_type``s (mirroring the loader's
``content.py`` ``CONTENT_BUILDERS``). For each section this module declares:

* the ``file_type`` (== ``ShardId``),
* the JSON field(s) the corresponding loader ``_content_*`` builder reads, so the builder
  agent generates the SAME shape the loader/derive_content expects,
* a short human description used in the generation prompt,
* a worked EXAMPLE (a realistic shard for a *different* actor) so the model matches the
  corpus structure and depth, and
* per-section QUALITY minimums used by :mod:`quality_gate` to reject shallow output.

Everything here is static data + pure helpers (no AWS, no model calls), so it is fully
unit-testable. The minimums were chosen to approximate the depth of the existing seed
corpus (see ``docs/CREATE_PROFILE_DESIGN.md``): every section must clear a minimum derived
``Content`` length, and list-bearing sections must carry a minimum number of list items.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SectionSpec:
    """Definition of one profile section (shard) the builder must generate.

    Attributes:
        file_type: The shard ``file_type`` / ``ShardId``.
        description: Human description injected into the generation prompt.
        json_fields: The JSON field names the loader's ``_content_*`` builder reads for
            this ``file_type`` (the shape the model must emit under a ``fields`` object).
        list_fields: Which ``json_fields`` are lists (used for the min-items gate).
        min_content_chars: Minimum derived ``Content`` length to pass the quality gate.
        min_list_items: Minimum items required across the section's list fields combined.
        example: A worked example shard (for a DIFFERENT actor) to steer structure/depth.
    """

    file_type: str
    description: str
    json_fields: tuple[str, ...]
    list_fields: tuple[str, ...]
    min_content_chars: int
    min_list_items: int
    example: dict[str, object] = field(default_factory=dict)


# The 12 canonical sections, in a stable order. Field names MUST match what the loader's
# content.py per-file_type builders read so derive_content/derive_metadata produce
# corpus-consistent Content + metadata for the generated shards.
SECTION_SPECS: tuple[SectionSpec, ...] = (
    SectionSpec(
        file_type="core_identity",
        description=(
            "Core identity: aliases, threat category, primary target sectors, and target "
            "regions for the actor."
        ),
        json_fields=("aliases", "category", "target_sectors", "target_regions"),
        list_fields=("aliases", "category", "target_sectors", "target_regions"),
        min_content_chars=120,
        min_list_items=6,
        example={
            "aliases": ["Scattered Spider", "Octo Tempest", "Muddled Libra"],
            "category": ["Identity-focused cybercrime", "Social engineering"],
            "target_sectors": ["Telecommunications", "Technology", "Financial services"],
            "target_regions": ["North America", "Europe"],
        },
    ),
    SectionSpec(
        file_type="core_description",
        description=(
            "Narrative description of who the actor is, their strategic objectives, and "
            "operating characteristics."
        ),
        json_fields=("description", "strategic_objectives", "operating_characteristics"),
        list_fields=("description", "strategic_objectives"),
        min_content_chars=300,
        min_list_items=2,
        example={
            "description": [
                "A financially motivated group known for aggressive help-desk social "
                "engineering and SIM-swap-driven account takeover."
            ],
            "strategic_objectives": ["Financial theft", "Data extortion"],
            "operating_characteristics": {"sophistication": "high", "opsec": "moderate"},
        },
    ),
    SectionSpec(
        file_type="summary",
        description="A concise analyst summary of the actor.",
        json_fields=("summary",),
        list_fields=("summary",),
        min_content_chars=200,
        min_list_items=1,
        example={
            "summary": [
                "0ktapus is an identity-centric cybercrime cluster that phishes SaaS and "
                "IdP credentials at scale, then abuses valid accounts for downstream fraud."
            ]
        },
    ),
    SectionSpec(
        file_type="tactics_ttp",
        description="Common tactics and common initial-access techniques.",
        json_fields=("common_tactics", "common_initial_access"),
        list_fields=("common_tactics", "common_initial_access"),
        min_content_chars=200,
        min_list_items=6,
        example={
            "common_tactics": [
                "Phishing for credentials",
                "MFA fatigue / push bombing",
                "Valid account abuse",
            ],
            "common_initial_access": ["Smishing", "Help-desk social engineering"],
        },
    ),
    SectionSpec(
        file_type="tactics_mitre",
        description="MITRE ATT&CK tactics and techniques (with technique IDs).",
        json_fields=("mitre_tactics", "mitre_techniques"),
        list_fields=("mitre_tactics", "mitre_techniques"),
        min_content_chars=150,
        min_list_items=5,
        example={
            "mitre_tactics": ["Initial Access", "Credential Access", "Persistence"],
            "mitre_techniques": [
                {"id": "T1566", "name": "Phishing"},
                {"id": "T1078", "name": "Valid Accounts"},
                {"id": "T1621", "name": "Multi-Factor Authentication Request Generation"},
            ],
        },
    ),
    SectionSpec(
        file_type="detection",
        description="Concrete detection opportunities for defenders.",
        json_fields=("detection_opportunities",),
        list_fields=("detection_opportunities",),
        min_content_chars=200,
        min_list_items=4,
        example={
            "detection_opportunities": [
                "Alert on impossible-travel and new-device sign-ins to IdP",
                "Monitor for bulk MFA push denials followed by an approval",
                "Detect help-desk-initiated MFA resets outside change windows",
                "Flag OAuth grants to unverified third-party apps",
            ]
        },
    ),
    SectionSpec(
        file_type="response",
        description="Incident-response investigation questions and containment steps.",
        json_fields=("investigation_questions", "containment"),
        list_fields=("investigation_questions", "containment"),
        min_content_chars=200,
        min_list_items=6,
        example={
            "investigation_questions": [
                "Which identity was compromised first, and how?",
                "Were any MFA methods or recovery settings changed?",
            ],
            "containment": [
                "Invalidate active sessions and refresh tokens",
                "Reset credentials and re-enroll MFA for affected identities",
                "Revoke suspicious OAuth grants",
            ],
        },
    ),
    SectionSpec(
        file_type="purple_team",
        description="Purple-team exercises and their difficulty.",
        json_fields=("purple_team", "difficulty"),
        list_fields=("purple_team", "difficulty"),
        min_content_chars=150,
        min_list_items=3,
        example={
            "purple_team": [
                "Simulate MFA-fatigue push bombing against a test identity",
                "Exercise help-desk social-engineering call handling",
            ],
            "difficulty": ["intermediate"],
        },
    ),
    SectionSpec(
        file_type="tabletop",
        description="Tabletop use cases and simulator injects.",
        json_fields=("tabletop_use_cases", "simulator_injects"),
        list_fields=("tabletop_use_cases", "simulator_injects"),
        min_content_chars=200,
        min_list_items=4,
        example={
            "tabletop_use_cases": [
                "Executive account takeover via help-desk impersonation",
                "SaaS admin compromise leading to data exfiltration",
            ],
            "simulator_injects": [
                "SOC observes an MFA reset from an unusual location",
                "A finance user reports an unexpected SSO prompt",
            ],
        },
    ),
    SectionSpec(
        file_type="ai_tooling",
        description=(
            "AI/automation tooling, observed behaviors, AI-enabled tactics, and "
            "AI-confirmed/suspected flags."
        ),
        json_fields=("tooling", "behaviors", "ai_tactics", "ai_confirmed", "ai_suspected"),
        list_fields=("tooling", "behaviors", "ai_tactics"),
        min_content_chars=200,
        min_list_items=4,
        example={
            "tooling": ["Phishing kits", "Credential-harvesting proxies"],
            "behaviors": ["Rapid iteration of phishing lures", "Targets IdP/SaaS logins"],
            "ai_tactics": ["LLM-generated phishing lures", "Automated OSINT on targets"],
            "ai_confirmed": False,
            "ai_suspected": True,
        },
    ),
    SectionSpec(
        file_type="cloud_general",
        description=(
            "General cloud relevance: how much cloud matters, why, and SaaS targets."
        ),
        json_fields=("cloud_relevance", "cloud_why", "saas_targets"),
        list_fields=("cloud_why", "saas_targets"),
        min_content_chars=200,
        min_list_items=3,
        example={
            "cloud_relevance": ["critical"],
            "cloud_why": [
                "The actor targets IdP and SaaS trust relationships directly",
                "Stolen sessions survive password resets",
            ],
            "saas_targets": ["Okta", "Microsoft 365", "Google Workspace"],
        },
    ),
    SectionSpec(
        file_type="cloud_aws",
        description="AWS-specific relevance, attack paths, and targeted AWS services.",
        json_fields=("aws_relevance", "aws_paths", "aws_targets"),
        list_fields=("aws_paths", "aws_targets"),
        min_content_chars=180,
        min_list_items=3,
        example={
            "aws_relevance": ["high"],
            "aws_paths": [
                "Federated SSO into the AWS console via a compromised IdP identity",
                "AssumeRole abuse using stolen session material",
            ],
            "aws_targets": ["IAM Identity Center", "STS", "S3"],
        },
    ),
)

# Convenience: the canonical file_type list, and a by-file_type lookup.
SECTION_FILE_TYPES: tuple[str, ...] = tuple(spec.file_type for spec in SECTION_SPECS)
SECTIONS_BY_TYPE: dict[str, SectionSpec] = {spec.file_type: spec for spec in SECTION_SPECS}


def all_section_file_types() -> tuple[str, ...]:
    """Return the 12 canonical section file_types (== the loader's builder keys)."""
    return SECTION_FILE_TYPES

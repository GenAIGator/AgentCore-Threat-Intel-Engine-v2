"""Deterministic ``Content`` and metadata derivation from v1 threat-profile shards.

The v1 corpus stores each threat actor as a set of JSON *shards*, one per
``file_type`` (``summary``, ``detection``, ``ai_tooling``, ...). v2 loads one DynamoDB
item per shard, embedding a single ``Content`` string and promoting a fixed set of
metadata attributes to first-class columns. This module owns that transformation
(Requirements 6.1, 6.4, 7.1, 7.2, 7.3):

* :func:`derive_content` builds the deterministic text that gets embedded. It dispatches
  on the shard's ``file_type`` to a per-type builder that concatenates that type's
  meaningful fields behind a stable ``"{Name} ({file_type}):"`` prefix. Unknown or
  unmapped types fall back to :func:`_content_default`, which flattens the shard's
  remaining string/list fields. Determinism matters: the same shard must always yield
  byte-identical ``Content`` so re-runs of the loader produce identical embeddings and
  the load stays idempotent (Requirement 1.6).

* :func:`derive_metadata` promotes the metadata attributes declared in the data model
  (Requirement 6.1): ``Name``, ``Aliases``, ``Country``, ``Region``, ``Category``,
  ``FileType``, ``CloudRelevance``, ``AiConfirmed`` — plus the item keys ``ProfileId``
  (``id``) and ``ShardId`` (``file_type``). Absent fields are **omitted** rather than
  stored as empty values (Requirement 6.4).

Text is used exactly as it appears in the source, including the mid-word truncation left
over from v1's S3 Vectors metadata cap (Requirement 7.2); no cleanup or re-truncation is
applied. Provenance attributes (``Source``, ``LastUpdated``, ...) and the ``RawJson``
attribute are the loader's responsibility (task 5), not this module's.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Fields present on every shard that are handled explicitly (as keys, prefix, or
# promoted metadata) and therefore must never be swept into the DEFAULT content flatten.
_STRUCTURAL_FIELDS = frozenset({"id", "name", "attribution", "file_type"})


def _as_str_list(value: Any) -> list[str]:
    """Coerce a shard field into a list of non-empty, stripped strings.

    Accepts a single string or a list of strings (the two shapes v1 uses for text
    fields). Non-string entries are stringified; ``None`` and blank entries are dropped
    so they never contribute empty fragments to ``Content``.
    """
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in items:
        if item is None:
            continue
        text = item if isinstance(item, str) else str(item)
        text = text.strip()
        if text:
            result.append(text)
    return result


def _join(parts: list[str]) -> str:
    """Join non-empty content fragments with a stable separator."""
    return " ".join(part for part in parts if part)


# --- Per-file_type content builders ------------------------------------------------
#
# Each builder receives the raw shard dict and returns the body text (without the
# "{Name} (file_type):" prefix, which derive_content prepends). Builders read only the
# fields meaningful to their type, in a fixed order, so output is deterministic.


def _content_summary(shard: dict[str, Any]) -> str:
    return _join(_as_str_list(shard.get("summary")))


def _content_core_description(shard: dict[str, Any]) -> str:
    parts = _as_str_list(shard.get("description"))
    objectives = _as_str_list(shard.get("strategic_objectives"))
    if objectives:
        parts.append("Strategic objectives: " + "; ".join(objectives) + ".")
    characteristics = shard.get("operating_characteristics")
    if isinstance(characteristics, dict):
        pairs = [
            f"{key}: {str(val).strip()}"
            for key, val in characteristics.items()
            if val is not None and str(val).strip()
        ]
        if pairs:
            parts.append("Operating characteristics: " + "; ".join(pairs) + ".")
    return _join(parts)


def _content_core_identity(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    aliases = _as_str_list(shard.get("aliases"))
    if aliases:
        parts.append("Aliases: " + ", ".join(aliases) + ".")
    category = _as_str_list(shard.get("category"))
    if category:
        parts.append("Category: " + ", ".join(category) + ".")
    sectors = _as_str_list(shard.get("target_sectors"))
    if sectors:
        parts.append("Target sectors: " + ", ".join(sectors) + ".")
    regions = _as_str_list(shard.get("target_regions"))
    if regions:
        parts.append("Target regions: " + ", ".join(regions) + ".")
    return _join(parts)


def _content_tactics_ttp(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    tactics = _as_str_list(shard.get("common_tactics"))
    if tactics:
        parts.append("Common tactics: " + "; ".join(tactics) + ".")
    access = _as_str_list(shard.get("common_initial_access"))
    if access:
        parts.append("Common initial access: " + "; ".join(access) + ".")
    return _join(parts)


def _content_tactics_mitre(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    tactics = _as_str_list(shard.get("mitre_tactics"))
    if tactics:
        parts.append("MITRE tactics: " + ", ".join(tactics) + ".")
    techniques = shard.get("mitre_techniques")
    if isinstance(techniques, list):
        pairs: list[str] = []
        for technique in techniques:
            if not isinstance(technique, dict):
                continue
            tid = str(technique.get("id", "")).strip()
            tname = str(technique.get("name", "")).strip()
            if tid and tname:
                pairs.append(f"{tid}: {tname}")
            elif tid:
                pairs.append(tid)
            elif tname:
                pairs.append(tname)
        if pairs:
            parts.append("MITRE techniques: " + "; ".join(pairs) + ".")
    return _join(parts)


def _content_tabletop(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    use_cases = _as_str_list(shard.get("tabletop_use_cases"))
    if use_cases:
        parts.append("Tabletop use cases: " + "; ".join(use_cases) + ".")
    injects = _as_str_list(shard.get("simulator_injects"))
    if injects:
        parts.append("Simulator injects: " + "; ".join(injects) + ".")
    return _join(parts)


def _content_response(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    questions = _as_str_list(shard.get("investigation_questions"))
    if questions:
        parts.append("Investigation questions: " + "; ".join(questions) + ".")
    containment = _as_str_list(shard.get("containment"))
    if containment:
        parts.append("Containment: " + "; ".join(containment) + ".")
    return _join(parts)


def _content_purple_team(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    exercises = _as_str_list(shard.get("purple_team"))
    if exercises:
        parts.append("Purple team exercises: " + "; ".join(exercises) + ".")
    difficulty = _as_str_list(shard.get("difficulty"))
    if difficulty:
        parts.append("Difficulty: " + ", ".join(difficulty) + ".")
    return _join(parts)


def _content_detection(shard: dict[str, Any]) -> str:
    opportunities = _as_str_list(shard.get("detection_opportunities"))
    if opportunities:
        return "Detection opportunities: " + "; ".join(opportunities) + "."
    return ""


def _content_ai_tooling(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    tooling = _as_str_list(shard.get("tooling"))
    if tooling:
        parts.append("Tooling: " + ", ".join(tooling) + ".")
    behaviors = _as_str_list(shard.get("behaviors"))
    if behaviors:
        parts.append("Behaviors: " + "; ".join(behaviors) + ".")
    ai_tactics = _as_str_list(shard.get("ai_tactics"))
    if ai_tactics:
        parts.append("AI tactics: " + "; ".join(ai_tactics) + ".")
    if isinstance(shard.get("ai_confirmed"), bool):
        parts.append(f"AI confirmed: {str(shard['ai_confirmed']).lower()}.")
    if isinstance(shard.get("ai_suspected"), bool):
        parts.append(f"AI suspected: {str(shard['ai_suspected']).lower()}.")
    return _join(parts)


def _content_cloud_general(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    relevance = _as_str_list(shard.get("cloud_relevance"))
    if relevance:
        parts.append("Cloud relevance: " + ", ".join(relevance) + ".")
    why = _as_str_list(shard.get("cloud_why"))
    if why:
        parts.append("Why cloud matters: " + "; ".join(why) + ".")
    saas = _as_str_list(shard.get("saas_targets"))
    if saas:
        parts.append("SaaS targets: " + ", ".join(saas) + ".")
    return _join(parts)


def _content_cloud_aws(shard: dict[str, Any]) -> str:
    parts: list[str] = []
    relevance = _as_str_list(shard.get("aws_relevance"))
    if relevance:
        parts.append("AWS relevance: " + ", ".join(relevance) + ".")
    paths = _as_str_list(shard.get("aws_paths"))
    if paths:
        parts.append("AWS attack paths: " + "; ".join(paths) + ".")
    targets = _as_str_list(shard.get("aws_targets"))
    if targets:
        parts.append("AWS targets: " + ", ".join(targets) + ".")
    return _join(parts)


def _content_default(shard: dict[str, Any]) -> str:
    """Flatten a shard's remaining string/list fields for unmapped ``file_type``\\ s.

    Iterates the shard's own key order (insertion order is preserved by ``dict``), so
    output is deterministic for a given source file. Structural fields (``id``,
    ``name``, ``attribution``, ``file_type``) are skipped because they are handled by
    the prefix / metadata. String and list-of-string fields are rendered as
    ``"<field>: <values>."``; other shapes are ignored.
    """
    parts: list[str] = []
    for key, value in shard.items():
        if key in _STRUCTURAL_FIELDS:
            continue
        values = _as_str_list(value)
        if values:
            label = key.replace("_", " ")
            parts.append(f"{label}: " + "; ".join(values) + ".")
    return _join(parts)


# Dispatch table keyed on the shard's ``file_type`` value.
CONTENT_BUILDERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "summary": _content_summary,
    "core_description": _content_core_description,
    "core_identity": _content_core_identity,
    "tactics_ttp": _content_tactics_ttp,
    "tactics_mitre": _content_tactics_mitre,
    "tabletop": _content_tabletop,
    "response": _content_response,
    "purple_team": _content_purple_team,
    "detection": _content_detection,
    "ai_tooling": _content_ai_tooling,
    "cloud_general": _content_cloud_general,
    "cloud_aws": _content_cloud_aws,
}


def _name(shard: dict[str, Any]) -> str:
    """Display name for the actor, falling back to ``id`` then a placeholder."""
    name = _as_str_list(shard.get("name"))
    if name:
        return name[0]
    profile_id = _as_str_list(shard.get("id"))
    if profile_id:
        return profile_id[0]
    return "Unknown"


def derive_content(shard: dict[str, Any]) -> str:
    """Build the deterministic ``Content`` string embedded for a shard.

    The result is ``"{Name} ({file_type}): {body}"``, where ``body`` is produced by the
    per-``file_type`` builder in :data:`CONTENT_BUILDERS`, or by :func:`_content_default`
    when the ``file_type`` is unmapped or missing. Field selection and ordering are
    fixed per type, so the same shard always yields identical text — a prerequisite for
    idempotent loads and stable embeddings (Requirements 7.1, 1.6). Source text is used
    verbatim, including any v1 mid-word truncation (Requirement 7.2).

    Args:
        shard: The parsed shard JSON (``id``, ``name``, ``attribution``, ``file_type``
            plus the type-specific fields).

    Returns:
        The prefixed ``Content`` string. If a shard carries no meaningful body fields,
        only the ``"{Name} ({file_type}):"`` prefix is returned (trailing space
        stripped).
    """
    file_type = ""
    raw_file_type = shard.get("file_type")
    if isinstance(raw_file_type, str):
        file_type = raw_file_type.strip()

    builder = CONTENT_BUILDERS.get(file_type, _content_default)
    body = builder(shard)

    prefix = f"{_name(shard)} ({file_type}):" if file_type else f"{_name(shard)}:"
    return f"{prefix} {body}".rstrip() if body else prefix


def _attribution(shard: dict[str, Any]) -> dict[str, Any]:
    """Return the ``attribution`` sub-object as a dict (empty if absent/malformed)."""
    attribution = shard.get("attribution")
    return attribution if isinstance(attribution, dict) else {}


def derive_metadata(shard: dict[str, Any]) -> dict[str, Any]:
    """Promote a shard's metadata to the first-class DynamoDB attributes.

    Populates the attributes from the data model (Requirement 6.1) using native Python
    types, deferring DynamoDB ``AttributeValue`` serialization to the loader (task 5):

    * ``ProfileId`` — the actor ``id`` (partition key).
    * ``ShardId`` — the shard ``file_type`` (sort key).
    * ``Name`` — actor display name.
    * ``Aliases`` — ``list[str]`` from ``core_identity.aliases`` (string set at write).
    * ``Country`` / ``Region`` — from ``attribution``.
    * ``Category`` — ``list[str]`` from ``core_identity.category``.
    * ``FileType`` — mirrors ``ShardId`` (declared for the vector index inline filter).
    * ``CloudRelevance`` — from ``cloud_general.cloud_relevance`` when present.
    * ``AiConfirmed`` — bool from ``ai_tooling.ai_confirmed`` when present.

    Any field absent (or empty) in the source shard is **omitted** from the returned
    mapping rather than stored as an empty value (Requirement 6.4). Because shards are
    per-``file_type``, most calls populate only a subset (e.g. ``Aliases``/``Category``
    only appear on ``core_identity`` shards); this is expected — each item carries the
    metadata its own shard provides.

    Args:
        shard: The parsed shard JSON.

    Returns:
        A mapping of attribute name to value, containing only present fields.
    """
    metadata: dict[str, Any] = {}

    profile_id = _as_str_list(shard.get("id"))
    if profile_id:
        metadata["ProfileId"] = profile_id[0]

    file_type = _as_str_list(shard.get("file_type"))
    if file_type:
        metadata["ShardId"] = file_type[0]
        metadata["FileType"] = file_type[0]

    name = _as_str_list(shard.get("name"))
    if name:
        metadata["Name"] = name[0]

    aliases = _as_str_list(shard.get("aliases"))
    if aliases:
        metadata["Aliases"] = aliases

    attribution = _attribution(shard)
    country = _as_str_list(attribution.get("country"))
    if country:
        metadata["Country"] = country[0]
    region = _as_str_list(attribution.get("region"))
    if region:
        metadata["Region"] = region[0]

    category = _as_str_list(shard.get("category"))
    if category:
        metadata["Category"] = category

    cloud_relevance = _as_str_list(shard.get("cloud_relevance"))
    if cloud_relevance:
        metadata["CloudRelevance"] = cloud_relevance[0]

    if isinstance(shard.get("ai_confirmed"), bool):
        metadata["AiConfirmed"] = shard["ai_confirmed"]

    return metadata

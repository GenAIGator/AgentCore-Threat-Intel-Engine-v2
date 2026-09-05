"""Generate one profile section's JSON fields via a web-researching Strands agent.

For a given actor + section, the builder runs a Strands agent (with the managed
web-search MCP tool, when the gateway is configured) and asks it to return ONLY a JSON
object of the section's fields, matching the worked example's shape. The agent is
instructed to research current, real reporting before answering.

The prompt assembly and the tolerant JSON extraction are pure and unit-testable
(:func:`build_section_prompt`, :func:`extract_json_fields`); the actual model call
(:func:`generate_section_fields`) is isolated so tests exercise the pure parts without a
model or gateway.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from sections import SectionSpec

logger = logging.getLogger("builder.section_generator")

# Matches the first ```json ... ``` fenced block, or a bare {...} object, in model output.
_FENCED_JSON = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def build_section_prompt(
    profile_name: str,
    intent: str,
    attribution: dict[str, Any] | None,
    spec: SectionSpec,
) -> str:
    """Build the generation prompt for one section.

    Instructs the model to research the actor and return ONLY a JSON object with the
    section's fields, using the worked example as a shape/depth guide and meeting the
    minimum-item expectations. The prompt is deterministic given its inputs.
    """
    attribution = attribution or {}
    attribution_line = ""
    if attribution:
        parts = [f"{k}: {v}" for k, v in attribution.items() if v]
        if parts:
            attribution_line = f"Known attribution — {', '.join(parts)}.\n"

    example_json = json.dumps(spec.example, indent=2)
    fields_list = ", ".join(spec.json_fields)

    return (
        f"You are building the '{spec.file_type}' section of a threat-intelligence "
        f"profile for the threat actor '{profile_name}'.\n"
        f"Actor context: {intent}\n"
        f"{attribution_line}"
        f"\nSection purpose: {spec.description}\n"
        f"\nFIRST research the actor using the web search tool to gather current, real, "
        f"verifiable information. Base the section on that reporting; do not invent "
        f"actors, aliases, MITRE technique IDs, or campaigns that are not supported.\n"
        f"\nReturn ONLY a single JSON object (no prose, no markdown outside the JSON) "
        f"containing exactly these fields: {fields_list}. Match the structure and depth "
        f"of this example (for a DIFFERENT actor — do not copy its content):\n"
        f"```json\n{example_json}\n```\n"
        f"\nMake it thorough and specific to '{profile_name}': provide at least "
        f"{spec.min_list_items} concrete list items across the list fields, and enough "
        f"detail to be genuinely useful to an analyst. Output the JSON object only."
    )


def extract_json_fields(text: str) -> dict[str, Any]:
    """Tolerantly extract the JSON object of section fields from model output.

    Tries a fenced ```json block first, then a bare object. Returns ``{}`` when nothing
    parseable is found (the caller treats that as a failed generation and retries).
    """
    if not text:
        return {}
    for pattern in (_FENCED_JSON, _BARE_OBJECT):
        match = pattern.search(text)
        if not match:
            continue
        candidate = match.group(1) if pattern is _FENCED_JSON else match.group(0)
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def generate_section_fields(
    agent: Any,
    profile_name: str,
    intent: str,
    attribution: dict[str, Any] | None,
    spec: SectionSpec,
) -> dict[str, Any]:
    """Run the agent to generate one section's fields and parse the JSON out.

    Args:
        agent: A callable Strands ``Agent`` (invoked as ``agent(prompt)``) whose response
            has a ``.message`` / string form containing the JSON.
        profile_name, intent, attribution, spec: Section inputs.

    Returns:
        The parsed fields dict (possibly empty if the model returned nothing parseable —
        the orchestrator retries/fails on that).
    """
    prompt = build_section_prompt(profile_name, intent, attribution, spec)
    result = agent(prompt)
    text = _result_to_text(result)
    return extract_json_fields(text)


def _result_to_text(result: Any) -> str:
    """Best-effort extraction of the text body from a Strands agent result."""
    if isinstance(result, str):
        return result
    # Strands AgentResult commonly stringifies to the assistant text.
    try:
        return str(result)
    except Exception:  # pragma: no cover - defensive
        return ""

"""Pure quality-gate logic for generated profile sections.

The builder generates each of the 12 sections, then this module decides whether a section
is deep enough to keep (on par with the seed corpus) or must be regenerated. There is NO
second human review (see ``docs/CREATE_PROFILE_DESIGN.md``), so this gate is what enforces
quality — it must be strict.

A section passes when BOTH hold:

* the derived ``Content`` (the text that will be embedded) is at least
  ``spec.min_content_chars`` long, AND
* the combined number of items across the section's ``list_fields`` is at least
  ``spec.min_list_items``.

Everything here is pure (no AWS, no model calls). :func:`evaluate_section` takes the
generated ``fields`` dict plus a ``content_deriver`` callable — the builder passes the
loader's ``derive_content`` so the measured length matches exactly what gets embedded —
which keeps this module unit-testable with a trivial fake deriver.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sections import SectionSpec


@dataclass(frozen=True)
class SectionVerdict:
    """Result of grading one generated section.

    Attributes:
        file_type: The section graded.
        passed: Whether it met both the length and list-item minimums.
        content_chars: The derived ``Content`` length measured.
        list_items: The combined list-item count across the section's list fields.
        reasons: Human-readable failure reasons (empty when passed).
    """

    file_type: str
    passed: bool
    content_chars: int
    list_items: int
    reasons: tuple[str, ...] = ()


def count_list_items(fields: dict[str, Any], spec: SectionSpec) -> int:
    """Count the combined items across a section's declared list fields.

    Non-list values are ignored (a field the model emitted as a scalar contributes 0);
    ``mitre_techniques``-style lists of dicts count by element. Blank string entries are
    not counted so padding with empty strings can't game the gate.
    """
    total = 0
    for name in spec.list_fields:
        value = fields.get(name)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    if item.strip():
                        total += 1
                elif item is not None:
                    total += 1
    return total


def evaluate_section(
    file_type: str,
    fields: dict[str, Any],
    spec: SectionSpec,
    content_deriver: Callable[[dict[str, Any]], str],
    *,
    profile_name: str = "Actor",
) -> SectionVerdict:
    """Grade one generated section against its spec's minimums.

    Args:
        file_type: The section's ``file_type``.
        fields: The model-generated JSON fields for the section (the ``fields`` object).
        spec: The :class:`SectionSpec` carrying the minimums.
        content_deriver: A callable turning a shard dict into its embedded ``Content``
            string (the builder passes the loader's ``derive_content``). Called with a
            shard assembled as ``{"name", "file_type", **fields}``.
        profile_name: Actor display name, used to assemble the shard for the deriver.

    Returns:
        A :class:`SectionVerdict`.
    """
    shard: dict[str, Any] = {"name": profile_name, "file_type": file_type, **fields}
    content = content_deriver(shard)
    content_chars = len(content.strip())
    list_items = count_list_items(fields, spec)

    reasons: list[str] = []
    if content_chars < spec.min_content_chars:
        reasons.append(
            f"content too short ({content_chars} < {spec.min_content_chars} chars)"
        )
    if list_items < spec.min_list_items:
        reasons.append(
            f"too few list items ({list_items} < {spec.min_list_items})"
        )

    return SectionVerdict(
        file_type=file_type,
        passed=not reasons,
        content_chars=content_chars,
        list_items=list_items,
        reasons=tuple(reasons),
    )

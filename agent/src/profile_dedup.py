"""Variation-aware duplicate detection for new threat-actor profiles.

Both the main agent's ``create_profile`` HITL tool and the autonomous builder runtime
call this BEFORE running any research, so a profile that already exists — even under a
slightly different name variation ("0ktapus" vs "Oktapus" vs "0ktapus group", "ALPHV" vs
"ALPHV/BlackCat") — never triggers the expensive 12-section build (see
``docs/CREATE_PROFILE_DESIGN.md``).

Detection is two-tier; either tier tripping means "treat as duplicate":

1. **Normalized exact-ish match** (:func:`normalize`, :func:`is_normalized_duplicate`).
   Lowercase, strip punctuation/whitespace, drop common actor-name filler tokens
   ("group", "apt", "team", "gang", ...), and compare the proposed id/name/aliases
   against the normalized id/name/aliases of every existing profile.

2. **Semantic similarity** (:func:`is_semantic_duplicate`). Embed the proposed name +
   short intent and run the DynamoDB vector ``SearchVectors``; if the nearest existing
   shard's COSINE distance is at/below a tight duplicate threshold (tighter than the
   retrieval relevance threshold), it is a likely near-duplicate.

The pure logic (normalization + the two decision predicates operating on already-fetched
data) is separated from the AWS-touching collectors (:func:`fetch_existing_identities`,
:func:`semantic_nearest`) so it can be unit-tested with no AWS access. :func:`check_duplicate`
composes them into a single :class:`DuplicateVerdict`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from config import DDB_TABLE_NAME, DDB_VECTOR_INDEX

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_dynamodb import DynamoDBClient

# COSINE distance at/below which the nearest existing profile is considered the "same"
# actor for creation purposes. Tighter (smaller) than retrieval_tools'
# DEFAULT_RELEVANCE_THRESHOLD (0.6): retrieval wants "topically relevant", dedup wants
# "essentially the same actor", so the bar is much stricter.
DEFAULT_DUPLICATE_DISTANCE = 0.18

# Filler tokens stripped during name normalization so "X Group"/"X APT"/"X gang" all
# collapse to "x". Kept conservative: only generic actor-descriptor words, never tokens
# that could distinguish two real actors.
_FILLER_TOKENS = frozenset(
    {
        "group",
        "groups",
        "apt",
        "team",
        "gang",
        "crew",
        "collective",
        "actor",
        "actors",
        "threat",
        "the",
    }
)

# Characters that separate or decorate names; all become spaces before tokenizing so
# "ALPHV/BlackCat", "ALPHV-BlackCat" and "ALPHV BlackCat" normalize identically.
_SEPARATORS = re.compile(r"[^a-z0-9]+")


def normalize(value: str | None) -> str:
    """Normalize an actor id/name/alias to a comparable canonical form.

    Lowercases, replaces every run of non-alphanumeric characters with a single space,
    drops generic filler tokens (:data:`_FILLER_TOKENS`), and rejoins the remaining
    tokens with no separator. Digits are preserved (they are meaningful in names like
    ``0ktapus``/``apt29``). Empty/``None`` input yields ``""``.

    Examples::

        "0ktapus"           -> "0ktapus"
        "0ktapus Group"     -> "0ktapus"
        "ALPHV/BlackCat"    -> "alphvblackcat"
        "APT 29"            -> "29"        (filler "apt" dropped; keep the number)

    Note the ``APT 29`` case: because "apt" is filler, ``apt29`` and ``29`` both reduce to
    ``29`` — intentional, so "APT29" and "29" match, but be aware ids should still be
    compared alongside names/aliases (below) rather than relying on one field.
    """
    if not value:
        return ""
    lowered = value.strip().lower()
    spaced = _SEPARATORS.sub(" ", lowered)
    tokens = [t for t in spaced.split() if t and t not in _FILLER_TOKENS]
    return "".join(tokens)


def normalized_set(*values: Any) -> set[str]:
    """Return the set of non-empty normalized forms of ``values``.

    Each value may be a string or a list/tuple/set of strings (aliases). Blank results
    are dropped so an all-filler string never contributes an empty match key.
    """
    out: set[str] = set()
    for value in values:
        items: list[Any]
        if isinstance(value, (list, tuple, set)):
            items = list(value)
        else:
            items = [value]
        for item in items:
            if isinstance(item, str):
                norm = normalize(item)
                if norm:
                    out.add(norm)
    return out


@dataclass(frozen=True)
class ProfileIdentity:
    """The identity fields of one existing profile, used for normalized matching."""

    profile_id: str
    name: str | None = None
    aliases: tuple[str, ...] = ()

    def match_keys(self) -> set[str]:
        """All normalized keys this profile can be matched on (id + name + aliases)."""
        return normalized_set(self.profile_id, self.name, list(self.aliases))


@dataclass
class DuplicateVerdict:
    """Outcome of a duplicate check.

    Attributes:
        is_duplicate: True if either tier flagged an existing profile.
        reason: Which tier tripped (``"normalized"``, ``"semantic"``) or ``""``.
        existing_profile_id: The matched existing ``ProfileId``, when known.
        existing_name: The matched existing display name, when known.
        distance: The semantic COSINE distance of the nearest match, when computed.
        detail: A human-readable explanation for the tool to surface to the analyst.
    """

    is_duplicate: bool
    reason: str = ""
    existing_profile_id: str | None = None
    existing_name: str | None = None
    distance: float | None = None
    detail: str = ""


def is_normalized_duplicate(
    proposed_id: str,
    proposed_name: str | None,
    proposed_aliases: list[str] | None,
    existing: list[ProfileIdentity],
) -> ProfileIdentity | None:
    """Return the existing profile whose normalized keys intersect the proposal, if any.

    Pure: operates only on already-fetched identities. The proposed id, name, and aliases
    are normalized into a key set and intersected with each existing profile's key set;
    the first profile sharing any key is returned (a duplicate), else ``None``.
    """
    proposed_keys = normalized_set(proposed_id, proposed_name, proposed_aliases or [])
    if not proposed_keys:
        return None
    for identity in existing:
        if proposed_keys & identity.match_keys():
            return identity
    return None


def is_semantic_duplicate(
    nearest_distance: float | None,
    threshold: float = DEFAULT_DUPLICATE_DISTANCE,
) -> bool:
    """Whether the nearest existing shard is close enough to be the same actor.

    COSINE ``Score`` is a distance (lower = more similar), so a match at/below
    ``threshold`` is a likely duplicate. ``None`` (no neighbor / not computed) is not a
    duplicate.
    """
    return nearest_distance is not None and nearest_distance <= threshold


# --- AWS-touching collectors (thin; excluded from pure unit tests) --------------------


def fetch_existing_identities(client: DynamoDBClient | None = None) -> list[ProfileIdentity]:
    """Scan the table for the identity fields of every existing profile.

    Projects only ``ProfileId``/``Name``/``Aliases`` and dedupes by ``ProfileId`` (a
    profile has ~12 shard items but one identity). Aliases are stored as a DynamoDB string
    set (``SS``); ``Name`` as ``S``. Boto3 is imported lazily so importing this module
    never requires AWS.

    Args:
        client: Optional low-level DynamoDB client (injected for tests). A real client is
            created when omitted.

    Returns:
        One :class:`ProfileIdentity` per distinct ``ProfileId`` found.
    """
    if client is None:  # pragma: no cover - exercised only with AWS creds
        from ddb import dynamodb_client

        client = dynamodb_client()

    identities: dict[str, ProfileIdentity] = {}
    kwargs: dict[str, Any] = {
        "TableName": DDB_TABLE_NAME,
        "ProjectionExpression": "#pid, #nm, #al",
        "ExpressionAttributeNames": {"#pid": "ProfileId", "#nm": "Name", "#al": "Aliases"},
    }
    while True:
        response = client.scan(**kwargs)
        for item in response.get("Items", []):
            pid_attr = item.get("ProfileId", {})
            profile_id = pid_attr.get("S") if isinstance(pid_attr, dict) else None
            if not profile_id or profile_id in identities:
                continue
            name_attr = item.get("Name", {})
            name = name_attr.get("S") if isinstance(name_attr, dict) else None
            alias_attr = item.get("Aliases", {})
            aliases: tuple[str, ...] = ()
            if isinstance(alias_attr, dict):
                if "SS" in alias_attr:
                    aliases = tuple(alias_attr["SS"])
                elif "L" in alias_attr:
                    aliases = tuple(
                        e.get("S", "") for e in alias_attr["L"] if isinstance(e, dict)
                    )
            identities[profile_id] = ProfileIdentity(
                profile_id=profile_id, name=name, aliases=aliases
            )
        token = response.get("LastEvaluatedKey")
        if not token:
            break
        kwargs["ExclusiveStartKey"] = token
    return list(identities.values())


def semantic_nearest(query_text: str) -> tuple[float | None, str | None, str | None]:
    """Return ``(distance, profile_id, name)`` of the nearest existing shard to ``query_text``.

    Embeds ``query_text`` (Titan v2) and runs a top-1 ``SearchVectors`` over the vector
    index, reusing the same embed + request/response helpers as ``retrieve_profiles``.
    Returns ``(None, None, None)`` when there are no results. AWS clients are created lazily
    by the imported helpers.
    """
    from ddb import dynamodb_client, from_search_results, to_vector_attr
    from embeddings import embed_text

    request: dict[str, Any] = {
        "TableName": DDB_TABLE_NAME,
        "IndexName": DDB_VECTOR_INDEX,
        "SearchVector": to_vector_attr(embed_text(query_text)),
        "TopK": 1,
        "ProjectionExpression": "#pid, #nm",
        "ExpressionAttributeNames": {"#pid": "ProfileId", "#nm": "Name"},
    }
    response: dict[str, Any] = dict(dynamodb_client().search_vectors(**request))
    results = from_search_results(response)
    if not results:
        return None, None, None
    top = results[0]
    score = top.get("Score")
    distance = float(score) if isinstance(score, (int, float)) else None
    return distance, top.get("ProfileId"), top.get("Name")


def check_duplicate(
    proposed_id: str,
    proposed_name: str | None = None,
    proposed_aliases: list[str] | None = None,
    intent: str | None = None,
    *,
    existing: list[ProfileIdentity] | None = None,
    nearest: tuple[float | None, str | None, str | None] | None = None,
    duplicate_distance: float = DEFAULT_DUPLICATE_DISTANCE,
) -> DuplicateVerdict:
    """Run both dedup tiers and return a single verdict.

    Tier 1 (normalized) is checked first because it is exact and cheap. Tier 2 (semantic)
    only runs if tier 1 found nothing. AWS collectors are called only when ``existing`` /
    ``nearest`` are not injected, so tests can pass both and exercise the composition with
    no AWS access.

    Args:
        proposed_id: The proposed new ``ProfileId``.
        proposed_name: The proposed display name.
        proposed_aliases: Any known aliases for the proposed actor.
        intent: A short free-text description of the actor (used as the semantic query,
            alongside the name). Falls back to the name when omitted.
        existing: Injected existing identities (skips the scan when provided).
        nearest: Injected ``(distance, profile_id, name)`` (skips the search when provided).
        duplicate_distance: Semantic duplicate threshold.

    Returns:
        A :class:`DuplicateVerdict`. ``is_duplicate`` is True if either tier tripped.
    """
    if existing is None:
        existing = fetch_existing_identities()

    match = is_normalized_duplicate(proposed_id, proposed_name, proposed_aliases, existing)
    if match is not None:
        label = match.name or match.profile_id
        return DuplicateVerdict(
            is_duplicate=True,
            reason="normalized",
            existing_profile_id=match.profile_id,
            existing_name=match.name,
            detail=(
                f"A profile for '{label}' already exists (ProfileId='{match.profile_id}') "
                f"and matches the proposed name/aliases. Use enrich_profile to update it "
                f"instead of creating a duplicate."
            ),
        )

    # Tier 2: semantic. Query on name + intent so a renamed/aliased actor still matches.
    query_text = " ".join(p for p in [proposed_name or proposed_id, intent] if p).strip()
    if nearest is None:
        nearest = semantic_nearest(query_text)
    distance, near_id, near_name = nearest

    if is_semantic_duplicate(distance, duplicate_distance):
        label = near_name or near_id or "an existing actor"
        return DuplicateVerdict(
            is_duplicate=True,
            reason="semantic",
            existing_profile_id=near_id,
            existing_name=near_name,
            distance=distance,
            detail=(
                f"This looks very similar to an existing profile '{label}' "
                f"(ProfileId='{near_id}', similarity distance={distance:.3f}). It may be "
                f"the same actor under a different name. Confirm it is genuinely new, or "
                f"use enrich_profile to update the existing one."
            ),
        )

    return DuplicateVerdict(is_duplicate=False, distance=distance)

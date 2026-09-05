"""End-to-end integration test for the HITL enrichment cycle (task 9.5).

This test verifies the full human-in-the-loop enrichment flow at the *logic* level
against an in-memory fake DynamoDB — NO live AWS or Bedrock. It proves the real state
transitions the requirements describe by storing items in a dict and applying the
``UpdateItem`` SET expression to them, so that "the item was updated" and "the item was
unchanged" are asserted against actual stored state rather than call recording.

Coverage (Requirements 5.1–5.7, 6.2):

* APPROVE path — invoking :func:`enrich_profile` with an interrupt that returns ``"yes"``
  loads the seeded shard, fires the approval interrupt surfacing the proposal + sources
  (Req 5.1, 5.2), and on approval overwrites ``Content``, regenerates ``Embedding`` to a
  distinct new vector, and stamps provenance (``Source="web-enrichment"``, ``SourceUrl``,
  ``LastUpdated``, ``UpdatedBy``) in place (Req 5.4, 6.2). The updated content is then
  shown to be what is now retrievable via :func:`retrieve_profiles` (Req 5.4 →
  retrievability).
* REJECT path — an interrupt returning ``"no"`` leaves the stored item completely
  unchanged: no ``UpdateItem`` reached the table, ``Content`` and ``Source`` are the
  seeded values (Req 5.3, 5.5).
* ORPHANED FALLBACK approve — the ``/invocations`` resume path with no cached agent and a
  complete echoed payload reuses :func:`apply_enrichment` to write the update directly to
  the same in-memory table (Req 5.7), proving the fallback performs the same terminal
  state transition.

``embed_text`` and ``dynamodb_client`` are monkeypatched so no Bedrock/AWS call is made.

Deferred to task 14 (live integration): the vector index re-derives the new ``Embedding``
from the base-table write asynchronously (backfill/eventual-consistency lag), so proving
the *index* returns the enriched shard requires a real DynamoDB vector table and polling
for readiness. Here we simulate "new content retrievable" by pointing the retrieval
``search_vectors`` fake at the same in-memory table, which is sufficient to prove that the
content now stored is the content that comes back.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

import tools.enrich_tools as et
import tools.retrieval_tools as rt
from agentcore_app import app

# --------------------------------------------------------------------------------------
# In-memory fake DynamoDB
# --------------------------------------------------------------------------------------


class FakeDynamoTable:
    """A minimal in-memory DynamoDB stand-in keyed by ``(ProfileId, ShardId)``.

    Stores items as native ``AttributeValue`` maps (e.g. ``{"Content": {"S": "..."}}``)
    exactly as the real client would, and implements just enough of ``get_item`` and
    ``update_item`` to prove the enrichment state transitions:

    * :meth:`get_item` returns ``{"Item": {...}}`` for a stored key, or ``{}`` when the
      key is absent (matching the low-level client's "no Item key" behavior).
    * :meth:`update_item` parses the SET expression's ``ExpressionAttributeNames`` /
      ``ExpressionAttributeValues`` and overwrites exactly those attributes on the stored
      item, mutating real state so the update is observable afterwards.

    ``search_vectors`` is intentionally NOT implemented here — retrieval is faked
    separately so retrieval remains decoupled from the write path.
    """

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.update_item_calls: list[dict[str, Any]] = []
        self.get_item_calls: list[dict[str, Any]] = []

    @staticmethod
    def _key_tuple(key: dict[str, Any]) -> tuple[str, str]:
        return (key["ProfileId"]["S"], key["ShardId"]["S"])

    def seed(self, profile_id: str, shard_id: str, item: dict[str, Any]) -> None:
        """Store an item, ensuring its key attributes are present."""
        stored = dict(item)
        stored["ProfileId"] = {"S": profile_id}
        stored["ShardId"] = {"S": shard_id}
        self.items[(profile_id, shard_id)] = stored

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.get_item_calls.append(kwargs)
        stored = self.items.get(self._key_tuple(kwargs["Key"]))
        if stored is None:
            return {}
        # Return a copy so callers cannot mutate stored state via the read path.
        return {"Item": dict(stored)}

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self.update_item_calls.append(kwargs)
        key = self._key_tuple(kwargs["Key"])
        item = self.items.setdefault(key, {})

        names: dict[str, str] = kwargs.get("ExpressionAttributeNames", {})
        values: dict[str, Any] = kwargs.get("ExpressionAttributeValues", {})
        expression: str = kwargs["UpdateExpression"]

        # Parse "SET #a = :x, #b = :y" into (attribute_name, attribute_value) pairs and
        # overwrite exactly those attributes on the stored item.
        assert expression.startswith("SET ")
        for clause in expression[len("SET ") :].split(","):
            lhs, rhs = (part.strip() for part in clause.split("="))
            attr_name = names.get(lhs, lhs)
            item[attr_name] = values[rhs]
        return {}


class FakeToolContext:
    """Tool context whose ``interrupt`` returns a scripted approval and records calls."""

    def __init__(self, approval: Any, user_email: str | None = None) -> None:
        self._approval = approval
        self.user_email = user_email
        self.interrupt_calls: list[dict[str, Any]] = []

    def interrupt(self, key: str, reason: dict[str, Any]) -> Any:
        self.interrupt_calls.append({"key": key, "reason": reason})
        return self._approval


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

OLD_CONTENT = "old detection guidance"
NEW_CONTENT = "new detection guidance"
OLD_VECTOR = [0.11, 0.22, 0.33, 0.44]
NEW_VECTOR = [0.91, 0.92, 0.93, 0.94]
PROFILE_ID = "apt29"
SHARD_ID = "detection"


def _vector_attr(vector: list[float]) -> dict[str, Any]:
    """Wrap a vector as a stored ``{"L": [{"N": ...}]}`` embedding attribute."""
    return {"L": [{"N": str(component)} for component in vector]}


def _embedding_from_item(item: dict[str, Any]) -> list[float]:
    """Read a stored ``Embedding`` list attribute back into a list of floats."""
    return [float(component["N"]) for component in item["Embedding"]["L"]]


def _seed_table(table: FakeDynamoTable) -> None:
    """Seed the fake table with an existing seed-provenance detection shard."""
    table.seed(
        PROFILE_ID,
        SHARD_ID,
        {
            "Content": {"S": OLD_CONTENT},
            "Embedding": _vector_attr(OLD_VECTOR),
            "Source": {"S": "seed"},
            "Name": {"S": "APT29"},
            "FileType": {"S": SHARD_ID},
        },
    )


def _install_enrich_fakes(monkeypatch: Any, table: FakeDynamoTable) -> None:
    """Point enrich_tools at the fake table and a deterministic new-vector embedder."""
    monkeypatch.setattr(et, "dynamodb_client", lambda: table)
    # New content embeds to a DISTINCT new vector so re-embedding is observable.
    monkeypatch.setattr(et, "embed_text", lambda _text: list(NEW_VECTOR))


def _call_enrich(**kwargs: Any) -> str:
    """Invoke the @tool-wrapped enrich_profile with plain kwargs via __wrapped__."""
    func = getattr(et.enrich_profile, "__wrapped__", None)
    if callable(func):
        return func(**kwargs)  # type: ignore[no-any-return]
    return et.enrich_profile(**kwargs)  # type: ignore[no-any-return]


def _retrieve_from_table(monkeypatch: Any, table: FakeDynamoTable, query: str) -> str:
    """Run retrieve_profiles against a fake search that returns the table's shard.

    Simulates "the updated content is what's now retrievable": the fake ``search_vectors``
    reads the current stored item straight from the in-memory table and returns it as the
    single ``SearchResults`` match with a distance below the relevance threshold, so
    whatever ``Content`` is currently stored is what surfaces in the citation context.
    """
    # A query embedder for retrieval (value irrelevant; the search is faked).
    monkeypatch.setattr(rt, "embed_text", lambda _text: [0.0, 0.0, 0.0, 0.0])

    stored = table.items[(PROFILE_ID, SHARD_ID)]

    class _FakeSearchClient:
        def search_vectors(self, **_kwargs: Any) -> dict[str, Any]:
            return {
                "SearchResults": [
                    {
                        "Item": {
                            "ProfileId": stored["ProfileId"],
                            "Name": stored.get("Name", {"S": "APT29"}),
                            "FileType": stored.get("FileType", {"S": SHARD_ID}),
                            "Content": stored["Content"],
                        },
                        "Score": 0.05,  # well below DEFAULT_RELEVANCE_THRESHOLD
                    }
                ]
            }

    monkeypatch.setattr(rt, "dynamodb_client", lambda: _FakeSearchClient())

    func = getattr(rt.retrieve_profiles, "__wrapped__", None)
    if callable(func):
        return func(query)  # type: ignore[no-any-return]
    return rt.retrieve_profiles(query)  # type: ignore[no-any-return]


# --------------------------------------------------------------------------------------
# APPROVE path — interrupt fires → approve → item updated + re-embedded → retrievable
# (Requirements 5.1, 5.2, 5.4, 6.2)
# --------------------------------------------------------------------------------------


def test_approve_updates_item_reembeds_and_new_content_is_retrievable(
    monkeypatch: Any,
) -> None:
    table = FakeDynamoTable()
    _seed_table(table)
    _install_enrich_fakes(monkeypatch, table)

    ctx = FakeToolContext(approval="yes", user_email="analyst@example.com")

    # Sanity: the seeded starting state is the old content + old vector + seed source.
    before = table.items[(PROFILE_ID, SHARD_ID)]
    assert before["Content"] == {"S": OLD_CONTENT}
    assert _embedding_from_item(before) == OLD_VECTOR
    assert before["Source"] == {"S": "seed"}

    result = _call_enrich(
        tool_context=ctx,
        profile_id=PROFILE_ID,
        shard_id=SHARD_ID,
        proposed_content=NEW_CONTENT,
        sources=["https://ex.com"],
        updated_by="analyst@example.com",
    )

    # The approval interrupt fired, surfacing the proposal + sources (Req 5.1, 5.2).
    assert len(ctx.interrupt_calls) == 1
    reason = ctx.interrupt_calls[0]["reason"]
    assert reason["proposed_content"] == NEW_CONTENT
    assert reason["sources"] == ["https://ex.com"]
    assert reason["current_content"] == OLD_CONTENT

    # AFTER approval, the stored item reflects real state changes (Req 5.4, 6.2).
    after = table.items[(PROFILE_ID, SHARD_ID)]
    assert after["Content"] == {"S": NEW_CONTENT}
    # Re-embedded: the stored Embedding is the NEW distinct vector, not the old one.
    assert _embedding_from_item(after) == NEW_VECTOR
    assert _embedding_from_item(after) != OLD_VECTOR
    # Provenance stamped.
    assert after["Source"] == {"S": "web-enrichment"}
    assert after["SourceUrl"] == {"S": "https://ex.com"}
    assert after["UpdatedBy"] == {"S": "analyst@example.com"}
    assert "S" in after["LastUpdated"] and after["LastUpdated"]["S"]
    # Exactly one write reached the table.
    assert len(table.update_item_calls) == 1
    assert "Enrichment applied" in result

    # "New content retrievable": retrieval now surfaces the UPDATED content (Req 5.4).
    context = _retrieve_from_table(monkeypatch, table, "detection guidance for apt29")
    assert NEW_CONTENT in context
    assert OLD_CONTENT not in context


# --------------------------------------------------------------------------------------
# REJECT path — interrupt fires → reject → item unchanged
# (Requirements 5.3, 5.5)
# --------------------------------------------------------------------------------------


def test_reject_leaves_item_unchanged(monkeypatch: Any) -> None:
    table = FakeDynamoTable()
    _seed_table(table)
    _install_enrich_fakes(monkeypatch, table)

    ctx = FakeToolContext(approval="no", user_email="analyst@example.com")

    result = _call_enrich(
        tool_context=ctx,
        profile_id=PROFILE_ID,
        shard_id=SHARD_ID,
        proposed_content=NEW_CONTENT,
        sources=["https://ex.com"],
        updated_by="analyst@example.com",
    )

    # The approval was requested (Req 5.2) but rejected (Req 5.5).
    assert len(ctx.interrupt_calls) == 1
    assert "cancelled" in result.lower()

    # The stored item is COMPLETELY unchanged: old content, old vector, seed source.
    after = table.items[(PROFILE_ID, SHARD_ID)]
    assert after["Content"] == {"S": OLD_CONTENT}
    assert _embedding_from_item(after) == OLD_VECTOR
    assert after["Source"] == {"S": "seed"}
    assert "SourceUrl" not in after
    assert "UpdatedBy" not in after
    # No UpdateItem was applied while approval was pending / on rejection (Req 5.3, 5.5).
    assert table.update_item_calls == []

    # And retrieval still returns the ORIGINAL content — nothing was re-embedded.
    context = _retrieve_from_table(monkeypatch, table, "detection guidance for apt29")
    assert OLD_CONTENT in context
    assert NEW_CONTENT not in context


# --------------------------------------------------------------------------------------
# ORPHANED FALLBACK approve — /invocations resume with no cached agent reuses
# apply_enrichment to write the update directly to the same in-memory table (Req 5.7).
# --------------------------------------------------------------------------------------


def test_orphaned_fallback_approve_updates_item_via_apply_enrichment(
    monkeypatch: Any,
) -> None:
    table = FakeDynamoTable()
    _seed_table(table)
    # apply_enrichment (reused by the fallback) writes via enrich_tools' client +
    # embedder, so point those at the same in-memory table.
    _install_enrich_fakes(monkeypatch, table)

    session_id = "orphaned-e2e"
    # Ensure no cached agent so the orphaned-interrupt fallback path runs.
    import agentcore_app as app_mod

    app_mod._sessions.pop(session_id, None)

    client = TestClient(app)
    response = client.post(
        "/invocations",
        json={
            "session_id": session_id,
            "action": "enrich",
            "user_email": "analyst@example.com",
            "profile_id": PROFILE_ID,
            "shard_id": SHARD_ID,
            "proposed_content": NEW_CONTENT,
            "sources": ["https://ex.com"],
            "responses": [{"interrupt_id": "int-1", "response": "yes"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # The same terminal state transition was applied directly to the in-memory table.
    after = table.items[(PROFILE_ID, SHARD_ID)]
    assert after["Content"] == {"S": NEW_CONTENT}
    assert _embedding_from_item(after) == NEW_VECTOR
    assert after["Source"] == {"S": "web-enrichment"}
    assert after["SourceUrl"] == {"S": "https://ex.com"}
    assert after["UpdatedBy"] == {"S": "analyst@example.com"}
    assert len(table.update_item_calls) == 1

"""Unit tests for :mod:`tools.enrich_tools`.

These tests exercise the HITL enrichment tool without touching AWS, per task 9.1:

- ``apply_enrichment`` — the terminal write helper. We assert it issues a single
  ``UpdateItem`` against ``(ProfileId, ShardId)`` that overwrites ``Content``, stores the
  regenerated ``Embedding`` as a ``{"L": [{"N": ...}]}`` list attribute, and stamps
  provenance (``Source="web-enrichment"``, ``SourceUrl``, ``LastUpdated``, ``UpdatedBy``),
  omitting ``SourceUrl`` when there are no sources (Requirements 5.4, 6.2, 6.4).
- ``enrich_profile`` — the ``@tool(context=True)`` flow. We assert: a missing shard
  returns a clear message and writes nothing (Requirement 5.4); a non-``"yes"`` approval
  returns a cancelled message and writes nothing (Requirements 5.3, 5.5); a ``"yes"``
  approval loads the shard, raises an interrupt whose ``reason`` carries
  ``proposed_content``/``sources``/``profile_id``/``shard_id`` (Requirement 5.2), and then
  applies the write (Requirement 5.4).

``embed_text`` and ``dynamodb_client`` are monkeypatched with fakes so no live AWS or
Bedrock call is made.
"""

from __future__ import annotations

from typing import Any

import tools.enrich_tools as et

# --------------------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------------------


class _FakeDdbClient:
    """Records get_item / update_item calls and returns scripted get_item items."""

    def __init__(self, get_item_result: dict[str, Any] | None) -> None:
        self._get_item_result = get_item_result
        self.get_item_calls: list[dict[str, Any]] = []
        self.update_item_calls: list[dict[str, Any]] = []

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.get_item_calls.append(kwargs)
        if self._get_item_result is None:
            return {}
        return {"Item": self._get_item_result}

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self.update_item_calls.append(kwargs)
        return {}


class _FakeToolContext:
    """Minimal tool context whose interrupt returns a scripted approval string."""

    def __init__(self, approval: Any, user_email: str | None = None) -> None:
        self._approval = approval
        self.user_email = user_email
        self.interrupt_calls: list[dict[str, Any]] = []

    def interrupt(self, key: str, reason: dict[str, Any]) -> Any:
        self.interrupt_calls.append({"key": key, "reason": reason})
        return self._approval


def _install_fakes(
    monkeypatch: Any, client: _FakeDdbClient, dims: int = 4
) -> None:
    monkeypatch.setattr(et, "dynamodb_client", lambda: client)
    monkeypatch.setattr(et, "embed_text", lambda _text: [0.1] * dims)


def _call_enrich(**kwargs: Any) -> str:
    """Invoke the (possibly @tool-wrapped) enrich_profile with plain kwargs."""
    func = getattr(et.enrich_profile, "__wrapped__", None)
    if callable(func):
        return func(**kwargs)  # type: ignore[no-any-return]
    return et.enrich_profile(**kwargs)


# --------------------------------------------------------------------------------------
# apply_enrichment — the terminal write (Requirements 5.4, 6.2)
# --------------------------------------------------------------------------------------


def test_apply_enrichment_builds_expected_update_item(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={})
    _install_fakes(monkeypatch, client, dims=3)

    result = et.apply_enrichment(
        profile_id="apt29",
        shard_id="detection",
        proposed_content="Updated detection guidance.",
        sources=["https://example.com/a", "https://example.com/b"],
        updated_by="analyst@example.com",
    )

    assert len(client.update_item_calls) == 1
    call = client.update_item_calls[0]

    assert call["TableName"] == et.DDB_TABLE_NAME
    assert call["Key"] == {"ProfileId": {"S": "apt29"}, "ShardId": {"S": "detection"}}

    values = call["ExpressionAttributeValues"]
    assert values[":content"] == {"S": "Updated detection guidance."}
    # Embedding stored as a list-of-number attribute (not the bare SearchVector form).
    assert values[":embedding"] == {"L": [{"N": "0.1"}, {"N": "0.1"}, {"N": "0.1"}]}
    assert values[":source"] == {"S": "web-enrichment"}
    assert values[":source_url"] == {"S": "https://example.com/a https://example.com/b"}
    assert values[":updated_by"] == {"S": "analyst@example.com"}
    assert set(values[":last_updated"].keys()) == {"S"}

    # The update expression sets every provenance attribute via aliased names.
    expr = call["UpdateExpression"]
    assert expr.startswith("SET ")
    assert call["ExpressionAttributeNames"]["#content"] == "Content"
    assert call["ExpressionAttributeNames"]["#embedding"] == "Embedding"
    assert call["ExpressionAttributeNames"]["#source_url"] == "SourceUrl"

    assert "web-enrichment" in result
    assert "apt29" in result


def test_apply_enrichment_omits_source_url_without_sources(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={})
    _install_fakes(monkeypatch, client)

    et.apply_enrichment(
        profile_id="p",
        shard_id="summary",
        proposed_content="text",
        sources=None,
        updated_by="loader",
    )

    call = client.update_item_calls[0]
    assert ":source_url" not in call["ExpressionAttributeValues"]
    assert "#source_url" not in call["ExpressionAttributeNames"]
    assert "SourceUrl" not in call["ExpressionAttributeNames"].values()


def test_apply_enrichment_ignores_blank_sources(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={})
    _install_fakes(monkeypatch, client)

    et.apply_enrichment(
        profile_id="p",
        shard_id="summary",
        proposed_content="text",
        sources=["  ", ""],
        updated_by="loader",
    )

    call = client.update_item_calls[0]
    assert ":source_url" not in call["ExpressionAttributeValues"]


# --------------------------------------------------------------------------------------
# enrich_profile — HITL flow (Requirements 5.2, 5.3, 5.4, 5.5)
# --------------------------------------------------------------------------------------


def test_enrich_profile_missing_shard_returns_message_and_no_write(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result=None)  # GetItem finds nothing
    _install_fakes(monkeypatch, client)
    ctx = _FakeToolContext(approval="yes")

    result = _call_enrich(
        tool_context=ctx,
        profile_id="ghost",
        shard_id="detection",
        proposed_content="draft",
        sources=["https://example.com"],
    )

    assert "No existing" in result
    assert "ghost" in result
    # No interrupt raised and no write performed for a missing shard.
    assert ctx.interrupt_calls == []
    assert client.update_item_calls == []


def test_enrich_profile_rejection_writes_nothing(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={"Content": {"S": "current"}})
    _install_fakes(monkeypatch, client)
    ctx = _FakeToolContext(approval="no")

    result = _call_enrich(
        tool_context=ctx,
        profile_id="apt29",
        shard_id="detection",
        proposed_content="draft",
        sources=["https://example.com"],
    )

    assert "cancelled" in result.lower()
    assert len(ctx.interrupt_calls) == 1  # the approval was requested
    assert client.update_item_calls == []  # but nothing was written


def test_enrich_profile_non_yes_approval_is_treated_as_rejection(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={"Content": {"S": "current"}})
    _install_fakes(monkeypatch, client)
    ctx = _FakeToolContext(approval="maybe later")

    result = _call_enrich(
        tool_context=ctx,
        profile_id="apt29",
        shard_id="detection",
        proposed_content="draft",
    )

    assert "cancelled" in result.lower()
    assert client.update_item_calls == []


def test_enrich_profile_approval_interrupt_payload_and_write(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={"Content": {"S": "current detection text"}})
    _install_fakes(monkeypatch, client)
    ctx = _FakeToolContext(approval="YES", user_email="analyst@example.com")

    result = _call_enrich(
        tool_context=ctx,
        profile_id="apt29",
        shard_id="detection",
        proposed_content="new detection text",
        sources=["https://example.com/report"],
    )

    # The interrupt fired with the expected key and reason payload shape (Req 5.2).
    assert len(ctx.interrupt_calls) == 1
    interrupt = ctx.interrupt_calls[0]
    assert interrupt["key"] == "enrich-apt29-detection"
    reason = interrupt["reason"]
    assert reason["profile_id"] == "apt29"
    assert reason["shard_id"] == "detection"
    assert reason["proposed_content"] == "new detection text"
    assert reason["sources"] == ["https://example.com/report"]
    assert reason["current_content"] == "current detection text"

    # Approval granted -> the write was applied with the resolved analyst identity.
    assert len(client.update_item_calls) == 1
    values = client.update_item_calls[0]["ExpressionAttributeValues"]
    assert values[":content"] == {"S": "new detection text"}
    assert values[":updated_by"] == {"S": "analyst@example.com"}
    assert "Enrichment applied" in result


def test_enrich_profile_empty_content_short_circuits(monkeypatch: Any) -> None:
    client = _FakeDdbClient(get_item_result={"Content": {"S": "current"}})
    _install_fakes(monkeypatch, client)
    ctx = _FakeToolContext(approval="yes")

    result = _call_enrich(
        tool_context=ctx,
        profile_id="apt29",
        shard_id="detection",
        proposed_content="   ",
    )

    assert "nothing to enrich" in result.lower()
    assert ctx.interrupt_calls == []
    assert client.get_item_calls == []
    assert client.update_item_calls == []

"""Unit tests for :mod:`tools.memory_tools`.

These tests exercise the HITL clear-memory tool without touching AWS:

- ``clear_memory`` — the terminal deletion helper. We assert it lists + deletes STM
  events and lists + deletes LTM records for the v2 namespaces
  (``/threat-intel/facts/{actorId}``, ``/users/preferences/{actorId}``, and the
  SESSION-scoped ``/summaries/{sessionId}``), returns the ``__NEW_SESSION_REQUIRED__``
  message with a correct deleted count, handles the not-configured case, and degrades
  gracefully on a ``ClientError``.
- ``clear_all_memory`` — the ``@tool(context=True)`` flow. We assert: a non-``"yes"``
  response returns a cancelled message and deletes nothing; a ``"yes"`` response calls
  the helper. The interrupt key is ``clear_memory-<email>`` and its ``reason`` carries
  ``action``/``session_id``/``user_email``.

``boto3.client`` is monkeypatched with a fake ``bedrock-agentcore`` client so no live AWS
call is made.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

import tools.memory_tools as mt

# --------------------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------------------


class _FakeAgentCoreClient:
    """Fake bedrock-agentcore client recording list/delete calls.

    ``events`` seeds the STM list; ``records_by_namespace`` maps each namespace to the
    LTM records ``list_memory_records`` should return. Optional ``*_error`` flags make a
    given call raise a ``ClientError`` so graceful-degradation paths can be exercised.
    """

    def __init__(
        self,
        events: list[dict[str, Any]] | None = None,
        records_by_namespace: dict[str, list[dict[str, Any]]] | None = None,
        list_events_error: bool = False,
        list_records_error_ns: set[str] | None = None,
    ) -> None:
        self._events = events or []
        self._records_by_namespace = records_by_namespace or {}
        self._list_events_error = list_events_error
        self._list_records_error_ns = list_records_error_ns or set()

        self.list_events_calls: list[dict[str, Any]] = []
        self.delete_event_calls: list[dict[str, Any]] = []
        self.list_memory_records_calls: list[dict[str, Any]] = []
        self.delete_memory_record_calls: list[dict[str, Any]] = []

    def list_events(self, **kwargs: Any) -> dict[str, Any]:
        self.list_events_calls.append(kwargs)
        if self._list_events_error:
            raise ClientError({"Error": {"Code": "X", "Message": "boom"}}, "ListEvents")
        return {"events": self._events}

    def delete_event(self, **kwargs: Any) -> dict[str, Any]:
        self.delete_event_calls.append(kwargs)
        return {}

    def list_memory_records(self, **kwargs: Any) -> dict[str, Any]:
        self.list_memory_records_calls.append(kwargs)
        namespace = kwargs.get("namespace", "")
        if namespace in self._list_records_error_ns:
            raise ClientError(
                {"Error": {"Code": "X", "Message": "boom"}}, "ListMemoryRecords"
            )
        return {"memoryRecordSummaries": self._records_by_namespace.get(namespace, [])}

    def delete_memory_record(self, **kwargs: Any) -> dict[str, Any]:
        self.delete_memory_record_calls.append(kwargs)
        return {}


class _FakeToolContext:
    """Minimal tool context whose interrupt returns a scripted approval string."""

    def __init__(self, approval: Any) -> None:
        self._approval = approval
        self.interrupt_calls: list[dict[str, Any]] = []

    def interrupt(self, key: str, reason: dict[str, Any]) -> Any:
        self.interrupt_calls.append({"key": key, "reason": reason})
        return self._approval


def _install_client(monkeypatch: Any, client: _FakeAgentCoreClient) -> None:
    """Patch config + boto3 so clear_memory uses the fake client and a memory id."""
    monkeypatch.setattr(mt, "AGENTCORE_MEMORY_ID", "mem-123")
    monkeypatch.setattr(mt, "AWS_REGION", "us-east-1")
    monkeypatch.setattr(mt.boto3, "client", lambda *a, **k: client)


def _call_clear_all_memory(**kwargs: Any) -> str:
    """Invoke the (possibly @tool-wrapped) clear_all_memory with plain kwargs."""
    func = getattr(mt.clear_all_memory, "__wrapped__", None)
    if callable(func):
        return func(**kwargs)  # type: ignore[no-any-return]
    return mt.clear_all_memory(**kwargs)


# --------------------------------------------------------------------------------------
# clear_memory — terminal deletion helper
# --------------------------------------------------------------------------------------


def test_clear_memory_deletes_stm_and_v2_ltm_namespaces(monkeypatch: Any) -> None:
    client = _FakeAgentCoreClient(
        events=[{"eventId": "e1"}, {"eventId": "e2"}],
        records_by_namespace={
            "/threat-intel/facts/a-at-b-com": [
                {"memoryRecordId": "f1"},
                {"memoryRecordId": "f2"},
            ],
            "/users/preferences/a-at-b-com": [{"memoryRecordId": "p1"}],
            "/summaries/sess-9": [{"memoryRecordId": "s1"}],
        },
    )
    _install_client(monkeypatch, client)

    result = mt.clear_memory(session_id="sess-9", user_email="a@b.com")

    # STM events listed for the session/actor, then each deleted by eventId.
    assert len(client.list_events_calls) == 1
    assert client.list_events_calls[0] == {
        "memoryId": "mem-123",
        "sessionId": "sess-9",
        "actorId": "a-at-b-com",
    }
    assert {c["eventId"] for c in client.delete_event_calls} == {"e1", "e2"}

    # LTM listed for exactly the three v2 namespaces: facts + preferences are
    # actor-scoped; summaries are SESSION-scoped (session id, not actor id).
    listed = [c["namespace"] for c in client.list_memory_records_calls]
    assert listed == [
        "/threat-intel/facts/a-at-b-com",
        "/users/preferences/a-at-b-com",
        "/summaries/sess-9",
    ]

    # Every returned record was deleted (2 facts + 1 pref + 1 summary = 4).
    assert {c["memoryRecordId"] for c in client.delete_memory_record_calls} == {
        "f1",
        "f2",
        "p1",
        "s1",
    }

    # Confirmation carries the count and the new-session sentinel the frontend keys off.
    assert "4 stored facts/preferences/summaries" in result
    assert result.endswith(mt.NEW_SESSION_SENTINEL)


def test_clear_memory_handles_both_record_response_keys(monkeypatch: Any) -> None:
    # list_memory_records may return records under "memoryRecords" instead of
    # "memoryRecordSummaries"; both must be handled.
    class _AltKeyClient(_FakeAgentCoreClient):
        def list_memory_records(self, **kwargs: Any) -> dict[str, Any]:
            self.list_memory_records_calls.append(kwargs)
            if kwargs.get("namespace") == "/threat-intel/facts/anonymous":
                return {"memoryRecords": [{"memoryRecordId": "f1"}]}
            return {"memoryRecordSummaries": []}

    client = _AltKeyClient()
    _install_client(monkeypatch, client)

    result = mt.clear_memory(session_id="sess-1", user_email="")

    assert client.delete_memory_record_calls == [
        {"memoryId": "mem-123", "memoryRecordId": "f1"}
    ]
    assert "1 stored facts/preferences/summaries" in result


def test_clear_memory_anonymous_actor_when_no_email(monkeypatch: Any) -> None:
    client = _FakeAgentCoreClient()
    _install_client(monkeypatch, client)

    mt.clear_memory(session_id="sess-1", user_email="")

    assert client.list_events_calls[0]["actorId"] == "anonymous"
    listed = [c["namespace"] for c in client.list_memory_records_calls]
    assert "/threat-intel/facts/anonymous" in listed
    assert "/users/preferences/anonymous" in listed
    # Summary namespace is session-scoped, never actor-scoped.
    assert "/summaries/sess-1" in listed


def test_clear_memory_not_configured_returns_error(monkeypatch: Any) -> None:
    monkeypatch.setattr(mt, "AGENTCORE_MEMORY_ID", "")

    result = mt.clear_memory(session_id="sess-1", user_email="a@b.com")

    assert "not configured" in result.lower()


def test_clear_memory_collects_errors_but_reports_progress(monkeypatch: Any) -> None:
    # A per-namespace ClientError must not abort the whole clear: successful deletes are
    # still counted and reported.
    client = _FakeAgentCoreClient(
        records_by_namespace={
            "/users/preferences/a-at-b-com": [{"memoryRecordId": "p1"}],
        },
        list_records_error_ns={"/threat-intel/facts/a-at-b-com"},
    )
    _install_client(monkeypatch, client)

    result = mt.clear_memory(session_id="sess-1", user_email="a@b.com")

    # The preferences delete succeeded despite the facts-namespace error.
    assert client.delete_memory_record_calls == [
        {"memoryId": "mem-123", "memoryRecordId": "p1"}
    ]
    assert "1 stored facts/preferences/summaries" in result
    assert result.endswith(mt.NEW_SESSION_SENTINEL)


def test_clear_memory_total_failure_returns_error(monkeypatch: Any) -> None:
    # Every namespace erroring and nothing deleted surfaces as an error message.
    client = _FakeAgentCoreClient(
        list_events_error=True,
        list_records_error_ns={
            "/threat-intel/facts/a-at-b-com",
            "/users/preferences/a-at-b-com",
            "/summaries/sess-1",
        },
    )
    _install_client(monkeypatch, client)

    result = mt.clear_memory(session_id="sess-1", user_email="a@b.com")

    assert "error clearing memory records" in result.lower()
    assert mt.NEW_SESSION_SENTINEL not in result


# --------------------------------------------------------------------------------------
# clear_all_memory — HITL tool flow
# --------------------------------------------------------------------------------------


def test_clear_all_memory_rejection_deletes_nothing(monkeypatch: Any) -> None:
    called: list[tuple[str, str]] = []

    def _fake_clear(session_id: str, user_email: str) -> str:
        called.append((session_id, user_email))
        return "x"

    monkeypatch.setattr(mt, "clear_memory", _fake_clear)
    ctx = _FakeToolContext(approval="no")

    result = _call_clear_all_memory(
        tool_context=ctx, session_id="sess-1", user_email="a@b.com"
    )

    assert "cancelled" in result.lower()
    assert "unchanged" in result.lower()
    assert called == []  # helper never invoked
    # The interrupt fired with the load-bearing key + reason payload.
    assert len(ctx.interrupt_calls) == 1
    assert ctx.interrupt_calls[0]["key"] == "clear_memory-a@b.com"
    reason = ctx.interrupt_calls[0]["reason"]
    assert reason["action"] == "clear_memory"
    assert reason["session_id"] == "sess-1"
    assert reason["user_email"] == "a@b.com"


def test_clear_all_memory_non_yes_is_rejection(monkeypatch: Any) -> None:
    called: list[Any] = []
    monkeypatch.setattr(mt, "clear_memory", lambda *a, **k: called.append(a) or "x")
    ctx = _FakeToolContext(approval="maybe")

    result = _call_clear_all_memory(
        tool_context=ctx, session_id="sess-1", user_email="a@b.com"
    )

    assert "cancelled" in result.lower()
    assert called == []


def test_clear_all_memory_approval_calls_helper(monkeypatch: Any) -> None:
    calls: list[dict[str, str]] = []

    def _fake_clear(session_id: str, user_email: str) -> str:
        calls.append({"session_id": session_id, "user_email": user_email})
        return f"All memory cleared. ... {mt.NEW_SESSION_SENTINEL}"

    monkeypatch.setattr(mt, "clear_memory", _fake_clear)
    ctx = _FakeToolContext(approval="YES")

    result = _call_clear_all_memory(
        tool_context=ctx, session_id="sess-42", user_email="a@b.com"
    )

    assert calls == [{"session_id": "sess-42", "user_email": "a@b.com"}]
    assert result.endswith(mt.NEW_SESSION_SENTINEL)

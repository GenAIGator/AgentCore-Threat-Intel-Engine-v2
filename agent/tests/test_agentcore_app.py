"""Unit tests for the SSE streaming pieces of :mod:`agentcore_app` (task 7.2).

These tests exercise the pure formatting and streaming orchestration without touching
AWS, Bedrock, or a real Strands ``Agent``:

- ``format_sse`` — every event is a single ``data:`` frame terminated by a blank line and
  carries valid JSON (Requirement 8.2).
- ``stream_agent_response`` — iterates a fake agent's ``stream_async``, emitting a
  ``{"content": ...}`` frame per data event and a terminal ``{"done": True}`` on normal
  completion or ``{"pending_approval": ...}`` when the result reports a HITL interrupt
  (Requirements 3.1–3.3, 3.5, 8.2). Errors surface as an ``{"error": ...}`` frame.

The fake agent mirrors the shape ``agent.stream_async`` yields (``{"data": ...}`` and a
final ``{"result": ...}`` event) and the ``_interrupt_state`` attribute the eviction guard
reads.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

import agentcore_app as app_mod


def _events_from_sse(frames: list[str]) -> list[dict[str, Any]]:
    """Parse a list of SSE frames back into their JSON payloads."""
    payloads: list[dict[str, Any]] = []
    for frame in frames:
        assert frame.startswith("data: ")
        assert frame.endswith("\n\n")
        payloads.append(json.loads(frame[len("data: ") : -2]))
    return payloads


class _FakeInterruptState:
    def __init__(self, activated: bool = False) -> None:
        self.activated = activated

    def deactivate(self) -> None:
        self.activated = False


class _FakeInterrupt:
    def __init__(self, id: str, reason: str, name: str) -> None:
        self.id = id
        self.reason = reason
        self.name = name


class _FakeResult:
    def __init__(self, stop_reason: str = "end_turn", interrupts: list[Any] | None = None) -> None:
        self.stop_reason = stop_reason
        self.interrupts = interrupts or []


class _FakeAgent:
    """Stand-in for a Strands Agent whose stream_async yields scripted events."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events
        self._interrupt_state = _FakeInterruptState()

    async def stream_async(self, _prompt: str) -> AsyncIterator[dict[str, Any]]:
        for event in self._events:
            yield event


def _collect(gen: AsyncIterator[str]) -> list[str]:
    """Drain an async generator to a list using a fresh event loop (no plugin needed)."""

    async def _drain() -> list[str]:
        return [frame async for frame in gen]

    return asyncio.run(_drain())


# --------------------------------------------------------------------------------------
# format_sse (Requirement 8.2)
# --------------------------------------------------------------------------------------


def test_format_sse_wraps_json_in_data_frame() -> None:
    frame = app_mod.format_sse({"content": "hello"})

    assert frame == 'data: {"content": "hello"}\n\n'


def test_format_sse_payload_roundtrips_through_json() -> None:
    frame = app_mod.format_sse({"done": True})

    assert frame.startswith("data: ")
    assert frame.endswith("\n\n")
    assert json.loads(frame[len("data: ") : -2]) == {"done": True}


# --------------------------------------------------------------------------------------
# stream_agent_response — normal completion (Requirements 3.1-3.3, 8.2)
# --------------------------------------------------------------------------------------


def test_stream_emits_content_then_done(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _FakeAgent(
        [
            {"data": "The "},
            {"data": "actor "},
            {"data": "is APT29."},
            {"result": _FakeResult(stop_reason="end_turn")},
        ]
    )
    monkeypatch.setattr(app_mod, "get_or_create_agent", lambda *a, **k: agent)

    frames = _collect(app_mod.stream_agent_response("who is apt29?", session_id="s1"))
    payloads = _events_from_sse(frames)

    assert payloads == [
        {"content": "The "},
        {"content": "actor "},
        {"content": "is APT29."},
        {"done": True},
    ]
    # The stream must terminate with a single terminal frame.
    assert payloads[-1] == {"done": True}


def test_stream_skips_empty_data_events(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _FakeAgent(
        [
            {"data": ""},
            {"data": "text"},
            {"other": "ignored"},
            {"result": _FakeResult()},
        ]
    )
    monkeypatch.setattr(app_mod, "get_or_create_agent", lambda *a, **k: agent)

    payloads = _events_from_sse(
        _collect(app_mod.stream_agent_response("q", session_id="s1"))
    )

    assert payloads == [{"content": "text"}, {"done": True}]


# --------------------------------------------------------------------------------------
# stream_agent_response — HITL interrupt terminal frame (Requirement 3.5)
# --------------------------------------------------------------------------------------


def test_stream_emits_pending_approval_on_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interrupt = _FakeInterrupt(id="int-1", reason="Approve enrichment?", name="enrich-abc")
    agent = _FakeAgent(
        [
            {"data": "Proposing an update."},
            {"result": _FakeResult(stop_reason="interrupt", interrupts=[interrupt])},
        ]
    )
    monkeypatch.setattr(app_mod, "get_or_create_agent", lambda *a, **k: agent)

    payloads = _events_from_sse(
        _collect(app_mod.stream_agent_response("enrich apt29", session_id="s1"))
    )

    assert payloads[0] == {"content": "Proposing an update."}
    terminal = payloads[-1]
    assert terminal["pending_approval"] is True
    assert terminal["interrupts"] == [
        {"interrupt_id": "int-1", "prompt": "Approve enrichment?", "action": "enrich"}
    ]
    assert "done" not in terminal


# --------------------------------------------------------------------------------------
# stream_agent_response — enrich_profile "working, up to 60s" tool-running frame
# The enrich_profile tool STARTING is surfaced by Strands as a contentBlockStart event
# carrying a toolUse dict; we emit ONE {"tool_running": "enrich_profile", "notice": ...}
# frame ONLY for that tool so the UI can show a transient waiting indicator.
# --------------------------------------------------------------------------------------


def _tool_start_event(name: str, tool_use_id: str = "t1") -> dict[str, Any]:
    """Build a Strands tool-start event (contentBlockStart carrying a toolUse dict)."""
    return {
        "event": {
            "contentBlockStart": {"start": {"toolUse": {"name": name, "toolUseId": tool_use_id}}}
        }
    }


def test_stream_emits_tool_running_frame_for_enrich_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An enrich_profile tool-start event must produce a single tool_running frame with a
    # notice mentioning the 60-second wait, emitted BEFORE the terminal frame.
    agent = _FakeAgent(
        [
            _tool_start_event("enrich_profile"),
            {"data": "Drafting and submitting now:"},
            {"result": _FakeResult(stop_reason="end_turn")},
        ]
    )
    monkeypatch.setattr(app_mod, "get_or_create_agent", lambda *a, **k: agent)

    payloads = _events_from_sse(
        _collect(app_mod.stream_agent_response("enrich apt29", session_id="s1"))
    )

    tool_running = [p for p in payloads if p.get("tool_running")]
    assert len(tool_running) == 1
    assert tool_running[0]["tool_running"] == "enrich_profile"
    assert "60 seconds" in tool_running[0]["notice"]
    # It must arrive before the terminal frame.
    assert payloads.index(tool_running[0]) < payloads.index({"done": True})
    assert payloads[-1] == {"done": True}


def test_stream_does_not_emit_tool_running_for_other_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A tool-start event for a DIFFERENT tool (e.g. retrieve_profiles) must NOT produce a
    # tool_running frame — the indicator is scoped to enrich_profile only.
    agent = _FakeAgent(
        [
            _tool_start_event("retrieve_profiles"),
            {"data": "Here is what I found."},
            {"result": _FakeResult(stop_reason="end_turn")},
        ]
    )
    monkeypatch.setattr(app_mod, "get_or_create_agent", lambda *a, **k: agent)

    payloads = _events_from_sse(
        _collect(app_mod.stream_agent_response("who is apt29?", session_id="s1"))
    )

    assert all("tool_running" not in p for p in payloads)
    assert payloads == [{"content": "Here is what I found."}, {"done": True}]


# --------------------------------------------------------------------------------------
# stream_agent_response — error surfacing
# --------------------------------------------------------------------------------------


def test_stream_emits_error_frame_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(app_mod, "get_or_create_agent", _boom)

    payloads = _events_from_sse(
        _collect(app_mod.stream_agent_response("q", session_id="s1"))
    )

    assert payloads == [{"error": "model unavailable"}]


# --------------------------------------------------------------------------------------
# GET /ping — AgentCore Runtime health check (task 7.3, Requirements 3.1, 8.2)
# --------------------------------------------------------------------------------------


def test_ping_returns_healthy_status() -> None:
    client = TestClient(app_mod.app)

    response = client.get("/ping")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_stream_evicts_stuck_interrupted_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A stuck (activated) agent is cached; the guard must evict it from _sessions and
    # rebuild a fresh one before streaming.
    stuck = _FakeAgent([{"result": _FakeResult()}])
    stuck._interrupt_state = _FakeInterruptState(activated=True)
    fresh = _FakeAgent([{"data": "ok"}, {"result": _FakeResult()}])

    session_id = "stuck-sess"
    app_mod._sessions[session_id] = stuck

    def _fake_get_or_create(sid: str, **_k: Any) -> _FakeAgent:
        # Mirror the real cache semantics: return the cached agent if present, else the
        # fresh one and store it.
        if sid in app_mod._sessions:
            return app_mod._sessions[sid]  # type: ignore[return-value]
        app_mod._sessions[sid] = fresh  # type: ignore[assignment]
        return fresh

    monkeypatch.setattr(app_mod, "get_or_create_agent", _fake_get_or_create)

    try:
        payloads = _events_from_sse(
            _collect(app_mod.stream_agent_response("q", session_id=session_id))
        )

        # The stuck agent was evicted and replaced by the fresh one.
        assert app_mod._sessions[session_id] is fresh
        assert payloads == [{"content": "ok"}, {"done": True}]
    finally:
        app_mod._sessions.pop(session_id, None)


# --------------------------------------------------------------------------------------
# SYSTEM_PROMPT — WebSearch usage + distinct web-source attribution (task 8.2)
# (Requirements 3.4, 4.1, 4.3, 4.4)
# --------------------------------------------------------------------------------------


def test_system_prompt_includes_web_search_guidance() -> None:
    prompt = app_mod._build_system_prompt()

    # The model is told it has, and when to use, the WebSearch tool.
    assert "WebSearch" in prompt
    # Both triggers are covered: a thin/empty KB result ...
    assert "NO_RELEVANT_CONTEXT" in prompt
    # ... and an explicit request for current/recent information.
    assert "current" in prompt and "recent" in prompt
    # Retrieve-then-generate stays primary: WebSearch supplements, retrieval runs first.
    assert "retrieve_profiles FIRST" in prompt


def test_system_prompt_requires_distinct_web_attribution() -> None:
    prompt = app_mod._build_system_prompt()

    # Web sources must be attributed DISTINCTLY from knowledge-base citations (Req 4.3).
    assert "ATTRIBUTE WEB SOURCES DISTINCTLY" in prompt
    assert "Web sources:" in prompt


def test_system_prompt_notes_web_unavailability() -> None:
    prompt = app_mod._build_system_prompt()

    # Graceful degradation must be surfaced to the analyst (Req 4.4): note when web
    # results were used or unavailable and answer from the KB alone.
    assert "degrade gracefully" in prompt
    assert "unavailable" in prompt


def test_system_prompt_routes_enrichment_through_enrich_profile() -> None:
    # Task 9.2 replaces the task-9 seam with enrich_profile routing guidance: the TODO
    # is gone and profile-update requests MUST route through enrich_profile so the HITL
    # interrupt fires (Requirement 5.1).
    prompt = app_mod._build_system_prompt()

    assert "TODO(task 9)" not in app_mod.SYSTEM_PROMPT
    assert "enrich_profile" in prompt
    # The agent is told to route updates through the tool and never write directly.
    assert "MUST be routed through enrich_profile" in prompt
    assert "NEVER write to the knowledge base directly" in prompt
    # The pre-call workflow (retrieve current shard + web research) is spelled out.
    assert "Retrieve the current shard" in prompt
    assert "WebSearch" in prompt


# --------------------------------------------------------------------------------------
# get_mcp_client / _build_tools — graceful degradation (task 8.3)
# (Requirements 3.4, 4.1, 4.3, 4.4)
# --------------------------------------------------------------------------------------


def test_get_mcp_client_returns_none_quietly_when_no_gateway_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No gateway configured: return None quietly, without touching MCPClient.
    monkeypatch.setattr(app_mod, "get_gateway_url", lambda: "")

    def _should_not_build(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("MCPClient must not be constructed when no gateway URL is set")

    monkeypatch.setattr(app_mod, "MCPClient", _should_not_build)

    assert app_mod.get_mcp_client() is None


def test_get_mcp_client_builds_client_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A configured gateway builds an MCP client (success path stays green).
    monkeypatch.setattr(app_mod, "get_gateway_url", lambda: "https://gw.example/mcp")

    sentinel = object()
    monkeypatch.setattr(app_mod, "MCPClient", lambda _factory: sentinel)

    assert app_mod.get_mcp_client() is sentinel


def test_get_mcp_client_returns_none_and_warns_when_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A configured-but-unreachable/misconfigured gateway must NOT crash agent creation:
    # a construction error is caught, logged as a warning, and None is returned (Req 4.4).
    monkeypatch.setattr(app_mod, "get_gateway_url", lambda: "https://gw.example/mcp")

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise ConnectionError("gateway unreachable")

    monkeypatch.setattr(app_mod, "MCPClient", _boom)

    with caplog.at_level(logging.WARNING, logger=app_mod.logger.name):
        result = app_mod.get_mcp_client()

    assert result is None
    assert any(record.levelno == logging.WARNING for record in caplog.records)
    assert "without web search" in caplog.text


def test_build_tools_includes_mcp_client_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()
    monkeypatch.setattr(app_mod, "get_mcp_client", lambda: sentinel)

    tools = app_mod._build_tools()

    # Local tools are always present, and the MCP client is appended when built.
    assert app_mod.current_time in tools
    assert app_mod.retrieve_profiles in tools
    assert app_mod.enrich_profile in tools
    assert sentinel in tools


def test_build_tools_returns_only_local_tools_when_gateway_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When the gateway is unavailable get_mcp_client returns None; _build_tools must
    # still return the local tools (current_time, retrieve_profiles, enrich_profile,
    # create_profile, clear_all_memory) and never raise (Req 4.4).
    monkeypatch.setattr(app_mod, "get_mcp_client", lambda: None)

    tools = app_mod._build_tools()

    assert tools == [
        app_mod.current_time,
        app_mod.retrieve_profiles,
        app_mod.enrich_profile,
        app_mod.create_profile,
        app_mod.clear_all_memory,
    ]


# --------------------------------------------------------------------------------------
# POST /invocations — HITL resume path (task 9.3)
# (Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 6.2)
# --------------------------------------------------------------------------------------


class _FakeResumeAgent:
    """Stand-in Agent whose ``invoke_async`` returns a scripted result or raises.

    Records the argument it was resumed with so tests can assert the interruptResponse
    payload shape the resume path builds.
    """

    def __init__(self, result: Any = None, exc: Exception | None = None) -> None:
        self._result = result
        self._exc = exc
        self.invoked_with: Any = None
        self._interrupt_state = _FakeInterruptState()

    async def invoke_async(self, arg: Any) -> Any:
        self.invoked_with = arg
        if self._exc is not None:
            raise self._exc
        return self._result


def _invoke_json(body: dict[str, Any]) -> dict[str, Any]:
    """POST ``body`` to /invocations via TestClient and return the parsed JSON."""
    client = TestClient(app_mod.app)
    response = client.post("/invocations", json=body)
    assert response.status_code == 200
    return response.json()  # type: ignore[no-any-return]


def test_resume_success_returns_success_and_evicts_agent() -> None:
    # A cached agent whose resumed run completes normally: the resume path returns
    # status "success" with the response text and evicts the agent from _sessions so the
    # consumed interrupt cannot be resumed again (Requirements 5.4/5.5, 5.6).
    session_id = "resume-ok"
    agent = _FakeResumeAgent(result=_FakeResult(stop_reason="end_turn"))
    app_mod._sessions[session_id] = agent  # type: ignore[assignment]

    try:
        result = _invoke_json(
            {
                "session_id": session_id,
                "action": "enrich",
                "responses": [{"interrupt_id": "int-1", "response": "yes"}],
            }
        )

        assert result["status"] == "success"
        assert "response" in result
        # The agent was resumed with the documented interruptResponse payload shape.
        assert agent.invoked_with == [
            {"interruptResponse": {"interruptId": "int-1", "response": "yes"}}
        ]
        # A terminal resume evicts the agent so the next request starts fresh.
        assert session_id not in app_mod._sessions
    finally:
        app_mod._sessions.pop(session_id, None)


def test_resume_reject_still_resumes_cached_agent_and_evicts() -> None:
    # Rejection ("no") is also a terminal resume: the tool discards the draft (no write)
    # and the agent is evicted (Requirement 5.5).
    session_id = "resume-reject"
    agent = _FakeResumeAgent(result=_FakeResult(stop_reason="end_turn"))
    app_mod._sessions[session_id] = agent  # type: ignore[assignment]

    try:
        result = _invoke_json(
            {
                "session_id": session_id,
                "action": "enrich",
                "responses": [{"interrupt_id": "int-1", "response": "no"}],
            }
        )

        assert result["status"] == "success"
        assert agent.invoked_with == [
            {"interruptResponse": {"interruptId": "int-1", "response": "no"}}
        ]
        assert session_id not in app_mod._sessions
    finally:
        app_mod._sessions.pop(session_id, None)


def test_resume_returns_pending_approval_when_result_is_interrupt() -> None:
    # A resumed run that itself raises another interrupt returns pending_approval and
    # keeps the agent cached so it can be resumed again (Requirement 5.2).
    session_id = "resume-again"
    interrupt = _FakeInterrupt(id="int-2", reason="Approve follow-up?", name="enrich-xyz")
    agent = _FakeResumeAgent(
        result=_FakeResult(stop_reason="interrupt", interrupts=[interrupt])
    )
    app_mod._sessions[session_id] = agent  # type: ignore[assignment]

    try:
        result = _invoke_json(
            {
                "session_id": session_id,
                "responses": [{"interrupt_id": "int-1", "response": "yes"}],
            }
        )

        assert result["status"] == "pending_approval"
        assert result["interrupts"] == [
            {"interrupt_id": "int-2", "prompt": "Approve follow-up?"}
        ]
        assert result["session_id"] == session_id
        # Still cached for the next resume.
        assert app_mod._sessions[session_id] is agent
    finally:
        app_mod._sessions.pop(session_id, None)


def test_resume_error_evicts_agent_and_returns_error() -> None:
    # If resuming raises, the resume path evicts the broken agent and returns an error
    # result rather than crashing.
    session_id = "resume-boom"
    agent = _FakeResumeAgent(exc=RuntimeError("resume failed"))
    app_mod._sessions[session_id] = agent  # type: ignore[assignment]

    try:
        result = _invoke_json(
            {
                "session_id": session_id,
                "responses": [{"interrupt_id": "int-1", "response": "yes"}],
            }
        )

        assert result["status"] == "error"
        assert result["error"] == "resume failed"
        assert session_id not in app_mod._sessions
    finally:
        app_mod._sessions.pop(session_id, None)


# --------------------------------------------------------------------------------------
# POST /invocations — orphaned-interrupt fallback (task 9.4, Requirement 5.7)
# No agent cached (container recycled): the terminal write is applied directly from the
# echoed interrupt payload on approval, no write on rejection, and NEVER a partial write.
# --------------------------------------------------------------------------------------


class _EnrichSpy:
    """Records apply_enrichment calls and returns a scripted confirmation/raise."""

    def __init__(self, confirmation: str = "applied", exc: Exception | None = None) -> None:
        self.confirmation = confirmation
        self.exc = exc
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return self.confirmation


def _invoke_orphaned(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any], spy: _EnrichSpy
) -> dict[str, Any]:
    """POST an orphaned resume (no cached agent) with apply_enrichment spied."""
    session_id = body.get("session_id", "orphaned-sess")
    app_mod._sessions.pop(session_id, None)
    monkeypatch.setattr(app_mod, "apply_enrichment", spy)
    return _invoke_json(body)


def test_resume_orphaned_approved_with_payload_applies_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No cached agent + approved ("yes") + a complete top-level interrupt payload: the
    # terminal write is applied directly from the payload and success is returned
    # (Requirements 5.4, 5.7, 6.2).
    spy = _EnrichSpy(confirmation="Enrichment applied to apt29/detection.")
    result = _invoke_orphaned(
        monkeypatch,
        {
            "session_id": "orphaned-approve",
            "action": "enrich",
            "user_email": "analyst@example.com",
            "profile_id": "apt29",
            "shard_id": "detection",
            "proposed_content": "Updated detection guidance.",
            "sources": ["https://example.com/report"],
            "responses": [{"interrupt_id": "int-1", "response": "yes"}],
        },
        spy,
    )

    assert result["status"] == "success"
    assert result["response"] == "Enrichment applied to apt29/detection."
    # apply_enrichment was called exactly once with the payload fields + analyst email.
    assert len(spy.calls) == 1
    call = spy.calls[0]
    assert call["profile_id"] == "apt29"
    assert call["shard_id"] == "detection"
    assert call["proposed_content"] == "Updated detection guidance."
    assert call["sources"] == ["https://example.com/report"]
    assert call["updated_by"] == "analyst@example.com"


def test_resume_orphaned_approved_reads_nested_reason_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The interrupt payload may arrive nested under a per-response "reason" dict (the
    # shape enrich_profile passes to tool_context.interrupt). It must still be extracted.
    spy = _EnrichSpy()
    result = _invoke_orphaned(
        monkeypatch,
        {
            "session_id": "orphaned-nested",
            "action": "enrich",
            "responses": [
                {
                    "interrupt_id": "int-1",
                    "response": "yes",
                    "reason": {
                        "profile_id": "lazarus",
                        "shard_id": "tactics_mitre",
                        "proposed_content": "New TTPs.",
                        "sources": ["https://example.com/a"],
                    },
                }
            ],
        },
        spy,
    )

    assert result["status"] == "success"
    assert len(spy.calls) == 1
    call = spy.calls[0]
    assert call["profile_id"] == "lazarus"
    assert call["shard_id"] == "tactics_mitre"
    assert call["proposed_content"] == "New TTPs."
    # No user_email in body: falls back to the web-enrichment marker.
    assert call["updated_by"] == "web-enrichment"


def test_resume_orphaned_approved_without_payload_asks_reissue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No cached agent + approved but the interrupt payload is missing (frontend did not
    # echo it): NEVER apply a partial write — return a re-issue message (Requirement 5.7).
    spy = _EnrichSpy()
    result = _invoke_orphaned(
        monkeypatch,
        {
            "session_id": "orphaned-nopayload",
            "action": "enrich",
            "responses": [{"interrupt_id": "int-1", "response": "yes"}],
        },
        spy,
    )

    assert result["status"] == "success"
    assert "re-issue" in result["response"].lower()
    # Absolutely no write was attempted.
    assert spy.calls == []


def test_resume_orphaned_approved_partial_payload_asks_reissue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A partial payload (missing proposed_content) must NOT trigger a partial write.
    spy = _EnrichSpy()
    result = _invoke_orphaned(
        monkeypatch,
        {
            "session_id": "orphaned-partial",
            "action": "enrich",
            "profile_id": "apt29",
            "shard_id": "detection",
            "responses": [{"interrupt_id": "int-1", "response": "yes"}],
        },
        spy,
    )

    assert result["status"] == "success"
    assert "re-issue" in result["response"].lower()
    assert spy.calls == []


def test_resume_orphaned_rejected_makes_no_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No cached agent + rejected ("no"): no write, cancellation message (Requirement 5.5).
    spy = _EnrichSpy()
    result = _invoke_orphaned(
        monkeypatch,
        {
            "session_id": "orphaned-reject",
            "action": "enrich",
            "profile_id": "apt29",
            "shard_id": "detection",
            "proposed_content": "Updated detection guidance.",
            "responses": [{"interrupt_id": "int-1", "response": "no"}],
        },
        spy,
    )

    assert result["status"] == "success"
    assert "cancelled" in result["response"].lower()
    assert "no changes were made" in result["response"].lower()
    assert spy.calls == []


def test_resume_orphaned_write_failure_returns_graceful_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # apply_enrichment failing on the direct write returns a graceful error with no
    # partial-write claim (Requirement 5.7).
    from botocore.exceptions import ClientError

    spy = _EnrichSpy(
        exc=ClientError({"Error": {"Code": "X", "Message": "boom"}}, "UpdateItem")
    )
    result = _invoke_orphaned(
        monkeypatch,
        {
            "session_id": "orphaned-fail",
            "action": "enrich",
            "profile_id": "apt29",
            "shard_id": "detection",
            "proposed_content": "Updated detection guidance.",
            "responses": [{"interrupt_id": "int-1", "response": "yes"}],
        },
        spy,
    )

    assert result["status"] == "error"
    assert "no partial change was applied" in result["error"].lower()
    assert len(spy.calls) == 1


def test_resume_runs_before_stream_path() -> None:
    # Even with stream=True and a prompt present, a non-empty "responses" list routes to
    # the sync resume path (Requirement 5.6), returning JSON — not an SSE stream.
    session_id = "resume-before-stream"
    agent = _FakeResumeAgent(result=_FakeResult(stop_reason="end_turn"))
    app_mod._sessions[session_id] = agent  # type: ignore[assignment]

    try:
        client = TestClient(app_mod.app)
        response = client.post(
            "/invocations",
            json={
                "session_id": session_id,
                "prompt": "ignored because this is a resume",
                "stream": True,
                "responses": [{"interrupt_id": "int-1", "response": "yes"}],
            },
        )

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["status"] == "success"
        assert agent.invoked_with is not None
    finally:
        app_mod._sessions.pop(session_id, None)


# --------------------------------------------------------------------------------------
# get_session_manager — AgentCore Memory wiring (task 10, Requirement 8.5)
# Guarded by an SDK-present check; actor_id derived from the sanitized user email;
# retrieval namespaces consistent with the Semantic/Summary/UserPreference strategies.
# --------------------------------------------------------------------------------------


def test_sanitize_actor_id_replaces_at_and_dots() -> None:
    # Email must be sanitized to match AgentCore's [a-zA-Z0-9][a-zA-Z0-9-_/]* rule.
    assert app_mod.sanitize_actor_id("a.b@c.com") == "a-b-at-c-com"


def test_sanitize_actor_id_defaults_to_anonymous() -> None:
    assert app_mod.sanitize_actor_id("") == "anonymous"


def test_get_session_manager_returns_none_without_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No memory SDK importable: return None (agent is built without memory).
    monkeypatch.setattr(app_mod, "HAS_MEMORY_SDK", False)
    monkeypatch.setattr(app_mod, "AGENTCORE_MEMORY_ID", "mem-123")

    assert app_mod.get_session_manager("analyst@example.com", "sess-1") is None


def test_get_session_manager_returns_none_without_memory_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # SDK present but no memory id configured: return None.
    monkeypatch.setattr(app_mod, "HAS_MEMORY_SDK", True)
    monkeypatch.setattr(app_mod, "AGENTCORE_MEMORY_ID", "")

    assert app_mod.get_session_manager("analyst@example.com", "sess-1") is None


def test_get_session_manager_returns_none_without_session_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # SDK + memory id present but no session id: return None.
    monkeypatch.setattr(app_mod, "HAS_MEMORY_SDK", True)
    monkeypatch.setattr(app_mod, "AGENTCORE_MEMORY_ID", "mem-123")

    assert app_mod.get_session_manager("analyst@example.com", "") is None


def test_get_session_manager_builds_config_with_sanitized_actor_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Happy path: with the SDK present and both a memory id and session id configured,
    # get_session_manager builds an AgentCoreMemoryConfig with the sanitized actor_id and
    # the design's memory namespaces, then hands it to the session manager. We spy on the
    # config + manager constructors so no live AWS is touched.
    monkeypatch.setattr(app_mod, "HAS_MEMORY_SDK", True)
    monkeypatch.setattr(app_mod, "AGENTCORE_MEMORY_ID", "mem-123")
    monkeypatch.setattr(app_mod, "AWS_REGION", "us-east-1")

    captured: dict[str, Any] = {}

    class _FakeConfig:
        def __init__(
            self,
            memory_id: str,
            session_id: str,
            actor_id: str,
            retrieval_config: dict[str, Any],
        ) -> None:
            captured["memory_id"] = memory_id
            captured["session_id"] = session_id
            captured["actor_id"] = actor_id
            captured["retrieval_config"] = retrieval_config

    sentinel_manager = object()

    class _FakeManager:
        def __new__(cls, *, agentcore_memory_config: Any, region_name: str) -> Any:
            captured["config"] = agentcore_memory_config
            captured["region_name"] = region_name
            return sentinel_manager

    monkeypatch.setattr(app_mod, "AgentCoreMemoryConfig", _FakeConfig)
    monkeypatch.setattr(app_mod, "AgentCoreMemorySessionManager", _FakeManager)

    result = app_mod.get_session_manager("a.b@c.com", "sess-42")

    assert result is sentinel_manager
    # actor_id derived from the sanitized email.
    assert captured["actor_id"] == "a-b-at-c-com"
    assert captured["memory_id"] == "mem-123"
    assert captured["session_id"] == "sess-42"
    assert captured["region_name"] == "us-east-1"
    # Retrieval namespaces mirror the Semantic/Summary/UserPreference strategies; the
    # summary namespace is scoped by the concrete session id.
    namespaces = set(captured["retrieval_config"].keys())
    assert namespaces == {
        "/threat-intel/facts",
        "/summaries/sess-42",
        "/users/preferences",
    }


def test_get_session_manager_returns_none_on_construction_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A failure while building the manager degrades gracefully to None (memoryless).
    monkeypatch.setattr(app_mod, "HAS_MEMORY_SDK", True)
    monkeypatch.setattr(app_mod, "AGENTCORE_MEMORY_ID", "mem-123")

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("memory backend unreachable")

    monkeypatch.setattr(app_mod, "AgentCoreMemoryConfig", _boom)

    with caplog.at_level(logging.WARNING, logger=app_mod.logger.name):
        result = app_mod.get_session_manager("analyst@example.com", "sess-1")

    assert result is None
    assert any(record.levelno == logging.WARNING for record in caplog.records)
    assert "without" in caplog.text and "memory" in caplog.text


def test_get_or_create_agent_attaches_session_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # get_or_create_agent must pass the session manager returned by get_session_manager
    # into the Agent it builds (Requirement 8.5).
    sentinel_manager = object()
    monkeypatch.setattr(
        app_mod, "get_session_manager", lambda _email, _sid: sentinel_manager
    )
    monkeypatch.setattr(app_mod, "_build_tools", lambda: [])
    monkeypatch.setattr(app_mod, "get_model", lambda override="": "model-x")

    captured: dict[str, Any] = {}

    class _FakeAgentCtor:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(app_mod, "Agent", _FakeAgentCtor)

    session_id = "attach-mgr-sess"
    app_mod._sessions.pop(session_id, None)
    try:
        app_mod.get_or_create_agent(session_id, user_email="analyst@example.com")
        assert captured["session_manager"] is sentinel_manager
    finally:
        app_mod._sessions.pop(session_id, None)


# --------------------------------------------------------------------------------------
# _build_tools / SYSTEM_PROMPT — clear_all_memory registration + routing
# --------------------------------------------------------------------------------------


def test_build_tools_includes_clear_all_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # clear_all_memory must be registered alongside the other local tools so the model
    # can call it (the button-driven "clear all memory" prompt routes to it).
    monkeypatch.setattr(app_mod, "get_mcp_client", lambda: None)

    tools = app_mod._build_tools()

    assert app_mod.clear_all_memory in tools
    # create_profile is registered between enrich_profile and clear_all_memory.
    assert tools == [
        app_mod.current_time,
        app_mod.retrieve_profiles,
        app_mod.enrich_profile,
        app_mod.create_profile,
        app_mod.clear_all_memory,
    ]


def test_system_prompt_routes_clear_memory_through_tool() -> None:
    # The prompt must instruct the model to call clear_all_memory (never refuse) when the
    # analyst asks to clear/forget all memory, and not confuse it with enrich_profile.
    prompt = app_mod._build_system_prompt()

    assert "clear_all_memory" in prompt
    assert "forget everything" in prompt
    assert "MUST call clear_all_memory" in prompt
    # Explicitly disambiguated from enrich_profile.
    assert "Do NOT confuse clear_all_memory with enrich_profile" in prompt


# --------------------------------------------------------------------------------------
# POST /invocations — orphaned-interrupt fallback for the clear_memory action
# No cached agent (container recycled): on approval the deletion is reconstructed from
# session_id + user_email and run directly; on rejection nothing is deleted.
# --------------------------------------------------------------------------------------


class _ClearSpy:
    """Records clear_memory calls and returns a scripted confirmation."""

    def __init__(self, confirmation: str = "All memory cleared. __NEW_SESSION_REQUIRED__") -> None:
        self.confirmation = confirmation
        self.calls: list[dict[str, Any]] = []

    def __call__(self, session_id: str, user_email: str) -> str:
        self.calls.append({"session_id": session_id, "user_email": user_email})
        return self.confirmation


def test_resume_orphaned_clear_memory_approved_calls_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No cached agent + approved + action="clear_memory": the deletion runs directly via
    # the clear_memory helper (reconstructed from session_id + user_email) and its result
    # is returned.
    session_id = "orphaned-clear-approve"
    app_mod._sessions.pop(session_id, None)
    spy = _ClearSpy()
    monkeypatch.setattr(app_mod, "clear_memory", spy)

    result = _invoke_json(
        {
            "session_id": session_id,
            "action": "clear_memory",
            "user_email": "analyst@example.com",
            "responses": [{"interrupt_id": "int-1", "response": "yes"}],
        }
    )

    assert result["status"] == "success"
    assert result["response"] == "All memory cleared. __NEW_SESSION_REQUIRED__"
    assert spy.calls == [
        {"session_id": session_id, "user_email": "analyst@example.com"}
    ]


def test_resume_orphaned_clear_memory_rejected_makes_no_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No cached agent + rejected + action="clear_memory": no deletion, cancellation msg.
    session_id = "orphaned-clear-reject"
    app_mod._sessions.pop(session_id, None)
    spy = _ClearSpy()
    monkeypatch.setattr(app_mod, "clear_memory", spy)

    result = _invoke_json(
        {
            "session_id": session_id,
            "action": "clear_memory",
            "user_email": "analyst@example.com",
            "responses": [{"interrupt_id": "int-1", "response": "no"}],
        }
    )

    assert result["status"] == "success"
    assert "cancelled" in result["response"].lower()
    assert "no changes were made" in result["response"].lower()
    assert spy.calls == []

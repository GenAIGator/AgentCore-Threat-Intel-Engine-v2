"""Offline unit tests for the create_profile HITL tool + launch_builder helper.

No AWS access: the dedup check is stubbed via monkeypatch, and the builder invoke uses a
fake ``bedrock-agentcore`` client. Covers dedup-first short-circuit, the approve/reject
HITL gate, and the fire-and-forget launch payload.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import tools.create_tools as ct
from profile_dedup import DuplicateVerdict


class _FakeToolContext:
    """A tool_context whose interrupt() returns a preset approval response."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.interrupt_calls: list[tuple[str, dict[str, Any]]] = []

    def interrupt(self, name: str, reason: dict[str, Any]) -> Any:
        self.interrupt_calls.append((name, reason))
        return self._response


class _FakeAgentCoreClient:
    """Captures invoke_agent_runtime calls instead of hitting AWS."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def invoke_agent_runtime(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"statusCode": 202}


def _no_duplicate(*_a: Any, **_k: Any) -> DuplicateVerdict:
    return DuplicateVerdict(is_duplicate=False, distance=0.9)


def _is_duplicate(*_a: Any, **_k: Any) -> DuplicateVerdict:
    return DuplicateVerdict(
        is_duplicate=True,
        reason="normalized",
        existing_profile_id="0ktapus",
        existing_name="0ktapus",
        detail="A profile for '0ktapus' already exists. Use enrich_profile instead.",
    )


# --- dedup short-circuits BEFORE any interrupt/launch ---------------------------------


def test_create_profile_stops_on_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "check_duplicate", _is_duplicate)
    ctx = _FakeToolContext("yes")

    result = ct.create_profile(
        ctx, profile_id="scattered_spider", name="Scattered Spider", intent="Okta phishing"
    )

    assert "already exists" in result
    # Duplicate detection must happen BEFORE any approval interrupt is raised.
    assert ctx.interrupt_calls == []


# --- HITL gate ------------------------------------------------------------------------


def test_create_profile_rejected_launches_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "check_duplicate", _no_duplicate)
    launched: list[Any] = []
    monkeypatch.setattr(ct, "launch_builder", lambda **kw: launched.append(kw) or "started")

    ctx = _FakeToolContext("no")
    result = ct.create_profile(
        ctx, profile_id="volt_typhoon", name="Volt Typhoon", intent="China LOTL"
    )

    assert "cancelled" in result.lower()
    assert launched == []  # rejection => no launch
    assert len(ctx.interrupt_calls) == 1
    # The interrupt name prefix drives the frontend action.
    assert ctx.interrupt_calls[0][0].startswith("create_profile-")
    assert ctx.interrupt_calls[0][1]["action"] == "create_profile"


def test_create_profile_approved_launches_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "check_duplicate", _no_duplicate)
    captured: list[dict[str, Any]] = []

    def _fake_launch(**kwargs: Any) -> str:
        captured.append(kwargs)
        return "Creation of the 'Volt Typhoon' profile ... has started."

    monkeypatch.setattr(ct, "launch_builder", _fake_launch)

    ctx = _FakeToolContext("yes")
    result = ct.create_profile(
        ctx,
        profile_id="Volt Typhoon",  # exercises normalization to volt_typhoon
        name="Volt Typhoon",
        intent="China LOTL",
        country="China",
        aliases=["Vanguard Panda"],
        user_email="a@b.com",
    )

    assert "has started" in result
    assert len(captured) == 1
    assert captured[0]["profile_id"] == "volt_typhoon"
    assert captured[0]["attribution"] == {"country": "China"}
    assert captured[0]["aliases"] == ["Vanguard Panda"]
    assert captured[0]["requested_by"] == "a@b.com"


def test_create_profile_requires_id_and_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "check_duplicate", _no_duplicate)
    ctx = _FakeToolContext("yes")
    assert "needs at least" in ct.create_profile(ctx, profile_id="", name="", intent="x")


# --- launch_builder payload -----------------------------------------------------------


def test_launch_builder_builds_expected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    arn = "arn:aws:bedrock-agentcore:us-east-1:1:runtime/B"
    monkeypatch.setattr(ct, "BUILDER_RUNTIME_ARN", arn)
    client = _FakeAgentCoreClient()

    msg = ct.launch_builder(
        profile_id="volt_typhoon",
        name="Volt Typhoon",
        intent="China LOTL",
        attribution={"country": "China"},
        aliases=["Vanguard Panda"],
        requested_by="a@b.com",
        client=client,
    )

    # The invoke fires on a detached daemon thread; join it before asserting.
    assert ct._LAST_INVOKE_THREAD is not None
    ct._LAST_INVOKE_THREAD.join(timeout=5)

    assert "has started" in msg
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["agentRuntimeArn"].endswith("/B")
    # AgentCore requires runtimeSessionId to be at least 33 characters.
    assert call["runtimeSessionId"].startswith("build-")
    assert len(call["runtimeSessionId"]) >= 33
    payload = json.loads(call["payload"].decode("utf-8"))
    assert payload["action"] == "create_profile"
    assert payload["profile_id"] == "volt_typhoon"
    assert payload["attribution"] == {"country": "China"}


def test_launch_builder_session_id_meets_min_length(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: AgentCore rejects runtimeSessionId < 33 chars. A short profile_id like
    # "team_pcp" must NOT produce a too-short session id.
    arn = "arn:aws:bedrock-agentcore:us-east-1:1:runtime/B"
    monkeypatch.setattr(ct, "BUILDER_RUNTIME_ARN", arn)
    client = _FakeAgentCoreClient()
    ct.launch_builder(profile_id="team_pcp", name="TeamPCP", intent="x", client=client)
    assert ct._LAST_INVOKE_THREAD is not None
    ct._LAST_INVOKE_THREAD.join(timeout=5)
    assert len(client.calls[0]["runtimeSessionId"]) >= 33


def test_launch_builder_unconfigured_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "BUILDER_RUNTIME_ARN", "")
    with pytest.raises(RuntimeError):
        ct.launch_builder(profile_id="x", name="X", intent="y", client=_FakeAgentCoreClient())

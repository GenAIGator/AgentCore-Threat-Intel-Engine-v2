"""Integration-style verification of the retrieve-then-generate flow (task 7.4).

A live AWS DynamoDB vector table and Bedrock generation are not available in this
environment, so these tests verify the retrieve-then-generate wiring at the logic level
with fakes/monkeypatches — NO live AWS calls. They cover the seam between the
``retrieve_profiles`` grounding tool (task 6) and the per-session Strands agent factory
(task 7.1) that together implement Requirement 3 (retrieve, then generate a cited answer):

- ``retrieve_profiles`` end-to-end (Requirements 3.1, 3.3, 2.1, 2.4, 2.6): ``embed_text``
  is monkeypatched to a fixed 1024-dim vector and ``dynamodb_client`` to a fake whose
  ``search_vectors`` returns a small ``SearchResults`` fixture (three shards, some at/below
  and some above the relevance threshold). We assert the tool returns a citation-tagged
  context block carrying Name/ProfileId/FileType/Content for the relevant shards and
  excludes the above-threshold shard. The tool is invoked through its ``__wrapped__``
  so the plain function logic is exercised without the Strands tool runtime.

- Agent wiring (Requirements 3.5, 8.2, 8.4): ``_build_tools`` registers ``retrieve_profiles``
  and ``current_time`` (and no MCP web-search client while ``AGENTCORE_GATEWAY_URL`` is
  unset), and ``get_or_create_agent`` caches one agent per ``session_id``. The Strands
  ``Agent`` is replaced with a fake so no real Bedrock model is constructed or invoked.

- The retrieve -> cited-context -> generate ordering at the logic level (Requirements
  3.1, 3.2, 3.3): a fake agent calls the (monkeypatched) ``retrieve_profiles`` first, then emits
  a grounded answer that cites the retrieved actors, and ``stream_agent_response`` surfaces
  that answer as ``{"content": ...}`` frames followed by a terminal ``{"done": True}``.

Anything that needs actual Bedrock generation or a live vector index (semantic ranking,
index warm-up against real data) is out of scope here and is deferred to task 14
(integration verification).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from strands_tools import current_time

import agentcore_app as app_mod
import tools.retrieval_tools as rt
from tools.retrieval_tools import retrieve_profiles

# --------------------------------------------------------------------------------------
# Fixtures / fakes
# --------------------------------------------------------------------------------------

# A three-shard SearchResults fixture shaped exactly like a DynamoDB SearchVectors
# response: each match is {"Item": <AttributeValue map>, "Score": <COSINE distance>}.
# 0ktapus (0.08) and volt-typhoon (0.55) are at/below the 0.6 relevance threshold and must
# survive; 8base (1.4) is above it and must be dropped (Requirement 2.6).
_SEARCH_RESULTS_FIXTURE: dict[str, Any] = {
    "SearchResults": [
        {
            "Item": {
                "ProfileId": {"S": "0ktapus"},
                "Name": {"S": "0ktapus"},
                "FileType": {"S": "detection"},
                "Content": {"S": "SMS phishing kit harvesting Okta credentials."},
            },
            "Score": 0.08,
        },
        {
            "Item": {
                "ProfileId": {"S": "volt-typhoon"},
                "Name": {"S": "Volt Typhoon"},
                "FileType": {"S": "tactics_mitre"},
                "Content": {"S": "Living-off-the-land intrusions vs critical infra (T1059)."},
            },
            "Score": 0.55,
        },
        {
            "Item": {
                "ProfileId": {"S": "8base"},
                "Name": {"S": "8Base"},
                "FileType": {"S": "summary"},
                "Content": {"S": "Unrelated ransomware crew - filtered out as low relevance."},
            },
            "Score": 1.4,
        },
    ]
}


class _FakeDdbClient:
    """Fake DynamoDB client whose search_vectors returns a scripted response."""

    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def search_vectors(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self._response


def _call_retrieve(**kwargs: Any) -> str:
    """Invoke the @tool-wrapped retrieve_profiles with plain kwargs via __wrapped__."""
    func = getattr(rt.retrieve_profiles, "__wrapped__", None)
    assert callable(func), "retrieve_profiles must expose its wrapped function"
    return func(**kwargs)


def _patch_retrieval(
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, Any] = _SEARCH_RESULTS_FIXTURE,
) -> _FakeDdbClient:
    """Monkeypatch embed_text -> fixed vector and dynamodb_client -> a fake. No AWS."""
    fake = _FakeDdbClient(response)
    monkeypatch.setattr(rt, "embed_text", lambda _query: [0.01] * 1024)
    monkeypatch.setattr(rt, "dynamodb_client", lambda: fake)
    return fake


# --------------------------------------------------------------------------------------
# retrieve_profiles end-to-end — retrieve step of retrieve-then-generate
# (Requirements 3.1, 3.3, 2.1, 2.4, 2.6)
# --------------------------------------------------------------------------------------


def test_retrieve_returns_cited_context_for_relevant_shards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _patch_retrieval(monkeypatch)

    context = _call_retrieve(query="who runs the okta phishing kit?")

    # Exactly one SearchVectors call was made against the fake (no AWS).
    assert len(fake.calls) == 1
    assert context != rt.EMPTY_CONTEXT

    # Both relevant shards contribute citation metadata + content (Requirements 2.4, 3.3).
    assert "Name=0ktapus" in context
    assert "ProfileId=0ktapus" in context
    assert "FileType=detection" in context
    assert "SMS phishing kit harvesting Okta credentials" in context

    assert "Name=Volt Typhoon" in context
    assert "ProfileId=volt-typhoon" in context
    assert "FileType=tactics_mitre" in context
    assert "Living-off-the-land intrusions" in context

    # The two survivors are numbered so the model can attribute per-source.
    assert "[1]" in context
    assert "[2]" in context


def test_retrieve_excludes_shard_above_relevance_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_retrieval(monkeypatch)

    context = _call_retrieve(query="okta phishing")

    # 8base scored 1.4 > 0.6 threshold and must not appear (Requirement 2.6).
    assert "8base" not in context
    assert "8Base" not in context
    assert "ransomware crew" not in context
    # Only the two qualifying shards are rendered.
    assert "[3]" not in context


def test_retrieve_embeds_query_and_sends_vector_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _patch_retrieval(monkeypatch)

    _call_retrieve(query="china critical infrastructure ttps")

    request = fake.calls[0]
    # The query was embedded to a 1024-dim plain-list SearchVector (Requirement 2.1).
    assert len(request["SearchVector"]) == 1024
    assert request["SearchVector"][0] == {"N": str(0.01)}
    # Ranked search over the configured index (no HASH key), default Top K.
    assert request["IndexName"]
    assert request["TopK"] == rt.DEFAULT_TOP_K


def test_retrieve_returns_sentinel_when_all_shards_below_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every match is above the relevance threshold -> empty context sentinel so the
    # agent falls back rather than answering from low-quality matches (Requirement 2.6).
    only_far = {
        "SearchResults": [
            {"Item": {"ProfileId": {"S": "x"}, "Content": {"S": "irrelevant"}}, "Score": 1.9},
        ]
    }
    _patch_retrieval(monkeypatch, response=only_far)

    assert _call_retrieve(query="totally unrelated") == rt.EMPTY_CONTEXT


# --------------------------------------------------------------------------------------
# Agent wiring — the generate step is grounded by the retrieve tool
# (Requirements 3.5, 8.2, 8.4)
# --------------------------------------------------------------------------------------


def test_build_tools_registers_retrieve_and_current_time_without_web_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With no gateway configured, no MCP web-search client is added (task 8 wires that).
    monkeypatch.setattr(app_mod, "get_mcp_client", lambda: None)

    tools = app_mod._build_tools()

    assert retrieve_profiles in tools
    assert current_time in tools
    assert app_mod.enrich_profile in tools
    assert app_mod.create_profile in tools
    assert app_mod.clear_all_memory in tools
    # Only the local tools (current_time, retrieve_profiles, enrich_profile,
    # create_profile, clear_all_memory) — no MCP client object.
    assert len(tools) == 5


def test_build_tools_appends_mcp_client_when_gateway_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel_client = object()
    monkeypatch.setattr(app_mod, "get_mcp_client", lambda: sentinel_client)

    tools = app_mod._build_tools()

    assert retrieve_profiles in tools
    assert current_time in tools
    assert sentinel_client in tools


class _FakeAgent:
    """Minimal stand-in for a Strands Agent so no real Bedrock model is built."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.tools = kwargs.get("tools", [])
        self.system_prompt = kwargs.get("system_prompt", "")


def _patch_fake_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Agent + get_model so agent construction touches no AWS/Bedrock."""
    monkeypatch.setattr(app_mod, "Agent", _FakeAgent)
    monkeypatch.setattr(app_mod, "get_model", lambda override="": "fake-model-id")
    monkeypatch.setattr(app_mod, "get_mcp_client", lambda: None)


def test_get_or_create_agent_registers_retrieve_tool_without_bedrock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_fake_agent(monkeypatch)
    app_mod._sessions.clear()

    agent = app_mod.get_or_create_agent("sess-wiring")

    assert isinstance(agent, _FakeAgent)
    # The grounding tool is registered so the agent can retrieve before generating.
    assert retrieve_profiles in agent.tools
    assert current_time in agent.tools
    # System prompt drives retrieve-then-generate + citation behavior (Reqs 3.1-3.3).
    assert "retrieve_profiles" in agent.system_prompt
    assert "CITATION RULES" in agent.system_prompt

    app_mod._sessions.clear()


def test_get_or_create_agent_caches_by_session_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_fake_agent(monkeypatch)
    app_mod._sessions.clear()

    first = app_mod.get_or_create_agent("sess-A")
    same = app_mod.get_or_create_agent("sess-A")
    other = app_mod.get_or_create_agent("sess-B")

    # Same session id returns the identical cached instance; a new id gets a new agent.
    assert same is first
    assert other is not first
    assert app_mod._sessions["sess-A"] is first
    assert app_mod._sessions["sess-B"] is other

    app_mod._sessions.clear()


# --------------------------------------------------------------------------------------
# retrieve -> cited-context -> generate ordering at the logic level
# (Requirements 3.1, 3.2, 3.3, 8.2) — no live Bedrock
# --------------------------------------------------------------------------------------


def _events_from_sse(frames: list[str]) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for frame in frames:
        assert frame.startswith("data: ")
        assert frame.endswith("\n\n")
        payloads.append(json.loads(frame[len("data: ") : -2]))
    return payloads


class _RetrieveThenGenerateAgent:
    """Fake agent that retrieves first, then streams a grounded, cited answer.

    Mirrors the real retrieve-then-generate contract without a Bedrock call: on
    stream_async it invokes the (monkeypatched) retrieve_profiles tool, records that the
    retrieval happened before any text was produced, then yields answer deltas that cite
    the retrieved actors, followed by a terminal result event.
    """

    def __init__(self, **_kwargs: Any) -> None:
        self._interrupt_state = _FakeInterruptState()
        self.retrieved_context: str | None = None

    async def stream_async(self, prompt: str) -> AsyncIterator[dict[str, Any]]:
        # Retrieve step (must precede generation — Requirement 3.1).
        self.retrieved_context = _call_retrieve(query=prompt)
        # Generate step: a grounded answer citing the retrieved actors (Reqs 3.2, 3.3).
        yield {"data": "Based on the knowledge base: "}
        yield {"data": "0ktapus runs the Okta phishing kit; "}
        yield {"data": "Volt Typhoon targets critical infrastructure."}
        yield {"result": _FakeResult(stop_reason="end_turn")}


class _FakeInterruptState:
    def __init__(self, activated: bool = False) -> None:
        self.activated = activated

    def deactivate(self) -> None:
        self.activated = False


class _FakeResult:
    def __init__(self, stop_reason: str = "end_turn", interrupts: list[Any] | None = None) -> None:
        self.stop_reason = stop_reason
        self.interrupts = interrupts or []


def test_stream_retrieves_then_generates_cited_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    _patch_retrieval(monkeypatch)
    agent = _RetrieveThenGenerateAgent()
    monkeypatch.setattr(app_mod, "get_or_create_agent", lambda *a, **k: agent)

    async def _drain() -> list[str]:
        return [
            frame
            async for frame in app_mod.stream_agent_response(
                "who runs the okta phishing kit?", session_id="sess-flow"
            )
        ]

    payloads = _events_from_sse(asyncio.run(_drain()))

    # Retrieval ran and produced grounding context (retrieve happened, Requirement 3.1).
    assert agent.retrieved_context is not None
    assert agent.retrieved_context != rt.EMPTY_CONTEXT
    assert "0ktapus" in agent.retrieved_context

    # The streamed answer cites the retrieved actors, then terminates cleanly (Reqs 3.3, 8.2).
    content = "".join(p["content"] for p in payloads if "content" in p)
    assert "0ktapus" in content
    assert "Volt Typhoon" in content
    assert payloads[-1] == {"done": True}

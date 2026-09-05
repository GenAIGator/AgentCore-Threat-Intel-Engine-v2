"""Unit tests for the managed Web Search MCP wiring (task 8.1).

Task 8.1 constructs the AgentCore managed Web Search client and registers it on the
agent's tool list. These tests pin that wiring at the logic level with NO live AWS,
Bedrock, or gateway calls — ``MCPClient`` and ``aws_iam_streamablehttp_client`` are
replaced with spies:

- ``get_mcp_client`` returns ``None`` when no gateway URL is configured, so the agent can
  still be built for local/testing runs without web search (Requirement 4.4 seam).
- ``get_mcp_client`` builds an ``MCPClient`` whose transport factory calls
  ``aws_iam_streamablehttp_client`` with ``endpoint=<gateway url>``, ``aws_region``, and
  ``aws_service="bedrock-agentcore"`` — i.e. SigV4/IAM auth against the AgentCore Gateway
  MCP target (Requirements 4.1, 8.4).
- ``_build_tools`` appends that MCP client to the agent's tool list so the WebSearch tool
  is available to the model alongside ``retrieve_profiles`` and ``current_time``
  (Requirement 8.4).

The ``get_mcp_client`` transport factory is a lambda that the real ``MCPClient`` only
invokes at connect time; the spy ``MCPClient`` invokes it eagerly so the arguments passed
to ``aws_iam_streamablehttp_client`` can be asserted without a real connection.
"""

from __future__ import annotations

from typing import Any

import pytest
from strands_tools import current_time

import agentcore_app as app_mod
from tools.retrieval_tools import retrieve_profiles


class _SpyMCPClient:
    """Stand-in for strands MCPClient that eagerly runs its transport factory.

    The real client defers the factory until connect; running it here lets the test
    capture the arguments handed to ``aws_iam_streamablehttp_client``.
    """

    def __init__(self, transport_factory: Any) -> None:
        self.transport_factory = transport_factory
        # Invoke the factory now so the underlying transport builder is exercised.
        self.transport = transport_factory()


class _SpyTransport:
    """Records the kwargs the transport builder was called with."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _patch_mcp(
    monkeypatch: pytest.MonkeyPatch, gateway_url: str, region: str
) -> list[dict[str, Any]]:
    """Wire spies for MCPClient + the IAM transport and pin the gateway URL/region.

    Returns a list that captures each ``aws_iam_streamablehttp_client`` call's kwargs.
    """
    calls: list[dict[str, Any]] = []

    def _fake_transport(**kwargs: Any) -> _SpyTransport:
        calls.append(kwargs)
        return _SpyTransport(**kwargs)

    monkeypatch.setattr(app_mod, "MCPClient", _SpyMCPClient)
    monkeypatch.setattr(app_mod, "aws_iam_streamablehttp_client", _fake_transport)
    monkeypatch.setattr(app_mod, "get_gateway_url", lambda: gateway_url)
    monkeypatch.setattr(app_mod, "AWS_REGION", region)
    return calls


# --------------------------------------------------------------------------------------
# get_mcp_client — no gateway configured (local/testing) (Requirement 4.4 seam)
# --------------------------------------------------------------------------------------


def test_get_mcp_client_returns_none_when_gateway_url_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_mcp(monkeypatch, gateway_url="", region="us-east-1")

    client = app_mod.get_mcp_client()

    assert client is None
    # No transport was constructed when web search is not configured.
    assert calls == []


# --------------------------------------------------------------------------------------
# get_mcp_client — gateway configured: IAM/SigV4 against bedrock-agentcore
# (Requirements 4.1, 8.4)
# --------------------------------------------------------------------------------------


def test_get_mcp_client_builds_iam_client_against_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway_url = "https://gw.example.com/mcp"
    calls = _patch_mcp(monkeypatch, gateway_url=gateway_url, region="us-east-1")

    client = app_mod.get_mcp_client()

    # An MCP client was constructed (not None) ...
    assert isinstance(client, _SpyMCPClient)
    # ... and its transport factory called the managed IAM streamable-HTTP client with
    # SigV4 auth against the AgentCore Gateway for the bedrock-agentcore service.
    assert len(calls) == 1
    assert calls[0] == {
        "endpoint": gateway_url,
        "aws_region": "us-east-1",
        "aws_service": "bedrock-agentcore",
    }


def test_get_mcp_client_uses_configured_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_mcp(
        monkeypatch, gateway_url="https://gw.example.com/mcp", region="us-west-2"
    )

    app_mod.get_mcp_client()

    # The region flows from config.AWS_REGION into the transport, not a hardcoded value.
    assert calls[0]["aws_region"] == "us-west-2"


# --------------------------------------------------------------------------------------
# _build_tools — the MCP web-search client is registered on the agent (Requirement 8.4)
# --------------------------------------------------------------------------------------


def test_build_tools_appends_constructed_mcp_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Drive the real get_mcp_client (via the spies) so this exercises the full 8.1 path:
    # construct the MCP client, then register it on the tool list.
    _patch_mcp(monkeypatch, gateway_url="https://gw.example.com/mcp", region="us-east-1")

    tools = app_mod._build_tools()

    # The local grounding + utility tools are present ...
    assert retrieve_profiles in tools
    assert current_time in tools
    # ... plus exactly one MCP web-search client so WebSearch is available to the model.
    mcp_clients = [t for t in tools if isinstance(t, _SpyMCPClient)]
    assert len(mcp_clients) == 1

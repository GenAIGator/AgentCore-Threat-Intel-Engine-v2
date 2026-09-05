"""Shared configuration for the Threat Intelligence Engine v2 agent.

All runtime configuration is read from environment variables. On AgentCore Runtime
these are injected by the CloudFormation stack; for local development they can be
placed in ``agent/.env``. Import ``config`` and read the module-level values, or call
:func:`get_config` for a snapshot dataclass.

Env vars (see design.md, Requirement 8.4):
    AWS_REGION              AWS region. Web Search MCP requires ``us-east-1``.
    DDB_TABLE_NAME          DynamoDB base table (``ThreatProfilesV2``).
    DDB_VECTOR_INDEX        Vector index name (``profile-embeddings``).
    EMBEDDING_MODEL         Titan embeddings model id.
    EMBEDDING_DIMENSIONS    Embedding dimensionality (1024 for Titan v2).
    MODEL_ID                Generation model id (Claude Sonnet).
    AGENTCORE_GATEWAY_URL   AgentCore Gateway MCP URL for web search.
    AGENTCORE_MEMORY_ID     AgentCore Memory id for conversation continuity.
    BUILDER_RUNTIME_ARN     ARN of the autonomous profile-builder AgentCore Runtime,
                            invoked fire-and-forget by the create_profile tool.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Defaults chosen to match design.md. Empty strings mark values that must be
# supplied by the deployment environment before the dependent feature is used.
DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_DDB_TABLE_NAME = "ThreatProfilesV2"
DEFAULT_DDB_VECTOR_INDEX = "profile-embeddings"
DEFAULT_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
DEFAULT_EMBEDDING_DIMENSIONS = 1024
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-6"


def _get_str(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Config:
    """Immutable snapshot of the agent configuration."""

    aws_region: str
    ddb_table_name: str
    ddb_vector_index: str
    embedding_model: str
    embedding_dimensions: int
    model_id: str
    agentcore_gateway_url: str
    agentcore_memory_id: str
    builder_runtime_arn: str


def get_config() -> Config:
    """Read the current environment into a :class:`Config` snapshot."""
    return Config(
        aws_region=_get_str("AWS_REGION", DEFAULT_AWS_REGION),
        ddb_table_name=_get_str("DDB_TABLE_NAME", DEFAULT_DDB_TABLE_NAME),
        ddb_vector_index=_get_str("DDB_VECTOR_INDEX", DEFAULT_DDB_VECTOR_INDEX),
        embedding_model=_get_str("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL),
        embedding_dimensions=_get_int("EMBEDDING_DIMENSIONS", DEFAULT_EMBEDDING_DIMENSIONS),
        model_id=_get_str("MODEL_ID", DEFAULT_MODEL_ID),
        agentcore_gateway_url=_get_str("AGENTCORE_GATEWAY_URL", ""),
        agentcore_memory_id=_get_str("AGENTCORE_MEMORY_ID", ""),
        builder_runtime_arn=_get_str("BUILDER_RUNTIME_ARN", ""),
    )


# Module-level convenience values (evaluated at import time).
AWS_REGION = _get_str("AWS_REGION", DEFAULT_AWS_REGION)
DDB_TABLE_NAME = _get_str("DDB_TABLE_NAME", DEFAULT_DDB_TABLE_NAME)
DDB_VECTOR_INDEX = _get_str("DDB_VECTOR_INDEX", DEFAULT_DDB_VECTOR_INDEX)
EMBEDDING_MODEL = _get_str("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL)
EMBEDDING_DIMENSIONS = _get_int("EMBEDDING_DIMENSIONS", DEFAULT_EMBEDDING_DIMENSIONS)
MODEL_ID = _get_str("MODEL_ID", DEFAULT_MODEL_ID)
AGENTCORE_GATEWAY_URL = _get_str("AGENTCORE_GATEWAY_URL", "")
AGENTCORE_MEMORY_ID = _get_str("AGENTCORE_MEMORY_ID", "")
BUILDER_RUNTIME_ARN = _get_str("BUILDER_RUNTIME_ARN", "")

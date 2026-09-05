"""Configuration for the autonomous profile-builder runtime.

Reads all settings from environment variables injected by the CloudFormation stack
(mirrors ``agent/src/config.py`` conventions). The builder shares the same table, models,
and web-search gateway as the main agent, and additionally knows its SNS failure topic.

Env vars:
    AWS_REGION              AWS region (web-search MCP requires us-east-1).
    DDB_TABLE_NAME          DynamoDB base table (ThreatProfilesV2).
    DDB_VECTOR_INDEX        Vector index name (profile-embeddings).
    EMBEDDING_MODEL         Titan embeddings model id.
    EMBEDDING_DIMENSIONS    Embedding dimensionality (1024 for Titan v2).
    MODEL_ID                Generation model id (Claude Sonnet).
    AGENTCORE_GATEWAY_URL   AgentCore Gateway MCP URL for web search.
    FAILURE_SNS_TOPIC_ARN   SNS topic for builder failure alerts (out-of-band).
    SECTION_MAX_RETRIES     Max regeneration attempts per section before failing (default 2).
"""

from __future__ import annotations

import os

DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_DDB_TABLE_NAME = "ThreatProfilesV2"
DEFAULT_DDB_VECTOR_INDEX = "profile-embeddings"
DEFAULT_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
DEFAULT_EMBEDDING_DIMENSIONS = 1024
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
DEFAULT_SECTION_MAX_RETRIES = 2


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


AWS_REGION = _get_str("AWS_REGION", DEFAULT_AWS_REGION)
DDB_TABLE_NAME = _get_str("DDB_TABLE_NAME", DEFAULT_DDB_TABLE_NAME)
DDB_VECTOR_INDEX = _get_str("DDB_VECTOR_INDEX", DEFAULT_DDB_VECTOR_INDEX)
EMBEDDING_MODEL = _get_str("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL)
EMBEDDING_DIMENSIONS = _get_int("EMBEDDING_DIMENSIONS", DEFAULT_EMBEDDING_DIMENSIONS)
MODEL_ID = _get_str("MODEL_ID", DEFAULT_MODEL_ID)
AGENTCORE_GATEWAY_URL = _get_str("AGENTCORE_GATEWAY_URL", "")
FAILURE_SNS_TOPIC_ARN = _get_str("FAILURE_SNS_TOPIC_ARN", "")
SECTION_MAX_RETRIES = _get_int("SECTION_MAX_RETRIES", DEFAULT_SECTION_MAX_RETRIES)

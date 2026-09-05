"""Titan Text Embeddings v2 helper for the Threat Intelligence Engine v2 agent.

This module wraps Amazon Bedrock's Titan Text Embeddings v2 model, producing the
1024-dimension embeddings that back the DynamoDB vector index (Requirements 2.1, 2.4).
Both the ingestion loader and the ``retrieve_profiles`` tool embed text through
:func:`embed_text` so that stored shard vectors and query vectors are generated
identically.

It also provides :func:`ensure_search_vectors_supported`, a guard that fails fast with
a clear, actionable message when the installed boto3 is too old to expose the
``SearchVectors`` API (``dynamodb.search_vectors``). That API is required for retrieval;
detecting its absence early avoids confusing ``AttributeError`` failures deep in a
search call.

Configuration (model id, dimensions, region) is read from :mod:`config`, which in turn
reads environment variables injected by the deployment stack.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import TYPE_CHECKING, Any

import boto3

from config import AWS_REGION, EMBEDDING_DIMENSIONS, EMBEDDING_MODEL

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_bedrock_runtime import BedrockRuntimeClient
    from mypy_boto3_dynamodb import DynamoDBClient


@lru_cache(maxsize=1)
def _bedrock_client() -> BedrockRuntimeClient:
    """Return a cached Bedrock runtime client used to generate embeddings."""
    return boto3.client("bedrock-runtime", region_name=AWS_REGION)


def ensure_search_vectors_supported(client: DynamoDBClient | None = None) -> None:
    """Verify the installed boto3 exposes the DynamoDB ``SearchVectors`` API.

    The vector-search retrieval path depends on ``dynamodb.search_vectors``, which is
    only present in newer boto3 releases (>= 1.43.88). When it is missing the caller is
    almost certainly on an older SDK or the wrong interpreter (e.g. a virtualenv that
    was not activated). Raise a clear :class:`RuntimeError` explaining how to fix it
    rather than letting an opaque ``AttributeError`` surface later.

    Args:
        client: An optional low-level DynamoDB client to inspect. When omitted a
            throwaway client is created for the check.

    Raises:
        RuntimeError: If the client lacks the ``search_vectors`` method.
    """
    ddb: Any = client if client is not None else boto3.client("dynamodb", region_name=AWS_REGION)
    if not hasattr(ddb, "search_vectors"):
        raise RuntimeError(
            f"This boto3 ({boto3.__version__}) has no DynamoDB search_vectors API, which "
            "is required for vector retrieval. Upgrade boto3 (needs >= 1.43.88) or run "
            "inside the project environment, e.g. `uv run ...` from agent/, so the "
            "pinned boto3 (~=1.43) is used."
        )


def embed_text(text: str) -> list[float]:
    """Embed ``text`` with Titan Text Embeddings v2 and return the vector.

    Produces a fixed-dimension embedding (1024 for Titan v2, per
    :data:`config.EMBEDDING_DIMENSIONS`) as a plain list of floats. The same function
    is used to embed shard content at ingestion time and query/enrichment text at
    request time so that the vectors compared by the index are always generated the
    same way.

    Args:
        text: The non-empty text to embed.

    Returns:
        The embedding as a ``list[float]`` of length :data:`config.EMBEDDING_DIMENSIONS`.

    Raises:
        ValueError: If ``text`` is empty or whitespace-only, or if the model returns an
            embedding whose dimensionality does not match the configured dimensions.
    """
    if not text or not text.strip():
        raise ValueError("embed_text requires non-empty text.")

    body = json.dumps({"inputText": text, "dimensions": EMBEDDING_DIMENSIONS})
    response = _bedrock_client().invoke_model(modelId=EMBEDDING_MODEL, body=body)
    payload = json.loads(response["body"].read())
    embedding = payload["embedding"]

    if len(embedding) != EMBEDDING_DIMENSIONS:
        raise ValueError(
            f"Titan returned a {len(embedding)}-dim embedding but "
            f"{EMBEDDING_DIMENSIONS} was requested; check EMBEDDING_MODEL / "
            "EMBEDDING_DIMENSIONS and the vector index Dimensions."
        )

    return [float(value) for value in embedding]

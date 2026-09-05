"""Unit tests for :mod:`embeddings`.

These tests avoid live AWS calls by injecting fake Bedrock/DynamoDB clients:
- ``embed_text`` is exercised against a fake Bedrock runtime that returns a canned
  Titan payload, so we verify the request shape and the parsing/validation of the
  response without network access.
- ``ensure_search_vectors_supported`` is exercised with stub clients that either
  expose or omit ``search_vectors`` (Requirements 2.1, 2.4).
"""

from __future__ import annotations

import io
import json

import pytest

import embeddings
from config import EMBEDDING_DIMENSIONS, EMBEDDING_MODEL


class _FakeBody:
    """Minimal stand-in for a botocore streaming body (only ``read`` is used)."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def read(self) -> bytes:
        return self._buf.read()


class _FakeBedrockClient:
    """Records the invoke_model call and returns a canned Titan embedding payload."""

    def __init__(self, embedding: list[float]) -> None:
        self._embedding = embedding
        self.last_call: dict[str, object] = {}

    def invoke_model(self, *, modelId: str, body: str) -> dict[str, object]:  # noqa: N803
        self.last_call = {"modelId": modelId, "body": body}
        payload = json.dumps({"embedding": self._embedding}).encode("utf-8")
        return {"body": _FakeBody(payload)}


@pytest.fixture(autouse=True)
def _clear_client_cache() -> None:
    """Ensure the lru_cached Bedrock client does not leak between tests."""
    embeddings._bedrock_client.cache_clear()
    yield
    embeddings._bedrock_client.cache_clear()


def _install_fake_bedrock(
    monkeypatch: pytest.MonkeyPatch, embedding: list[float]
) -> _FakeBedrockClient:
    fake = _FakeBedrockClient(embedding)
    monkeypatch.setattr(embeddings, "_bedrock_client", lambda: fake)
    return fake


def test_embed_text_returns_configured_dimension_vector(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install_fake_bedrock(monkeypatch, [0.5] * EMBEDDING_DIMENSIONS)

    vector = embeddings.embed_text("russian espionage credential theft")

    assert len(vector) == EMBEDDING_DIMENSIONS
    assert all(isinstance(v, float) for v in vector)
    # Request targets the configured Titan model and passes the requested dimensions.
    assert fake.last_call["modelId"] == EMBEDDING_MODEL
    sent = json.loads(fake.last_call["body"])
    assert sent == {
        "inputText": "russian espionage credential theft",
        "dimensions": EMBEDDING_DIMENSIONS,
    }


def test_embed_text_coerces_integers_to_floats(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_bedrock(monkeypatch, [0] * EMBEDDING_DIMENSIONS)

    vector = embeddings.embed_text("some text")

    assert all(isinstance(v, float) for v in vector)


@pytest.mark.parametrize("text", ["", "   ", "\n\t"])
def test_embed_text_rejects_empty_text(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    _install_fake_bedrock(monkeypatch, [0.0] * EMBEDDING_DIMENSIONS)

    with pytest.raises(ValueError, match="non-empty"):
        embeddings.embed_text(text)


def test_embed_text_rejects_dimension_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_bedrock(monkeypatch, [0.1] * (EMBEDDING_DIMENSIONS - 1))

    with pytest.raises(ValueError, match="embedding"):
        embeddings.embed_text("mismatched dims")


class _ClientWithSearch:
    def search_vectors(self, **_: object) -> dict[str, object]:
        return {}


class _ClientWithoutSearch:
    pass


def test_ensure_search_vectors_supported_passes_with_capable_client() -> None:
    # Should not raise.
    embeddings.ensure_search_vectors_supported(_ClientWithSearch())


def test_ensure_search_vectors_supported_raises_without_api() -> None:
    with pytest.raises(RuntimeError, match="search_vectors"):
        embeddings.ensure_search_vectors_supported(_ClientWithoutSearch())

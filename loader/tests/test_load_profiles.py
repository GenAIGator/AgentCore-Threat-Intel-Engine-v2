"""Unit tests for :mod:`load_profiles` item building (task 5.1).

These tests cover the pure/local behavior of the loader: DynamoDB ``AttributeValue``
serialization, single-item assembly, corpus walking, and per-file resilience. The Titan
embed call is monkeypatched to a deterministic stub so no AWS access is required
(importing the module also never touches AWS — clients are created lazily).

Coverage:
- ``metadata_to_attrs``: SS for Aliases/Category, BOOL for AiConfirmed, S for scalars,
  empty string sets skipped (data model in design.md).
- ``to_ddb_number_list``: embedding stored as ``{"L": [{"N": ...}]}``.
- ``build_item``: keys, Content, Embedding, RawJson, seed provenance (Reqs 1.2/1.3/1.4/6.2/7.3).
- ``build_item`` raises when the shard lacks id/file_type keys.
- ``iter_profile_files``: sorted ``*.json`` discovery (Req 1.1) + missing-dir error.
- ``iter_built_items`` / ``build_items``: skip + count bad files, respect ``--limit`` (Req 1.5).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import load_profiles


def _stub_embed(text: str) -> list[float]:
    """Deterministic, AWS-free embedding stub (length independent of config)."""
    return [float(len(text)), 0.5, -0.25]


@pytest.fixture(autouse=True)
def _no_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the Titan embed call so no test touches Bedrock."""
    monkeypatch.setattr(load_profiles, "embed_text", _stub_embed)


def _shard(file_type: str, **fields: Any) -> dict[str, Any]:
    return {
        "id": "testactor",
        "name": "Test Actor",
        "attribution": {"country": "Testland", "region": "Test Region"},
        "file_type": file_type,
        **fields,
    }


# --- metadata_to_attrs ----------------------------------------------------------------


def test_metadata_to_attrs_uses_string_set_for_aliases_and_category() -> None:
    metadata = {
        "ProfileId": "actor",
        "ShardId": "core_identity",
        "Aliases": ["A", "B"],
        "Category": ["Cybercrime"],
    }
    attrs = load_profiles.metadata_to_attrs(metadata)
    assert attrs["Aliases"] == {"SS": ["A", "B"]}
    assert attrs["Category"] == {"SS": ["Cybercrime"]}
    assert attrs["ProfileId"] == {"S": "actor"}
    assert attrs["ShardId"] == {"S": "core_identity"}


def test_metadata_to_attrs_uses_bool_for_ai_confirmed() -> None:
    attrs = load_profiles.metadata_to_attrs({"AiConfirmed": False})
    assert attrs["AiConfirmed"] == {"BOOL": False}


def test_metadata_to_attrs_skips_empty_string_set() -> None:
    attrs = load_profiles.metadata_to_attrs({"Aliases": ["", "  "]})
    assert "Aliases" not in attrs


# --- to_ddb_number_list ---------------------------------------------------------------


def test_to_ddb_number_list_wraps_in_l_of_n() -> None:
    attr = load_profiles.to_ddb_number_list([0.1, -0.2, 3.0])
    assert attr == {"L": [{"N": "0.1"}, {"N": "-0.2"}, {"N": "3.0"}]}


# --- build_item -----------------------------------------------------------------------


def test_build_item_has_keys_content_embedding_rawjson_and_provenance() -> None:
    shard = _shard("summary", summary="A short summary.")
    raw = json.dumps(shard)
    item = load_profiles.build_item(shard, raw_json=raw)

    # Keys (Req 1.2)
    assert item["ProfileId"] == {"S": "testactor"}
    assert item["ShardId"] == {"S": "summary"}
    assert item["FileType"] == {"S": "summary"}

    # Content is the deterministic derived text (Req 1.4)
    assert item["Content"] == {"S": "Test Actor (summary): A short summary."}

    # Embedding stored as list-of-number (Req 1.3), matching the stub
    assert item["Embedding"]["L"][1] == {"N": "0.5"}

    # RawJson preserved verbatim (Req 7.3)
    assert item["RawJson"] == {"S": raw}

    # Seed provenance (Req 6.2)
    assert item["Source"] == {"S": "seed"}
    assert item["UpdatedBy"] == {"S": "loader"}
    assert item["LastUpdated"]["S"]  # non-empty ISO-8601 string


def test_build_item_promotes_core_identity_metadata() -> None:
    shard = _shard(
        "core_identity",
        aliases=["Alpha", "Beta"],
        category=["Cybercrime"],
    )
    item = load_profiles.build_item(shard, raw_json=json.dumps(shard))
    assert item["Aliases"] == {"SS": ["Alpha", "Beta"]}
    assert item["Category"] == {"SS": ["Cybercrime"]}
    assert item["Country"] == {"S": "Testland"}
    assert item["Name"] == {"S": "Test Actor"}


def test_build_item_raises_when_missing_keys() -> None:
    with pytest.raises(ValueError):
        load_profiles.build_item({"name": "No Id", "summary": "x"}, raw_json="{}")


# --- iter_profile_files ---------------------------------------------------------------


def _write(dir_path: Path, name: str, payload: Any) -> Path:
    path = dir_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def test_iter_profile_files_returns_sorted_json(tmp_path: Path) -> None:
    _write(tmp_path, "b.json", _shard("summary", summary="b"))
    _write(tmp_path, "a.json", _shard("summary", summary="a"))
    _write(tmp_path, "ignore.txt", "not json")
    files = load_profiles.iter_profile_files(tmp_path)
    assert [p.name for p in files] == ["a.json", "b.json"]


def test_iter_profile_files_missing_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_profiles.iter_profile_files(tmp_path / "does-not-exist")


# --- iter_built_items / build_items (resilience + limit, Req 1.1/1.5) -----------------


def test_build_items_skips_bad_files_and_counts(tmp_path: Path) -> None:
    _write(tmp_path, "01_good.json", _shard("summary", summary="ok"))
    _write(tmp_path, "02_bad_json.json", "{ this is not valid json")
    _write(tmp_path, "03_not_object.json", [1, 2, 3])
    _write(tmp_path, "04_missing_keys.json", {"name": "no id or file_type"})
    _write(tmp_path, "05_good.json", _shard("detection", detection_opportunities=["x"]))

    result = load_profiles.build_items(tmp_path)
    assert result.succeeded == 2
    assert result.failed == 3
    assert len(result.items) == 2


def test_build_items_respects_limit(tmp_path: Path) -> None:
    for i in range(5):
        _write(tmp_path, f"{i}.json", _shard("summary", summary=f"s{i}"))
    result = load_profiles.build_items(tmp_path, limit=2)
    assert result.succeeded == 2
    assert len(result.items) == 2


def test_iter_built_items_yields_path_and_item(tmp_path: Path) -> None:
    _write(tmp_path, "a.json", _shard("summary", summary="a"))
    pairs = list(load_profiles.iter_built_items(tmp_path))
    assert len(pairs) == 1
    path, item = pairs[0]
    assert path.name == "a.json"
    assert item["ProfileId"] == {"S": "testactor"}


# --- write_items batch writer (task 5.2, Reqs 1.2/1.5/1.6) ----------------------------


class _FakeDynamoDBClient:
    """A minimal fake DynamoDB client recording ``batch_write_item`` calls.

    Optionally returns a slice of each batch as ``UnprocessedItems`` for the first
    ``fail_first_n`` calls, letting tests drive the unprocessed-item retry path without
    live AWS.
    """

    def __init__(self, *, unprocessed_per_call: list[int] | None = None) -> None:
        # unprocessed_per_call[i] = how many items to leave unprocessed on call i.
        self._unprocessed_per_call = unprocessed_per_call or []
        self.calls: list[dict[str, list[dict[str, Any]]]] = []

    def batch_write_item(
        self, *, RequestItems: dict[str, list[dict[str, Any]]]  # noqa: N803 - boto3 API name
    ) -> dict[str, Any]:
        self.calls.append(RequestItems)
        call_index = len(self.calls) - 1
        leave = (
            self._unprocessed_per_call[call_index]
            if call_index < len(self._unprocessed_per_call)
            else 0
        )
        if leave <= 0:
            return {"UnprocessedItems": {}}
        (table, requests), = RequestItems.items()
        return {"UnprocessedItems": {table: requests[:leave]}}


def _put_item(profile: str, shard: str) -> dict[str, dict[str, Any]]:
    return {"ProfileId": {"S": profile}, "ShardId": {"S": shard}}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make backoff instantaneous so retry tests stay fast."""
    monkeypatch.setattr(load_profiles.time, "sleep", lambda _seconds: None)


def _use_fake_client(
    monkeypatch: pytest.MonkeyPatch, client: _FakeDynamoDBClient
) -> None:
    monkeypatch.setattr(load_profiles, "_dynamodb_client", lambda: client)


def test_write_items_empty_returns_zero_without_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom() -> Any:
        raise AssertionError("client should not be created for an empty write")

    monkeypatch.setattr(load_profiles, "_dynamodb_client", _boom)
    assert load_profiles.write_items([]) == 0


def test_write_items_chunks_into_batches_of_25(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeDynamoDBClient()
    _use_fake_client(monkeypatch, fake)
    items = [_put_item("actor", f"shard{i}") for i in range(57)]

    written = load_profiles.write_items(items, table="T")

    assert written == 57
    # 57 -> batches of 25, 25, 7
    batch_sizes = [len(call["T"]) for call in fake.calls]
    assert batch_sizes == [25, 25, 7]
    # Every request is a PutRequest (upsert-by-key semantics, Req 1.6).
    assert all(
        "PutRequest" in req for call in fake.calls for req in call["T"]
    )


def test_write_items_retries_unprocessed_until_drained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First call leaves 2 unprocessed, second call leaves 1, third drains.
    fake = _FakeDynamoDBClient(unprocessed_per_call=[2, 1, 0])
    _use_fake_client(monkeypatch, fake)
    items = [_put_item("actor", f"s{i}") for i in range(3)]

    written = load_profiles.write_items(items, table="T")

    assert written == 3
    assert len(fake.calls) == 3
    # Retry payloads shrink to only the previously-unprocessed items.
    assert [len(call["T"]) for call in fake.calls] == [3, 2, 1]


def test_write_items_gives_up_after_max_retries_and_counts_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Always leave 1 item unprocessed -> exceeds the retry budget.
    always_stuck = [1] * (load_profiles.MAX_UNPROCESSED_RETRIES + 1)
    fake = _FakeDynamoDBClient(unprocessed_per_call=always_stuck)
    _use_fake_client(monkeypatch, fake)
    items = [_put_item("actor", f"s{i}") for i in range(3)]

    written = load_profiles.write_items(items, table="T")

    # One item never lands; the other two did on the first call.
    assert written == 2
    assert len(fake.calls) == load_profiles.MAX_UNPROCESSED_RETRIES + 1


def test_write_items_skips_failed_batch_without_aborting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _RaisingClient:
        def __init__(self) -> None:
            self.calls = 0

        def batch_write_item(self, **_kwargs: Any) -> dict[str, Any]:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("throttled hard")
            return {"UnprocessedItems": {}}

    client = _RaisingClient()
    monkeypatch.setattr(load_profiles, "_dynamodb_client", lambda: client)
    items = [_put_item("actor", f"s{i}") for i in range(30)]  # two batches: 25 + 5

    written = load_profiles.write_items(items, table="T")

    # First batch raised (25 lost), second batch (5) succeeded.
    assert written == 5
    assert client.calls == 2


# --- run() orchestration --------------------------------------------------------------


def test_run_builds_then_writes_and_reports_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "01_good.json", _shard("summary", summary="ok"))
    _write(tmp_path, "02_bad_json.json", "{ not valid json")
    _write(tmp_path, "03_good.json", _shard("detection", detection_opportunities=["x"]))

    captured: dict[str, Any] = {}

    def _fake_write(items: list[dict[str, Any]], *, table: Any = None) -> int:
        captured["count"] = len(items)
        return len(items)

    monkeypatch.setattr(load_profiles, "write_items", _fake_write)

    result = load_profiles.run(tmp_path)

    assert result.succeeded == 2
    assert result.failed == 1
    assert result.written == 2
    assert captured["count"] == 2


# --- CLI parsing / count_table_items / verify_idempotency (task 5.3, Req 1.6) --------


class _CountingClient:
    """Fake DynamoDB client returning a scripted sequence of Scan COUNT pages.

    Each entry in ``pages`` is ``(count, last_key)``: ``last_key`` is the
    ``LastEvaluatedKey`` to return (``None`` ends pagination). Records every ``scan``
    kwargs so tests can assert the paginated Select=COUNT contract.
    """

    def __init__(self, pages: list[tuple[int, dict[str, Any] | None]]) -> None:
        self._pages = pages
        self.scan_calls: list[dict[str, Any]] = []

    def scan(self, **kwargs: Any) -> dict[str, Any]:
        self.scan_calls.append(kwargs)
        count, last_key = self._pages[len(self.scan_calls) - 1]
        response: dict[str, Any] = {"Count": count}
        if last_key is not None:
            response["LastEvaluatedKey"] = last_key
        return response


def test_build_arg_parser_parses_all_flags() -> None:
    parser = load_profiles.build_arg_parser()
    args = parser.parse_args(
        [
            "--limit",
            "5",
            "--profiles-dir",
            "/tmp/profiles",
            "--table",
            "MyTable",
            "--verify-idempotency",
        ]
    )
    assert args.limit == 5
    assert args.profiles_dir == Path("/tmp/profiles")
    assert args.table == "MyTable"
    assert args.verify_idempotency is True


def test_build_arg_parser_defaults() -> None:
    args = load_profiles.build_arg_parser().parse_args([])
    assert args.limit is None
    assert args.profiles_dir is None
    assert args.table is None
    assert args.verify_idempotency is False


def test_count_table_items_paginates_and_sums(monkeypatch: pytest.MonkeyPatch) -> None:
    # Three pages: 25 + 25 + 7 = 57, following LastEvaluatedKey until it's absent.
    client = _CountingClient(
        pages=[
            (25, {"ProfileId": {"S": "a"}}),
            (25, {"ProfileId": {"S": "b"}}),
            (7, None),
        ]
    )
    monkeypatch.setattr(load_profiles, "_dynamodb_client", lambda: client)

    total = load_profiles.count_table_items("T")

    assert total == 57
    assert len(client.scan_calls) == 3
    # Every page requests Select=COUNT against the target table.
    assert all(call["Select"] == "COUNT" for call in client.scan_calls)
    assert all(call["TableName"] == "T" for call in client.scan_calls)
    # First page has no start key; later pages carry the prior LastEvaluatedKey.
    assert "ExclusiveStartKey" not in client.scan_calls[0]
    assert client.scan_calls[1]["ExclusiveStartKey"] == {"ProfileId": {"S": "a"}}
    assert client.scan_calls[2]["ExclusiveStartKey"] == {"ProfileId": {"S": "b"}}


def test_count_table_items_single_page(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _CountingClient(pages=[(3, None)])
    monkeypatch.setattr(load_profiles, "_dynamodb_client", lambda: client)
    assert load_profiles.count_table_items("T") == 3
    assert len(client.scan_calls) == 1


def test_verify_idempotency_stable_when_counts_equal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_calls: list[Any] = []

    def _fake_run(directory: Any = None, *, limit: Any = None, table: Any = None) -> Any:
        run_calls.append((directory, limit, table))
        return load_profiles.LoadResult(succeeded=10, failed=0, written=10)

    # Same count reported after each run -> stable (upsert produced no duplicates).
    counts = iter([10, 10])
    monkeypatch.setattr(load_profiles, "run", _fake_run)
    monkeypatch.setattr(load_profiles, "count_table_items", lambda _t=None: next(counts))

    result = load_profiles.verify_idempotency(limit=10, table="T")

    assert result.stable is True
    assert result.count_after_first == 10
    assert result.count_after_second == 10
    # run() invoked exactly twice against the same target/limit.
    assert len(run_calls) == 2
    assert run_calls == [(None, 10, "T"), (None, 10, "T")]


def test_verify_idempotency_unstable_when_counts_differ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        load_profiles,
        "run",
        lambda directory=None, *, limit=None, table=None: load_profiles.LoadResult(),
    )
    counts = iter([10, 20])  # count grew between runs -> not idempotent
    monkeypatch.setattr(load_profiles, "count_table_items", lambda _t=None: next(counts))

    result = load_profiles.verify_idempotency(table="T")

    assert result.stable is False
    assert result.count_after_first == 10
    assert result.count_after_second == 20


def test_main_runs_load_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def _fake_run(directory: Any = None, *, limit: Any = None, table: Any = None) -> Any:
        seen.update(directory=directory, limit=limit, table=table)
        return load_profiles.LoadResult()

    monkeypatch.setattr(load_profiles, "run", _fake_run)
    # Guard: verify_idempotency must NOT run without the flag.
    monkeypatch.setattr(
        load_profiles,
        "verify_idempotency",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not verify")),
    )

    code = load_profiles.main(["--limit", "3", "--table", "T"])

    assert code == 0
    assert seen == {"directory": None, "limit": 3, "table": "T"}


def test_main_verify_idempotency_returns_zero_when_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        load_profiles,
        "verify_idempotency",
        lambda directory=None, *, limit=None, table=None: load_profiles.IdempotencyResult(
            first=load_profiles.LoadResult(),
            second=load_profiles.LoadResult(),
            count_after_first=5,
            count_after_second=5,
        ),
    )
    assert load_profiles.main(["--verify-idempotency"]) == 0


def test_main_verify_idempotency_returns_one_when_unstable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        load_profiles,
        "verify_idempotency",
        lambda directory=None, *, limit=None, table=None: load_profiles.IdempotencyResult(
            first=load_profiles.LoadResult(),
            second=load_profiles.LoadResult(),
            count_after_first=5,
            count_after_second=6,
        ),
    )
    assert load_profiles.main(["--verify-idempotency"]) == 1

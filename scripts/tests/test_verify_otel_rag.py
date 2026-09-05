"""Offline unit tests for :mod:`scripts.verify_otel_rag`.

These tests exercise the **pure** logic of the OTEL RAG span verifier with no AWS /
network access, using realistic fixtures built from the real log-record shape:

- :func:`classify_log_message` / :func:`is_otel_span_record` — the trust gate that tells
  a genuine Strands-tracer OTEL **span** apart from other-scope OTEL records and from a
  plain application log line that merely *contains* the substring ``retrieve_profiles``
  (the critical proof that substring != span).
- :func:`extract_tool_calls_from_span` / :func:`extract_span_summary` — digging the
  ``retrieve_profiles`` tool call (and its ``input.query``) out of the double-encoded
  span payload, plus defensive handling of already-list content and malformed bodies.
- :func:`runtime_arn_to_log_group` — the ARN → log-group derivation.

boto3 is imported lazily inside the script's fetch functions, so importing the module
and running these tests requires neither boto3 nor AWS credentials.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Make the script importable as a top-level module (scripts/ is not a package).
_SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import verify_otel_rag as vor  # noqa: I001, E402  (import follows the sys.path setup above)


# --- Fixtures mirroring the real live-log shapes --------------------------------------


def _span_record(
    *,
    trace_id: str = "1a2b3c4d5e6f70819a0b1c2d3e4f5061",
    span_id: str = "a1b2c3d4e5f60718",
    session_id: str = "sess-12345",
    service_name: str = "ThreatIntelEngineV2Stack_ThreatIntelAgent.DEFAULT",
    query: str = "Russian ransomware-as-a-service group",
    content_as_list: bool = False,
    include_body: bool = True,
) -> dict[str, Any]:
    """Build a genuine Strands-tracer OTEL span record.

    The assistant message ``content`` is a JSON-ENCODED string (double-encoded, as in the
    real logs) unless ``content_as_list`` is set, which exercises the defensive
    already-a-list path.
    """
    tool_use_blocks = [
        {
            "toolUse": {
                "name": "retrieve_profiles",
                "input": {"query": query, "top_k": 10},
                "toolUseId": "tooluse_abc123",
            }
        }
    ]
    content: Any = tool_use_blocks if content_as_list else json.dumps(tool_use_blocks)
    record: dict[str, Any] = {
        "resource": {
            "attributes": {
                "telemetry.sdk.name": "opentelemetry",
                "telemetry.auto.version": "0.19.0-aws",
                "service.name": service_name,
            }
        },
        "scope": {"name": "strands.telemetry.tracer"},
        "traceId": trace_id,
        "spanId": span_id,
        "attributes": {
            "event.name": "strands.telemetry.tracer",
            "session.id": session_id,
        },
        "timeUnixNano": "1725470761000000000",
    }
    if include_body:
        record["body"] = {
            "output": {
                "messages": [
                    {"role": "assistant", "content": content},
                ]
            },
            "input": {"messages": []},
        }
    return record


def _span_message(**kwargs: Any) -> str:
    """A span record serialised the way CloudWatch stores the event ``message``."""
    return json.dumps(_span_record(**kwargs))


def _otel_exporter_message() -> str:
    """An OTEL record that is NOT a Strands span: exporter scope + empty/null ids."""
    return json.dumps(
        {
            "resource": {"attributes": {"telemetry.sdk.name": "opentelemetry"}},
            "scope": {"name": "opentelemetry.exporter.otlp.proto.http._log_exporter"},
            "traceId": "",
            "spanId": "0",
            "body": "Exporting 5 log record(s)",
        }
    )


_APP_LOG_LINE = (
    "2026-09-04 17:26:01,683 INFO [agentcore_app] handling tool call retrieve_profiles "
    "for session sess-12345 (query='Russian ransomware')"
)


# --- classify_log_message / is_otel_span_record ---------------------------------------


def test_genuine_span_classifies_as_otel_span() -> None:
    message = _span_message()
    assert vor.classify_log_message(message) == "otel_span"
    assert vor.is_otel_span_record(json.loads(message)) is True


def test_exporter_record_classifies_as_otel_other() -> None:
    message = _otel_exporter_message()
    assert vor.classify_log_message(message) == "otel_other"
    assert vor.is_otel_span_record(json.loads(message)) is False


def test_plain_app_log_with_substring_classifies_as_app_log() -> None:
    # The critical test: the line CONTAINS 'retrieve_profiles' but is NOT OTEL JSON.
    assert "retrieve_profiles" in _APP_LOG_LINE
    assert vor.classify_log_message(_APP_LOG_LINE) == "app_log"
    # And it must never masquerade as a span.
    try:
        parsed = json.loads(_APP_LOG_LINE)
    except ValueError:
        parsed = {}
    assert vor.is_otel_span_record(parsed) is False


def test_empty_and_zero_trace_ids_rejected() -> None:
    rec = _span_record()
    rec["traceId"] = ""
    assert vor.is_otel_span_record(rec) is False
    rec = _span_record()
    rec["spanId"] = "0"
    assert vor.is_otel_span_record(rec) is False
    rec = _span_record()
    rec["traceId"] = "00000000000000000000000000000000"
    assert vor.is_otel_span_record(rec) is False


def test_non_strands_scope_rejected_even_with_valid_ids() -> None:
    rec = _span_record()
    rec["scope"] = {"name": "botocore.credentials"}
    assert vor.is_otel_span_record(rec) is False
    assert vor.classify_log_message(json.dumps(rec)) == "otel_other"


def test_missing_sdk_name_treated_as_app_log() -> None:
    rec = _span_record()
    rec["resource"]["attributes"].pop("telemetry.sdk.name")
    assert vor.classify_log_message(json.dumps(rec)) == "app_log"


# --- extract_tool_calls_from_span / extract_span_summary ------------------------------


def test_extract_tool_calls_from_double_encoded_content() -> None:
    obj = _span_record(query="Okta phishing kit")
    calls = vor.extract_tool_calls_from_span(obj)
    assert len(calls) == 1
    assert calls[0]["name"] == "retrieve_profiles"
    assert calls[0]["input"]["query"] == "Okta phishing kit"
    assert calls[0]["toolUseId"] == "tooluse_abc123"


def test_extract_span_summary_fields() -> None:
    obj = _span_record(
        trace_id="deadbeefdeadbeefdeadbeefdeadbeef",
        session_id="sess-xyz",
        service_name="Svc.DEFAULT",
        query="ransomware group",
    )
    summary = vor.extract_span_summary(obj)
    assert summary["traceId"] == "deadbeefdeadbeefdeadbeefdeadbeef"
    assert summary["sessionId"] == "sess-xyz"
    assert summary["serviceName"] == "Svc.DEFAULT"
    assert summary["toolCalls"] == ["retrieve_profiles"]
    assert summary["hasRetrieveProfiles"] is True
    assert summary["timeUnixNano"] == "1725470761000000000"


def test_extract_tool_calls_when_content_already_list() -> None:
    # Defensive: content may already be a list rather than a JSON-encoded string.
    obj = _span_record(content_as_list=True, query="already a list")
    calls = vor.extract_tool_calls_from_span(obj)
    assert len(calls) == 1
    assert calls[0]["name"] == "retrieve_profiles"
    assert calls[0]["input"]["query"] == "already a list"


def test_extract_tool_calls_missing_body_returns_empty() -> None:
    obj = _span_record(include_body=False)
    assert vor.extract_tool_calls_from_span(obj) == []
    # And a malformed body must not throw either.
    obj_bad = _span_record()
    obj_bad["body"] = {"output": {"messages": "not-a-list"}}
    assert vor.extract_tool_calls_from_span(obj_bad) == []
    obj_bad2 = _span_record()
    obj_bad2["body"] = "totally not a dict"
    assert vor.extract_tool_calls_from_span(obj_bad2) == []


def test_summary_without_retrieve_profiles_is_false() -> None:
    obj = _span_record()
    obj["body"]["output"]["messages"] = [
        {
            "role": "assistant",
            "content": json.dumps(
                [{"toolUse": {"name": "current_time", "input": {}, "toolUseId": "t1"}}]
            ),
        }
    ]
    summary = vor.extract_span_summary(obj)
    assert summary["toolCalls"] == ["current_time"]
    assert summary["hasRetrieveProfiles"] is False


# --- runtime_arn_to_log_group ---------------------------------------------------------


def test_runtime_arn_to_log_group_derivation() -> None:
    arn = (
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/"
        "ThreatIntelEngineV2Stack_ThreatIntelAgent-abc123"
    )
    assert vor.runtime_arn_to_log_group(arn) == (
        "/aws/bedrock-agentcore/runtimes/"
        "ThreatIntelEngineV2Stack_ThreatIntelAgent-abc123-DEFAULT"
    )


def test_runtime_arn_to_log_group_empty_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        vor.runtime_arn_to_log_group("")


# --- classify_events (pure accumulation over a mixed batch) ---------------------------


def test_classify_events_counts_and_confirms() -> None:
    events = [
        {"message": _span_message(query="q1")},
        {"message": _otel_exporter_message()},
        {"message": _APP_LOG_LINE},
        {"message": _span_message(query="q2", trace_id="ffeeddccbbaa99887766554433221100")},
    ]
    scan = vor.classify_events(events, target_tool="retrieve_profiles", show_traces=5)
    assert scan.total_events == 4
    assert scan.otel_spans == 2
    assert scan.otel_other == 1
    assert scan.app_logs == 1
    assert scan.spans_with_tool == 2
    assert scan.confirmed is True
    assert len(scan.example_spans) == 2


def test_classify_events_show_traces_cap() -> None:
    events = [{"message": _span_message(query=f"q{i}")} for i in range(5)]
    scan = vor.classify_events(events, target_tool="retrieve_profiles", show_traces=2)
    assert scan.otel_spans == 5
    assert len(scan.example_spans) == 2


def test_resolve_log_group_precedence() -> None:
    # Explicit log group wins.
    assert vor.resolve_log_group(
        log_group="/explicit/group", runtime_arn="arn:.../runtime/x", stack_name="S"
    ) == "/explicit/group"
    # Runtime ARN next.
    assert vor.resolve_log_group(
        log_group=None,
        runtime_arn="arn:aws:bedrock-agentcore:us-east-1:1:runtime/Stack_Agent-ABC",
        stack_name="S",
    ) == "/aws/bedrock-agentcore/runtimes/Stack_Agent-ABC-DEFAULT"


def test_resolve_log_group_from_cfn_stack() -> None:
    class _FakeCfn:
        def describe_stacks(self, StackName: str) -> dict[str, Any]:  # noqa: N803 - boto3 arg
            return {
                "Stacks": [
                    {
                        "Outputs": [
                            {"OutputKey": "Other", "OutputValue": "nope"},
                            {
                                "OutputKey": "RuntimeArn",
                                "OutputValue": (
                                    "arn:aws:bedrock-agentcore:us-east-1:1:runtime/Stack_Agent-ZZZ"
                                ),
                            },
                        ]
                    }
                ]
            }

    group = vor.resolve_log_group(
        log_group=None, runtime_arn=None, stack_name="ThreatIntelEngineV2Stack",
        cfn_client=_FakeCfn(),
    )
    assert group == "/aws/bedrock-agentcore/runtimes/Stack_Agent-ZZZ-DEFAULT"


if __name__ == "__main__":  # pragma: no cover
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))


# --- Multi-agent discovery + selection (pure) -----------------------------------------


def test_agents_from_outputs_maps_known_runtime_outputs() -> None:
    outputs = {
        "RuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/S_ThreatIntelAgent-ABC",
        "BuilderRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/S_ProfileBuilder-XYZ",
        "SomethingElse": "ignored",
    }
    agents = vor.agents_from_outputs(outputs)
    labels = [a.label for a in agents]
    assert labels == ["main agent", "profile builder"]
    assert agents[0].log_group == (
        "/aws/bedrock-agentcore/runtimes/S_ThreatIntelAgent-ABC-DEFAULT"
    )
    assert agents[1].log_group == (
        "/aws/bedrock-agentcore/runtimes/S_ProfileBuilder-XYZ-DEFAULT"
    )


def test_agents_from_outputs_skips_missing() -> None:
    # Only the main runtime present (e.g. an older stack without the builder).
    agents = vor.agents_from_outputs(
        {"RuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/S_Agent-A"}
    )
    assert [a.label for a in agents] == ["main agent"]


class _FakeCfn:
    def __init__(self, outputs: dict[str, str]) -> None:
        self._outputs = outputs

    def describe_stacks(self, StackName: str) -> dict[str, Any]:  # noqa: N803 - boto3 arg
        return {
            "Stacks": [
                {"Outputs": [{"OutputKey": k, "OutputValue": v} for k, v in self._outputs.items()]}
            ]
        }


_BOTH_OUTPUTS = {
    "RuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/S_ThreatIntelAgent-A",
    "BuilderRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/S_ProfileBuilder-B",
}


def test_resolve_selected_agents_explicit_log_group_wins() -> None:
    agents = vor.resolve_selected_agents(
        log_group="/explicit/group", runtime_arn=None, stack_name="S",
        agent=None, menu=False,
    )
    assert len(agents) == 1
    assert agents[0].log_group == "/explicit/group"


def test_resolve_selected_agents_all_from_stack() -> None:
    agents = vor.resolve_selected_agents(
        log_group=None, runtime_arn=None, stack_name="S",
        agent="all", menu=False, cfn_client=_FakeCfn(_BOTH_OUTPUTS),
    )
    assert [a.label for a in agents] == ["main agent", "profile builder"]


def test_resolve_selected_agents_filters_main() -> None:
    agents = vor.resolve_selected_agents(
        log_group=None, runtime_arn=None, stack_name="S",
        agent="main", menu=False, cfn_client=_FakeCfn(_BOTH_OUTPUTS),
    )
    assert [a.label for a in agents] == ["main agent"]


def test_resolve_selected_agents_filters_builder() -> None:
    agents = vor.resolve_selected_agents(
        log_group=None, runtime_arn=None, stack_name="S",
        agent="builder", menu=False, cfn_client=_FakeCfn(_BOTH_OUTPUTS),
    )
    assert [a.label for a in agents] == ["profile builder"]


def test_resolve_selected_agents_unknown_agent_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        vor.resolve_selected_agents(
            log_group=None, runtime_arn=None, stack_name="S",
            agent="nope", menu=False, cfn_client=_FakeCfn(_BOTH_OUTPUTS),
        )

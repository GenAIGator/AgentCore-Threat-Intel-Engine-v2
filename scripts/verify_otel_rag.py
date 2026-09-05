#!/usr/bin/env python3
"""Confirm the deployed agent's RAG retrievals are captured as OpenTelemetry **spans**.

This script is run by an operator **against a live, deployed stack** to prove — from
CloudWatch Logs — that the agent's RAG tool calls (``retrieve_profiles`` against the
DynamoDB vector index) are being emitted as genuine OpenTelemetry (OTEL) **span**
records, not merely that the string ``retrieve_profiles`` shows up somewhere in the
plain application logs.

Why the distinction matters
----------------------------
The Bedrock AgentCore runtime log group
``/aws/bedrock-agentcore/runtimes/<RuntimeId>-DEFAULT`` interleaves **two** kinds of
lines:

* plain application logs (``logging`` output from the agent app), and
* OTEL log records emitted by the ``opentelemetry-instrument`` wrapper / the Strands
  telemetry tracer.

A raw ``retrieve_profiles`` substring is **not** proof that tracing works — it could just
be an app ``print``/``log.info``. The only trustworthy evidence is a parsed OTEL record
that carries ``resource.attributes."telemetry.sdk.name" == "opentelemetry"``, a
``scope.name == "strands.telemetry.tracer"``, and a valid (non-empty, non-``"0"``)
``traceId``/``spanId``. That triad is the gate implemented by
:func:`is_otel_span_record`.

To make the distinction *visible*, the script classifies every matched line three ways
via :func:`classify_log_message` — ``otel_span`` / ``otel_other`` / ``app_log`` — and
(under ``--compare``) also queries for lines merely *mentioning* the tool, so the summary
can state e.g. "of N lines mentioning retrieve_profiles, M were genuine OTEL spans and K
were plain app logs".

Pure logic (JSON classification, span-summary extraction, ARN→log-group derivation) is
factored out so it can be unit-tested with realistic fixtures and **no AWS/network**
(see ``scripts/tests/test_verify_otel_rag.py``). boto3 is imported lazily inside the
fetch functions so the pure helpers never require it.

Usage (against a deployed stack)::

    AWS_REGION=us-east-1 \\
    python scripts/verify_otel_rag.py --stack-name ThreatIntelEngineV2Stack --hours 6

Exit status: ``0`` when RAG retrievals are CONFIRMED as OTEL spans, ``2`` when NOT
CONFIRMED (queried the window but found no such spans), ``1`` on an operational error
(e.g. the log group does not exist).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

# --- OTEL log-record shape constants --------------------------------------------------
#
# Verified from a live log sample. OTEL records are JSON objects (the CloudWatch event
# ``message`` is a JSON string). The three fields below are what let us tell a genuine
# Strands agent span apart from other OTEL records (exporter/botocore/logging scopes)
# and from plain application log lines.
TELEMETRY_SDK_NAME = "opentelemetry"
STRANDS_TRACER_SCOPE = "strands.telemetry.tracer"

# The RAG tool name we headline on (the DynamoDB vector-search retrieval tool).
DEFAULT_TARGET_TOOL = "retrieve_profiles"

# ANSI colours (disabled automatically when stdout is not a TTY).
_ANSI = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


# --- Pure helpers (unit-testable without AWS) -----------------------------------------


def _dig(obj: Any, *path: str) -> Any:
    """Return a nested value at ``path`` from ``obj``, or ``None`` if any hop is missing.

    Defensive traversal used throughout: OTEL records nest fields (``resource.attributes``,
    ``scope.name``, ``body.output.messages``) and any of them may be absent or a
    non-dict, so this never raises.

    Args:
        obj: The object to traverse (expected to be nested dicts).
        *path: The sequence of dict keys to follow.

    Returns:
        The value at the end of ``path``, or ``None`` if any intermediate key is absent
        or a value along the way is not a dict.
    """
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _is_valid_trace_id(value: Any) -> bool:
    """True when ``value`` is a non-empty hex trace/span id and not the null id ``"0"``.

    Some OTEL log records (exporter errors, etc.) carry ``traceId == ""`` or
    ``spanId == "0"`` — those are not real spans, so they must be rejected.

    Args:
        value: The candidate ``traceId`` or ``spanId``.

    Returns:
        True only for a non-empty hex string that is not ``"0"`` (or all zeros).
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or v == "0":
        return False
    # All-zero ids (e.g. "00000000000000000000000000000000") are the OTEL "no trace"
    # sentinel — reject them too.
    if set(v) == {"0"}:
        return False
    try:
        int(v, 16)
    except ValueError:
        return False
    return True


def is_otel_span_record(obj: dict[str, Any]) -> bool:
    """Return True only for a genuine Strands-tracer OpenTelemetry **span** record.

    This is the trust gate that guarantees we are looking at OTEL span data and not a
    plain CloudWatch application log line. It requires **all** of:

    * ``resource.attributes."telemetry.sdk.name" == "opentelemetry"`` (this record was
      produced by the OTEL SDK), **and**
    * ``scope.name == "strands.telemetry.tracer"`` (it is an agent span, not an
      exporter/botocore/logging-scope OTEL record), **and**
    * a valid ``traceId`` **and** ``spanId`` — non-empty hex, not ``"0"`` /all-zero.

    Args:
        obj: A parsed OTEL log record (a ``dict``).

    Returns:
        True when ``obj`` is a valid Strands-tracer span record, else False.
    """
    if not isinstance(obj, dict):
        return False
    sdk_name = _dig(obj, "resource", "attributes", "telemetry.sdk.name")
    if sdk_name != TELEMETRY_SDK_NAME:
        return False
    if _dig(obj, "scope", "name") != STRANDS_TRACER_SCOPE:
        return False
    if not _is_valid_trace_id(obj.get("traceId")):
        return False
    if not _is_valid_trace_id(obj.get("spanId")):
        return False
    return True


def classify_log_message(message: str) -> str:
    """Classify a CloudWatch event ``message`` into one of three buckets.

    This three-way split is what lets the script report how many matched lines were
    *real* spans versus plain app logs (proving substring != span):

    * ``"otel_span"`` — parses as JSON and passes :func:`is_otel_span_record` (a genuine
      Strands-tracer span with a valid trace/span id).
    * ``"otel_other"`` — parses as JSON and is an OTEL record
      (``telemetry.sdk.name == "opentelemetry"``) but is **not** a Strands-tracer span
      (e.g. an exporter/botocore/logging-scope record, or an empty/``"0"`` trace id).
    * ``"app_log"`` — not OTEL JSON: a plain application log line, **even if** it
      contains the substring ``retrieve_profiles``.

    Args:
        message: The raw ``message`` string from a CloudWatch log event.

    Returns:
        One of ``"otel_span"``, ``"otel_other"``, or ``"app_log"``.
    """
    try:
        obj = json.loads(message)
    except (ValueError, TypeError):
        return "app_log"
    if not isinstance(obj, dict):
        return "app_log"
    if _dig(obj, "resource", "attributes", "telemetry.sdk.name") != TELEMETRY_SDK_NAME:
        # Valid JSON but not an OTEL record — treat as an app log line.
        return "app_log"
    return "otel_span" if is_otel_span_record(obj) else "otel_other"


def _coerce_message_content(content: Any) -> list[Any]:
    """Normalise a message ``content`` field into a list of content blocks.

    Strands span payloads encode assistant ``content`` in several shapes, all of which
    we must handle without throwing:

    * a JSON-encoded **string** (double-encoded) that parses to a list of blocks,
    * a **list** of blocks already,
    * a **dict** with a nested ``"content"`` key,
    * a JSON-encoded string that parses to a single dict.

    Args:
        content: The raw ``content`` value from a message.

    Returns:
        A list of content blocks (possibly empty). Never raises.
    """
    if content is None:
        return []
    if isinstance(content, str):
        try:
            parsed = json.loads(content)
        except (ValueError, TypeError):
            return []
        return _coerce_message_content(parsed)
    if isinstance(content, list):
        return content
    if isinstance(content, dict):
        # A dict may itself hold a nested "content" list, or be a single block.
        if "content" in content:
            return _coerce_message_content(content["content"])
        return [content]
    return []


def _tool_uses_from_blocks(blocks: list[Any]) -> list[dict[str, Any]]:
    """Extract ``{name, input, toolUseId}`` for every ``toolUse`` block in ``blocks``.

    Args:
        blocks: A list of content blocks (from :func:`_coerce_message_content`).

    Returns:
        One dict per ``toolUse`` block found, defensively defaulting missing fields.
    """
    calls: list[dict[str, Any]] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        tool_use = block.get("toolUse")
        if not isinstance(tool_use, dict):
            continue
        calls.append(
            {
                "name": tool_use.get("name"),
                "input": tool_use.get("input"),
                "toolUseId": tool_use.get("toolUseId"),
            }
        )
    return calls


def extract_tool_calls_from_span(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the tool calls recorded in a Strands-tracer span record.

    Digs into ``body.output.messages`` (falling back to ``body.input.messages``), finds
    assistant messages whose ``content`` encodes a list of content blocks, and returns
    ``{"name", "input", "toolUseId"}`` for each ``toolUse`` entry. Handles the several
    shapes ``content`` can take (JSON string, list, dict) via
    :func:`_coerce_message_content` and never throws on a malformed/missing body.

    Args:
        obj: A parsed OTEL Strands-tracer span record.

    Returns:
        A list of tool-call dicts (empty when the span records no tool calls).
    """
    calls: list[dict[str, Any]] = []
    for section in ("output", "input"):
        messages = _dig(obj, "body", section, "messages")
        if not isinstance(messages, list):
            continue
        for message in messages:
            if not isinstance(message, dict):
                continue
            # Tool calls live in assistant messages; be lenient about the role field
            # (it may be absent in some payload shapes).
            blocks = _coerce_message_content(message.get("content"))
            calls.extend(_tool_uses_from_blocks(blocks))
        if calls:
            # Prefer output messages; only fall back to input if output had none.
            break
    return calls


def extract_span_summary(obj: dict[str, Any]) -> dict[str, Any]:
    """Summarise a Strands-tracer span record into a small, JSON-friendly dict.

    Args:
        obj: A parsed OTEL Strands-tracer span record.

    Returns:
        A dict with ``traceId``, ``spanId``, ``sessionId`` (from
        ``attributes."session.id"``), ``serviceName`` (from
        ``resource.attributes."service.name"``), ``toolCalls`` (list of tool names),
        ``hasRetrieveProfiles`` (bool), and ``timeUnixNano`` if present.
    """
    tool_calls = extract_tool_calls_from_span(obj)
    tool_names = [c.get("name") for c in tool_calls if c.get("name")]
    return {
        "traceId": obj.get("traceId"),
        "spanId": obj.get("spanId"),
        "sessionId": _dig(obj, "attributes", "session.id"),
        "serviceName": _dig(obj, "resource", "attributes", "service.name"),
        "toolCalls": tool_names,
        "toolCallDetails": tool_calls,
        "hasRetrieveProfiles": DEFAULT_TARGET_TOOL in tool_names,
        "timeUnixNano": obj.get("timeUnixNano") or obj.get("observedTimeUnixNano"),
    }


def runtime_arn_to_log_group(arn: str) -> str:
    """Derive the runtime log group name from a Bedrock AgentCore runtime ARN.

    The runtime id is the part of the ARN after the last ``/``; the log group is
    ``/aws/bedrock-agentcore/runtimes/<runtime-id>-DEFAULT``.

    Args:
        arn: A runtime ARN, e.g.
            ``arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/Stack_Agent-abc123``.

    Returns:
        The derived log-group name.

    Raises:
        ValueError: If ``arn`` is empty or has no runtime-id segment.
    """
    if not arn or not arn.strip():
        raise ValueError("runtime ARN is empty")
    runtime_id = arn.strip().rsplit("/", 1)[-1]
    if not runtime_id:
        raise ValueError(f"could not extract runtime id from ARN: {arn!r}")
    return f"/aws/bedrock-agentcore/runtimes/{runtime_id}-DEFAULT"


# --- Scan accumulation (pure) ---------------------------------------------------------


@dataclass
class ScanResult:
    """Counts and example spans accumulated while classifying log events.

    Attributes:
        total_events: Every event returned by the fetch (before classification).
        otel_spans: Count classified as genuine Strands-tracer spans.
        otel_other: Count classified as other-scope / invalid-trace OTEL records.
        app_logs: Count classified as plain application log lines.
        spans_with_tool: Count of spans containing the target tool call.
        example_spans: Span summaries (capped by ``--show-traces``) for the report.
    """

    total_events: int = 0
    otel_spans: int = 0
    otel_other: int = 0
    app_logs: int = 0
    spans_with_tool: int = 0
    example_spans: list[dict[str, Any]] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        """True when at least one span recorded the target tool call."""
        return self.spans_with_tool > 0


@dataclass
class CompareResult:
    """Outcome of the secondary "mentions the tool" query (``--compare``).

    Attributes:
        ran: Whether the secondary query executed successfully.
        mentioning: Total lines that *mention* the tool name.
        genuine_spans: How many of those were genuine OTEL spans.
        app_logs: How many were plain app-log lines.
        note: A human-readable note (e.g. why it was skipped).
    """

    ran: bool = False
    mentioning: int = 0
    genuine_spans: int = 0
    app_logs: int = 0
    note: str = ""


def classify_events(
    events: Sequence[dict[str, Any]],
    *,
    target_tool: str,
    show_traces: int,
) -> ScanResult:
    """Classify fetched log ``events`` and accumulate counts + example spans.

    For each event this runs :func:`classify_log_message`; for spans it parses the
    record and runs :func:`extract_span_summary`, tracking how many spans contained the
    ``target_tool`` and keeping up to ``show_traces`` example summaries.

    Args:
        events: CloudWatch log events (dicts with a ``message`` key).
        target_tool: The tool name to headline on (e.g. ``retrieve_profiles``).
        show_traces: How many example span summaries to retain for the report.

    Returns:
        A populated :class:`ScanResult`.
    """
    scan = ScanResult()
    for event in events:
        scan.total_events += 1
        message = event.get("message", "")
        kind = classify_log_message(message)
        if kind == "app_log":
            scan.app_logs += 1
            continue
        if kind == "otel_other":
            scan.otel_other += 1
            continue
        # otel_span — re-parse (classify already proved it parses) and summarise.
        scan.otel_spans += 1
        try:
            obj = json.loads(message)
        except (ValueError, TypeError):  # pragma: no cover - classify guarantees JSON
            continue
        summary = extract_span_summary(obj)
        if target_tool in summary["toolCalls"]:
            scan.spans_with_tool += 1
        if len(scan.example_spans) < show_traces:
            scan.example_spans.append(summary)
    return scan


# --- AWS log fetching (boto3 imported lazily) -----------------------------------------


def resolve_log_group(
    *,
    log_group: str | None,
    runtime_arn: str | None,
    stack_name: str | None,
    cfn_client: Any = None,
) -> str:
    """Resolve the runtime log-group name from the provided options.

    Resolution order: explicit ``--log-group`` wins; else derive from ``--runtime-arn``;
    else read the ``RuntimeArn`` output of the CloudFormation stack ``--stack-name`` and
    derive from that. The CFN client is injected so this can be unit-tested; the pure
    ARN→group derivation lives in :func:`runtime_arn_to_log_group`.

    Args:
        log_group: Explicit log-group override (highest priority).
        runtime_arn: A runtime ARN to derive the group from.
        stack_name: A CloudFormation stack whose ``RuntimeArn`` output is read.
        cfn_client: A boto3 ``cloudformation`` client (lazily created when needed).

    Returns:
        The resolved log-group name.

    Raises:
        ValueError: When nothing can be resolved (no inputs) or the stack has no
            ``RuntimeArn`` output.
    """
    if log_group and log_group.strip():
        return log_group.strip()
    if runtime_arn and runtime_arn.strip():
        return runtime_arn_to_log_group(runtime_arn)
    if not stack_name:
        raise ValueError("no --log-group, --runtime-arn, or --stack-name provided")

    if cfn_client is None:  # pragma: no cover - exercised only with AWS creds
        import boto3

        cfn_client = boto3.client("cloudformation")

    response = cfn_client.describe_stacks(StackName=stack_name)
    stacks = response.get("Stacks", [])
    if not stacks:
        raise ValueError(f"CloudFormation stack {stack_name!r} not found")
    outputs = stacks[0].get("Outputs", []) or []
    for output in outputs:
        if output.get("OutputKey") == "RuntimeArn":
            arn = output.get("OutputValue", "")
            return runtime_arn_to_log_group(arn)
    raise ValueError(
        f"stack {stack_name!r} has no 'RuntimeArn' output; pass --runtime-arn or --log-group"
    )


# --- Multi-agent discovery + selection ------------------------------------------------

# Stack outputs that carry a runtime ARN, mapped to a friendly agent label. Extend this
# if more runtimes are added to the stack.
RUNTIME_OUTPUT_LABELS: dict[str, str] = {
    "RuntimeArn": "main agent",
    "BuilderRuntimeArn": "profile builder",
}


@dataclass(frozen=True)
class AgentTarget:
    """One selectable agent runtime: a friendly label + its CloudWatch log group."""

    label: str
    log_group: str


def agents_from_outputs(outputs: dict[str, str]) -> list[AgentTarget]:
    """Build the list of selectable agents from CloudFormation stack outputs.

    Pure: takes an ``{OutputKey: OutputValue}`` mapping and returns one
    :class:`AgentTarget` per known runtime-ARN output present (see
    :data:`RUNTIME_OUTPUT_LABELS`), in a stable order. Outputs without a usable ARN are
    skipped. Testable with no AWS access.
    """
    targets: list[AgentTarget] = []
    for output_key, label in RUNTIME_OUTPUT_LABELS.items():
        arn = (outputs.get(output_key) or "").strip()
        if not arn:
            continue
        try:
            log_group = runtime_arn_to_log_group(arn)
        except ValueError:
            continue
        targets.append(AgentTarget(label=label, log_group=log_group))
    return targets


def discover_agents(stack_name: str, cfn_client: Any = None) -> list[AgentTarget]:
    """Read the stack's outputs and return the selectable agent runtimes.

    Args:
        stack_name: The CloudFormation stack to inspect.
        cfn_client: A boto3 ``cloudformation`` client (injected for tests; created lazily
            when omitted).

    Returns:
        The list of :class:`AgentTarget`s discovered from the stack outputs.

    Raises:
        ValueError: If the stack is not found or exposes no known runtime outputs.
    """
    if cfn_client is None:  # pragma: no cover - exercised only with AWS creds
        import boto3

        cfn_client = boto3.client("cloudformation")

    response = cfn_client.describe_stacks(StackName=stack_name)
    stacks = response.get("Stacks", [])
    if not stacks:
        raise ValueError(f"CloudFormation stack {stack_name!r} not found")
    outputs = {
        o.get("OutputKey", ""): o.get("OutputValue", "")
        for o in (stacks[0].get("Outputs", []) or [])
    }
    targets = agents_from_outputs(outputs)
    if not targets:
        raise ValueError(
            f"stack {stack_name!r} exposes no known runtime outputs "
            f"({', '.join(RUNTIME_OUTPUT_LABELS)})."
        )
    return targets


def select_agents_interactively(targets: list[AgentTarget]) -> list[AgentTarget]:
    """Prompt the operator to choose which agent(s) to inspect.

    Presents a numbered menu of the discovered agents plus an "All agents" option, reads
    a choice from stdin, and returns the selected subset. On EOF/blank/invalid input it
    defaults to all agents (safe, read-only). Not unit-tested (interactive I/O).
    """
    print("\nSelect which agent's OTEL logs to inspect:")
    for i, target in enumerate(targets, start=1):
        print(f"  {i}) {target.label}  [{target.log_group}]")
    all_choice = len(targets) + 1
    print(f"  {all_choice}) All agents")
    try:
        raw = input(f"Choice [1-{all_choice}, default {all_choice}=all]: ").strip()
    except EOFError:
        raw = ""
    if not raw:
        return targets
    try:
        choice = int(raw)
    except ValueError:
        print("  (unrecognized input — defaulting to all agents)")
        return targets
    if 1 <= choice <= len(targets):
        return [targets[choice - 1]]
    return targets


def resolve_selected_agents(
    *,
    log_group: str | None,
    runtime_arn: str | None,
    stack_name: str | None,
    agent: str | None,
    menu: bool,
    cfn_client: Any = None,
) -> list[AgentTarget]:
    """Resolve which agent runtime(s) to inspect from flags / discovery / the menu.

    Precedence: an explicit ``--log-group`` or ``--runtime-arn`` selects exactly one
    target (single-agent, no discovery). Otherwise the stack is queried for its runtimes
    and ``--agent`` (``main``/``builder``/``all``) filters them; when ``--agent`` is not
    given and ``menu`` is True, the interactive menu is shown; the default is all agents.

    Args:
        log_group: Explicit log-group override.
        runtime_arn: Explicit runtime ARN.
        stack_name: Stack to discover runtimes from.
        agent: One of ``main`` / ``builder`` / ``all`` / ``None`` (label substring match).
        menu: Whether to show the interactive menu when no ``--agent`` is given.
        cfn_client: Injected boto3 ``cloudformation`` client (for discovery/tests).

    Returns:
        The list of :class:`AgentTarget`s to inspect (one, or all).
    """
    if log_group and log_group.strip():
        return [AgentTarget(label="log group", log_group=log_group.strip())]
    if runtime_arn and runtime_arn.strip():
        return [AgentTarget(label="runtime", log_group=runtime_arn_to_log_group(runtime_arn))]

    if not stack_name:
        raise ValueError("no --log-group, --runtime-arn, or --stack-name provided")

    targets = discover_agents(stack_name, cfn_client=cfn_client)

    # Explicit --agent filter (non-interactive).
    if agent and agent.lower() != "all":
        key = agent.lower()
        # Match against label ("main agent" / "profile builder") by substring.
        matched = [t for t in targets if key in t.label.lower()]
        if not matched:
            raise ValueError(
                f"--agent {agent!r} matched no runtime; available: "
                f"{', '.join(t.label for t in targets)}"
            )
        return matched

    # No explicit --agent: menu (if requested + interactive) else all.
    if agent is None and menu and sys.stdin.isatty():
        return select_agents_interactively(targets)
    return targets


def fetch_log_events(
    logs_client: Any,
    *,
    log_group: str,
    start_ms: int,
    filter_pattern: str,
    max_events: int,
) -> list[dict[str, Any]]:
    """Fetch log events via ``filter_log_events``, paginating up to ``max_events``.

    A **server-side** ``filter_pattern`` narrows volume (a substring match). Note that a
    substring match is *not* proof of a span — the caller still re-validates each event
    client-side via :func:`classify_log_message`. That is the whole point: we prove each
    counted hit is a parsed OTEL span with a valid trace/span id and the Strands tracer
    scope, not just a string match.

    Args:
        logs_client: A boto3 ``logs`` client.
        log_group: The log-group name to query.
        start_ms: Start time (epoch milliseconds).
        filter_pattern: CloudWatch Logs ``filterPattern`` (substring narrowing).
        max_events: Safety cap on the number of events collected across pages.

    Returns:
        The collected log events (each a dict with at least ``message``).
    """
    events: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "logGroupName": log_group,
            "startTime": start_ms,
            "filterPattern": filter_pattern,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        response = logs_client.filter_log_events(**kwargs)
        events.extend(response.get("events", []))
        if len(events) >= max_events:
            return events[:max_events]
        next_token = response.get("nextToken")
        if not next_token:
            return events


def run_compare_query(
    logs_client: Any,
    *,
    log_group: str,
    start_ms: int,
    target_tool: str,
    max_events: int,
) -> CompareResult:
    """Query lines *mentioning* ``target_tool`` and classify them (the OTEL-vs-CWL proof).

    This second, scope-agnostic query (``filterPattern`` = the bare tool name) is what
    directly demonstrates the distinction the operator cares about: of all lines that
    mention the tool, how many were genuine OTEL spans versus plain app logs. It is
    best-effort — any error is captured in :attr:`CompareResult.note` and the caller
    continues.

    Args:
        logs_client: A boto3 ``logs`` client.
        log_group: The log-group name to query.
        start_ms: Start time (epoch milliseconds).
        target_tool: The tool name to search for.
        max_events: Safety cap on collected events.

    Returns:
        A :class:`CompareResult` (``ran=False`` with a ``note`` on failure).
    """
    result = CompareResult()
    try:
        events = fetch_log_events(
            logs_client,
            log_group=log_group,
            start_ms=start_ms,
            filter_pattern=f'"{target_tool}"',
            max_events=max_events,
        )
    except Exception as error:  # noqa: BLE001 - best-effort; report, don't crash
        result.note = f"compare query skipped: {error}"
        return result
    result.ran = True
    for event in events:
        result.mentioning += 1
        kind = classify_log_message(event.get("message", ""))
        if kind == "otel_span":
            result.genuine_spans += 1
        else:
            result.app_logs += 1
    return result


# --- Output rendering -----------------------------------------------------------------


def _colorize(enabled: bool, text: str, *styles: str) -> str:
    """Wrap ``text`` in ANSI ``styles`` when ``enabled``, else return it unchanged."""
    if not enabled or not styles:
        return text
    prefix = "".join(_ANSI[s] for s in styles if s in _ANSI)
    return f"{prefix}{text}{_ANSI['reset']}"


def _short_trace(trace_id: Any, width: int = 16) -> str:
    """Return a short, readable prefix of a (possibly long) trace/span id."""
    s = str(trace_id or "")
    return s[:width] + ("…" if len(s) > width else "")


def _truncate(text: Any, limit: int = 120) -> str:
    """Return ``text`` as a single line truncated to ``limit`` characters."""
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _retrieve_query(tool_call: dict[str, Any]) -> str | None:
    """Best-effort extract of the ``input.query`` for a retrieve_profiles tool call."""
    tool_input = tool_call.get("input")
    if isinstance(tool_input, dict):
        return tool_input.get("query")
    return None


def format_report(
    scan: ScanResult,
    compare: CompareResult,
    *,
    label: str,
    log_group: str,
    region: str,
    hours: int,
    target_tool: str,
    color: bool,
) -> str:
    """Render the friendly terminal summary (verdict, counts, example spans, footer).

    Args:
        scan: The primary scan result (scope-filtered, client re-validated).
        compare: The optional "mentions the tool" comparison result.
        label: The agent label for the header (e.g. "main agent", "profile builder").
        log_group: The resolved log-group name (for the header).
        region: The AWS region (for the header).
        hours: The look-back window size in hours (for the header).
        target_tool: The tool name headlined on.
        color: Whether to emit ANSI colour.

    Returns:
        The formatted multi-line report (no trailing newline).
    """
    lines: list[str] = []
    bar = "=" * 72
    lines.append(bar)
    lines.append(_colorize(color, f" OTEL span verification — {label}", "bold"))
    lines.append(bar)
    lines.append(f" Log group : {log_group}")
    lines.append(f" Region    : {region}")
    lines.append(f" Window    : last {hours}h")
    lines.append(f" Target    : {target_tool}")
    lines.append("")

    # Verdict. Three states:
    #  - spans with the target tool  -> CONFIRMED (green)
    #  - OTEL spans but none with the tool -> spans present, tool not seen (yellow).
    #    This is the normal state for the builder runtime, which never calls
    #    retrieve_profiles — it still emits OTEL spans for its own work.
    #  - no OTEL spans at all -> NOT CONFIRMED (red)
    if scan.confirmed:
        lines.append(
            _colorize(
                color,
                f"✅ CONFIRMED: RAG retrievals are captured as OpenTelemetry spans "
                f"({scan.spans_with_tool} span(s) with '{target_tool}')",
                "green",
                "bold",
            )
        )
    elif scan.otel_spans > 0:
        lines.append(
            _colorize(
                color,
                f"🟡 OTEL spans present ({scan.otel_spans}) but none called '{target_tool}' "
                "in this window.",
                "yellow",
                "bold",
            )
        )
        lines.append(
            _colorize(
                color,
                "   Expected for the builder runtime (it does not call retrieve_profiles) "
                "or if no RAG query ran recently.",
                "dim",
            )
        )
    else:
        lines.append(
            _colorize(color, "❌ NOT CONFIRMED: no OTEL spans found in this window", "red", "bold")
        )
        lines.append(
            _colorize(
                color,
                "   Possible causes: the runtime received no traffic in this window; it is "
                "not launched under 'opentelemetry-instrument'; or the wrong log group.",
                "dim",
            )
        )
    lines.append("")

    # Counts table.
    lines.append(_colorize(color, " Counts", "bold"))
    lines.append(f"   total events scanned            : {scan.total_events}")
    lines.append(f"   OTEL spans (strands tracer)      : {scan.otel_spans}")
    lines.append(f"   OTEL other-scope records         : {scan.otel_other}")
    lines.append(f"   plain app-log lines              : {scan.app_logs}")
    lines.append(f"   spans containing '{target_tool}' : {scan.spans_with_tool}")
    # Because the primary query prefilters server-side on the OTEL scope string,
    # app-log count here will usually be ~0 — that is expected. Client-side
    # classification is still run to PROVE each hit is a real span, not a string match.
    lines.append(
        _colorize(
            color,
            "   (app-log count is ~0 by design: the primary query prefilters on the OTEL "
            "scope string; each hit is still re-validated as a real span)",
            "dim",
        )
    )
    lines.append("")

    # Compare line — the direct OTEL-vs-CWL demonstration.
    if compare.ran:
        lines.append(_colorize(color, " OTEL vs. plain CloudWatch logs", "bold"))
        lines.append(
            f"   of {compare.mentioning} log line(s) mentioning '{target_tool}' → "
            f"{compare.genuine_spans} genuine OTEL span(s) / {compare.app_logs} plain app log(s)"
        )
        lines.append("")
    elif compare.note:
        lines.append(_colorize(color, f" (compare) {compare.note}", "dim"))
        lines.append("")

    # Example spans.
    if scan.example_spans:
        lines.append(_colorize(color, f" Example spans (up to {len(scan.example_spans)})", "bold"))
        for i, span in enumerate(scan.example_spans, start=1):
            lines.append(
                f"   [{i}] trace={_short_trace(span.get('traceId'))} "
                f"session={_truncate(span.get('sessionId'), 40)} "
                f"service={_truncate(span.get('serviceName'), 48)}"
            )
            tool_names = span.get("toolCalls") or []
            lines.append(f"       tools: {', '.join(str(t) for t in tool_names) or '<none>'}")
            for call in span.get("toolCallDetails", []):
                if call.get("name") == target_tool:
                    query = _retrieve_query(call)
                    if query is not None:
                        lines.append(f"       {target_tool} query: {_truncate(query, 100)}")
        lines.append("")

    # Footer — restate the evidence basis.
    lines.append(bar)
    lines.append(
        _colorize(
            color,
            " Evidence basis: telemetry.sdk.name=opentelemetry + scope=strands.telemetry.tracer "
            "+ valid traceId/spanId. This is span data, not plain CloudWatch app logs.",
            "dim",
        )
    )
    lines.append(bar)
    return "\n".join(lines)


def build_json_summary(
    scan: ScanResult,
    compare: CompareResult,
    *,
    log_group: str,
    region: str,
    hours: int,
    target_tool: str,
) -> dict[str, Any]:
    """Build the machine-readable summary emitted under ``--json``."""
    return {
        "logGroup": log_group,
        "region": region,
        "windowHours": hours,
        "targetTool": target_tool,
        "confirmed": scan.confirmed,
        "counts": {
            "totalEvents": scan.total_events,
            "otelSpans": scan.otel_spans,
            "otelOther": scan.otel_other,
            "appLogs": scan.app_logs,
            "spansWithTool": scan.spans_with_tool,
        },
        "compare": {
            "ran": compare.ran,
            "mentioning": compare.mentioning,
            "genuineSpans": compare.genuine_spans,
            "appLogs": compare.app_logs,
            "note": compare.note,
        },
        "exampleSpans": scan.example_spans,
    }


# --- Orchestration --------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the ``verify_otel_rag`` CLI parser."""
    default_region = os.environ.get("AWS_REGION", "us-east-1")
    parser = argparse.ArgumentParser(
        prog="verify_otel_rag",
        description=(
            "Confirm, from CloudWatch Logs, that the deployed agent's RAG retrievals are "
            "captured as genuine OpenTelemetry spans (not merely a 'retrieve_profiles' "
            "substring in plain app logs). Exits 0 when CONFIRMED, 2 when NOT CONFIRMED, "
            "1 on operational error."
        ),
    )
    parser.add_argument(
        "--region", default=default_region, help=f"AWS region (default {default_region!r})."
    )
    parser.add_argument(
        "--log-group",
        default=None,
        help="Explicit runtime log-group override (highest priority).",
    )
    parser.add_argument(
        "--runtime-arn",
        default=None,
        help="Runtime ARN to derive the log group from (used if --log-group is absent).",
    )
    parser.add_argument(
        "--stack-name",
        default="ThreatIntelEngineV2Stack",
        help="CloudFormation stack whose runtime outputs are read (fallback resolver).",
    )
    parser.add_argument(
        "--agent",
        default=None,
        help=(
            "Which agent runtime to inspect: 'main', 'builder', or 'all' "
            "(matched against the runtime label). Omit to get the interactive menu "
            "(when run in a terminal) or all agents."
        ),
    )
    parser.add_argument(
        "--menu",
        dest="menu",
        action="store_true",
        default=True,
        help="Show the interactive agent-selection menu when --agent is not given (default ON).",
    )
    parser.add_argument(
        "--no-menu",
        dest="menu",
        action="store_false",
        help="Disable the menu; inspect all agents when --agent is not given.",
    )
    parser.add_argument(
        "--hours", type=int, default=6, metavar="H", help="Look-back window in hours (default 6)."
    )
    parser.add_argument(
        "--tool",
        default=DEFAULT_TARGET_TOOL,
        help=f"Tool name to headline on (default {DEFAULT_TARGET_TOOL!r}).",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=2000,
        metavar="N",
        help="Safety cap on paginated events per query (default 2000).",
    )
    parser.add_argument(
        "--show-traces",
        type=int,
        default=5,
        metavar="N",
        help="How many example spans to print in detail (default 5).",
    )
    parser.add_argument(
        "--compare",
        dest="compare",
        action="store_true",
        default=True,
        help="Also query lines mentioning the tool to show the OTEL-vs-app-log split (default ON).",
    )
    parser.add_argument(
        "--no-compare",
        dest="compare",
        action="store_false",
        help="Disable the secondary 'mentions the tool' comparison query.",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit a machine-readable JSON summary instead of the pretty table.",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    """Run the OTEL RAG span verification and print a summary.

    Resolves the log group, fetches OTEL-scope-filtered events, re-validates each one
    client-side (proving they are real spans), optionally runs the compare query, and
    prints either the pretty report or JSON. boto3 is imported lazily so the pure
    helpers and their tests never require it.

    Args:
        argv: Argument vector; defaults to ``sys.argv[1:]``.

    Returns:
        Exit code: ``0`` CONFIRMED, ``2`` NOT CONFIRMED, ``1`` operational error.
    """
    args = build_arg_parser().parse_args(argv)
    color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    # Lazy imports of boto3 (needs the SDK installed + AWS creds).
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError as error:  # pragma: no cover - env without boto3
        print(f"error: boto3 is required to query CloudWatch Logs: {error}", file=sys.stderr)
        return 1

    session = boto3.session.Session(region_name=args.region)

    # 1. Resolve which agent runtime(s) to inspect (explicit > --agent filter > menu > all).
    try:
        need_stack = not (args.log_group or args.runtime_arn)
        cfn_client = session.client("cloudformation") if need_stack else None
        agents = resolve_selected_agents(
            log_group=args.log_group,
            runtime_arn=args.runtime_arn,
            stack_name=args.stack_name,
            agent=args.agent,
            menu=args.menu,
            cfn_client=cfn_client,
        )
    except (ValueError, ClientError) as error:
        print(f"error: could not resolve agent(s): {error}", file=sys.stderr)
        return 1

    start_ms = int((time.time() - args.hours * 3600) * 1000)
    logs_client = session.client("logs")

    # 2. Inspect each selected agent and collect results for output + exit code.
    per_agent: list[dict[str, Any]] = []
    for target in agents:
        try:
            events = fetch_log_events(
                logs_client,
                log_group=target.log_group,
                start_ms=start_ms,
                filter_pattern=f'"{STRANDS_TRACER_SCOPE}"',
                max_events=args.max_events,
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                note = (
                    f"log group {target.log_group!r} not found "
                    "(runtime may not have emitted logs yet)."
                )
            else:
                note = f"filter_log_events failed ({code}): {error}"
            print(_colorize(color, f"⚠️  {target.label}: {note}", "yellow"))
            per_agent.append(
                {
                    "label": target.label,
                    "scan": ScanResult(),
                    "compare": CompareResult(note=note),
                    "error": note,
                }
            )
            continue

        scan = classify_events(events, target_tool=args.tool, show_traces=args.show_traces)
        compare = CompareResult(note="disabled (--no-compare)")
        if args.compare:
            compare = run_compare_query(
                logs_client,
                log_group=target.log_group,
                start_ms=start_ms,
                target_tool=args.tool,
                max_events=args.max_events,
            )
        per_agent.append(
            {
                "label": target.label,
                "log_group": target.log_group,
                "scan": scan,
                "compare": compare,
            }
        )

    # 3. Output — per-agent report, or a combined JSON array.
    if args.as_json:
        payload = []
        for entry in per_agent:
            summary = build_json_summary(
                entry["scan"],
                entry["compare"],
                log_group=entry.get("log_group", ""),
                region=args.region,
                hours=args.hours,
                target_tool=args.tool,
            )
            summary["agent"] = entry["label"]
            if entry.get("error"):
                summary["error"] = entry["error"]
            payload.append(summary)
        print(json.dumps(payload if len(payload) != 1 else payload[0], indent=2, default=str))
    else:
        for entry in per_agent:
            if entry.get("error"):
                continue
            print(
                format_report(
                    entry["scan"],
                    entry["compare"],
                    label=entry["label"],
                    log_group=entry["log_group"],
                    region=args.region,
                    hours=args.hours,
                    target_tool=args.tool,
                    color=color,
                )
            )
            print()

    # 4. Exit code across all inspected agents:
    #   0 if any agent CONFIRMED the target tool; 2 if none confirmed but some had OTEL
    #   spans (present, tool not seen); 1 if every agent errored / had no spans at all.
    scans = [e["scan"] for e in per_agent]
    if any(s.confirmed for s in scans):
        return 0
    if any(s.otel_spans > 0 for s in scans):
        return 2
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI dispatch
    raise SystemExit(run())

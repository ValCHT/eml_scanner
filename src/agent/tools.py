"""Exact agent tool set and the typing-safe executor (TICKET-19A/B/C §6-§8).

Exactly four tools are exposed to the LLM::

    lookup_virustotal <observable_id>
    lookup_opencti    <observable_id>
    scan_urlscan      <observable_id>
    finalize_assessment {assessment}

T19C §7: ``finalize_assessment.assessment`` exposes the COMPLETE frozen
Assessment JSON Schema (``schemas/assessment.schema.json``, loaded here and
never duplicated) instead of a generic object; the validation chain remains
tool JSON schema -> Pydantic ``src.state.Assessment`` -> existing verifier ->
existing policy. T19C §8: each tool description is short and states only
WHAT it checks, WHEN it is useful and WHAT a negative/unavailable result does
NOT prove; long documentation stays out of the system prompt.

The three investigation tools accept ONLY ``observable_id``. The executor
resolves the identifier against the trusted parser-produced registry of the
CURRENT email and invokes the existing typed adapter
(``src.tools.virustotal|opencti|urlscan``) with the same source profile,
egress policy, credentials, visibility mapping and per-phase deadlines as
the V1 pipeline. The model never provides a raw URL/domain/IP/hash/query.

Typed refusals (zero provider request): unknown tool, malformed arguments,
missing/invalid/unknown observable id, recipient target, duplicate
``(tool, observable)``, provider budget exceeded. Duplicates are planning
errors and never consume a provider call. Tool-discovered observables are
evidence only: the executor registry is the original parser registry and is
never extended (no recursive pivot in T19B).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import ValidationError

from ..config import EgressConfig, SourceProfile, ToolsConfig
from ..state import Assessment, Observable, ParsedEmail, ToolResult
from ..tools import ToolContext
from .models import (
    DEFAULT_AGENT_LIMITS,
    FINALIZE_TOOL,
    INVESTIGATION_TOOLS,
    TOOL_PROVIDER,
    AgentLimits,
    ToolCall,
    ToolExecution,
)

#: Refusal vocabulary of the executor (typed, model-visible).
REFUSAL_REASONS: tuple[str, ...] = (
    "missing_tool_call_id",
    "unknown_tool",
    "not_an_investigation_tool",
    "malformed_arguments",
    "unexpected_argument",
    "missing_observable_id",
    "invalid_observable_id",
    "unknown_observable_id",
    "recipient_not_a_query_target",
    "duplicate_tool_call",
    "tool_budget_exhausted",
    "urlscan_budget_exhausted",
)

#: Human-readable messages for the model (deterministic, content-free).
#: The two budget reasons live in ``_refusal_message`` instead: their numeric
#: claims are derived from the applied ``AgentLimits`` so a model-visible
#: refusal can never announce a different budget than the executor enforces.
_REFUSAL_MESSAGES: dict[str, str] = {
    "missing_tool_call_id": (
        "the provider tool call has no id: it cannot be executed or answered"
    ),
    "unknown_tool": "unknown tool: only the four declared tools exist",
    "not_an_investigation_tool": (
        "finalize_assessment is terminal and is not executed by the provider executor"
    ),
    "malformed_arguments": "the tool arguments are not a valid JSON object",
    "unexpected_argument": (
        "only the declared arguments are accepted; extra fields are refused"
    ),
    "missing_observable_id": (
        "observable_id is required: the tool accepts ONLY an observable_id from "
        "OBSERVABLE_REGISTRY"
    ),
    "invalid_observable_id": "observable_id must be a non-empty string",
    "unknown_observable_id": (
        "unknown observable_id: it is not part of the parser-produced registry of "
        "this email (tool-discovered observables are never query targets in T19B)"
    ),
    "recipient_not_a_query_target": (
        "recipients are actors, never IOC/query targets"
    ),
    "duplicate_tool_call": (
        "duplicate request refused: this (tool, observable_id) pair was already "
        "executed; no provider call was made"
    ),
}


def _refusal_message(reason: str, limits: AgentLimits | None = None) -> str:
    """Model-facing refusal text bound to the APPLIED limits.

    ``ProviderToolExecutor`` enforces ``self.limits``; the refusal payload it
    returns to the model derives its numeric claims from the same object.
    ``max_urlscan_calls`` is structurally frozen to 1 (``AgentLimits``), so
    the urlscan claim is exact for every constructible run.
    """

    effective = limits if limits is not None else DEFAULT_AGENT_LIMITS
    if reason == "tool_budget_exhausted":
        return (
            "provider tool-call budget exhausted (at most "
            f"{effective.max_tool_calls} provider calls in total): no provider "
            "call was made; finalize with the evidence already available"
        )
    if reason == "urlscan_budget_exhausted":
        return (
            "urlscan budget exhausted (at most "
            f"{effective.max_urlscan_calls} submission): no provider call was "
            "made; finalize with the evidence already available"
        )
    return _REFUSAL_MESSAGES.get(reason, "request refused")


#: Frozen Assessment JSON Schema (schemas/ is normative, read-only): the
#: EXACT object ``parse_finalize_arguments`` validates with
#: ``Assessment.model_validate``. Never a second format.
_ASSESSMENT_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "schemas" / "assessment.schema.json"
)


def assessment_schema() -> dict[str, Any]:
    """Load the frozen Assessment JSON Schema exposed by finalize_assessment."""

    schema = json.loads(_ASSESSMENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(schema, dict)
    return schema


#: The exact four tool schemas exposed to the model (§9). No description
#: carries a configurable number: the urlscan claim ("at most one submission
#: exists per run") matches the structurally frozen
#: ``AgentLimits.max_urlscan_calls``, so the schema is valid for every
#: constructible run.
AGENT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "lookup_virustotal",
            "description": (
                "WHAT: one real VirusTotal GET lookup for an observable_id from "
                "OBSERVABLE_REGISTRY. WHEN: a reputation signal on this exact "
                "observable could change the assessment. NOT PROOF: unavailable, "
                "not_found or zero detections never prove benignity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "observable_id": {
                        "type": "string",
                        "description": "observable id from OBSERVABLE_REGISTRY",
                    }
                },
                "required": ["observable_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_opencti",
            "description": (
                "WHAT: one real read-only OpenCTI lookup for an observable_id from "
                "OBSERVABLE_REGISTRY. WHEN: knowing whether this exact observable is "
                "known in CTI could change the assessment. NOT PROOF: presence is "
                "not proof of malice; unavailability never proves benignity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "observable_id": {
                        "type": "string",
                        "description": "observable id from OBSERVABLE_REGISTRY",
                    }
                },
                "required": ["observable_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_urlscan",
            "description": (
                "WHAT: one real urlscan submission for a URL observable_id from "
                "OBSERVABLE_REGISTRY; at most one submission exists per run. WHEN: "
                "an unvisited URL's real page could change the assessment. NOT "
                "PROOF: refusal, unavailable or a clean page never proves benignity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "observable_id": {
                        "type": "string",
                        "description": "URL observable id from OBSERVABLE_REGISTRY",
                    }
                },
                "required": ["observable_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": FINALIZE_TOOL,
            "description": (
                "Terminal call: deliver the final Assessment. The assessment "
                "object must validate exactly against the exposed frozen "
                "Assessment JSON Schema. An invalid assessment is rejected and "
                "never becomes a verdict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    # T19C §7: the COMPLETE frozen Assessment JSON Schema
                    # (schemas/assessment.schema.json), never a generic object
                    # and never a second format. Validated by
                    # parse_finalize_arguments exactly as src.state.Assessment.
                    "assessment": assessment_schema(),
                },
                "required": ["assessment"],
                "additionalProperties": False,
            },
        },
    },
]


@dataclass
class ProviderAdapterSet:
    """The three existing typed adapters, injected (never rebuilt here)."""

    virustotal: Any
    opencti: Any
    urlscan: Any


# ---------------------------------------------------------------------------
# Model-facing payloads
# ---------------------------------------------------------------------------


def normalize_result_payload(
    result: ToolResult, max_chars: int = 12_000
) -> str:
    """Canonical JSON of the normalized result, deterministically bounded.

    The whole normalized ``ToolResult`` is sent when its canonical JSON fits
    ``max_chars``. Otherwise the documented bounded projection is sent
    (identity/status fields plus the first 20 evidence and observables sorted
    by id); a field is NEVER cut in the middle. If even that projection does
    not fit, whole lists are dropped deterministically, never truncated.
    """

    full = json.dumps(
        result.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )
    if len(full) <= max_chars:
        return full

    evidence = sorted(result.evidence, key=lambda entry: entry.id)[:20]
    observables = sorted(result.observables, key=lambda entry: entry.id)[:20]
    payload: dict[str, Any] = {
        "tool": result.tool,
        "query_observable_id": result.query_observable_id,
        "status": result.status,
        "reason": result.reason,
        "requests_sent": result.requests_sent,
        "visibility": result.visibility,
        "evidence": [entry.model_dump(mode="json") for entry in evidence],
        "observables": [entry.model_dump(mode="json") for entry in observables],
        "truncated": True,
    }
    for drop in ("observables", "evidence"):
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False)
        if len(text) <= max_chars:
            return text
        payload[drop] = []
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False)
    if len(text) <= max_chars:
        return text
    # Minimal deterministic core: identity/status only, still no field cut.
    core = {
        "tool": result.tool,
        "query_observable_id": result.query_observable_id,
        "status": result.status,
        "reason": result.reason,
        "requests_sent": result.requests_sent,
        "visibility": result.visibility,
        "truncated": True,
        "omitted": "evidence_and_observables_over_payload_budget",
    }
    return json.dumps(core, ensure_ascii=False, sort_keys=True, allow_nan=False)


def refusal_payload(
    execution: ToolExecution, limits: AgentLimits | None = None
) -> str:
    """Model-facing typed refusal payload (canonical JSON).

    ``limits`` must be the executor's effective ``AgentLimits``: the budget
    claims in the message are derived from it.
    """

    payload = {
        "refused": True,
        "tool": execution.tool,
        "observable_id": execution.observable_id,
        "reason": execution.refusal_reason,
        "message": _refusal_message(execution.refusal_reason or "", limits),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False)


def execution_payload(
    execution: ToolExecution,
    max_chars: int = 12_000,
    limits: AgentLimits | None = None,
) -> str:
    """Exact role=tool content for one execution."""

    if execution.outcome == "refused" or execution.result is None:
        return refusal_payload(execution, limits)
    return normalize_result_payload(execution.result, max_chars)


# ---------------------------------------------------------------------------
# finalize_assessment parsing (§11/§21)
# ---------------------------------------------------------------------------


def parse_finalize_arguments(
    arguments: dict[str, Any] | None,
) -> tuple[Assessment | None, list[str]]:
    """Validate the terminal assessment EXACTLY as ``src.state.Assessment``.

    Returns ``(assessment | None, issues)``; an invalid assessment is
    rejected (never repaired, never used as a verdict).
    """

    if not isinstance(arguments, dict):
        return None, ["finalize arguments must be a JSON object"]
    unknown = sorted(set(arguments) - {"assessment"})
    if unknown:
        return None, [
            f"unexpected argument {key!r}" for key in unknown
        ] + ["only the declared 'assessment' argument is accepted"]
    if "assessment" not in arguments:
        return None, ["missing required 'assessment' object"]
    candidate = arguments["assessment"]
    if not isinstance(candidate, dict):
        return None, [
            f"assessment must be an object, got {type(candidate).__name__}"
        ]
    try:
        model = Assessment.model_validate(candidate)
    except ValidationError as error:
        issues: list[str] = []
        for err in error.errors()[:10]:
            location = ".".join(str(part) for part in err["loc"]) or "$"
            issues.append(f"schema: {location}: {err['msg']}")
        return None, issues
    return model, []


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


@dataclass
class ProviderToolExecutor:
    """Typed execution of the three investigation tools against real adapters.

    The registry is the parser registry of the CURRENT email only; it is
    never extended with tool-discovered observables (§19).
    """

    parsed: ParsedEmail
    adapters: ProviderAdapterSet
    tools_config: ToolsConfig
    run_id: str
    source_profile: SourceProfile
    egress: EgressConfig
    capture_dir: Path
    deadline: float
    mode: Literal["live", "recorded"] = "live"
    clock: Callable[[], float] = time.monotonic
    limits: AgentLimits = field(default_factory=lambda: DEFAULT_AGENT_LIMITS)

    def __post_init__(self) -> None:
        self._registry: dict[str, Observable] = {
            observable.id: observable for observable in self.parsed.observables
        }
        self._executed: set[tuple[str, str]] = set()
        self._results: list[ToolResult] = []
        self._provider_calls = 0
        self._urlscan_calls = 0
        self._duplicate_refusals = 0
        self._planning_errors = 0
        self._refusals: list[ToolExecution] = []
        self._adapter_exceptions: list[str] = []

    # -- counters -------------------------------------------------------------

    @property
    def registry(self) -> dict[str, Observable]:
        return dict(self._registry)

    @property
    def results(self) -> list[ToolResult]:
        return list(self._results)

    @property
    def refusals(self) -> list[ToolExecution]:
        return list(self._refusals)

    @property
    def provider_tool_call_count(self) -> int:
        return self._provider_calls

    @property
    def duplicate_refusal_count(self) -> int:
        return self._duplicate_refusals

    @property
    def planning_error_count(self) -> int:
        return self._planning_errors

    @property
    def adapter_exceptions(self) -> list[str]:
        return list(self._adapter_exceptions)

    def tool_counts_by_provider(self) -> dict[str, int]:
        counts = {provider: 0 for provider in ("virustotal", "opencti", "urlscan")}
        for result in self._results:
            counts[result.tool] = counts.get(result.tool, 0) + 1
        return counts

    def tool_statuses_by_provider(self) -> dict[str, dict[str, int]]:
        statuses: dict[str, dict[str, int]] = {
            provider: {"ok": 0, "not_found": 0, "unavailable": 0, "skipped": 0}
            for provider in ("virustotal", "opencti", "urlscan")
        }
        for result in self._results:
            provider_counts = statuses.setdefault(result.tool, {})
            provider_counts[result.status] = provider_counts.get(result.status, 0) + 1
        return statuses

    # -- execution ------------------------------------------------------------

    def execute(self, call: ToolCall) -> ToolExecution:
        """Validate and execute one provider request (or refuse it)."""

        tool = call.name or ""
        provider = TOOL_PROVIDER.get(tool)

        def _refuse(reason: str, observable_id: str | None = None) -> ToolExecution:
            self._planning_errors += 1
            if reason == "duplicate_tool_call":
                self._duplicate_refusals += 1
            execution = ToolExecution(
                tool=tool or "unknown",
                provider=provider,
                call_id=call.call_id,
                observable_id=observable_id,
                outcome="refused",
                refusal_reason=reason,
            )
            self._refusals.append(execution)
            return execution

        if not call.call_id:
            extracted_id = (
                call.arguments.get("observable_id") if call.arguments else None
            )
            return _refuse(
                "missing_tool_call_id",
                extracted_id if isinstance(extracted_id, str) else None,
            )
        if tool not in INVESTIGATION_TOOLS:
            if tool == FINALIZE_TOOL:
                return _refuse("not_an_investigation_tool", None)
            return _refuse("unknown_tool", None)
        if call.arguments_error is not None or call.arguments is None:
            return _refuse("malformed_arguments", None)
        unexpected = sorted(set(call.arguments) - {"observable_id"})
        if unexpected:
            return _refuse("unexpected_argument", None)
        observable_id = call.arguments.get("observable_id")
        if observable_id is None:
            return _refuse("missing_observable_id", None)
        if not isinstance(observable_id, str) or not observable_id.strip():
            return _refuse("invalid_observable_id", None)
        observable = self._registry.get(observable_id)
        if observable is None:
            return _refuse("unknown_observable_id", observable_id)
        if "recipient" in observable.roles:
            return _refuse("recipient_not_a_query_target", observable_id)
        if (tool, observable_id) in self._executed:
            return _refuse("duplicate_tool_call", observable_id)
        if self._provider_calls >= self.limits.max_tool_calls:
            return _refuse("tool_budget_exhausted", observable_id)
        if tool == "scan_urlscan" and self._urlscan_calls >= self.limits.max_urlscan_calls:
            return _refuse("urlscan_budget_exhausted", observable_id)

        self._executed.add((tool, observable_id))
        self._provider_calls += 1
        if tool == "scan_urlscan":
            self._urlscan_calls += 1
        result = self._invoke_adapter(tool, observable)
        self._results.append(result)
        return ToolExecution(
            tool=tool,
            provider=result.tool,
            call_id=call.call_id,
            observable_id=observable_id,
            outcome="executed",
            result=result,
            elapsed_ms=result.elapsed_ms,
        )

    def _phase_timeout(self, provider: str) -> float:
        if provider == "virustotal":
            return float(self.tools_config.virustotal.phase_timeout_s)
        if provider == "opencti":
            return float(self.tools_config.opencti.phase_timeout_s)
        return float(self.tools_config.urlscan.phase_timeout_s)

    def _tool_context(self, provider: str) -> ToolContext:
        deadline = min(
            self.deadline, self.clock() + self._phase_timeout(provider)
        )
        return ToolContext(
            run_id=self.run_id,
            source_profile=self.source_profile,
            deadline=deadline,
            egress=self.egress,
            capture_dir=self.capture_dir,
            mode=self.mode,
        )

    def _invoke_adapter(self, tool: str, observable: Observable) -> ToolResult:
        provider = TOOL_PROVIDER[tool]
        context = self._tool_context(provider)
        try:
            if tool == "lookup_virustotal":
                return self.adapters.virustotal.lookup(observable, context)
            if tool == "lookup_opencti":
                return self.adapters.opencti.lookup(observable, context)
            return self.adapters.urlscan.scan(observable, context)
        except Exception as error:  # noqa: BLE001 - a provider error never crashes the loop
            # An adapter exception is a LOCAL failure, never a fabricated
            # provider observation: honest unavailable/api_error with zero
            # claimed requests and no capture reference.
            self._adapter_exceptions.append(
                f"{provider}:{type(error).__name__}:{str(error)[:200]}"
            )
            return ToolResult(
                tool=provider,  # type: ignore[arg-type]
                query_observable_id=observable.id,
                status="unavailable",
                reason="api_error",
                mode="none",
                requests_sent=0,
            )


__all__ = [
    "AGENT_TOOLS",
    "REFUSAL_REASONS",
    "ProviderAdapterSet",
    "ProviderToolExecutor",
    "assessment_schema",
    "execution_payload",
    "normalize_result_payload",
    "parse_finalize_arguments",
    "refusal_payload",
]

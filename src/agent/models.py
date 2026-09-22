"""Agentic runtime data models and the FROZEN loop limits (T19A/B §15).

Plain dataclasses, like the harness-side ``Services``/``PolicyInputs``
containers: these objects are never checkpointed, never serialized into the
agent artifacts as-is (the runner writes explicit bounded projections) and
never carry a secret. The ``Assessment``/``ToolResult`` objects they hold
are the existing contract models from ``src.state``.

Frozen limits are implementation limits for the bounded smoke. They must
not be tuned based on whether a classification is correct; TICKET-19E may
later define benchmark conditions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..state import Assessment, ToolResult

#: Historical T19A/B artifact architecture marker (docs/tickets/TICKET-19B.md §22).
ARCHITECTURE_NAME = "agentic_core_v1"

#: T19C converged runtime marker: bounded agentic loop + T15 public RAG +
#: T16 QR/Vision, still exactly four tools and one agent (TICKET-19C).
CONVERGED_ARCHITECTURE_NAME = "agentic_core_v2"

#: T19D-OSINT runtime marker: the same single agent and bounded loop, plus
#: the single lookup_osint tool and the four agentic profiles
#: (agentic_core/context/osint/full). V1/V2 markers above are kept for
#: reading historical artifacts/tests.
OSINT_ARCHITECTURE_NAME = "agentic_core_v3"

#: A smoke never allows a performance claim (operator amendment 2026-09-21).
MEASUREMENT_SCOPE = "smoke"
PERFORMANCE_CLAIMS_ALLOWED = False

# --- frozen loop limits (§15) ----------------------------------------------

#: At most five assistant turns per email.
MAX_LLM_TURNS = 5
#: At most four provider tool calls in total (duplicates never count).
MAX_TOOL_CALLS = 4
#: At most one urlscan submission per run (adapter journal enforces it too).
MAX_URLSCAN_CALLS = 1
#: Whole agentic loop wall-clock budget.
MAX_AGENT_SECONDS = 300.0
#: One LLM request never exceeds this (bounded further by the loop budget).
MAX_SINGLE_LLM_SECONDS = 90.0
#: Maximum characters of a normalized tool result returned to the model.
MAX_TOOL_RESULT_CHARS = 12_000

#: Reasoning effort of every agentic LLM turn. Frozen implementation
#: parameter of the bounded smoke (recorded in the manifest), not a tuned
#: benchmark setting: the multi-turn loop must fit in MAX_AGENT_SECONDS.
AGENT_REASONING_EFFORT = "medium"

# --- exact tool set (§9) ----------------------------------------------------

FINALIZE_TOOL = "finalize_assessment"

INVESTIGATION_TOOLS: tuple[str, ...] = (
    "lookup_virustotal",
    "lookup_opencti",
    "scan_urlscan",
)

AGENT_TOOL_NAMES: tuple[str, ...] = (*INVESTIGATION_TOOLS, FINALIZE_TOOL)

#: TICKET-19D-OSINT §3: exactly ONE new investigation tool. The frozen
#: T19B triple above is untouched; the OSINT tool is declared separately so
#: the four-tool default contract can never silently change.
LOOKUP_OSINT_TOOL = "lookup_osint"

#: All investigation tools (T19B triple + lookup_osint).
ALL_INVESTIGATION_TOOLS: tuple[str, ...] = (*INVESTIGATION_TOOLS, LOOKUP_OSINT_TOOL)

#: Agent tool name -> existing typed adapter / ToolResult producer.
TOOL_PROVIDER: dict[str, str] = {
    "lookup_virustotal": "virustotal",
    "lookup_opencti": "opencti",
    "scan_urlscan": "urlscan",
    "lookup_osint": "osint",
}

#: TICKET-19D-OSINT §24: exactly four agentic profiles. No registry, no
#: framework — plain static logic.
AgentProfile = Literal[
    "agentic_core",
    "agentic_context",
    "agentic_osint",
    "agentic_full",
]

AGENT_PROFILES: tuple[str, ...] = (
    "agentic_core",
    "agentic_context",
    "agentic_osint",
    "agentic_full",
)

#: Default profile: preserves the T19D behavior (§24).
DEFAULT_AGENT_PROFILE: AgentProfile = "agentic_context"

#: Profiles whose tools include lookup_osint (§24).
OSINT_PROFILES: tuple[str, ...] = ("agentic_osint", "agentic_full")

#: Profiles allowed to run the RAG/QR/Vision deterministic preprocessing
#: (§24.1–§24.2). The profile ALLOWS the capability; Settings decide.
CONTEXT_PROFILES: tuple[str, ...] = ("agentic_context", "agentic_full")


def context_allowed(profile: str) -> bool:
    """Whether this profile may run RAG/QR/Vision preprocessing (§24)."""

    return profile in CONTEXT_PROFILES


def osint_exposed(profile: str) -> bool:
    """Whether this profile exposes lookup_osint (§24)."""

    return profile in OSINT_PROFILES


@dataclass
class AgentLimits:
    """Bounded-loop limits; the defaults are the frozen §15 values.

    ``max_urlscan_calls`` is STRUCTURALLY frozen to ``MAX_URLSCAN_CALLS`` (1):
    the frozen T19B contract allows exactly one urlscan submission per run and
    the model-visible urlscan texts (tool schema, system prompt, refusal
    vocabulary) all state "at most one submission". Any other value is a
    programming error, so no constructible run can contradict them.
    """

    max_llm_turns: int = MAX_LLM_TURNS
    max_tool_calls: int = MAX_TOOL_CALLS
    max_urlscan_calls: int = MAX_URLSCAN_CALLS
    max_agent_seconds: float = MAX_AGENT_SECONDS
    max_single_llm_seconds: float = MAX_SINGLE_LLM_SECONDS
    max_tool_result_chars: int = MAX_TOOL_RESULT_CHARS

    def __post_init__(self) -> None:
        if self.max_urlscan_calls != MAX_URLSCAN_CALLS:
            raise ValueError(
                "max_urlscan_calls is structurally frozen to "
                f"{MAX_URLSCAN_CALLS} (T19B §15): the model-visible urlscan "
                "tool schema, prompt and refusal messages state 'at most one "
                "submission per run'"
            )


DEFAULT_AGENT_LIMITS = AgentLimits()


@dataclass
class ToolCall:
    """One NATIVE tool call exactly as returned by the provider.

    ``arguments`` is the parsed object when the provider sent valid JSON
    (or a mapping); ``arguments_error`` is the typed local parse failure
    otherwise. A malformed call is never repaired: it is refused by the
    executor or rejected by the finalize validation.
    """

    call_id: str | None
    name: str | None
    arguments_raw: str | None
    arguments: dict[str, Any] | None
    arguments_error: str | None = None


@dataclass
class AgentLLMResponse:
    """One real agentic LLM turn (never a fabricated answer)."""

    status: Literal["ok", "error"]
    requested_model: str
    returned_model: str | None = None
    finish_reason: str | None = None
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    request_sha256: str | None = None
    response_sha256: str | None = None
    # T19D §5: passive observation of a native provider reasoning text field.
    # The text itself is NEVER stored, interpreted or reinjected; only
    # presence, character count and SHA-256 are archived (metadata only).
    reasoning_content_present: bool = False
    reasoning_content_chars: int | None = None
    reasoning_content_sha256: str | None = None
    attempts: int = 0
    elapsed_ms: float = 0.0
    error: str | None = None


@dataclass
class ToolExecution:
    """Outcome of one agent tool request (executed or typed refusal)."""

    tool: str
    provider: str | None
    call_id: str | None
    observable_id: str | None
    outcome: Literal["executed", "refused"]
    refusal_reason: str | None = None
    result: ToolResult | None = None
    elapsed_ms: float = 0.0

    @property
    def provider_status(self) -> str | None:
        return self.result.status if self.result is not None else None


@dataclass
class AgentRunResult:
    """Bounded agentic run outcome (artifacts are already written)."""

    run_id: str
    status: Literal["finalized", "incomplete", "error"]
    action: Literal["AUTO", "REVIEW", "ESCALATE"]
    policy_reasons: list[str]
    assessment: Assessment | None
    verdict: str | None
    confidence: float | None
    margin: float | None
    run_dir: Path
    llm_turn_count: int
    provider_tool_call_count: int
    duplicate_tool_refusal_count: int
    tool_counts_by_provider: dict[str, int]
    tool_statuses_by_provider: dict[str, dict[str, int]]
    total_ms: float
    prompt_sha256: str
    email_sha256: str | None
    sample_id: str | None = None
    parse_error: str | None = None
    llm_error: bool = False
    agent_error: str | None = None

    def to_index_row(self) -> dict[str, Any]:
        """Bounded row for the smoke batch index (never a metric value)."""

        return {
            "run_id": self.run_id,
            "sample_id": self.sample_id,
            # T19C: the prompt carries conditional RAG/visual guidance, so the
            # effective hash is archived PER SAMPLE; a batch-wide value would
            # be false whenever two samples received different guidance
            # (PR #19 review, blocker 2).
            "effective_prompt_sha256": self.prompt_sha256,
            "status": self.status,
            "action": self.action,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "margin": self.margin,
            "llm_turn_count": self.llm_turn_count,
            "provider_tool_call_count": self.provider_tool_call_count,
            "duplicate_tool_refusal_count": self.duplicate_tool_refusal_count,
            "tool_counts_by_provider": dict(self.tool_counts_by_provider),
            "tool_statuses_by_provider": {
                provider: dict(counts)
                for provider, counts in self.tool_statuses_by_provider.items()
            },
            "total_ms": self.total_ms,
            "policy_reasons": list(self.policy_reasons),
            "parse_error": self.parse_error,
            "llm_error": self.llm_error,
            "agent_error": self.agent_error,
            "run_dir": str(self.run_dir),
        }


__all__ = [
    "AGENT_PROFILES",
    "AGENT_REASONING_EFFORT",
    "AGENT_TOOL_NAMES",
    "ALL_INVESTIGATION_TOOLS",
    "ARCHITECTURE_NAME",
    "CONTEXT_PROFILES",
    "CONVERGED_ARCHITECTURE_NAME",
    "DEFAULT_AGENT_LIMITS",
    "DEFAULT_AGENT_PROFILE",
    "FINALIZE_TOOL",
    "INVESTIGATION_TOOLS",
    "LOOKUP_OSINT_TOOL",
    "MAX_AGENT_SECONDS",
    "MAX_LLM_TURNS",
    "MAX_SINGLE_LLM_SECONDS",
    "MAX_TOOL_CALLS",
    "MAX_TOOL_RESULT_CHARS",
    "MAX_URLSCAN_CALLS",
    "MEASUREMENT_SCOPE",
    "OSINT_ARCHITECTURE_NAME",
    "OSINT_PROFILES",
    "PERFORMANCE_CLAIMS_ALLOWED",
    "TOOL_PROVIDER",
    "AgentLimits",
    "AgentLLMResponse",
    "AgentProfile",
    "AgentRunResult",
    "ToolCall",
    "ToolExecution",
    "context_allowed",
    "osint_exposed",
]

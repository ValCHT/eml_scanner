"""Bounded converged agentic SOC triage loop (TICKET-19B, converged by T19C).

``run_agentic_email`` is a simple bounded Python loop. It does NOT use
LangGraph, does not touch ``src/graph.py`` and adds no second agent:

    parse email
      -> T15 deterministic public RAG retrieval (preprocessing, never a tool)
      -> T16 deterministic QR decode / bounded pixel staging (preprocessing)
      -> LLM turn (native tool calls, real endpoint)
      -> validate each call / execute allowed provider calls in order
      -> normalized ToolResult returned as role=tool
      -> ... until finalize_assessment or a frozen limit
      -> existing deterministic merge / verifier / policy
      -> runs/agentic/<run_id>/{manifest,trace,final,summary}

The T19C convergence adds NO agent, NO tool and NO architectural redesign:
RAG stays a deterministic preprocessing step (its results travel in
``RAG_CONTEXT`` and its conditional guidance in the system prompt), QR
payloads join the existing parser contracts (INTERNE evidence/observables)
and staged pixels travel as ``image_url`` parts of the same Qwen request.
The default tool set is unchanged: ``lookup_virustotal``,
``lookup_opencti``, ``scan_urlscan``, ``finalize_assessment``.
T19D-OSINT adds the ``lookup_osint`` tool and the four profiles
(``agentic_core``/``context``/``osint``/``full``); the default profile
(``agentic_context``) keeps the four-tool behavior.

Frozen limits (§15): 5 LLM turns, 4 provider calls, 1 urlscan call, 300 s
total, 90 s per LLM request, 12,000 chars per tool result. A duplicate
``(tool, observable)`` never reaches a provider; provider
unavailable/not_found is honest data, never a crash and never benign proof.
If no valid assessment is produced, the status is ``incomplete`` and the
policy yields REVIEW: no benign verdict is fabricated.

Artifacts are diagnostic smoke artifacts only:
``measurement_scope=smoke`` and ``performance_claims_allowed=false``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

import yaml

from ..config import (
    PolicyConfig,
    Settings,
    SourceProfile,
    ToolsConfig,
    load_yaml_config,
)
from ..evidence import EvidenceMergeError, merge_evidence
from ..metrics import PRICING_SNAPSHOT, estimate_cost_usd
from ..parsing import ParseFailure, ParseLimits, parse_email
from ..policy import PolicyInputs, decide_policy
from ..prompts import ContextLimits
from ..state import (
    Assessment,
    Enrichment,
    Evidence,
    Link,
    Observable,
    ParsedEmail,
    RagCase,
    ToolResult,
    VerificationIssue,
)
from ..tools.osint import PSL_VERSION
from ..tools.rag import (
    RagError,
    RagUnavailableError,
    create_rag_adapter_if_enabled,
    rag_query_from_parsed,
)
from ..verify import (
    RunContext,
    is_admissible_malicious_confirmation,
    verify_assessment,
)
from ..vision import (
    VisionPreparation,
    load_image_bytes,
    prepare_visual_bundle,
    qr_contract,
)
from .client import AgentChatClient
from .models import (
    AGENT_REASONING_EFFORT,
    DEFAULT_AGENT_LIMITS,
    DEFAULT_AGENT_PROFILE,
    FINALIZE_TOOL,
    MEASUREMENT_SCOPE,
    OSINT_ARCHITECTURE_NAME,
    PERFORMANCE_CLAIMS_ALLOWED,
    AgentLimits,
    AgentProfile,
    AgentRunResult,
    ToolExecution,
    context_allowed,
    osint_exposed,
)
from .prompt import agent_system_prompt_sha256, initial_messages
from .tools import (
    ProviderAdapterSet,
    ProviderToolExecutor,
    assessment_schema_sha256,
    execution_payload,
    parse_finalize_arguments,
    tool_schema_sha256,
    tools_for_profile,
)

#: Subdirectory of ``settings.RUNS_DIR`` holding every agentic run.
AGENTIC_RUNS_SUBDIR = "agentic"

#: Maximum output tokens of one agentic turn (Settings.FINAL_MAX_OUTPUT_TOKENS
#: is the frozen FINAL generation budget; the agent plays that role here).
_DEFAULT_MAX_OUTPUT_TOKENS = 16_384

#: Deterministic nudge sent when a turn returned no tool call at all.
_NO_TOOL_CALLS_NUDGE = (
    "No tool call was received. Call one of the declared tools, or — when enough "
    "evidence exists — call finalize_assessment with the complete assessment "
    "object. Prose alone cannot become a verdict."
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _code_commit() -> str | None:
    """Best-effort HEAD commit of the working tree; None when unavailable."""

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_PROJECT_ROOT,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False),
        encoding="utf-8",
    )


def _load_pricing(settings: Settings) -> dict[str, Any] | None:
    """Pricing snapshot from ``configs/evaluation.yaml`` when available."""

    path = Path(settings.CONFIG_DIR) / "evaluation.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    pricing = data.get("pricing_snapshot")
    return dict(pricing) if isinstance(pricing, dict) else None


def _build_real_adapters(
    settings: Settings, tools_config: ToolsConfig, clock: Callable[[], float]
) -> ProviderAdapterSet:
    """Build the existing typed adapters with the repository's own wiring."""

    from ..tools.opencti import OpenCTIAdapter
    from ..tools.osint import OsintAdapter
    from ..tools.urlscan import UrlscanAdapter
    from ..tools.virustotal import VirusTotalAdapter

    quota_dir = Path(settings.RUNS_DIR) / "quota"
    return ProviderAdapterSet(
        virustotal=VirusTotalAdapter(
            settings,
            tools_config.virustotal,
            clock=clock,
            quota_journal_path=quota_dir / "virustotal.json",
        ),
        opencti=OpenCTIAdapter(settings, tools_config.opencti, clock=clock),
        urlscan=UrlscanAdapter(
            settings,
            tools_config.urlscan,
            clock=clock,
            quota_journal_path=quota_dir / "urlscan.json",
        ),
        osint=OsintAdapter(settings, tools_config.osint, clock=clock),
    )


# ---------------------------------------------------------------------------
# Deterministic preprocessing: T15 RAG + T16 QR/Vision (TICKET-19C §3-§5)
# ---------------------------------------------------------------------------


@dataclass
class _RagPreprocessing:
    """T15 retrieval outcome; a typed failure is fail-closed (no context)."""

    cases: list[RagCase] = field(default_factory=list)
    error: str | None = None
    enabled: bool = False


@dataclass
class _VisualPreprocessing:
    """T16 preparation outcome: prepared visuals + QR contract entries."""

    preparation: VisionPreparation
    links: list[Link] = field(default_factory=list)
    observables: list[Observable] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    vision_enabled: bool = False
    qr_enabled: bool = False


def _empty_visual_preprocessing() -> _VisualPreprocessing:
    return _VisualPreprocessing(
        preparation=VisionPreparation(
            visuals=[],
            staged=(),
            qr_decode_requested=False,
            qr_decoder_available=False,
            pixel_decoder_available=False,
        )
    )


def _rag_preprocess(
    parsed: ParsedEmail,
    settings: Settings,
    tools_config: ToolsConfig,
    rag: Any | None,
    exclusions: set[str],
) -> _RagPreprocessing:
    """Deterministic public-only RAG retrieval, exactly as the V1 RAG node.

    The adapter is the existing T15 one (injected in tests, built from
    ``RAG_ENABLED`` + ``tools.rag.enabled`` in production); the query and the
    retrieval limits are the frozen T15 ones. A RAG failure is typed,
    fail-closed state: empty context and a recorded error, never a fabricated
    neighbour and never an agent tool.
    """

    adapter = (
        rag
        if rag is not None
        else create_rag_adapter_if_enabled(settings, tools_config.rag)
    )
    if adapter is None:
        return _RagPreprocessing()
    query = rag_query_from_parsed(parsed, tools_config.rag.max_case_chars)
    if not query:
        return _RagPreprocessing(enabled=True)
    try:
        cases = adapter.search(query, exclusions=set(exclusions), k=tools_config.rag.k)
        validated = [
            case if isinstance(case, RagCase) else RagCase.model_validate(case)
            for case in cases
        ]
    except RagUnavailableError as error:
        return _RagPreprocessing(error=f"rag_unavailable:{type(error).__name__}", enabled=True)
    except RagError as error:
        return _RagPreprocessing(
            error=f"rag_lookup_failed:{type(error).__name__}", enabled=True
        )
    except Exception as error:  # noqa: BLE001 - fail-closed, never simulated
        return _RagPreprocessing(
            error=f"rag_lookup_failed:{type(error).__name__}", enabled=True
        )
    return _RagPreprocessing(cases=validated, enabled=True)


def _vision_preprocess(
    parsed: ParsedEmail,
    raw_email: bytes,
    settings: Settings,
    tools_config: ToolsConfig,
) -> _VisualPreprocessing:
    """T16 QR decode + bounded pixel staging, exactly as the T16 capability.

    Pixel staging obeys ``MODEL_SUPPORTS_VISION`` (the frozen
    ``configs/tools.yaml`` keeps ``vision.enabled=false``; the operator
    switch is applied IN MEMORY for this run only, exactly like the T16
    capability smoke). QR decoding obeys ``QR_DECODE_ENABLED`` independently:
    ``text+QR`` decodes without staging a pixel and a disabled QR switch
    never executes the decoder. The optional stack is never imported when
    neither switch is requested. QR payloads join the existing parser
    contracts through ``qr_contract`` (INTERNE evidence/observables); no
    decoded URL is ever visited or submitted by this preprocessing.
    """

    limits = tools_config.vision
    if settings.MODEL_SUPPORTS_VISION and not limits.enabled:
        limits = limits.model_copy(update={"enabled": True})
    qr_enabled = bool(settings.QR_DECODE_ENABLED)
    needs_bytes = bool(limits.enabled) or qr_enabled
    image_bytes = (
        load_image_bytes(
            raw_email,
            parsed,
            ParseLimits.from_config(tools_config.parse_limits),
        )
        if needs_bytes
        else None
    )
    preparation = prepare_visual_bundle(
        parsed, limits, image_bytes=image_bytes, qr_enabled=qr_enabled
    )
    links, observables, evidence = qr_contract(preparation.visuals)
    return _VisualPreprocessing(
        preparation=preparation,
        links=links,
        observables=observables,
        evidence=evidence,
        vision_enabled=bool(limits.enabled),
        qr_enabled=qr_enabled,
    )


def _issue(
    code: str,
    severity: str,
    source: str,
    message: str,
    object_id: str | None = None,
) -> VerificationIssue:
    return VerificationIssue(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        object_id=object_id,
        message=message[:500],
    )


def _confirmation_flags(
    evidence: dict[str, Evidence], assessment: Assessment | None
) -> tuple[bool, bool]:
    """Admissible exact confirmation + same-scope contradiction (§4.3)."""

    admissible = any(
        entry.observable_id is not None
        and is_admissible_malicious_confirmation(entry, entry.observable_id)
        for entry in evidence.values()
    )
    contradicted = False
    if assessment is not None:
        for inference in assessment.inferences:
            if inference.code != "external_conflict":
                continue
            for evidence_id in inference.evidence_ids:
                entry = evidence.get(evidence_id)
                if entry is not None and entry.provenance in ("OSINT", "SANDBOX"):
                    contradicted = True
                    break
            if contradicted:
                break
    return admissible, contradicted


# ---------------------------------------------------------------------------
# Run bookkeeping (trace + counters)
# ---------------------------------------------------------------------------


@dataclass
class _RunTrace:
    """Chronological trace and counters of one agentic run."""

    started_monotonic: float
    clock: Callable[[], float]
    events: list[dict[str, Any]] = field(default_factory=list)

    def add(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {
            "ts": _iso_now(),
            "t_ms": round((self.clock() - self.started_monotonic) * 1000.0, 3),
            "event": event,
        }
        record.update(fields)
        self.events.append(record)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_agentic_email(
    email_path: Path,
    settings: Settings,
    *,
    source_profile: SourceProfile = "public_corpus",
    client: Any | None = None,
    adapters: ProviderAdapterSet | None = None,
    run_root: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
    limits: AgentLimits = DEFAULT_AGENT_LIMITS,
    sample_id: str | None = None,
    effort: str = AGENT_REASONING_EFFORT,
    rag: Any | None = None,
    rag_exclusions: Iterable[str] | None = None,
    current_duplicate_group: str | None = None,
    current_family_group: str | None = None,
    current_campaign_id: str | None = None,
    profile: AgentProfile = DEFAULT_AGENT_PROFILE,
) -> AgentRunResult:
    """Execute the bounded converged agentic runtime for ONE email.

    ``client``/``adapters``/``rag`` are injection points used by deterministic
    unit tests (stub clients are never live evidence). In production they are
    built from the real Settings/configs and every LLM/tool observation is a
    real response. ``rag`` defaults to the existing T15 factory
    (``RAG_ENABLED`` + ``tools.rag.enabled``); ``rag_exclusions`` and the
    three current-email group identities are caller-owned metadata exactly
    like the V1 RAG node (the adapter excludes them and V15 re-checks them).
    ``profile`` selects the agentic tool set and the deterministic context
    preprocessing (TICKET-19D-OSINT §24): ``agentic_core``/``agentic_osint``
    force RAG/QR/Vision OFF; ``agentic_context`` (default, T19D behavior)
    and ``agentic_full`` follow Settings.
    """

    started = clock()
    started_at = _iso_now()
    run_id = str(uuid.uuid4())
    agent_deadline = started + float(limits.max_agent_seconds)
    root = Path(run_root) if run_root is not None else Path(settings.RUNS_DIR) / AGENTIC_RUNS_SUBDIR
    run_dir = root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    capture_dir = run_dir / "responses"
    capture_dir.mkdir(parents=True, exist_ok=True)
    trace = _RunTrace(started_monotonic=started, clock=clock)

    tools_config = load_yaml_config(Path(settings.CONFIG_DIR) / "tools.yaml", ToolsConfig)
    policy_config = load_yaml_config(Path(settings.CONFIG_DIR) / "policy.yaml", PolicyConfig)
    assert isinstance(tools_config, ToolsConfig) and isinstance(policy_config, PolicyConfig)

    allow_context = context_allowed(profile)
    osint_on = osint_exposed(profile)
    active_tools = tools_for_profile(profile)

    email_hash: str | None = None
    parse_error: str | None = None
    llm_error = False
    agent_error: str | None = None
    finalize_attempts: list[dict[str, Any]] = []
    adapter_exceptions: list[str] = []
    turns_meta: list[dict[str, Any]] = []
    assessment: Assessment | None = None
    status: Literal["finalized", "incomplete", "error"] = "incomplete"
    rag_info = _RagPreprocessing()
    visual = _empty_visual_preprocessing()
    staged: tuple[Any, ...] = ()
    augmented: ParsedEmail | None = None
    exclusions: set[str] = set()
    has_rag = False
    has_visuals = False
    prompt_sha = agent_system_prompt_sha256(limits, has_osint=osint_on)
    # T19D §4: the exact values used by THIS run are captured once and reused
    # by the manifest, so the runtime contract fingerprint cannot diverge from
    # what the loop and the callers actually applied.
    max_output_tokens = int(
        getattr(settings, "FINAL_MAX_OUTPUT_TOKENS", _DEFAULT_MAX_OUTPUT_TOKENS)
    )
    tool_schema_sha = tool_schema_sha256(active_tools)
    assessment_schema_sha = assessment_schema_sha256()

    parsed = parse_email(
        Path(email_path), ParseLimits.from_config(tools_config.parse_limits)
    )
    if isinstance(parsed, ParseFailure):
        parse_error = f"{parsed.error}: {parsed.detail}"
        status = "error"
        agent_error = "parse_error"
        trace.add("error", kind="parse_error", message=parse_error)
        executor = None
    elif not allow_context:
        # T19D-OSINT §24.1: core/osint profiles force RAG/QR/Vision OFF. The
        # Settings are NOT modified; the preprocessing is simply never
        # called, even when the three switches are true.
        email_hash = parsed.email_sha256
        augmented = parsed
        staged = ()
        exclusions = set()
        prompt_sha = agent_system_prompt_sha256(limits, has_osint=osint_on)
        trace.add(
            "rag_lookup",
            enabled=False,
            forced_off_by_profile=profile,
            case_count=0,
            exclusion_count=0,
            error=None,
        )
        trace.add(
            "visual_preparation",
            vision_enabled=False,
            qr_decode_enabled=False,
            forced_off_by_profile=profile,
            visual_count=0,
            staged_count=0,
            qr_payload_count=0,
            qr_observable_count=0,
            statuses=[],
        )
    else:
        email_hash = parsed.email_sha256

        # --- deterministic T15/T16 preprocessing (never an agent tool) ------
        exclusions = {item for item in (rag_exclusions or ()) if isinstance(item, str)}
        rag_info = _rag_preprocess(parsed, settings, tools_config, rag, exclusions)
        visual = _vision_preprocess(
            parsed, Path(email_path).read_bytes(), settings, tools_config
        )
        augmented = parsed.model_copy(
            update={
                "links": [*parsed.links, *visual.links],
                "observables": [*parsed.observables, *visual.observables],
                "evidence": [*parsed.evidence, *visual.evidence],
                "images": list(visual.preparation.visuals),
            }
        )
        staged = visual.preparation.staged
        has_rag = bool(rag_info.cases)
        has_visuals = bool(staged)
        prompt_sha = agent_system_prompt_sha256(
            limits, has_rag=has_rag, has_visuals=has_visuals, has_osint=osint_on
        )
        trace.add(
            "rag_lookup",
            enabled=rag_info.enabled,
            case_count=len(rag_info.cases),
            exclusion_count=len(exclusions),
            error=rag_info.error,
        )
        trace.add(
            "visual_preparation",
            vision_enabled=visual.vision_enabled,
            qr_decode_enabled=visual.qr_enabled,
            visual_count=len(visual.preparation.visuals),
            staged_count=len(staged),
            qr_payload_count=sum(
                len(entry.qr_payloads) for entry in visual.preparation.visuals
            ),
            qr_observable_count=len(visual.observables),
            statuses=[entry.status for entry in visual.preparation.visuals],
        )

    if parse_error is None:
        assert augmented is not None
        executor = ProviderToolExecutor(
            parsed=augmented,
            adapters=adapters
            if adapters is not None
            else _build_real_adapters(settings, tools_config, clock),
            tools_config=tools_config,
            run_id=run_id,
            source_profile=source_profile,
            egress=tools_config.egress,
            capture_dir=capture_dir,
            deadline=agent_deadline,
            mode="live",
            clock=clock,
            limits=limits,
        )
        agent_client = client
        if agent_client is None:
            if settings.LITELLM_API_KEY is None:
                status = "error"
                llm_error = True
                agent_error = "llm_not_configured"
                trace.add(
                    "error",
                    kind="llm_not_configured",
                    message="LITELLM_API_KEY absent: no LLM request is attempted",
                )
            else:
                agent_client = AgentChatClient(
                    settings,
                    capture_dir=capture_dir,
                    clock=clock,
                    persist_request_body=(source_profile == "fixture"),
                )
        if agent_client is not None:
            messages = initial_messages(
                augmented,
                ContextLimits(),
                limits,
                rag_cases=rag_info.cases,
                staged=staged,
                has_osint=osint_on,
            )
            assessment, status, llm_error, agent_error, turns_meta = _run_loop(
                parsed=augmented,
                executor=executor,
                client=agent_client,
                messages=messages,
                tools=active_tools,
                trace=trace,
                limits=limits,
                agent_deadline=agent_deadline,
                effort=effort,
                max_output_tokens=max_output_tokens,
                finalize_attempts=finalize_attempts,
                include_content_excerpt=(source_profile == "fixture"),
            )

    if executor is not None:
        adapter_exceptions = executor.adapter_exceptions
        enrichment = Enrichment(
            virustotal=[r for r in executor.results if r.tool == "virustotal"],
            opencti=[r for r in executor.results if r.tool == "opencti"],
            urlscan=[r for r in executor.results if r.tool == "urlscan"],
            rag=list(rag_info.cases),
        )
        # OSINT results travel alongside the frozen Enrichment (never inside
        # it): merge/verify receive the combined deterministic list, so no
        # V1 contract changes shape.
        osint_results = [r for r in executor.results if r.tool == "osint"]
        combined_results: list[ToolResult] = [
            *enrichment.virustotal,
            *enrichment.opencti,
            *enrichment.urlscan,
            *osint_results,
        ]
        tool_counts = executor.tool_counts_by_provider()
        tool_statuses = executor.tool_statuses_by_provider()
        provider_tool_calls = executor.provider_tool_call_count
        duplicate_refusals = executor.duplicate_refusal_count
        planning_errors = executor.planning_error_count
    else:
        enrichment = Enrichment()
        osint_results = []
        combined_results = []
        tool_counts = {"virustotal": 0, "opencti": 0, "urlscan": 0, "osint": 0}
        tool_statuses = {
            provider: {"ok": 0, "not_found": 0, "unavailable": 0, "skipped": 0}
            for provider in ("virustotal", "opencti", "urlscan", "osint")
        }
        provider_tool_calls = 0
        duplicate_refusals = 0
        planning_errors = 0

    # --- deterministic merge / verifier / policy (never a second engine) ----
    agent_errors: list[VerificationIssue] = []
    evidence: dict[str, Evidence]
    observables: dict[str, Observable]
    merged_ok = True
    if augmented is not None:
        try:
            evidence, observables, _visuals = merge_evidence(augmented, combined_results)
        except EvidenceMergeError as error:
            merged_ok = False
            agent_errors.append(
                _issue(
                    "agent_evidence_merge_refused",
                    "critical",
                    "runtime",
                    str(error),
                )
            )
            evidence = {entry.id: entry for entry in augmented.evidence}
            observables = {entry.id: entry for entry in augmented.observables}
    else:
        evidence, observables = {}, {}

    verification = verify_assessment(
        assessment,
        "final",
        registry={"evidence": evidence, "observables": observables},
        tool_results=combined_results,
        parsed=augmented,
        rag_context=rag_info.cases,
        internal=None,
        run_context=RunContext(
            final_source="final_llm" if assessment is not None else "none",
            # Pixels actually attached to the agent request (0 when the
            # Vision switch is off): V10 can then tell a supplied screenshot
            # from an unprovided one.
            visual_count_sent=len(staged),
            current_duplicate_group=current_duplicate_group,
            current_family_group=current_family_group,
            current_campaign_id=current_campaign_id,
        ),
    )
    verdict = verification.verdict
    confidence = verification.confidence
    margin = verification.margin

    if parse_error is not None:
        agent_errors.append(
            _issue("agent_parse_error", "error", "parse", parse_error)
        )
    if llm_error:
        agent_errors.append(
            _issue(
                "agent_llm_error",
                "error",
                "runtime",
                agent_error or "llm turn failed",
            )
        )
    if status == "incomplete" and assessment is None:
        agent_errors.append(
            _issue(
                "agent_incomplete_no_final_assessment",
                "error",
                "runtime",
                agent_error or "the agent produced no valid final assessment",
            )
        )
    for exception in adapter_exceptions:
        agent_errors.append(
            _issue(
                "agent_adapter_exception",
                "warning",
                "tool",
                exception,
            )
        )

    admissible, contradicted = _confirmation_flags(evidence, verification.accepted)
    decision = decide_policy(
        PolicyInputs(
            assessment=verification.accepted,
            verification_issues=verification.issues,
            errors=agent_errors,
            final_source="final_llm" if assessment is not None else "none",
            parser_error=parse_error is not None,
            llm_error=llm_error,
            tool_results=enrichment,
            admissible_confirmation=admissible,
            confirmation_contradicted=contradicted,
        ),
        policy_config,
    )

    total_ms = round((clock() - started) * 1000.0, 3)

    # --- usage / cost aggregation -------------------------------------------
    usage = _aggregate_usage(turns_meta)
    pricing = _load_pricing(settings) or PRICING_SNAPSHOT
    cost_usd, cost_status = _estimate_total_cost(turns_meta, pricing)
    returned_models = sorted(
        {
            str(turn["returned_model"])
            for turn in turns_meta
            if turn.get("returned_model")
        }
    )

    trace.add(
        "run_end",
        status=status,
        action=decision.action,
        final_assessment_present=assessment is not None,
        policy_reasons=decision.reasons,
        total_ms=total_ms,
        merged_ok=merged_ok,
    )

    model_requested = (
        turns_meta[0]["requested_model"] if turns_meta else settings.LITELLM_MODEL
    )
    limits_payload = {
        "max_llm_turns": limits.max_llm_turns,
        "max_tool_calls": limits.max_tool_calls,
        "max_urlscan_calls": limits.max_urlscan_calls,
        "max_agent_seconds": limits.max_agent_seconds,
        "max_single_llm_seconds": limits.max_single_llm_seconds,
        "max_tool_result_chars": limits.max_tool_result_chars,
    }
    # T19D-OSINT §27.1: effective capabilities = the configuration ACTIVE
    # for THIS run (profile ∧ Settings ∧ tool config). Never the verdict,
    # never whether Qwen called a tool, never a provider hit.
    rag_index_fingerprint: str | None = None
    if rag_info.enabled and rag_info.cases:
        candidate_fp = rag_info.cases[0].embedding_model_id
        rag_index_fingerprint = candidate_fp if isinstance(candidate_fp, str) else None
    effective_capabilities = {
        "rag": bool(rag_info.enabled),
        "rag_index_fingerprint": rag_index_fingerprint,
        "qr": bool(allow_context and settings.QR_DECODE_ENABLED),
        "vision": bool(allow_context and settings.MODEL_SUPPORTS_VISION),
        "osint": bool(osint_on),
        "threatfox_configured": bool(osint_on and settings.ABUSECH_API_KEY is not None),
        "psl_version": PSL_VERSION if osint_on else None,
    }
    # T19D-OSINT §27: canonical runtime contract — exactly the ten required
    # fields, taken from the run actually executed. No timestamp, run_id,
    # email, model/tool result or secret enters it, so two runs under the
    # same contract share the same fingerprint (no second versioning system).
    runtime_contract = {
        "architecture": OSINT_ARCHITECTURE_NAME,
        "profile": profile,
        "model": model_requested,
        "reasoning_effort": effort,
        "max_output_tokens_per_turn": max_output_tokens,
        "limits": limits_payload,
        "effective_prompt_sha256": prompt_sha,
        "tool_schema_sha256": tool_schema_sha,
        "assessment_schema_sha256": assessment_schema_sha,
        "effective_capabilities": effective_capabilities,
    }
    runtime_contract_sha = hashlib.sha256(
        json.dumps(
            runtime_contract,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    manifest = {
        "schema_version": "1.0",
        "architecture": OSINT_ARCHITECTURE_NAME,
        "profile": profile,
        "run_kind": "t19c_agentic_runtime",
        "measurement_scope": MEASUREMENT_SCOPE,
        "performance_claims_allowed": PERFORMANCE_CLAIMS_ALLOWED,
        "run_id": run_id,
        "sample_id": sample_id,
        "email_sha256": email_hash,
        "source_profile": source_profile,
        "started_at": started_at,
        "completed_at": _iso_now(),
        "code_commit": _code_commit(),
        "model_requested": model_requested,
        "model_returned": returned_models[0] if len(returned_models) == 1 else returned_models,
        "effective_prompt_sha256": prompt_sha,
        "tool_schema_sha256": tool_schema_sha,
        "assessment_schema_sha256": assessment_schema_sha,
        "runtime_contract_sha256": runtime_contract_sha,
        "effective_capabilities": effective_capabilities,
        "reasoning_effort": effort,
        "max_output_tokens_per_turn": max_output_tokens,
        "limits": limits_payload,
        "llm_turn_count": len(turns_meta),
        "provider_tool_call_count": provider_tool_calls,
        "duplicate_tool_refusal_count": duplicate_refusals,
        "planning_error_count": planning_errors,
        "tool_counts_by_provider": tool_counts,
        "tool_statuses_by_provider": tool_statuses,
        "total_latency_ms": total_ms,
        "usage": usage,
        "estimated_cost_usd": cost_usd,
        "cost_status": cost_status,
        "pricing": pricing,
        "final_status": status,
        "final_action": decision.action,
        "final_verdict": verdict,
        "final_confidence": confidence,
        "final_margin": margin,
        "verification_issue_codes": [issue.code for issue in verification.issues],
        "finalize_attempt_count": len(finalize_attempts),
        # --- T19C convergence facts (effective, never inferred) --------------
        "rag_enabled": rag_info.enabled,
        "rag_case_count": len(rag_info.cases),
        "rag_lookup_error": rag_info.error,
        "rag_exclusion_count": len(exclusions),
        "vision_enabled": visual.vision_enabled,
        "qr_decode_enabled": visual.qr_enabled,
        "visual_count_sent": len(staged),
        "qr_payload_count": sum(
            len(entry.qr_payloads) for entry in visual.preparation.visuals
        ),
        "qr_observable_count": len(visual.observables),
        "prompt_guidance": {"rag": has_rag, "visuals": has_visuals, "osint": osint_on},
        "parse_error": parse_error,
        "llm_error": llm_error,
        "agent_error": agent_error,
    }
    final_document = {
        "run_id": run_id,
        "sample_id": sample_id,
        "status": status,
        "action": decision.action,
        "policy_reasons": decision.reasons,
        "assessment": (
            verification.accepted.model_dump(mode="json")
            if verification.accepted is not None
            else None
        ),
        "verdict": verdict,
        "confidence": confidence,
        "margin": margin,
        "finalize_attempts": finalize_attempts,
        "verification": {
            "accepted": verification.accepted is not None,
            "issues": [issue.model_dump(mode="json") for issue in verification.issues],
            "blocking_codes": list(verification.blocking_codes),
            "accepted_observable_ids": [
                observable.id for observable in verification.accepted_observables
            ],
        },
        "agent_errors": [issue.model_dump(mode="json") for issue in agent_errors],
        "merged_registries": {
            "evidence_count": len(evidence),
            "observable_count": len(observables),
        },
        "tool_results": [
            {
                "tool": result.tool,
                "query_observable_id": result.query_observable_id,
                "status": result.status,
                "reason": result.reason,
                "requests_sent": result.requests_sent,
                "mode": result.mode,
            }
            for result in _canonical_results(combined_results)
        ],
    }
    summary = _build_summary(
        run_id=run_id,
        sample_id=sample_id,
        status=status,
        action=decision.action,
        verdict=verdict,
        confidence=confidence,
        margin=margin,
        policy_reasons=decision.reasons,
        turn_count=len(turns_meta),
        provider_calls=provider_tool_calls,
        duplicate_refusals=duplicate_refusals,
        tool_statuses=tool_statuses,
        email_hash=email_hash,
        agent_error=agent_error,
    )

    _write_json(run_dir / "manifest.json", manifest)
    (run_dir / "trace.jsonl").write_text(
        "".join(
            json.dumps(event, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
            for event in trace.events
        ),
        encoding="utf-8",
    )
    _write_json(run_dir / "final.json", final_document)
    (run_dir / "summary.txt").write_text(summary, encoding="utf-8")

    return AgentRunResult(
        run_id=run_id,
        status=status,
        action=decision.action,
        policy_reasons=list(decision.reasons),
        assessment=verification.accepted,
        verdict=verdict,
        confidence=confidence,
        margin=margin,
        run_dir=run_dir,
        llm_turn_count=len(turns_meta),
        provider_tool_call_count=provider_tool_calls,
        duplicate_tool_refusal_count=duplicate_refusals,
        tool_counts_by_provider=tool_counts,
        tool_statuses_by_provider=tool_statuses,
        total_ms=total_ms,
        prompt_sha256=prompt_sha,
        email_sha256=email_hash,
        sample_id=sample_id,
        parse_error=parse_error,
        llm_error=llm_error,
        agent_error=agent_error,
    )


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def _run_loop(
    *,
    parsed: ParsedEmail,
    executor: ProviderToolExecutor,
    client: Any,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    trace: _RunTrace,
    limits: AgentLimits,
    agent_deadline: float,
    effort: str,
    max_output_tokens: int,
    finalize_attempts: list[dict[str, Any]],
    include_content_excerpt: bool,
) -> tuple[
    Assessment | None,
    Literal["finalized", "incomplete", "error"],
    bool,
    str | None,
    list[dict[str, Any]],
]:
    """Bounded LLM loop; returns (assessment, status, llm_error, error, turns)."""

    turns: list[dict[str, Any]] = []
    finalized: Assessment | None = None
    llm_error = False
    agent_error: str | None = None
    status: Literal["finalized", "incomplete", "error"] = "incomplete"
    turn_index = 0

    while turn_index < limits.max_llm_turns:
        if trace.clock() >= agent_deadline:
            agent_error = "deadline_exceeded"
            trace.add(
                "error",
                kind="deadline_exceeded",
                message="the agentic budget expired before the next LLM turn",
            )
            break
        turn_index += 1
        call_deadline = min(
            agent_deadline, trace.clock() + float(limits.max_single_llm_seconds)
        )
        response = client.complete_with_tools(
            messages,
            tools,
            deadline=call_deadline,
            max_output_tokens=max_output_tokens,
            turn_index=turn_index,
            effort=effort,
        )
        turn_meta = {
            "turn": turn_index,
            "status": response.status,
            "requested_model": response.requested_model,
            "returned_model": response.returned_model,
            "finish_reason": response.finish_reason,
            "input_tokens": response.input_tokens,
            "cached_input_tokens": response.cached_input_tokens,
            "output_tokens": response.output_tokens,
            "reasoning_tokens": response.reasoning_tokens,
            "request_sha256": response.request_sha256,
            "response_sha256": response.response_sha256,
            "elapsed_ms": response.elapsed_ms,
            "error": response.error,
        }
        turns.append(turn_meta)
        content = response.content or ""
        trace.add(
            "llm_turn",
            turn=turn_index,
            status=response.status,
            requested_model=response.requested_model,
            returned_model=response.returned_model,
            finish_reason=response.finish_reason,
            tool_calls=[
                {
                    "id": call.call_id,
                    "name": call.name,
                    "arguments": call.arguments,
                    "arguments_error": call.arguments_error,
                }
                for call in response.tool_calls
            ],
            content_chars=len(content),
            # Minimization: free-form model prose may quote email content, so
            # only its length and hash are persisted unless the source profile
            # explicitly allows fixture retention. The in-memory message keeps
            # the full content for the protocol.
            content_sha256=_sha256_text(content) if content else None,
            content_excerpt=(content[:1000] if include_content_excerpt else None),
            usage={
                "input_tokens": response.input_tokens,
                "cached_input_tokens": response.cached_input_tokens,
                "output_tokens": response.output_tokens,
                "reasoning_tokens": response.reasoning_tokens,
            },
            request_sha256=response.request_sha256,
            response_sha256=response.response_sha256,
            elapsed_ms=response.elapsed_ms,
            error=response.error,
        )
        if response.status != "ok":
            llm_error = True
            agent_error = f"llm_turn_error:{response.error}"
            status = "error"
            break

        # Native tool protocol: only calls carrying a provider id can be
        # echoed and answered with a role=tool message. A call without an id
        # is a protocol error and is refused below, never executed.
        echoed_calls = [call for call in response.tool_calls if call.call_id]
        assistant_message: dict[str, Any] = {
            "role": "assistant",
            "content": response.content or "",
        }
        if echoed_calls:
            assistant_message["tool_calls"] = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {
                        "name": call.name or "",
                        "arguments": call.arguments_raw
                        if call.arguments_raw is not None
                        else json.dumps(
                            call.arguments or {},
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                    },
                }
                for call in echoed_calls
            ]
        messages.append(assistant_message)

        answered_calls = echoed_calls
        unanswered_refusals: list[ToolExecution] = []
        finalized_this_turn = False

        for call in response.tool_calls:
            trace.add(
                "tool_request",
                turn=turn_index,
                call_id=call.call_id,
                tool=call.name,
                arguments=call.arguments,
                arguments_error=call.arguments_error,
            )
            if call.name == FINALIZE_TOOL:
                if not call.call_id:
                    # Native tool protocol: a terminal finalize without a
                    # provider tool_call_id is not attributable/auditable and
                    # must NEVER produce status=finalized. It is a typed
                    # protocol refusal; the loop may continue if budget
                    # remains, otherwise the run ends incomplete/REVIEW.
                    issue = (
                        "missing_tool_call_id: a finalize_assessment without a "
                        "native provider tool_call_id cannot be attributed and is "
                        "refused; it never finalizes the run"
                    )
                    finalize_attempts.append(
                        {
                            "turn": turn_index,
                            "call_id": None,
                            "valid": False,
                            "issues": [issue],
                        }
                    )
                    trace.add(
                        "finalization",
                        turn=turn_index,
                        call_id=None,
                        valid=False,
                        issues=[issue],
                    )
                    unanswered_refusals.append(
                        ToolExecution(
                            tool=FINALIZE_TOOL,
                            provider=None,
                            call_id=None,
                            observable_id=None,
                            outcome="refused",
                            refusal_reason="missing_tool_call_id",
                        )
                    )
                    continue
                candidate, issues = parse_finalize_arguments(call.arguments)
                finalize_attempts.append(
                    {
                        "turn": turn_index,
                        "call_id": call.call_id,
                        "valid": candidate is not None,
                        "issues": issues,
                    }
                )
                trace.add(
                    "finalization",
                    turn=turn_index,
                    call_id=call.call_id,
                    valid=candidate is not None,
                    issues=issues,
                )
                if candidate is not None:
                    finalized = candidate
                    finalized_this_turn = True
                    break
                reply = json.dumps(
                    {
                        "refused": True,
                        "tool": FINALIZE_TOOL,
                        "reason": "invalid_assessment",
                        "issues": issues[:5],
                        "message": (
                            "the assessment is invalid and was rejected; correct it "
                            "exactly against the schema and call finalize_assessment "
                            "again"
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                if call.call_id:
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.call_id,
                            "content": reply,
                        }
                    )
                else:
                    unanswered_refusals.append(
                        ToolExecution(
                            tool=FINALIZE_TOOL,
                            provider=None,
                            call_id=None,
                            observable_id=None,
                            outcome="refused",
                            refusal_reason="missing_tool_call_id",
                        )
                    )
                continue

            execution = executor.execute(call)
            trace.add(
                "tool_validation",
                turn=turn_index,
                call_id=call.call_id,
                tool=call.name,
                valid=execution.outcome == "executed",
                refusal_reason=execution.refusal_reason,
                observable_id=execution.observable_id,
            )
            if execution.outcome == "executed" and execution.result is not None:
                trace.add(
                    "provider_execution",
                    turn=turn_index,
                    call_id=call.call_id,
                    tool=execution.tool,
                    provider=execution.provider,
                    observable_id=execution.observable_id,
                    status=execution.result.status,
                    reason=execution.result.reason,
                    requests_sent=execution.result.requests_sent,
                    mode=execution.result.mode,
                    elapsed_ms=execution.result.elapsed_ms,
                )
            payload = execution_payload(
                execution, limits.max_tool_result_chars, limits
            )
            trace.add(
                "tool_result",
                turn=turn_index,
                call_id=call.call_id,
                tool=execution.tool,
                observable_id=execution.observable_id,
                outcome=execution.outcome,
                refusal_reason=execution.refusal_reason,
                provider_status=execution.provider_status,
                payload_chars=len(payload),
                payload_sha256=_sha256_text(payload),
            )
            if call.call_id:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.call_id,
                        "content": payload,
                    }
                )
            else:
                unanswered_refusals.append(execution)

        if finalized_this_turn:
            status = "finalized"
            break

        if unanswered_refusals:
            # Calls without a provider id cannot receive a role=tool answer:
            # they are reported in a deterministic protocol-error message.
            messages.append(
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "agent_protocol_error": (
                                "one or more tool calls had no call id; they were "
                                "refused and cannot be answered individually"
                            ),
                            "refusals": [
                                {
                                    "tool": refusal.tool,
                                    "reason": refusal.refusal_reason,
                                }
                                for refusal in unanswered_refusals
                            ],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                }
            )

        if not response.tool_calls:
            trace.add(
                "error",
                kind="no_tool_calls",
                turn=turn_index,
                content_chars=len(response.content or ""),
            )
            if turn_index < limits.max_llm_turns:
                messages.append({"role": "user", "content": _NO_TOOL_CALLS_NUDGE})
        if not answered_calls and response.tool_calls:
            trace.add(
                "error",
                kind="tool_calls_without_ids",
                turn=turn_index,
                count=len(response.tool_calls),
            )

    if finalized is not None:
        return finalized, "finalized", llm_error, agent_error, turns
    if status == "error":
        return None, "error", llm_error, agent_error, turns
    if agent_error is None:
        agent_error = (
            "turn_budget_exhausted"
            if turn_index >= limits.max_llm_turns
            else "no_final_assessment"
        )
        trace.add(
            "error",
            kind=agent_error,
            message="the agent stopped without a valid final assessment",
        )
    return None, "incomplete", llm_error, agent_error, turns


# ---------------------------------------------------------------------------
# Usage / cost / artifacts helpers
# ---------------------------------------------------------------------------


def _canonical_results(results: Any) -> list[ToolResult]:
    """Tool results in canonical order for the final document (§2.4).

    Accepts the historical ``Enrichment`` object or any explicit sequence
    (the agentic runner passes the combined V1 + OSINT list so OSINT
    observations are listed without reshaping the frozen V1 contract).
    """

    if results is None:
        return []
    if all(hasattr(results, name) for name in ("virustotal", "opencti", "urlscan")):
        return [
            *results.virustotal,
            *results.opencti,
            *results.urlscan,
        ]
    return list(results)


def _aggregate_usage(turns: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
    }
    known = {key: 0 for key in totals}
    for turn in turns:
        for key in totals:
            value = turn.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                totals[key] += value
                known[key] += 1
    return {
        **totals,
        "turns_with_usage": sum(
            1
            for turn in turns
            if isinstance(turn.get("input_tokens"), int)
            or isinstance(turn.get("output_tokens"), int)
        ),
        "usage_status": (
            "complete"
            if turns and all(
                isinstance(turn.get("input_tokens"), int)
                and isinstance(turn.get("output_tokens"), int)
                for turn in turns
            )
            else ("unknown" if not turns else "partial")
        ),
    }


def _estimate_total_cost(
    turns: list[dict[str, Any]], pricing: dict[str, Any]
) -> tuple[float | None, str]:
    costs: list[float] = []
    statuses: list[str] = []
    for turn in turns:
        call = {
            "input_tokens": turn.get("input_tokens"),
            "output_tokens": turn.get("output_tokens"),
            "cached_input_tokens": turn.get("cached_input_tokens"),
            "cost_usd": None,
            "cost_status": "unknown",
        }
        cost, status = estimate_cost_usd(call, pricing)
        statuses.append(status)
        if cost is not None:
            costs.append(cost)
    if not turns or not costs:
        return None, "unknown"
    status = "estimated" if all(item == "estimated" for item in statuses) else "partial"
    return round(sum(costs), 8), status


def _build_summary(
    *,
    run_id: str,
    sample_id: str | None,
    status: str,
    action: str,
    verdict: str | None,
    confidence: float | None,
    margin: float | None,
    policy_reasons: list[str],
    turn_count: int,
    provider_calls: int,
    duplicate_refusals: int,
    tool_statuses: dict[str, dict[str, int]],
    email_hash: str | None,
    agent_error: str | None,
) -> str:
    """Deterministic French summary of the bounded smoke run."""

    def _num(value: float | None) -> str:
        return "null" if value is None else f"{value:.4f}"

    tools = ", ".join(
        f"{provider}="
        + "/".join(f"{key}:{value}" for key, value in counts.items())
        for provider, counts in tool_statuses.items()
    )
    lines = [
        f"Bilan agentique (smoke) — run {run_id}",
        f"sample: {sample_id or (email_hash or 'inconnu')}",
        f"statut: {status}; action: {action}",
        f"verdict: {verdict or 'null'} (confiance {_num(confidence)}, marge {_num(margin)})",
        f"tours LLM: {turn_count}; appels fournisseurs: {provider_calls}; refus de doublon: {duplicate_refusals}",
        f"outils: {tools}",
        f"raisons policy: {', '.join(policy_reasons) if policy_reasons else 'aucune'}",
    ]
    if agent_error:
        lines.append(f"erreur agent: {agent_error}")
    lines.extend(
        [
            "portée: measurement_scope=smoke; performance_claims_allowed=false",
            "aucune conclusion de performance ne peut être tirée de ce run (T19E seul définit le benchmark).",
        ]
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "AGENTIC_RUNS_SUBDIR",
    "run_agentic_email",
]

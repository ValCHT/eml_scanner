"""Sequential StateGraph pipeline (TICKET-11, docs/architecture.md §1.2).

Exactly one ``add_conditional_edges`` exists, on ``complexity_gate``, with the
frozen mapping ``simple: verify`` / ``complex: virustotal``; every other link
is an ``add_edge``. No cycle, no fan-out, no subgraph. Recoverable provider or
parser errors become typed state data and never add an edge; a refused report
write raises and the caller exits non-zero (a saved report is never claimed).

``build_graph(services) -> CompiledStateGraph`` receives the harness by
explicit injection (``Services`` is a plain Python container OUTSIDE the
checkpointed state: clients, secrets, monotonic deadline and capture
directories never enter the state). A fresh ``InMemorySaver`` is created per
compiled graph, and ``run_email`` compiles one graph per email with
``configurable.thread_id = run_id``; the saver is released with the local
graph and no module-level registry retains it.

``run_email(path, settings) -> TriageReport`` creates the state, executes the
graph and returns the report that ``write_report`` actually archived.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from .config import (
    EgressConfig,
    GateConfig,
    PolicyConfig,
    Settings,
    SourceProfile,
    ToolsConfig,
    load_yaml_config,
)
from .evidence import (
    EvidenceMergeError,
    assess_final,
    final_selection,
    merge_evidence,
)
from .gate import decide_gate
from .llm import LunaClient
from .parsing import ParseFailure, ParseLimits, parse_email
from .policy import PolicyInputs, decide_policy
from .prompts import ContextLimits, canonical_bytes
from .reporting import (
    TriageReport,
    build_events,
    build_report,
    write_report,
)
from .state import (
    Assessment,
    CallRecord,
    EmailTriageState,
    Link,
    Observable,
    Timings,
    VerificationIssue,
    new_state,
)
from .tools import ToolContext
from .tools.opencti import OpenCTIAdapter
from .tools.urlscan import UrlscanAdapter
from .tools.virustotal import VirusTotalAdapter, plan_vt_targets
from .verify import (
    RunContext,
    assess_internal,
    is_admissible_malicious_confirmation,
    verify_assessment,
)

#: Link roles carrying an investigable destination (same frozen set as the
#: complexity gate R2 and the TICKET-06 VT plan).
_RELEVANT_ROLES = frozenset({"href", "visible_url", "form_action", "qr_url"})


@dataclass
class Services:
    """Per-run dependency container (docs/contracts.md §2.7).

    Plain Python object, never serialized into the checkpointed state. The two
    LLM clients are phase-bound because ``LunaClient`` owns its phase (INTERNAL
    and FINAL capture/audit names); both are injected, never rebuilt by nodes.
    """

    settings: Settings
    tools_config: ToolsConfig
    gate_config: GateConfig
    policy_config: PolicyConfig
    vt: VirusTotalAdapter
    cti: OpenCTIAdapter
    urlscan: UrlscanAdapter
    luna: LunaClient | None
    luna_final: LunaClient | None
    egress: EgressConfig
    run_dir: Path
    capture_dir: Path
    deadline: float
    clock: Callable[[], float]
    started_monotonic: float
    mode: Literal["live", "recorded"] = "live"
    rag: Any | None = None
    call_log: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Deterministic observable plans (only normalized parser observables)
# ---------------------------------------------------------------------------


def _link_ref(link: Link) -> str:
    """Observable source_ref convention of the parser (TICKET-03/TICKET-06)."""

    return f"{link.part_id}:link:{link.id[:16]}"


def _link_ref_sets(parsed: Any) -> tuple[set[str], set[str], dict[str, int]]:
    mismatch: set[str] = set()
    eligible: set[str] = set()
    order: dict[str, int] = {}
    if parsed is None:
        return mismatch, eligible, order
    for index, link in enumerate(parsed.links):
        if link.role not in _RELEVANT_ROLES:
            continue
        ref = _link_ref(link)
        if ref not in order:
            order[ref] = index
        eligible.add(ref)
        if link.href_display_mismatch:
            mismatch.add(ref)
    return mismatch, eligible, order


def plan_url_targets(
    parsed: Any, observables: list[Observable], max_targets: int
) -> list[Observable]:
    """URL-only deterministic plan: mismatch href/form first, then MIME order."""

    mismatch, eligible, order = _link_ref_sets(parsed)
    ranked: list[tuple[tuple[int, int], Observable]] = []
    for index, observable in enumerate(observables):
        if observable.type != "url":
            continue
        if observable.source_ref in mismatch:
            bucket = 0
        elif observable.source_ref in eligible:
            bucket = 1
        else:
            continue  # remote_resource or unknown provenance: never sent
        ranked.append(((bucket, order.get(observable.source_ref, index)), observable))
    ranked.sort(key=lambda pair: pair[0])
    return [observable for _, observable in ranked[:max_targets]]


def plan_opencti_targets(
    parsed: Any, observables: list[Observable], max_targets: int
) -> list[Observable]:
    """Up to ``max_targets`` CTI targets in the normative §1.6 priority order.

    The adapter still applies the per-type applicability rules (URL privacy
    refusals, non-global IPs, recipients have no comparable type): this plan
    only bounds and orders the candidates.
    """

    mismatch, eligible, _ = _link_ref_sets(parsed)

    def _rank(index: int, observable: Observable) -> tuple[int, int]:
        if observable.type == "sha256" and "attachment" in observable.roles:
            return 0, index
        if observable.type == "url":
            if observable.source_ref in mismatch:
                return 1, index
            if observable.source_ref in eligible:
                return 2, index
            return 99, index
        if observable.type == "domain" and ({"sender", "reply_to"} & set(observable.roles)):
            return 3, index
        if observable.type in ("ipv4", "ipv6"):
            return 4, index
        return 99, index

    scored = sorted(
        ((_rank(index, observable), observable) for index, observable in enumerate(observables)),
        key=lambda pair: (pair[0][0], pair[0][1]),
    )
    targets: list[Observable] = []
    for (bucket, _index), observable in scored:
        if len(targets) >= max_targets:
            break
        if bucket == 99:
            continue
        targets.append(observable)
    return targets


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


def _ms(start: float, clock: Callable[[], float]) -> float:
    return round((clock() - start) * 1000.0, 3)


def _timings(state: EmailTriageState, **updates: float) -> Timings:
    return state.timings.model_copy(update=updates)


def _issue(
    code: str, severity: str, source: str, message: str, object_id: str | None = None
) -> VerificationIssue:
    return VerificationIssue(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        object_id=object_id,
        message=message[:500],
    )


def _tool_context(services: Services, state: EmailTriageState, phase_seconds: float) -> ToolContext:
    deadline = min(services.deadline, services.clock() + float(phase_seconds))
    return ToolContext(
        run_id=state.run_id,
        source_profile=state.source_profile,
        deadline=deadline,
        egress=services.egress,
        capture_dir=services.capture_dir,
        mode=services.mode,
    )


# ---------------------------------------------------------------------------
# Nodes: node(state) -> patch (docs/architecture.md §1.3)
# ---------------------------------------------------------------------------


def node_parse_email(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """``.eml`` in bytes; no network. A parse failure is explicit state data."""

    start = services.clock()
    parsed = parse_email(
        Path(state.input_path),
        ParseLimits.from_config(services.tools_config.parse_limits),
    )
    elapsed = _ms(start, services.clock)
    if isinstance(parsed, ParseFailure):
        issue = _issue(
            "parse_error",
            "error",
            "parse",
            f"{parsed.error}: {parsed.detail}",
        )
        return {
            "parsed": None,
            "evidence": {},
            "observable_registry": {},
            "visual_evidence": [],
            "errors": [*state.errors, issue],
            "timings": _timings(state, parse_ms=elapsed),
        }
    return {
        "parsed": parsed,
        "evidence": {entry.id: entry for entry in parsed.evidence},
        "observable_registry": {entry.id: entry for entry in parsed.observables},
        "visual_evidence": list(parsed.images),
        "timings": _timings(state, parse_ms=elapsed),
    }


def node_internal_assessment(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """One real medium call at most; no call when parsing failed."""

    start = services.clock()
    if state.parsed is None:
        issue = _issue(
            "internal_not_attempted",
            "error",
            "internal",
            "parsed is null: the INTERNAL call is not attempted (no fabrication)",
        )
        return {
            "internal": None,
            "internal_call": None,
            "errors": [*state.errors, issue],
            "timings": _timings(state, internal_llm_ms=0.0),
        }
    if services.luna is None:
        issue = _issue(
            "internal_client_unavailable",
            "error",
            "internal",
            "no INTERNAL client configured: the call is not attempted",
        )
        return {
            "internal": None,
            "internal_call": None,
            "errors": [*state.errors, issue],
            "timings": _timings(state, internal_llm_ms=0.0),
        }
    if services.settings.LITELLM_API_KEY is None:
        issue = _issue(
            "internal_not_configured",
            "error",
            "internal",
            "LITELLM_API_KEY absent: no LLM request is attempted (never simulated)",
        )
        return {
            "internal": None,
            "internal_call": None,
            "errors": [*state.errors, issue],
            "timings": _timings(state, internal_llm_ms=0.0),
        }

    limits = ContextLimits().model_copy(
        update={
            "internal_phase_seconds": float(services.settings.INTERNAL_PHASE_SECONDS),
            "internal_max_output_tokens": int(services.settings.INTERNAL_MAX_OUTPUT_TOKENS),
        }
    )
    assessment, record = assess_internal(
        state.parsed,
        services.luna,
        limits,
        run_artifacts={
            "capture_dir": services.capture_dir,
            "source_profile": state.source_profile,
        },
    )
    elapsed = _ms(start, services.clock)
    errors = list(state.errors)
    if assessment is None:
        errors.append(
            _issue(
                "internal_assessment_unavailable",
                "error",
                "internal",
                f"status={record.status}, attempts={record.attempts}",
            )
        )
    return {
        "internal": assessment,
        "internal_call": record,
        "errors": errors,
        "timings": _timings(state, internal_llm_ms=elapsed),
    }


def node_complexity_gate(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Exactly R1–R3; on SIMPLE a deep copy of the INTERNAL result, no re-call."""

    start = services.clock()
    gate = decide_gate(state.parsed, state.internal, services.gate_config)
    patch: dict[str, Any] = {
        "gate": gate,
        "timings": _timings(state, gate_ms=_ms(start, services.clock)),
    }
    if gate.decision == "simple" and state.internal is not None:
        patch["final_candidate"] = state.internal.model_copy(deep=True)
        patch["final_source"] = "internal_copy"
        patch["final_call"] = None
    return patch


def node_virustotal(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """GET lookups only; an unavailable provider is a valid, typed outcome."""

    start = services.clock()
    observables = list(state.observable_registry.values())
    targets = plan_vt_targets(
        state.parsed, observables, services.tools_config.virustotal.max_targets
    )
    context = _tool_context(
        services, state, services.tools_config.virustotal.phase_timeout_s
    )
    results = [services.vt.lookup(target, context) for target in targets]
    return {
        "enrichment": state.enrichment.model_copy(update={"virustotal": results}),
        "timings": _timings(state, vt_ms=_ms(start, services.clock)),
    }


def node_opencti(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Read-only bounded CTI lookups; statuses carry their real cause."""

    start = services.clock()
    observables = list(state.observable_registry.values())
    targets = plan_opencti_targets(
        state.parsed, observables, services.tools_config.opencti.max_targets
    )
    context = _tool_context(
        services, state, services.tools_config.opencti.phase_timeout_s
    )
    results = [services.cti.lookup(target, context) for target in targets]
    return {
        "enrichment": state.enrichment.model_copy(update={"opencti": results}),
        "timings": _timings(state, opencti_ms=_ms(start, services.clock)),
    }


def node_urlscan(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """At most one URL submitted; private for real emails (adapter-enforced)."""

    start = services.clock()
    observables = list(state.observable_registry.values())
    targets = plan_url_targets(
        state.parsed, observables, services.tools_config.urlscan.max_urls
    )
    context = _tool_context(
        services, state, services.tools_config.urlscan.phase_timeout_s
    )
    results = [services.urlscan.scan(target, context) for target in targets]
    return {
        "enrichment": state.enrichment.model_copy(update={"urlscan": results}),
        "timings": _timings(state, urlscan_ms=_ms(start, services.clock)),
    }


def node_rag_lookup(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Documented no-op before G7-A (or when disabled): no context is invented.

    ``RAG_ENABLED`` is false in the frozen baseline; TICKET-15 replaces this
    node. An injected adapter is refused explicitly instead of being ignored,
    so an unfinished RAG path can never look enabled.
    """

    start = services.clock()
    errors = list(state.errors)
    if services.rag is not None:
        errors.append(
            _issue(
                "rag_not_implemented_before_g7a",
                "error",
                "runtime",
                "a RAG adapter was injected but rag_lookup is a documented "
                "no-op before G7-A: context stays empty",
            )
        )
    return {
        "enrichment": state.enrichment.model_copy(update={"rag": []}),
        "errors": errors,
        "timings": _timings(state, rag_ms=_ms(start, services.clock)),
    }


def node_merge_evidence(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Deterministic union by ID; collisions and dangling refs are refused."""

    start = services.clock()
    elapsed = _ms(start, services.clock)
    if state.parsed is None:
        return {
            "evidence": {},
            "observable_registry": {},
            "visual_evidence": [],
            "timings": _timings(state, merge_ms=elapsed),
        }
    try:
        evidence, observables, visuals = merge_evidence(state.parsed, state.enrichment)
    except EvidenceMergeError as error:
        issue = _issue(
            "evidence_merge_refused",
            "critical",
            "tool",
            str(error),
        )
        return {
            "errors": [*state.errors, issue],
            "timings": _timings(state, merge_ms=elapsed),
        }
    return {
        "evidence": evidence,
        "observable_registry": observables,
        "visual_evidence": visuals,
        "timings": _timings(state, merge_ms=elapsed),
    }


def _read_final_audit(capture_dir: Path) -> tuple[int | None, int | None]:
    """Actual §2.6.1 FINAL counters from the last archived attempt audit."""

    latest: tuple[int, Path] | None = None
    for path in capture_dir.glob("final_attempt_*.input_audit.json"):
        match = re.search(r"final_attempt_(\d+)\.input_audit\.json$", path.name)
        if match is None:
            continue
        attempt = int(match.group(1))
        if latest is None or attempt > latest[0]:
            latest = (attempt, path)
    if latest is None:
        return None, None
    try:
        audit = json.loads(latest[1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    external = audit.get("external_evidence_count_sent")
    visual = audit.get("visual_count_sent")
    return (
        external if isinstance(external, int) and not isinstance(external, bool) else None,
        visual if isinstance(visual, int) and not isinstance(visual, bool) else None,
    )


def node_final_assessment(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """One real xhigh call; any failure follows the documented fallback."""

    start = services.clock()
    if (
        state.parsed is None
        or services.luna_final is None
        or services.settings.LITELLM_API_KEY is None
    ):
        selection = final_selection(state.internal, None, None)
        return {
            "final_candidate": selection.candidate,
            "final_call": None,
            "final_source": selection.final_source,
            "errors": [*state.errors, *selection.warnings],
            "timings": _timings(state, final_llm_ms=0.0),
        }

    candidate, record = assess_final(
        state.parsed,
        state.internal,
        state.evidence,
        state.enrichment.rag,
        services.luna_final,
        observables=state.observable_registry,
        tool_results=state.enrichment,
        run_artifacts={"capture_dir": services.capture_dir},
    )
    selection = final_selection(state.internal, candidate, record)
    return {
        "final_candidate": selection.candidate,
        "final_call": record,
        "final_source": selection.final_source,
        "errors": [*state.errors, *selection.warnings],
        "timings": _timings(state, final_llm_ms=_ms(start, services.clock)),
    }


def node_verify(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Deterministic V01–V16 on the FINAL candidate (nothing is repaired)."""

    start = services.clock()
    external_count, visual_count = _read_final_audit(services.capture_dir)
    context = RunContext(
        final_source=state.final_source,
        internal_call=state.internal_call,
        final_call=state.final_call,
        timings=state.timings,
        external_evidence_count_sent=external_count,
        visual_count_sent=visual_count,
    )
    result = verify_assessment(
        state.final_candidate,
        "final",
        registry={
            "evidence": state.evidence,
            "observables": state.observable_registry,
        },
        tool_results=state.enrichment,
        parsed=state.parsed,
        rag_context=state.enrichment.rag,
        internal=state.internal,
        run_context=context,
    )
    return {
        "verification": result.issues,
        "accepted_observables": result.accepted_observables,
        "final_validated": result.accepted,
        "timings": _timings(state, verify_ms=_ms(start, services.clock)),
    }


def _confirmation_flags(state: EmailTriageState) -> tuple[bool, bool]:
    """Admissible exact confirmation and same-scope contradicted flag (§4.3)."""

    admissible = any(
        evidence.observable_id is not None
        and is_admissible_malicious_confirmation(evidence, evidence.observable_id)
        for evidence in state.evidence.values()
    )
    contradicted = False
    assessment = state.final_validated
    if assessment is not None:
        for inference in assessment.inferences:
            if inference.code != "external_conflict":
                continue
            for evidence_id in inference.evidence_ids:
                evidence = state.evidence.get(evidence_id)
                if evidence is not None and evidence.provenance in ("OSINT", "SANDBOX"):
                    contradicted = True
                    break
            if contradicted:
                break
    return admissible, contradicted


def node_policy(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Frozen priority order; recommendation only, no real email action."""

    start = services.clock()
    admissible, contradicted = _confirmation_flags(state)
    llm_error = any(
        record is not None and record.status == "error"
        for record in (state.internal_call, state.final_call)
    )
    inputs = PolicyInputs(
        assessment=state.final_validated,
        verification_issues=state.verification,
        errors=state.errors,
        final_source=state.final_source,
        parser_error=state.parsed is None,
        llm_error=llm_error,
        tool_results=state.enrichment,
        admissible_confirmation=admissible,
        confirmation_contradicted=contradicted,
    )
    decision = decide_policy(inputs, services.policy_config)
    return {
        "action": decision.action,
        "policy_reasons": decision.reasons,
        "timings": _timings(state, policy_ms=_ms(start, services.clock)),
    }


def node_write_report(state: EmailTriageState, services: Services) -> dict[str, Any]:
    """Validated JSON + deterministic summary; a refused write raises."""

    start = services.clock()
    target = services.run_dir / "report.json"
    events = build_events(state, str(target))
    report = build_report(state, services, report_started_monotonic=start)
    events[-1]["ms"] = report["timings"]["report_ms"]
    path = write_report(report, services.run_dir, events=events)
    return {
        "report_path": str(path),
        "timings": _timings(
            state,
            report_ms=report["timings"]["report_ms"],
            total_ms=report["timings"]["total_ms"],
        ),
    }


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------


def route_after_gate(state: EmailTriageState) -> str:
    """The ONLY conditional edge of the graph (docs/architecture.md §1.2)."""

    assert state.gate is not None, "complexity_gate must run before routing"
    return state.gate.decision


def build_graph(services: Services) -> Any:
    """Compile the frozen sequential pipeline with a fresh per-run saver."""

    builder = StateGraph(EmailTriageState)
    builder.add_node("parse_email", lambda state: node_parse_email(state, services))
    builder.add_node(
        "internal_assessment", lambda state: node_internal_assessment(state, services)
    )
    builder.add_node(
        "complexity_gate", lambda state: node_complexity_gate(state, services)
    )
    builder.add_node("virustotal", lambda state: node_virustotal(state, services))
    builder.add_node("opencti", lambda state: node_opencti(state, services))
    builder.add_node("urlscan", lambda state: node_urlscan(state, services))
    builder.add_node("rag_lookup", lambda state: node_rag_lookup(state, services))
    builder.add_node("merge_evidence", lambda state: node_merge_evidence(state, services))
    builder.add_node(
        "final_assessment", lambda state: node_final_assessment(state, services)
    )
    builder.add_node("verify", lambda state: node_verify(state, services))
    builder.add_node("policy", lambda state: node_policy(state, services))
    builder.add_node("write_report", lambda state: node_write_report(state, services))

    builder.add_edge(START, "parse_email")
    builder.add_edge("parse_email", "internal_assessment")
    builder.add_edge("internal_assessment", "complexity_gate")
    builder.add_conditional_edges(
        "complexity_gate",
        route_after_gate,
        {"simple": "verify", "complex": "virustotal"},
    )
    builder.add_edge("virustotal", "opencti")
    builder.add_edge("opencti", "urlscan")
    builder.add_edge("urlscan", "rag_lookup")
    builder.add_edge("rag_lookup", "merge_evidence")
    builder.add_edge("merge_evidence", "final_assessment")
    builder.add_edge("final_assessment", "verify")
    builder.add_edge("verify", "policy")
    builder.add_edge("policy", "write_report")
    builder.add_edge("write_report", END)

    saver = InMemorySaver()
    return builder.compile(checkpointer=saver)


# ---------------------------------------------------------------------------
# Run entry point
# ---------------------------------------------------------------------------


def _load_configs(settings: Settings) -> tuple[ToolsConfig, GateConfig, PolicyConfig]:
    tools = load_yaml_config(Path(settings.CONFIG_DIR) / "tools.yaml", ToolsConfig)
    gate = load_yaml_config(Path(settings.CONFIG_DIR) / "gate.yaml", GateConfig)
    policy = load_yaml_config(Path(settings.CONFIG_DIR) / "policy.yaml", PolicyConfig)
    assert isinstance(tools, ToolsConfig) and isinstance(gate, GateConfig)
    assert isinstance(policy, PolicyConfig)
    return tools, gate, policy


def config_sha256(
    settings: Settings, tools: ToolsConfig, gate: GateConfig, policy: PolicyConfig
) -> str:
    """Configuration fingerprint without secrets (docs/contracts.md §2.2)."""

    import hashlib

    payload = {
        "settings": settings.public_dump(),
        "gate": gate.model_dump(mode="json"),
        "policy": policy.model_dump(mode="json"),
        "tools": tools.model_dump(mode="json"),
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def build_services(
    settings: Settings,
    *,
    source_profile: SourceProfile,
    run_id: str,
    started_monotonic: float,
    mode: Literal["live", "recorded"] = "live",
    egress: EgressConfig | None = None,
) -> Services:
    """Build the per-run dependency container from Settings + configs."""

    tools, gate, policy = _load_configs(settings)
    run_dir = Path(settings.RUNS_DIR) / run_id
    capture_dir = run_dir / "responses"
    quota_dir = Path(settings.RUNS_DIR) / "quota"
    return Services(
        settings=settings,
        tools_config=tools,
        gate_config=gate,
        policy_config=policy,
        vt=VirusTotalAdapter(
            settings, tools.virustotal, quota_journal_path=quota_dir / "virustotal.json"
        ),
        cti=OpenCTIAdapter(settings, tools.opencti),
        urlscan=UrlscanAdapter(
            settings, tools.urlscan, quota_journal_path=quota_dir / "urlscan.json"
        ),
        luna=LunaClient(
            settings,
            phase="internal",
            capture_dir=capture_dir,
            persist_request_body=(source_profile == "fixture"),
        ),
        luna_final=LunaClient(
            settings,
            phase="final",
            capture_dir=capture_dir,
            persist_request_body=(source_profile == "fixture"),
        ),
        egress=egress if egress is not None else tools.egress,
        run_dir=run_dir,
        capture_dir=capture_dir,
        deadline=started_monotonic + float(settings.MAX_EMAIL_SECONDS),
        clock=time.monotonic,
        started_monotonic=started_monotonic,
        mode=mode,
    )


def run_email(
    path: Path, settings: Settings, *, source_profile: SourceProfile = "fixture"
) -> TriageReport:
    """Execute the frozen pipeline for one email and return the written report.

    A pure read/parse/analyse path: no email action, no network outside the
    typed adapters. ``settings.RUNS_DIR`` is the run root; the report is
    archived under ``RUNS_DIR/<run_id>/report.json`` and read back only after
    ``write_report`` actually wrote it.
    """

    path = Path(path).resolve()
    tools, gate, policy = _load_configs(settings)
    started = time.monotonic()
    state = new_state(path, source_profile, config_sha256(settings, tools, gate, policy))
    services = build_services(
        settings,
        source_profile=source_profile,
        run_id=state.run_id,
        started_monotonic=started,
    )
    graph = build_graph(services)
    final_state = graph.invoke(state, config={"configurable": {"thread_id": state.run_id}})
    report_path = final_state.get("report_path") if isinstance(final_state, dict) else None
    if not isinstance(report_path, str) or not Path(report_path).is_file():
        raise RuntimeError("pipeline completed without an archived report path")
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise RuntimeError("archived report is not a JSON object")
    return report


__all__ = [
    "Services",
    "build_graph",
    "build_services",
    "config_sha256",
    "node_complexity_gate",
    "node_final_assessment",
    "node_internal_assessment",
    "node_merge_evidence",
    "node_opencti",
    "node_parse_email",
    "node_policy",
    "node_rag_lookup",
    "node_urlscan",
    "node_verify",
    "node_virustotal",
    "node_write_report",
    "plan_opencti_targets",
    "plan_url_targets",
    "route_after_gate",
    "run_email",
]

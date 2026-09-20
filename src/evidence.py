"""Deterministic evidence merge and FINAL assessment driver (TICKET-09).

``merge_evidence(parsed, tool_results)`` combines the parser registries
(provenance INTERNE) with the normalized results of the real tool adapters
(OSINT for VirusTotal/OpenCTI, SANDBOX for urlscan) into the evidence and
observable registries consumed by the FINAL phase:

- the internal provenance of a locally computed hash or parser fact is
  preserved; a tool assertion about the same artifact is a SEPARATE
  evidence entry with its own provenance (docs/contracts.md §2.4);
- identical IDs with identical content are idempotent; identical IDs with
  different content are refused (``EvidenceMergeError``);
- only normalized ``Evidence`` / ``Observable`` objects enter the
  registries: raw provider JSON is never copied (§2.6/§2.7);
- an ``ok`` tool result must carry an archived response reference and
  fingerprint before any positive evidence is accepted; a non-``ok``
  result carrying positive evidence is refused;
- ordering is canonical (``canonical_tool_results``), so the same set of
  inputs in any order yields identical registries and audit digests.

``assess_final(parsed, internal, evidence, rag_context, client)`` performs
the real FINAL phase (xhigh, one serialization, exact-bytes audit by the
client, strict reference validation) and never fabricates a result: on any
failure it returns ``(None, CallRecord)``. The documented fallback (copy the
valid internal assessment, ``final_source=internal_fallback``, blocking
warning) is provided as ``final_selection`` so the graph can apply it
without inventing a replacement verdict.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .prompts import (
    ContextLimits,
    FINAL_EFFORT,
    build_final_messages,
    canonical_bytes,
    canonical_tool_results,
    envelope_has_useful_content,
)
from .state import (
    Assessment,
    CallRecord,
    Evidence,
    Observable,
    ParsedEmail,
    ToolResult,
    VerificationIssue,
    VisualEvidence,
)
from .verify import compute_verdict_confidence

#: Provenance enforced per producer (docs/decisions.md §4.2 V04).
PROVENANCE_BY_SOURCE_KIND: dict[str, str] = {
    "parser": "INTERNE",
    "virustotal": "OSINT",
    "opencti": "OSINT",
    "urlscan": "SANDBOX",
}

#: Provenance values a FINAL assessment may reference (never INFERENCE).
FACTUAL_PROVENANCE: tuple[str, ...] = ("INTERNE", "OSINT", "SANDBOX")

#: Confidence rise above which a verdict/confidence move without any
#: external evidence sent is signalled for the G5 verifier (V14 input).
CONFIDENCE_RISE_WITHOUT_EVIDENCE_THRESHOLD = 0.05


class EvidenceMergeError(ValueError):
    """Explicit refusal of the merge (collision, missing proof, raw data)."""


# ---------------------------------------------------------------------------
# merge_evidence
# ---------------------------------------------------------------------------


def _canonical_content(model: Evidence | Observable | VisualEvidence) -> bytes:
    return canonical_bytes(model.model_dump(mode="json"))


def _tool_result_objects(tool_results: Any) -> list[ToolResult]:
    if tool_results is None:
        return []
    if all(hasattr(tool_results, name) for name in ("virustotal", "opencti", "urlscan")):
        items: Iterable[Any] = [
            *tool_results.virustotal,
            *tool_results.opencti,
            *tool_results.urlscan,
        ]
    else:
        items = tool_results
    results: list[ToolResult] = []
    for item in items:
        if not isinstance(item, ToolResult):
            raise EvidenceMergeError(
                f"tool_results: expected ToolResult objects, got {type(item).__name__}"
            )
        results.append(item)
    return results


def merge_evidence(
    parsed: ParsedEmail,
    tool_results: Any = None,
) -> tuple[dict[str, Evidence], dict[str, Observable], list[VisualEvidence]]:
    """Merge parser registries with normalized tool results (docs/contracts.md §2.4).

    Returns ``(evidence, observables, visual_evidence)``: registry dicts
    keyed by deterministic ID, in stable order (parser entries first, then
    canonical tool order), plus the visual evidence list (INTERNE image
    metadata; G5 supplies no pixels).

    The function is pure, offline and never repairs: every refusal raises
    ``EvidenceMergeError`` with the concrete cause.
    """

    ordered_results = canonical_tool_results(_tool_result_objects(tool_results))

    evidence: dict[str, Evidence] = {}
    observables: dict[str, Observable] = {}
    visuals: list[VisualEvidence] = []

    def _insert_evidence(entry: Evidence, origin: str) -> None:
        if not entry.id.startswith("ev_"):
            raise EvidenceMergeError(f"{origin}: evidence ID {entry.id!r} is not ev_-prefixed")
        existing = evidence.get(entry.id)
        if existing is None:
            evidence[entry.id] = entry
            return
        if _canonical_content(existing) != _canonical_content(entry):
            raise EvidenceMergeError(
                f"{origin}: evidence ID collision with different content: {entry.id}"
            )
        # Identical ID + content: idempotent, the first occurrence is kept.

    def _insert_observable(entry: Observable, origin: str) -> None:
        if not entry.id.startswith("obs_"):
            raise EvidenceMergeError(f"{origin}: observable ID {entry.id!r} is not obs_-prefixed")
        existing = observables.get(entry.id)
        if existing is None:
            observables[entry.id] = entry
            return
        if _canonical_content(existing) != _canonical_content(entry):
            raise EvidenceMergeError(
                f"{origin}: observable ID collision with different content: {entry.id}"
            )

    def _insert_visual(entry: VisualEvidence, origin: str) -> None:
        if not entry.id.startswith("vis_"):
            raise EvidenceMergeError(f"{origin}: visual ID {entry.id!r} is not vis_-prefixed")
        for existing in visuals:
            if existing.id != entry.id:
                continue
            if _canonical_content(existing) != _canonical_content(entry):
                raise EvidenceMergeError(
                    f"{origin}: visual ID collision with different content: {entry.id}"
                )
            return
        visuals.append(entry)

    # --- parser registries first: INTERNE provenance, stable parser order.
    for entry in parsed.evidence:
        if entry.provenance != PROVENANCE_BY_SOURCE_KIND["parser"]:
            raise EvidenceMergeError(
                f"parser: evidence {entry.id!r} has provenance {entry.provenance!r}; "
                "parser evidence is INTERNE"
            )
        if not entry.source_ref:
            raise EvidenceMergeError(f"parser: evidence {entry.id!r} has no source_ref")
        _insert_evidence(entry, "parser")
    for entry in parsed.observables:
        if entry.provenance != PROVENANCE_BY_SOURCE_KIND["parser"]:
            raise EvidenceMergeError(
                f"parser: observable {entry.id!r} has provenance {entry.provenance!r}; "
                "parser observables are INTERNE"
            )
        _insert_observable(entry, "parser")
    for entry in parsed.images:
        _insert_visual(entry, "parser")

    # --- normalized tool results.
    for result in ordered_results:
        _merge_tool_result(result, _insert_evidence, _insert_observable)

    # --- reference integrity: no dangling reference ever enters a registry.
    for entry in evidence.values():
        if entry.observable_id is not None and entry.observable_id not in observables:
            raise EvidenceMergeError(
                f"evidence {entry.id!r} references unknown observable "
                f"{entry.observable_id!r}"
            )
    for entry in observables.values():
        for evidence_id in entry.evidence_ids:
            if evidence_id not in evidence:
                raise EvidenceMergeError(
                    f"observable {entry.id!r} references unknown evidence "
                    f"{evidence_id!r}"
                )

    return evidence, observables, visuals


def _merge_tool_result(
    result: ToolResult,
    insert_evidence: Any,
    insert_observable: Any,
) -> None:
    """Validate and insert one normalized ToolResult (§2.4, §2.6)."""

    origin = f"{result.tool}:{result.query_observable_id or '?'}"
    if result.status != "ok":
        # not_found / unavailable / skipped are statuses, never positive
        # evidence: a non-ok result carrying evidence or observables is
        # refused instead of silently accepted.
        if result.evidence or result.observables:
            raise EvidenceMergeError(
                f"{origin}: {result.status} result carries positive "
                "evidence/observables; refused"
            )
        return

    if not result.response_ref or not result.response_sha256:
        raise EvidenceMergeError(
            f"{origin}: ok result without archived response reference "
            "and fingerprint; positive evidence refused"
        )

    expected_provenance = PROVENANCE_BY_SOURCE_KIND[result.tool]
    for entry in result.evidence:
        if entry.source_kind != result.tool:
            raise EvidenceMergeError(
                f"{origin}: evidence {entry.id!r} source_kind {entry.source_kind!r} "
                f"does not match tool {result.tool!r}"
            )
        if entry.provenance != expected_provenance:
            raise EvidenceMergeError(
                f"{origin}: evidence {entry.id!r} has provenance "
                f"{entry.provenance!r}; expected {expected_provenance!r}"
            )
        if not entry.source_ref:
            raise EvidenceMergeError(
                f"{origin}: evidence {entry.id!r} has no source_ref "
                "(missing proof); refused"
            )
        if not entry.observed_at:
            raise EvidenceMergeError(
                f"{origin}: evidence {entry.id!r} has no observed_at "
                "(timestamp required by §2.4); refused"
            )
        insert_evidence(entry, origin)

    for entry in result.observables:
        if entry.provenance not in ("OSINT", "SANDBOX"):
            raise EvidenceMergeError(
                f"{origin}: tool-discovered observable {entry.id!r} has provenance "
                f"{entry.provenance!r}; expected OSINT or SANDBOX"
            )
        if not entry.source_ref:
            raise EvidenceMergeError(
                f"{origin}: tool-discovered observable {entry.id!r} has no source_ref"
            )
        insert_observable(entry, origin)


# ---------------------------------------------------------------------------
# FINAL candidate validation (local; the full V01–V16 verifier is TICKET-10)
# ---------------------------------------------------------------------------


def validate_final_candidate(
    candidate: object,
    evidence_registry: Mapping[str, Mapping[str, Any]],
    observable_registry: Mapping[str, Mapping[str, Any]],
    rag_case_ids: Sequence[str],
) -> list[str]:
    """Validate a FINAL candidate against the registries actually sent.

    Strict schema first (the model is ``extra='forbid'`` and enforces the
    probability sum), then every reference must exist and carry a factual
    provenance (INTERNE/OSINT/SANDBOX — never INFERENCE); RAG case IDs may
    only cite cases actually provided. Issues are returned; nothing is
    repaired.
    """

    if isinstance(candidate, Assessment):
        model = candidate
    elif isinstance(candidate, dict):
        try:
            model = Assessment.model_validate(candidate)
        except ValidationError as error:
            issues: list[str] = []
            for err in error.errors()[:10]:
                location = ".".join(str(part) for part in err["loc"]) or "$"
                issues.append(f"schema: {location}: {err['msg']}")
            return issues
    else:
        return [
            f"candidate: expected an Assessment object or dict, got "
            f"{type(candidate).__name__}"
        ]

    raw = model.model_dump()
    issues = []

    def _check_evidence(where: str, ids: object) -> None:
        if not isinstance(ids, list):
            issues.append(f"{where}: expected a list of evidence IDs")
            return
        for evidence_id in ids:
            if not isinstance(evidence_id, str):
                issues.append(f"{where}: non-string evidence ID {evidence_id!r}")
                continue
            entry = evidence_registry.get(evidence_id)
            if entry is None:
                issues.append(f"{where}: unknown evidence ID {evidence_id!r}")
                continue
            provenance = entry.get("provenance")
            if provenance not in FACTUAL_PROVENANCE:
                issues.append(
                    f"{where}: evidence {evidence_id!r} has provenance "
                    f"{provenance!r}; FINAL may reference INTERNE/OSINT/SANDBOX only"
                )

    _check_evidence("observations", raw.get("observations"))
    for index, inference in enumerate(raw.get("inferences") or []):
        where = f"inferences[{index}]"
        _check_evidence(f"{where}.evidence_ids", inference.get("evidence_ids"))
        for rag_id in inference.get("rag_case_ids") or []:
            if rag_id not in set(rag_case_ids):
                issues.append(
                    f"{where}.rag_case_ids: case {rag_id!r} was not provided "
                    "in RAG_CONTEXT"
                )
    for index, obs_assessment in enumerate(raw.get("observable_assessments") or []):
        where = f"observable_assessments[{index}]"
        observable_id = obs_assessment.get("observable_id")
        if observable_id not in observable_registry:
            issues.append(f"{where}.observable_id: unknown observable ID {observable_id!r}")
        _check_evidence(f"{where}.evidence_ids", obs_assessment.get("evidence_ids"))
    _check_evidence("decisive_evidence_ids", raw.get("decisive_evidence_ids"))
    return issues


# ---------------------------------------------------------------------------
# FINAL phase driver (TICKET-09 frozen interface)
# ---------------------------------------------------------------------------


def _final_limits(limits: ContextLimits | Mapping[str, Any] | None, client: Any) -> ContextLimits:
    if isinstance(limits, ContextLimits):
        base = limits
    elif isinstance(limits, Mapping):
        base = ContextLimits(**limits)
    else:
        base = ContextLimits()
    settings = getattr(client, "_settings", None)
    if settings is not None:
        # Settings are authoritative for the global phase budget; the
        # projection budgets stay the frozen §3 values.
        base = base.model_copy(
            update={
                "final_phase_seconds": float(settings.FINAL_PHASE_SECONDS),
                "final_max_output_tokens": int(settings.FINAL_MAX_OUTPUT_TOKENS),
            }
        )
    return base


def _assessment_schema() -> dict[str, Any]:
    schema_path = (
        Path(__file__).resolve().parent.parent / "schemas" / "assessment.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert isinstance(schema, dict)
    return schema


def _phase_error_record(
    client: Any, capture_dir: Path | None, filename: str, message: str
) -> CallRecord:
    settings = getattr(client, "_settings", None)
    record = CallRecord(
        phase="final",
        status="error",
        requested_model=(settings.LITELLM_MODEL if settings is not None else "unknown"),
        reasoning_effort=FINAL_EFFORT,
    )
    if capture_dir is not None:
        capture_dir.mkdir(parents=True, exist_ok=True)
        (capture_dir / filename).write_text(message, encoding="utf-8")
    return record


def _normalize_registries(
    evidence: Any,
    observables: Any,
) -> tuple[dict[str, Evidence], dict[str, Observable], list[VisualEvidence]]:
    """Accept the merge 3-tuple, mappings or sequences; refuse collisions.

    ``assess_final`` receives the MERGED registries. Passing the
    ``merge_evidence`` result directly as ``evidence`` is the intended
    convenience: the second element then provides the observables unless an
    explicit ``observables`` argument is given.
    """

    visuals: list[VisualEvidence] = []
    if (
        isinstance(evidence, tuple)
        and len(evidence) == 3
        and isinstance(evidence[0], Mapping)
        and isinstance(evidence[1], Mapping)
    ):
        # The (evidence, observables, visuals) tuple returned by merge_evidence.
        merged_evidence, merged_observables, merged_visuals = evidence
        evidence = merged_evidence
        if observables is None:
            observables = merged_observables
        visuals = list(merged_visuals)

    def _to_evidence_registry(value: Any) -> dict[str, Evidence]:
        if value is None:
            return {}
        if isinstance(value, Mapping):
            items = list(value.items())
            registry: dict[str, Evidence] = {}
            for key, entry in items:
                if not isinstance(entry, Evidence):
                    raise EvidenceMergeError(
                        f"evidence[{key!r}]: expected an Evidence object, got "
                        f"{type(entry).__name__}"
                    )
                if key != entry.id:
                    raise EvidenceMergeError(
                        f"evidence registry key {key!r} does not match id {entry.id!r}"
                    )
                registry[key] = entry
            return registry
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            registry = {}
            for entry in value:
                if not isinstance(entry, Evidence):
                    raise EvidenceMergeError(
                        f"evidence: expected Evidence objects, got {type(entry).__name__}"
                    )
                existing = registry.get(entry.id)
                if existing is not None and _canonical_content(existing) != _canonical_content(entry):
                    raise EvidenceMergeError(
                        f"evidence ID collision with different content: {entry.id}"
                    )
                registry[entry.id] = entry
            return registry
        raise EvidenceMergeError(f"evidence: unsupported value {type(value).__name__}")

    def _to_observable_registry(value: Any) -> dict[str, Observable]:
        if value is None:
            return {}
        if isinstance(value, Mapping):
            registry = {}
            for key, entry in value.items():
                if not isinstance(entry, Observable):
                    raise EvidenceMergeError(
                        f"observables[{key!r}]: expected an Observable object, got "
                        f"{type(entry).__name__}"
                    )
                if key != entry.id:
                    raise EvidenceMergeError(
                        f"observable registry key {key!r} does not match id {entry.id!r}"
                    )
                registry[key] = entry
            return registry
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            registry = {}
            for entry in value:
                if not isinstance(entry, Observable):
                    raise EvidenceMergeError(
                        f"observables: expected Observable objects, got "
                        f"{type(entry).__name__}"
                    )
                existing = registry.get(entry.id)
                if existing is not None and _canonical_content(existing) != _canonical_content(entry):
                    raise EvidenceMergeError(
                        f"observable ID collision with different content: {entry.id}"
                    )
                registry[entry.id] = entry
            return registry
        raise EvidenceMergeError(
            f"observables: unsupported value {type(value).__name__}"
        )

    evidence_registry = _to_evidence_registry(evidence)
    observable_registry = _to_observable_registry(observables)
    if observables is None:
        for entry in evidence_registry.values():
            if entry.observable_id is not None:
                raise EvidenceMergeError(
                    "observables registry is required: evidence "
                    f"{entry.id!r} references {entry.observable_id!r}"
                )
    for entry in evidence_registry.values():
        if entry.observable_id is not None and entry.observable_id not in observable_registry:
            raise EvidenceMergeError(
                f"evidence {entry.id!r} references unknown observable "
                f"{entry.observable_id!r}"
            )
    return evidence_registry, observable_registry, visuals


def assess_final(
    parsed: ParsedEmail,
    internal: Assessment | None,
    evidence: Any,
    rag_context: Any,
    client: Any,
    *,
    observables: Any = None,
    tool_results: Any = None,
    limits: ContextLimits | Mapping[str, Any] | None = None,
    run_artifacts: Mapping[str, Any] | None = None,
) -> tuple[Assessment | None, CallRecord]:
    """FINAL assessment: real xhigh call, strict validation, no simulation.

    Frozen interface (docs/tickets/TICKET-09.md):

        assess_final(parsed, internal, evidence, rag_context, client)
            -> (Assessment | None, CallRecord)

    ``evidence`` is the merged evidence registry (or the ``merge_evidence``
    3-tuple, whose observables are reused when ``observables`` is omitted).
    ``tool_results`` carries every normalized tool status — including
    ``unavailable`` / ``skipped`` with their cause — for ``TOOL_STATUS``;
    omitting it simply transmits an empty status list, never a fabricated
    one. ``run_artifacts`` optionally carries ``{"capture_dir": Path}``; the
    client owns the exact-bytes audit and request-body minimization.

    Any failure (merge/projection refusal, transport, refusal, invalid
    output) returns ``(None, record)`` with the real archived cause. There
    is no fabricate-on-failure path: apply ``final_selection`` for the
    documented internal fallback.
    """

    capture_dir: Path | None = None
    if run_artifacts:
        raw_dir = run_artifacts.get("capture_dir")
        if raw_dir is not None:
            capture_dir = Path(raw_dir)

    phase_limits = _final_limits(limits, client)

    try:
        evidence_registry, observable_registry, _visuals = _normalize_registries(
            evidence, observables
        )
    except EvidenceMergeError as error:
        record = _phase_error_record(
            client, capture_dir, "final_projection_error.txt", f"merge: {error}"
        )
        return None, record

    messages, envelope = build_final_messages(
        parsed,
        internal,
        evidence_registry,
        observable_registry,
        tool_results,
        rag_context,
        phase_limits,
    )
    if not envelope_has_useful_content(envelope):
        record = _phase_error_record(
            client,
            capture_dir,
            "final_projection_error.txt",
            "projection: empty or substituted envelope (no useful text, "
            "headers or actors) — call refused",
        )
        return None, record

    deadline = time.monotonic() + phase_limits.final_phase_seconds
    result, record = client.complete_json(
        messages=messages,
        schema=_assessment_schema(),
        effort=FINAL_EFFORT,
        max_output_tokens=phase_limits.final_max_output_tokens,
        deadline=deadline,
    )
    if result is None or record.status != "ok":
        return None, record

    issues = validate_final_candidate(
        result,
        envelope["EVIDENCE_REGISTRY"],
        envelope["OBSERVABLE_REGISTRY"],
        [case["case_id"] for case in envelope["RAG_CONTEXT"]],
    )
    if issues:
        if capture_dir is not None:
            capture_dir.mkdir(parents=True, exist_ok=True)
            (capture_dir / "final_validation_reject.json").write_text(
                json.dumps(
                    {"issues": issues, "candidate": result},
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        # Invalid output is an explicit rejection, never repaired.
        record.status = "error"
        if capture_dir is not None:
            record.response_refs = record.response_refs + [
                "final_validation_reject.json"
            ]
        return None, record

    return Assessment.model_validate(result), record


# ---------------------------------------------------------------------------
# Documented fallback and G5 verifier signal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FinalSelection:
    """Outcome of the FINAL phase for the graph / report (docs/contracts.md §2.6)."""

    candidate: Assessment | None
    final_source: str
    warnings: list[VerificationIssue] = field(default_factory=list)


def final_selection(
    internal: Assessment | None,
    final_candidate: Assessment | None,
    record: CallRecord | None,
) -> FinalSelection:
    """Apply the documented fallback without fabricating a replacement.

    - real FINAL success → ``final_llm`` with the validated candidate;
    - FINAL failure and a valid internal assessment → a DEEP COPY of the
      internal assessment with ``final_source=internal_fallback`` and a
      blocking warning (REVIEW at minimum), never a new verdict/confidence;
    - both unavailable → ``final_source=none`` with an explicit error
      warning; verdict/confidence stay null.
    """

    if final_candidate is not None and record is not None and record.status == "ok":
        return FinalSelection(candidate=final_candidate, final_source="final_llm")

    details = "no record"
    if record is not None:
        details = f"status={record.status}, attempts={record.attempts}"
    if internal is not None:
        return FinalSelection(
            candidate=internal.model_copy(deep=True),
            final_source="internal_fallback",
            warnings=[
                VerificationIssue(
                    code="final_fallback_internal_copy",
                    severity="warning",
                    source="final",
                    message=(
                        f"FINAL assessment unavailable ({details}); the valid "
                        "internal assessment is copied verbatim "
                        "(final_source=internal_fallback); AUTO is blocked"
                    ),
                )
            ],
        )
    return FinalSelection(
        candidate=None,
        final_source="none",
        warnings=[
            VerificationIssue(
                code="final_assessment_unavailable",
                severity="error",
                source="final",
                message=(
                    f"FINAL assessment unavailable ({details}) and no valid "
                    "internal assessment exists; verdict/confidence remain null"
                ),
            )
        ],
    )


def signals_gain_without_external_evidence(
    internal: Assessment | None,
    final_candidate: Assessment | None,
    external_evidence_count_sent: int,
) -> bool:
    """G5 signal for V14: a FINAL move with no external evidence sent.

    True when the FINAL candidate exists, NO external (OSINT/SANDBOX)
    evidence was actually sent to the FINAL call, and either the verdict
    changed or the confidence rose by more than 0.05. This is an audit
    signal for the deterministic verifier (TICKET-10 owns V14); it never
    changes a verdict or a confidence itself.
    """

    if internal is None or final_candidate is None:
        return False
    if external_evidence_count_sent > 0:
        return False
    internal_verdict, internal_confidence = compute_verdict_confidence(
        internal.model_dump()["probabilities"]
    )
    final_verdict, final_confidence = compute_verdict_confidence(
        final_candidate.model_dump()["probabilities"]
    )
    if final_verdict != internal_verdict:
        return True
    return final_confidence - internal_confidence > CONFIDENCE_RISE_WITHOUT_EVIDENCE_THRESHOLD


__all__ = [
    "CONFIDENCE_RISE_WITHOUT_EVIDENCE_THRESHOLD",
    "FACTUAL_PROVENANCE",
    "PROVENANCE_BY_SOURCE_KIND",
    "EvidenceMergeError",
    "FinalSelection",
    "assess_final",
    "final_selection",
    "merge_evidence",
    "signals_gain_without_external_evidence",
    "validate_final_candidate",
]

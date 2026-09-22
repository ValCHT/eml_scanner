"""Local assessment validation for G2 (TICKET-04, docs/contracts.md §2.5,
docs/decisions.md §4.2 V01/V02 subset).

``validate_assessment_shape_and_refs(assessment, registry, phase)`` returns
the list of issues for the given candidate. It implements exactly the G2
validation scope:

- strict Assessment schema (the model itself is strict: ``extra='forbid'``);
- exactly six probabilities, finite, in [0, 1], sum 1 ± 0.000001;
- observations reference existing INTERNAL evidence IDs;
- ``decisive_evidence_ids`` reference existing INTERNAL evidence IDs;
- inference ``evidence_ids`` exist and ``rag_case_ids == []``;
- ``observable_assessments[].observable_id`` exists;
- observable-assessment ``evidence_ids`` exist;
- no OSINT/SANDBOX evidence referenced (INTERNAL phase is email-only);
- no unknown reference of any kind;
- <= 6 inferences, <= 3 ``decisive_evidence_ids``;
- summary length limit (240 chars, enforced by the model too).

Invalid probabilities are rejected and never renormalized. Verdict and
confidence are calculated locally with the fixed taxonomy tie-break; they are
NOT part of the validated model output.

The later full verification rules (V03–V16, TICKET-10) are deliberately not
implemented here.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from pydantic import ValidationError

from .prompts import ContextLimits, build_internal_messages, envelope_has_useful_content
from .state import (
    Assessment,
    CallRecord,
    Evidence,
    Observable,
    ParsedEmail,
    TAXONOMY_ORDER,
    Timings,
    ToolResult,
    VerificationIssue,
)

#: Probability-sum tolerance frozen by docs/contracts.md §2.5.
PROBABILITY_SUM_TOLERANCE = 0.000001

#: Cardinality limits frozen by docs/contracts.md §2.5.
MAX_INFERENCES = 6
MAX_DECISIVE_EVIDENCE_IDS = 3

#: Maximum inference summary length (§2.5: summary <= 240 chars).
MAX_INFERENCE_SUMMARY_CHARS = 240


def compute_verdict_confidence(probabilities: dict[str, float]) -> tuple[str, float]:
    """Local verdict/confidence: argmax with fixed taxonomy tie-break.

    ``probabilities`` must already be validated (six finite values in [0, 1]
    summing to 1). Ties resolve in ``TAXONOMY_ORDER`` order (§2.1/§2.5).
    """

    best_label = TAXONOMY_ORDER[0]
    best_value = probabilities[TAXONOMY_ORDER[0]]
    for label in TAXONOMY_ORDER[1:]:
        # Strict > keeps the earliest label of TAXONOMY_ORDER on ties.
        if probabilities[label] > best_value:
            best_label = label
            best_value = probabilities[label]
    return best_label, best_value


def _bad_probabilities(probabilities: dict[str, Any]) -> list[str]:
    """Structural probability checks on a RAW dict (never renormalized)."""

    issues: list[str] = []
    if not isinstance(probabilities, dict):
        return [f"probabilities: expected an object of exactly six values, "
                f"got {type(probabilities).__name__}"]
    if set(probabilities.keys()) != set(TAXONOMY_ORDER):
        missing = sorted(set(TAXONOMY_ORDER) - set(probabilities.keys()))
        extra = sorted(set(probabilities.keys()) - set(TAXONOMY_ORDER))
        problems = []
        if missing:
            problems.append(f"missing {missing}")
        if extra:
            problems.append(f"unexpected {extra}")
        return [f"probabilities: must have exactly the six taxonomy keys; {'; '.join(problems)}"]
    for label in TAXONOMY_ORDER:
        value = probabilities[label]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            issues.append(f"probabilities.{label}: not a finite number ({value!r})")
            continue
        value = float(value)
        if value != value or value in (float("inf"), float("-inf")):
            issues.append(f"probabilities.{label}: not a finite number ({value!r})")
        elif value < 0 or value > 1:
            issues.append(f"probabilities.{label}: outside [0, 1] ({value})")
    if issues:
        return issues
    total = sum(float(probabilities[label]) for label in TAXONOMY_ORDER)
    if abs(total - 1.0) > PROBABILITY_SUM_TOLERANCE:
        issues.append(
            f"probabilities: sum {total!r} not within ±{PROBABILITY_SUM_TOLERANCE} of 1 "
            "(invalid probabilities are rejected, never renormalized)"
        )
    return issues


def validate_assessment_shape_and_refs(
    assessment: object,
    registry: dict[str, dict[str, Any]],
    phase: str,
) -> list[str]:
    """Validate an INTERNAL candidate against the G2 contract; issues, never repairs.

    ``registry`` is the evidence registry ACTUALLY supplied to this phase:
    ``{evidence_id: {"id": ..., "provenance": "INTERNE"|..., ...}}``. A
    candidate referencing an unknown ID or a non-INTERNE provenance is
    rejected. ``phase`` must be ``"internal"`` (the FINAL phase arrives with
    TICKET-08 and is out of scope here).

    Returns the list of problems; an empty list means the candidate is an
    accepted valid Assessment. Nothing is repaired, renormalized or filtered
    into a pseudo-valid form.
    """

    issues: list[str] = []
    if phase != "internal":
        return [f"phase: {phase!r} is not validated by this G2 validator"]

    if isinstance(assessment, Assessment):
        # Already-validated model: rebuild the raw view for the reference
        # checks below without re-raising on construction.
        raw = assessment.model_dump()
    elif isinstance(assessment, dict):
        raw = assessment
        # Strict schema check first (extra='forbid', types, list sizes).
        try:
            Assessment.model_validate(raw)
        except ValidationError as error:
            for err in error.errors()[:10]:
                loc = ".".join(str(part) for part in err["loc"]) or "$"
                issues.append(f"schema: {loc}: {err['msg']}")
            return issues
    else:
        return [
            f"assessment: expected an Assessment object or dict, got "
            f"{type(assessment).__name__}"
        ]

    # --- probabilities (six finite values, [0,1], sum 1 ± tolerance).
    probabilities = raw.get("probabilities")
    prob_issues = _bad_probabilities(probabilities)
    issues.extend(prob_issues)
    if prob_issues:
        # Reference checks stay meaningful only on a valid vector; the
        # candidate is already rejected, so stop here without duplicating.
        return issues

    # --- reference registries.
    evidence_registry = registry.get("evidence", {}) if isinstance(registry, dict) else {}
    observable_registry = registry.get("observables", {}) if isinstance(registry, dict) else {}
    if not isinstance(evidence_registry, dict) or not isinstance(observable_registry, dict):
        issues.append("registry: expected {evidence: {...}, observables: {...}}")
        return issues

    def _evidence_provenance(evidence_id: str) -> str | None:
        entry = evidence_registry.get(evidence_id)
        if isinstance(entry, dict):
            provenance = entry.get("provenance")
            return provenance if isinstance(provenance, str) else None
        return None

    def _check_evidence_ids(where: str, ids: object) -> None:
        if not isinstance(ids, list):
            issues.append(f"{where}: expected a list of evidence IDs")
            return
        for evidence_id in ids:
            if not isinstance(evidence_id, str):
                issues.append(f"{where}: non-string evidence ID {evidence_id!r}")
                continue
            if evidence_id not in evidence_registry:
                issues.append(f"{where}: unknown evidence ID {evidence_id!r}")
                continue
            provenance = _evidence_provenance(evidence_id)
            if provenance != "INTERNE":
                # INTERNAL is email-only: ANY non-INTERNE provenance is
                # rejected (not just OSINT/SANDBOX) — an unknown or missing
                # provenance value cannot be trusted either.
                issues.append(
                    f"{where}: evidence {evidence_id!r} has provenance {provenance!r}; "
                    "INTERNAL may reference INTERNE evidence only"
                )

    # --- observations: existing INTERNAL evidence IDs.
    _check_evidence_ids("observations", raw.get("observations"))

    # --- inferences: <= 6, existing evidence IDs, empty rag_case_ids, summary.
    inferences = raw.get("inferences")
    if not isinstance(inferences, list) or len(inferences) > MAX_INFERENCES:
        count = len(inferences) if isinstance(inferences, list) else "n/a"
        issues.append(f"inferences: at most {MAX_INFERENCES} allowed (got {count})")
    else:
        for index, inference in enumerate(inferences):
            where = f"inferences[{index}]"
            if not isinstance(inference, dict):
                issues.append(f"{where}: expected an object")
                continue
            summary = inference.get("summary")
            if isinstance(summary, str) and len(summary) > MAX_INFERENCE_SUMMARY_CHARS:
                issues.append(
                    f"{where}.summary: {len(summary)} chars exceeds "
                    f"{MAX_INFERENCE_SUMMARY_CHARS}"
                )
            rag_ids = inference.get("rag_case_ids")
            if rag_ids != []:
                issues.append(
                    f"{where}.rag_case_ids: must be [] in INTERNAL (got {rag_ids!r})"
                )
            _check_evidence_ids(f"{where}.evidence_ids", inference.get("evidence_ids"))

    # --- observable assessments: existing observable IDs, existing evidence.
    observable_assessments = raw.get("observable_assessments")
    if not isinstance(observable_assessments, list):
        issues.append("observable_assessments: expected a list")
    else:
        for index, obs_assessment in enumerate(observable_assessments):
            where = f"observable_assessments[{index}]"
            if not isinstance(obs_assessment, dict):
                issues.append(f"{where}: expected an object")
                continue
            observable_id = obs_assessment.get("observable_id")
            if not isinstance(observable_id, str) or observable_id not in observable_registry:
                issues.append(f"{where}.observable_id: unknown observable ID {observable_id!r}")
            _check_evidence_ids(f"{where}.evidence_ids", obs_assessment.get("evidence_ids"))

    # --- decisive evidence: <= 3, existing INTERNAL IDs.
    decisive = raw.get("decisive_evidence_ids")
    if not isinstance(decisive, list) or len(decisive) > MAX_DECISIVE_EVIDENCE_IDS:
        count = len(decisive) if isinstance(decisive, list) else "n/a"
        issues.append(
            f"decisive_evidence_ids: at most {MAX_DECISIVE_EVIDENCE_IDS} allowed (got {count})"
        )
    else:
        _check_evidence_ids("decisive_evidence_ids", decisive)

    return issues


__all__ = [
    "ADMISSIBLE_CONFIRMATION_PREDICATE",
    "CONFIDENCE_RISE_WITHOUT_NEW_EVIDENCE_THRESHOLD",
    "MALICIOUS_VERDICTS",
    "MAX_DECISIVE_EVIDENCE_IDS",
    "MAX_INFERENCES",
    "MAX_INFERENCE_SUMMARY_CHARS",
    "PROBABILITY_SUM_TOLERANCE",
    "RunContext",
    "VerificationResult",
    "assess_internal",
    "compute_verdict_confidence",
    "confidence_margin",
    "is_admissible_malicious_confirmation",
    "validate_assessment_shape_and_refs",
    "verify_assessment",
]


# ---------------------------------------------------------------------------
# INTERNAL phase driver (TICKET-04 frozen interface)
# ---------------------------------------------------------------------------


def assess_internal(
    parsed: ParsedEmail,
    client: Any,
    limits: ContextLimits,
    run_artifacts: dict[str, Any] | None = None,
) -> tuple[Assessment | None, CallRecord]:
    """INTERNAL assessment: real call, strict validation, no simulation.

    Frozen interface (docs/tickets/TICKET-04.md):

        assess_internal(parsed, client, limits) -> (Assessment | None, CallRecord)

    ``run_artifacts`` optionally carries harness context for evidence
    archiving: ``{"capture_dir": Path, "source_profile": str}``. Request-body
    persistence is enabled ONLY for ``source_profile="fixture"`` (§2.6.1
    minimization); the exact-bytes input audit is always computed by the
    client. The caller constructs ``LunaClient`` with the matching
    ``capture_dir``/``persist_request_body`` flags; this function never
    rebuilds a client.

    Flow: deterministic projection -> real ``complete_json`` call (medium
    effort, no tools) -> strict Assessment validation against the registries
    ACTUALLY sent -> local verdict/confidence. An invalid or failed attempt
    yields ``(None, record)`` with the real archived evidence — never a
    fabricated Assessment, never renormalized probabilities.
    """

    if isinstance(limits, dict):
        limits = ContextLimits(**limits)

    capture_dir = (run_artifacts or {}).get("capture_dir")
    if capture_dir is not None:
        from pathlib import Path

        capture_dir = Path(capture_dir)

    envelope_issues: list[str] = []
    messages, envelope = build_internal_messages(parsed, limits)
    if not envelope_has_useful_content(envelope):
        # An empty/substituted envelope is refused BEFORE any call: the
        # failure is explicit and archived, never a silent LLM round-trip.
        envelope_issues.append(
            "projection: empty or substituted envelope (no useful text, "
            "headers or actors) — call refused"
        )

    if envelope_issues:
        # No call is possible without a correct envelope: explicit typed
        # failure with a real CallRecord (status error, zero attempts).
        settings = getattr(client, "_settings", None)
        record = CallRecord(
            phase="internal",
            status="error",
            requested_model=(
                settings.LITELLM_MODEL if settings is not None else "unknown"
            ),
            reasoning_effort="medium",
        )
        if capture_dir is not None:
            capture_dir.mkdir(parents=True, exist_ok=True)
            (capture_dir / "internal_projection_error.txt").write_text(
                "\n".join(envelope_issues), encoding="utf-8"
            )
        return None, record

    deadline = time.monotonic() + limits.internal_phase_seconds
    result, record = client.complete_json(
        messages=messages,
        schema=_assessment_schema(),
        effort="medium",
        max_output_tokens=limits.internal_max_output_tokens,
        deadline=deadline,
    )

    if result is None or record.status != "ok":
        return None, record

    # Validate against the registries ACTUALLY sent (the same envelope that
    # was serialized into the request), never a rebuild.
    registry = {
        "evidence": envelope["EVIDENCE_REGISTRY"],
        "observables": envelope["OBSERVABLE_REGISTRY"],
    }
    issues = validate_assessment_shape_and_refs(result, registry, "internal")
    if issues:
        if capture_dir is not None:
            capture_dir.mkdir(parents=True, exist_ok=True)
            (capture_dir / "internal_validation_reject.json").write_text(
                json.dumps(
                    {"issues": issues, "candidate": result},
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        # Invalid output is an explicit rejection, never repaired: the phase
        # record leaves no ambiguous "ok without assessment" state (§2.7:
        # schema-invalid output is an explicit error with result=None). The
        # per-attempt artifacts (input audits, response metadata) and the
        # rejection file itself remain referenced for measurement.
        record.status = "error"
        if capture_dir is not None:
            record.response_refs = record.response_refs + [
                "internal_validation_reject.json"
            ]
        return None, record

    assessment = Assessment.model_validate(result)
    return assessment, record


def _assessment_schema() -> dict[str, Any]:
    """Load the frozen Assessment schema (schemas/ is normative, read-only)."""

    import json
    from pathlib import Path

    schema_path = (
        Path(__file__).resolve().parent.parent / "schemas" / "assessment.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert isinstance(schema, dict)
    return schema


# ---------------------------------------------------------------------------
# TICKET-10 — deterministic verifier (docs/decisions.md §4.2, V01–V16)
# ---------------------------------------------------------------------------
#
# ``verify_assessment`` checks whether a STRUCTURED claim is supported by the
# registries and tool results that already exist. It never solves phishing
# semantically, never re-writes or repairs a model response, and never
# converts an unsupported claim into an acceptable one:
#
# - a structurally invalid candidate is rejected (V01), the caller keeps the
#   original for audit;
# - unsupported references are recorded as unsupported claims (V02);
# - observables that are not traceable to the parser or to an ok archived
#   tool result are excluded from the accepted list (V03);
# - provenance/proof/sandbox/attribution/malicious-confirmation violations
#   are recorded with their frozen code and severity (V04–V13);
# - a verdict/confidence move without new evidence is a WARNING that blocks
#   AUTO but is never treated as proof that the verdict is wrong (V14);
# - RAG contamination and run inconsistencies are recorded (V15/V16).
#
# Determinism: registries are iterated in their insertion order, issues are
# appended in the fixed V01→V16 order, and the output contains no wall-clock
# or random component.

#: Verdict families frozen by docs/decisions.md §4.3 rules 4–5.
MALICIOUS_VERDICTS: tuple[str, ...] = ("spear_phishing", "phishing", "fraude", "menace")
BENIGN_VERDICTS: tuple[str, ...] = ("spam", "legitime")

#: Frozen V14 threshold (same value as
#: ``src.evidence.CONFIDENCE_RISE_WITHOUT_EVIDENCE_THRESHOLD``): a confidence
#: rise STRICTLY above this value without new evidence is signalled.
CONFIDENCE_RISE_WITHOUT_NEW_EVIDENCE_THRESHOLD = 0.05

#: V04: expected factual provenance per producer (docs/decisions.md V04).
PROVENANCE_BY_PRODUCER: dict[str, str] = {
    "parser": "INTERNE",
    "virustotal": "OSINT",
    "opencti": "OSINT",
    "urlscan": "SANDBOX",
    "osint": "OSINT",
}

#: V08: roles that may never inherit an M/S category from another object.
PROTECTED_ATTRIBUTION_ROLES: tuple[str, ...] = ("displayed_brand", "shared_host")

#: V06: observable types that represent a host (never an exact URL artifact).
HOST_OBSERVABLE_TYPES: tuple[str, ...] = ("domain", "ipv4", "ipv6")

#: V09: the admissible exact malicious confirmation of the frozen predicate
#: set: an explicit provider assertion on the exact scan. VT counts, CTI
#: presence/labels and RAG neighbours are never confirmations.
ADMISSIBLE_CONFIRMATION_PREDICATE = "sandbox_provider_malicious"

#: V11: inference codes whose support must be real OSINT/SANDBOX evidence.
EXTERNAL_REASON_CODES: tuple[str, ...] = ("external_support", "external_conflict")

#: V13: materially malicious inference codes vs a benign verdict.
CONFLICT_REASON_CODES: tuple[str, ...] = (
    "payment_diversion",
    "extortion",
    "credential_collection",
)

#: V12: absence-of-detection signals that can never be the whole benign basis.
ABSENCE_AUTH_PREDICATES: tuple[str, ...] = ("auth_reported", "auth_trusted")
VT_COUNT_PREDICATES: tuple[str, ...] = (
    "vt_malicious_count",
    "vt_suspicious_count",
    "vt_harmless_count",
    "vt_undetected_count",
    "vt_engine_total",
    "vt_analysis_time",
)

#: V16: allowed ``final_source`` values (docs/contracts.md §2.2).
FINAL_SOURCES: tuple[str, ...] = (
    "internal_copy",
    "final_llm",
    "internal_fallback",
    "none",
)

#: Severities that block AUTO (V14 warning included; docs/decisions.md V14).
BLOCKING_SEVERITIES: tuple[str, ...] = ("warning", "error", "critical")

_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)


@dataclass
class RunContext:
    """Optional phase/run facts needed by V14 and V16 (never content).

    ``external_evidence_count_sent`` is the FINAL audit counter
    (docs/contracts.md §2.6.1): it is the authoritative input for V14 when
    available. ``visual_count_sent`` decides whether a screenshot assertion
    was actually supplied before interpretation (V10). Every field defaults
    to the "not provided" value, so a caller that does not own a fact simply
    does not get the corresponding check.
    """

    final_source: str = "none"
    internal_call: CallRecord | None = None
    final_call: CallRecord | None = None
    timings: Timings | Mapping[str, Any] | None = None
    external_evidence_count_sent: int | None = None
    visual_count_sent: int | None = None
    current_duplicate_group: str | None = None
    current_family_group: str | None = None
    current_campaign_id: str | None = None


@dataclass
class VerificationResult:
    """Deterministic verifier output; ``accepted`` is None only for V01.

    ``accepted`` keeps the structurally valid assessment even when
    unsupported references or claims were recorded: the report keeps the
    original for audit and exposes the violations separately. Nothing is
    repaired or filtered into a pseudo-valid assessment.
    """

    phase: str
    accepted: Assessment | None
    issues: list[VerificationIssue]
    accepted_observables: list[Observable]
    excluded_observables: list[Observable]
    verdict: str | None
    confidence: float | None
    margin: float | None
    verdict_changed: bool | None
    blocking_codes: list[str]

    @property
    def unsupported_claims(self) -> list[VerificationIssue]:
        """Critical support violations (unsupported claims), stable order."""

        return [issue for issue in self.issues if issue.severity == "critical"]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe deterministic projection (for reports/archives)."""

        return {
            "phase": self.phase,
            "accepted": (
                self.accepted.model_dump(mode="json") if self.accepted is not None else None
            ),
            "issues": [issue.model_dump(mode="json") for issue in self.issues],
            "accepted_observables": [
                observable.model_dump(mode="json") for observable in self.accepted_observables
            ],
            "excluded_observable_ids": [
                observable.id for observable in self.excluded_observables
            ],
            "verdict": self.verdict,
            "confidence": self.confidence,
            "margin": self.margin,
            "verdict_changed": self.verdict_changed,
            "blocking_codes": list(self.blocking_codes),
        }


def confidence_margin(probabilities: Mapping[str, float]) -> float:
    """Distance between the two highest probabilities (docs/contracts.md §2.5)."""

    ordered = sorted((float(value) for value in probabilities.values()), reverse=True)
    if len(ordered) < 2:
        return 0.0
    return ordered[0] - ordered[1]


def is_admissible_malicious_confirmation(evidence: Evidence, observable_id: str) -> bool:
    """V09 admissible exact confirmation (presence and scope, not truth).

    An explicit provider malicious assertion on the EXACT same observable is
    the only admissible confirmation of the frozen predicate set. The code
    verifies provenance and scope; it cannot prove the assertion is right
    (docs/decisions.md §4.2).
    """

    return (
        evidence.predicate == ADMISSIBLE_CONFIRMATION_PREDICATE
        and evidence.provenance == "SANDBOX"
        and evidence.value is True
        and evidence.match_level == "EXACT"
        and evidence.observable_id == observable_id
    )


def _issue(
    code: str,
    severity: str,
    source: str,
    object_id: str | None,
    message: str,
) -> VerificationIssue:
    return VerificationIssue(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        object_id=object_id,
        message=message,
    )


def _canonical_dump(model: Evidence | Observable) -> str:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _coerce_assessment(value: object) -> Assessment | None:
    if value is None:
        return None
    if isinstance(value, Assessment):
        return value
    if isinstance(value, Mapping):
        try:
            return Assessment.model_validate(dict(value))
        except ValidationError:
            return None
    return None


def _coerce_run_context(value: RunContext | Mapping[str, Any] | None) -> RunContext:
    if value is None:
        return RunContext()
    if isinstance(value, RunContext):
        return value
    if isinstance(value, Mapping):
        allowed = set(RunContext.__dataclass_fields__)
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(f"run_context: unknown fields {unknown}")
        return RunContext(**dict(value))
    raise TypeError(f"run_context: expected RunContext or mapping, got {type(value).__name__}")


def _coerce_registry(
    registry: Mapping[str, Any] | None,
) -> tuple[dict[str, Evidence], dict[str, Observable]]:
    """Strictly coerce ``{"evidence": {...}, "observables": {...}}``.

    Entries may be contract models or their JSON dumps; keys must match the
    entry ``id``. A malformed registry is a caller contract violation and is
    refused explicitly (it is never silently treated as empty).
    """

    if registry is None:
        return {}, {}
    if not isinstance(registry, Mapping):
        raise TypeError(f"registry: expected a mapping, got {type(registry).__name__}")

    def _build(value: Any, model: type, label: str) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise TypeError(
                f"registry[{label!r}]: expected a mapping, got {type(value).__name__}"
            )
        entries: dict[str, Any] = {}
        for key, raw in value.items():
            entry = raw if isinstance(raw, model) else model.model_validate(raw)
            if key != entry.id:
                raise ValueError(
                    f"registry[{label!r}]: key {key!r} does not match id {entry.id!r}"
                )
            entries[key] = entry
        return entries

    evidence = _build(registry.get("evidence"), Evidence, "evidence")
    observables = _build(registry.get("observables"), Observable, "observables")
    return evidence, observables


def _coerce_rag_cases(rag_context: Any) -> list[Any]:
    from .state import RagCase

    if rag_context is None:
        return []
    if isinstance(rag_context, Mapping):
        raise TypeError("rag_context: expected a sequence of RagCase objects")
    cases: list[Any] = []
    for raw in rag_context:
        cases.append(raw if isinstance(raw, RagCase) else RagCase.model_validate(raw))
    return cases


def _coerce_tool_results(value: Any) -> list[ToolResult] | None:
    """None means "not provided" (distinct from an empty sequence)."""

    if value is None:
        return None
    if all(hasattr(value, name) for name in ("virustotal", "opencti", "urlscan")):
        items: list[Any] = [*value.virustotal, *value.opencti, *value.urlscan]
    else:
        items = list(value)
    return [
        item if isinstance(item, ToolResult) else ToolResult.model_validate(item)
        for item in items
    ]


def _parse_http_url(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
        return parsed
    return None


def _looks_like_bare_host(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if _parse_http_url(stripped) is not None:
        return False
    return bool(_HOSTNAME_RE.match(stripped))


def _is_iso_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_v01(
    assessment: object, source: str
) -> tuple[Assessment | None, list[VerificationIssue]]:
    """V01: strict schema, six finite probabilities, sum, sizes, argmax."""

    if assessment is None:
        return None, [
            _issue(
                "missing_assessment",
                "error",
                source,
                None,
                "no assessment exists for this phase; verdict/confidence stay null",
            )
        ]
    if isinstance(assessment, Assessment):
        return assessment, []
    if not isinstance(assessment, Mapping):
        return None, [
            _issue(
                "invalid_assessment",
                "error",
                source,
                None,
                f"assessment: expected an object, got {type(assessment).__name__}",
            )
        ]
    problems = _bad_probabilities(assessment.get("probabilities"))
    if problems:
        return None, [
            _issue("invalid_assessment", "error", source, None, "; ".join(problems))
        ]
    try:
        model = Assessment.model_validate(dict(assessment))
    except ValidationError as error:
        messages = []
        for err in error.errors()[:10]:
            location = ".".join(str(part) for part in err["loc"]) or "$"
            messages.append(f"{location}: {err['msg']}")
        return None, [
            _issue("invalid_assessment", "error", source, None, "; ".join(messages))
        ]
    return model, []


def _assessment_references(model: Assessment) -> list[tuple[str, str, str]]:
    """(kind, where, id) references of an assessment, stable model order."""

    refs: list[tuple[str, str, str]] = []
    for evidence_id in model.observations:
        refs.append(("evidence", "observations", evidence_id))
    for index, inference in enumerate(model.inferences):
        for evidence_id in inference.evidence_ids:
            refs.append(("evidence", f"inferences[{index}].evidence_ids", evidence_id))
        for case_id in inference.rag_case_ids:
            refs.append(("rag_case", f"inferences[{index}].rag_case_ids", case_id))
    for index, obs_assessment in enumerate(model.observable_assessments):
        refs.append(
            (
                "observable",
                f"observable_assessments[{index}].observable_id",
                obs_assessment.observable_id,
            )
        )
        for evidence_id in obs_assessment.evidence_ids:
            refs.append(
                ("evidence", f"observable_assessments[{index}].evidence_ids", evidence_id)
            )
    for evidence_id in model.decisive_evidence_ids:
        refs.append(("evidence", "decisive_evidence_ids", evidence_id))
    return refs


def verify_assessment(
    assessment: object,
    phase: str,
    registry: Mapping[str, Any] | None = None,
    tool_results: Any = None,
    parsed: ParsedEmail | None = None,
    rag_context: Any = None,
    *,
    internal: object = None,
    run_context: RunContext | Mapping[str, Any] | None = None,
) -> VerificationResult:
    """Deterministic V01–V16 verification of one phase candidate.

    ``phase`` is ``"internal"`` or ``"final"``. ``registry`` is
    ``{"evidence": {id: Evidence}, "observables": {id: Observable}}`` as
    actually provided to this phase; ``tool_results`` is the sequence (or
    ``Enrichment``) of normalized adapter results; ``parsed`` is the source
    email; ``rag_context`` is the RAG case sequence actually provided (empty
    in the baseline). ``internal`` and ``run_context`` carry the FINAL
    comparison inputs (V14) and the run facts (V16); both are optional.

    The result never repairs the candidate: invalid schema rejects it,
    unsupported registry objects are excluded from ``accepted_observables``,
    and every violation is returned in the fixed V01→V16 order.
    """

    if phase not in ("internal", "final"):
        raise ValueError(f"phase: expected 'internal' or 'final', got {phase!r}")
    source = phase
    has_context = run_context is not None
    context = _coerce_run_context(run_context)
    evidence_registry, observable_registry = _coerce_registry(registry)
    results = _coerce_tool_results(tool_results)
    rag_cases = _coerce_rag_cases(rag_context)

    issues: list[VerificationIssue] = []

    # --- producer indices ---------------------------------------------------
    producer_observables: dict[str, Observable] = {}
    if parsed is not None:
        for observable in parsed.observables:
            producer_observables[observable.id] = observable
    tool_observable_index: dict[str, Observable] = {}
    tool_index: dict[str, list[tuple[ToolResult, Evidence]]] = {}
    if results is not None:
        for result in results:
            for evidence in result.evidence:
                tool_index.setdefault(evidence.id, []).append((result, evidence))
            for observable in result.observables:
                tool_observable_index[observable.id] = observable
    producers_available = parsed is not None or results is not None

    # --- V01: strict schema / probabilities / list sizes --------------------
    model, v01_issues = _validate_v01(assessment, source)
    issues.extend(v01_issues)
    accepted = model

    cited_evidence: list[str] = []
    cited_observables: list[str] = []
    verdict: str | None = None
    confidence: float | None = None
    margin: float | None = None
    verdict_changed: bool | None = None

    # --- V02 (registry side): reference integrity of the provided input -----
    for evidence_id, evidence in evidence_registry.items():
        if (
            evidence.observable_id is not None
            and evidence.observable_id not in observable_registry
        ):
            issues.append(
                _issue(
                    "unsupported_claim",
                    "critical",
                    source,
                    evidence_id,
                    "evidence references unknown observable "
                    f"{evidence.observable_id!r}",
                )
            )
    for observable in observable_registry.values():
        for evidence_id in observable.evidence_ids:
            if evidence_id not in evidence_registry:
                issues.append(
                    _issue(
                        "unsupported_claim",
                        "critical",
                        source,
                        observable.id,
                        f"observable references unknown evidence {evidence_id!r}",
                    )
                )

    # --- V02 (assessment side): every referenced id exists in the input -----
    if model is not None:
        rag_ids = {case.case_id for case in rag_cases}
        for kind, where, reference in _assessment_references(model):
            if kind == "evidence":
                if reference not in evidence_registry:
                    issues.append(
                        _issue(
                            "unsupported_claim",
                            "critical",
                            source,
                            reference,
                            f"{where}: unknown evidence ID {reference!r} "
                            "(not present in the input actually provided)",
                        )
                    )
                elif reference not in cited_evidence:
                    cited_evidence.append(reference)
            elif kind == "observable":
                if reference not in observable_registry:
                    issues.append(
                        _issue(
                            "unsupported_claim",
                            "critical",
                            source,
                            reference,
                            f"{where}: unknown observable ID {reference!r} "
                            "(not present in the input actually provided)",
                        )
                    )
                elif reference not in cited_observables:
                    cited_observables.append(reference)
            else:
                if reference not in rag_ids:
                    issues.append(
                        _issue(
                            "unsupported_claim",
                            "critical",
                            source,
                            reference,
                            f"{where}: RAG case {reference!r} was not provided "
                            "in RAG_CONTEXT",
                        )
                    )

    # --- V03: observables keep a real producer's identity -------------------
    excluded_ids: list[str] = []
    excluded_set: set[str] = set()

    def _exclude(observable_id: str) -> None:
        if observable_id not in excluded_set:
            excluded_set.add(observable_id)
            excluded_ids.append(observable_id)

    for observable_id, observable in observable_registry.items():
        if observable.provenance == "INFERENCE":
            issues.append(
                _issue(
                    "fabricated_ioc",
                    "critical",
                    source,
                    observable_id,
                    "observable carries INFERENCE provenance: an interpretation "
                    "is not an observable",
                )
            )
            _exclude(observable_id)
            continue
        producer = producer_observables.get(observable_id)
        if producer is None:
            producer = tool_observable_index.get(observable_id)
        if producer is None:
            if producers_available:
                issues.append(
                    _issue(
                        "fabricated_ioc",
                        "critical",
                        source,
                        observable_id,
                        "observable is not produced by the parser or by an ok "
                        "archived tool result (LLM addition)",
                    )
                )
                _exclude(observable_id)
        elif _canonical_dump(observable) != _canonical_dump(producer):
            issues.append(
                _issue(
                    "fabricated_ioc",
                    "critical",
                    source,
                    observable_id,
                    "observable content differs from its real producer "
                    "(LLM alteration)",
                )
            )
            _exclude(observable_id)

    # --- V04: provenance coherent with the producer -------------------------
    for evidence_id, evidence in evidence_registry.items():
        expected = PROVENANCE_BY_PRODUCER.get(evidence.source_kind)
        if (
            evidence.provenance == "INFERENCE"
            or expected is None
            or evidence.provenance != expected
        ):
            issues.append(
                _issue(
                    "impossible_provenance",
                    "critical",
                    source,
                    evidence_id,
                    f"provenance {evidence.provenance!r} is impossible for "
                    f"producer {evidence.source_kind!r} (expected {expected!r})",
                )
            )

    if model is not None:
        # --- V05: external facts match a real ok archived response ----------
        for evidence_id in cited_evidence:
            evidence = evidence_registry.get(evidence_id)
            if evidence is None or evidence.provenance not in ("OSINT", "SANDBOX"):
                continue
            if not evidence.source_ref:
                issues.append(
                    _issue(
                        "unsupported_external_fact",
                        "critical",
                        source,
                        evidence_id,
                        "cited external evidence has no source_ref",
                    )
                )
                continue
            occurrences = tool_index.get(evidence_id, [])
            archived = [
                (result, entry)
                for result, entry in occurrences
                if result.status == "ok"
                and result.response_ref
                and result.response_sha256
                and result.collected_at
            ]
            if not occurrences:
                issues.append(
                    _issue(
                        "unsupported_external_fact",
                        "critical",
                        source,
                        evidence_id,
                        "cited external evidence matches no real tool result "
                        "(or tool results were not provided)",
                    )
                )
                continue
            if not archived:
                issues.append(
                    _issue(
                        "unsupported_external_fact",
                        "critical",
                        source,
                        evidence_id,
                        "cited external evidence comes only from a non-ok or "
                        "unarchived tool result",
                    )
                )
                continue
            for result, entry in archived:
                if _canonical_dump(evidence) != _canonical_dump(entry):
                    issues.append(
                        _issue(
                            "unsupported_external_fact",
                            "critical",
                            source,
                            evidence_id,
                            f"cited external fact differs from the archived "
                            f"{result.tool} result (false counter/URL/UUID)",
                        )
                    )
                    break

        # --- V06: exact evidence applies to the exact same observable -------
        for evidence_id in cited_evidence:
            evidence = evidence_registry.get(evidence_id)
            if (
                evidence is None
                or evidence.match_level != "EXACT"
                or evidence.observable_id is None
            ):
                continue
            observable = observable_registry.get(evidence.observable_id)
            if observable is None:
                continue
            if isinstance(evidence.value, str):
                if (
                    _parse_http_url(evidence.value) is not None
                    and observable.type in HOST_OBSERVABLE_TYPES
                ):
                    issues.append(
                        _issue(
                            "false_exact_match",
                            "error",
                            source,
                            evidence_id,
                            "an exact URL assertion is attributed to a host "
                            "observable (parent domain/IP is not the exact URL)",
                        )
                    )
                elif _looks_like_bare_host(evidence.value) and observable.type == "url":
                    issues.append(
                        _issue(
                            "false_exact_match",
                            "error",
                            source,
                            evidence_id,
                            "a host-level assertion is attributed to an exact "
                            "URL observable",
                        )
                    )
            for result, _entry in tool_index.get(evidence_id, []):
                if (
                    result.query_observable_id is not None
                    and evidence.observable_id != result.query_observable_id
                ):
                    issues.append(
                        _issue(
                            "false_exact_match",
                            "error",
                            source,
                            evidence_id,
                            f"exact evidence was produced for observable "
                            f"{result.query_observable_id!r}, not "
                            f"{evidence.observable_id!r}",
                        )
                    )
                    break

    # --- V07: recipients never become IOCs ----------------------------------
    recipients: set[str] = set()
    if parsed is not None:
        recipients = {
            address.strip().lower()
            for address in [*parsed.to_addresses, *parsed.cc_addresses]
            if address and address.strip()
        }
    recipient_observable_ids: set[str] = set()
    flagged_recipients: set[str] = set()
    for observable_id, observable in observable_registry.items():
        if (
            observable.type == "email"
            and observable.normalized_value.strip().lower() in recipients
        ):
            recipient_observable_ids.add(observable_id)
            _exclude(observable_id)  # actors, never IOCs / query targets
            if "recipient" not in observable.roles:
                flagged_recipients.add(observable_id)
                issues.append(
                    _issue(
                        "recipient_as_ioc",
                        "critical",
                        source,
                        observable_id,
                        "a known To/Cc/Bcc recipient is present as an IOC "
                        "candidate (recipient role missing)",
                    )
                )
    if model is not None:
        for index, obs_assessment in enumerate(model.observable_assessments):
            if obs_assessment.category not in ("M", "S", "C"):
                continue
            observable_id = obs_assessment.observable_id
            if (
                observable_id in recipient_observable_ids
                and observable_id not in flagged_recipients
            ):
                flagged_recipients.add(observable_id)
                issues.append(
                    _issue(
                        "recipient_as_ioc",
                        "critical",
                        source,
                        observable_id,
                        f"observable_assessments[{index}] proposes a known "
                        "recipient as an IOC",
                    )
                )

    if model is not None:
        # --- V08: protected roles / hosts cannot inherit M/S ----------------
        for index, obs_assessment in enumerate(model.observable_assessments):
            if obs_assessment.category not in ("M", "S"):
                continue
            observable = observable_registry.get(obs_assessment.observable_id)
            if observable is None:
                continue
            cited = [
                evidence_registry[evidence_id]
                for evidence_id in obs_assessment.evidence_ids
                if evidence_id in evidence_registry
            ]
            protected = bool(set(observable.roles) & set(PROTECTED_ATTRIBUTION_ROLES))
            precise = any(
                evidence.observable_id == observable.id
                and evidence.match_level == "EXACT"
                for evidence in cited
            )
            from_url = bool(cited) and all(
                _parse_http_url(evidence.value) is not None
                or (
                    evidence.observable_id is not None
                    and evidence.observable_id != observable.id
                    and evidence.observable_id in observable_registry
                    and observable_registry[evidence.observable_id].type == "url"
                )
                for evidence in cited
            )
            if (protected and not precise) or (
                observable.type in HOST_OBSERVABLE_TYPES and from_url
            ):
                issues.append(
                    _issue(
                        "unjustified_global_attribution",
                        "error",
                        source,
                        observable.id,
                        f"observable_assessments[{index}] attributes "
                        f"{obs_assessment.category} to a displayed brand/shared "
                        "host or propagates an exact URL category to its host "
                        "without evidence on that exact object",
                    )
                )

        # --- V09: M needs the admissible exact confirmation -----------------
        for index, obs_assessment in enumerate(model.observable_assessments):
            if obs_assessment.category != "M":
                continue
            observable = observable_registry.get(obs_assessment.observable_id)
            candidates: list[Evidence] = [
                evidence_registry[evidence_id]
                for evidence_id in obs_assessment.evidence_ids
                if evidence_id in evidence_registry
            ]
            if observable is not None:
                for evidence_id in observable.evidence_ids:
                    if evidence_id in evidence_registry:
                        candidates.append(evidence_registry[evidence_id])
            if not any(
                is_admissible_malicious_confirmation(evidence, obs_assessment.observable_id)
                for evidence in candidates
            ):
                issues.append(
                    _issue(
                        "insufficient_malicious_confirmation",
                        "error",
                        source,
                        obs_assessment.observable_id,
                        f"observable_assessments[{index}] proposes M without an "
                        "admissible exact malicious confirmation (VT counts, "
                        "CTI presence and RAG are never confirmations)",
                    )
                )

        # --- V10: sandbox assertions must exist; screenshot supplied --------
        for evidence_id in cited_evidence:
            evidence = evidence_registry.get(evidence_id)
            if evidence is None or evidence.provenance != "SANDBOX":
                continue
            if (
                evidence.predicate == "sandbox_screenshot"
                and context.visual_count_sent is not None
                and context.visual_count_sent <= 0
            ):
                issues.append(
                    _issue(
                        "screenshot_not_provided",
                        "error",
                        source,
                        evidence_id,
                        "a screenshot assertion is used but no pixel was "
                        "supplied to the model (visual_count_sent == 0)",
                    )
                )
            for result, _entry in tool_index.get(evidence_id, []):
                if result.status == "ok" and (
                    not result.response_ref
                    or not result.response_sha256
                    or not result.scan_id
                    or not result.collected_at
                ):
                    issues.append(
                        _issue(
                            "invented_sandbox_assertion",
                            "critical",
                            source,
                            evidence_id,
                            "sandbox assertion exists without a complete "
                            "archived scan capture "
                            "(response_ref/hash/scan_id/timestamp)",
                        )
                    )
                    break

        # --- V11: external reasons / targeting support ----------------------
        actor_addresses = {
            address.strip().lower()
            for address in (
                []
                if parsed is None
                else [
                    *parsed.from_addresses,
                    *parsed.to_addresses,
                    *parsed.cc_addresses,
                    *parsed.reply_to,
                    *parsed.return_path,
                ]
            )
            if address and address.strip()
        }

        def _actor_only(evidence: Evidence) -> bool:
            if evidence.predicate != "header_value":
                return False
            value = str(evidence.value or "").lower()
            return any(address in value for address in actor_addresses)

        for index, inference in enumerate(model.inferences):
            cited_inference = [
                evidence_registry[evidence_id]
                for evidence_id in inference.evidence_ids
                if evidence_id in evidence_registry
            ]
            if inference.code in EXTERNAL_REASON_CODES and not any(
                evidence.provenance in ("OSINT", "SANDBOX")
                for evidence in cited_inference
            ):
                issues.append(
                    _issue(
                        "unsupported_external_claim",
                        "error",
                        source,
                        inference.id,
                        f"inferences[{index}] ({inference.code}) cites no real "
                        "OSINT/SANDBOX evidence",
                    )
                )
            if (
                inference.code == "targeted_context"
                and cited_inference
                and all(_actor_only(evidence) for evidence in cited_inference)
            ):
                issues.append(
                    _issue(
                        "targeting_without_context",
                        "error",
                        source,
                        inference.id,
                        f"inferences[{index}] (targeted_context) cites only "
                        "actor headers (To/name), no contextual excerpt",
                    )
                )

        # --- local verdict/confidence/margin --------------------------------
        vector = model.model_dump()["probabilities"]
        verdict, confidence = compute_verdict_confidence(vector)
        margin = confidence_margin(vector)

        # --- V12: benignity cannot rest on absence of detection -------------
        if verdict in BENIGN_VERDICTS:
            all_cited: list[str] = []
            for kind, _where, reference in _assessment_references(model):
                if kind == "evidence" and reference not in all_cited:
                    all_cited.append(reference)

            def _non_substantive(evidence: Evidence) -> bool:
                if evidence.predicate in VT_COUNT_PREDICATES:
                    return True
                if evidence.predicate in ABSENCE_AUTH_PREDICATES:
                    return "pass" in str(evidence.value or "").lower()
                occurrences = tool_index.get(evidence.id, [])
                if occurrences and all(
                    result.status != "ok" for result, _entry in occurrences
                ):
                    return True
                return False

            substantive = [
                evidence_registry[evidence_id]
                for evidence_id in all_cited
                if evidence_id in evidence_registry
                and not _non_substantive(evidence_registry[evidence_id])
            ]
            if not all_cited or not substantive:
                issues.append(
                    _issue(
                        "benign_insufficient_basis",
                        "error",
                        source,
                        None,
                        "benign verdict rests only on PASS auth, zero "
                        "detection, not_found/unavailable, dead page or RAG "
                        "neighbour absence",
                    )
                )

        # --- V13: explicit malicious evidence vs benign verdict -------------
        if verdict in BENIGN_VERDICTS:
            confirmation = any(
                (evidence := evidence_registry.get(evidence_id)) is not None
                and evidence.observable_id is not None
                and evidence.observable_id in observable_registry
                and is_admissible_malicious_confirmation(
                    evidence, evidence.observable_id
                )
                for evidence_id in cited_evidence
            )
            supported_conflict = any(
                inference.code == "external_conflict"
                and any(
                    evidence_registry[evidence_id].provenance in ("OSINT", "SANDBOX")
                    for evidence_id in inference.evidence_ids
                    if evidence_id in evidence_registry
                )
                for inference in model.inferences
            )
            has_material_reason = any(
                inference.code in CONFLICT_REASON_CODES
                for inference in model.inferences
            )
            if confirmation or (has_material_reason and not supported_conflict):
                issues.append(
                    _issue(
                        "verdict_evidence_conflict",
                        "error",
                        source,
                        None,
                        "benign verdict contradicts an admissible malicious "
                        "confirmation or a material malicious reason without a "
                        "supported external_conflict",
                    )
                )

        # --- V14: verdict/confidence gain without new evidence --------------
        if phase == "final":
            internal_model = _coerce_assessment(internal)
            if internal_model is not None:
                internal_vector = internal_model.model_dump()["probabilities"]
                internal_verdict, internal_confidence = compute_verdict_confidence(
                    internal_vector
                )
                verdict_changed = verdict != internal_verdict
                if context.external_evidence_count_sent is not None:
                    new_external = context.external_evidence_count_sent > 0
                else:
                    new_external = any(
                        evidence.provenance in ("OSINT", "SANDBOX")
                        for evidence in evidence_registry.values()
                    )
                gain = verdict_changed or (
                    confidence - internal_confidence
                    > CONFIDENCE_RISE_WITHOUT_NEW_EVIDENCE_THRESHOLD
                )
                if gain and not new_external:
                    issues.append(
                        _issue(
                            "confidence_rise_without_new_evidence",
                            "warning",
                            source,
                            None,
                            "verdict/confidence moved without new evidence "
                            f"(internal {internal_verdict} "
                            f"{internal_confidence:.6f} -> final {verdict} "
                            f"{confidence:.6f}); AUTO is blocked, the verdict "
                            "is not declared wrong",
                        )
                    )

    # --- V15: RAG contamination controls ------------------------------------
    for case in rag_cases:
        problems: list[str] = []
        if case.is_public is not True:
            problems.append("case is not public")
        if case.split != "rag_reference":
            problems.append(f"split {case.split!r} is not rag_reference")
        if not case.validated_label:
            problems.append("no validated label")
        if not case.analyst_validation_ref:
            problems.append("no analyst validation reference")
        if not case.public_source_url:
            problems.append("no public source URL")
        if (
            context.current_duplicate_group
            and case.duplicate_group == context.current_duplicate_group
        ):
            problems.append("duplicate group matches the current case")
        if (
            context.current_family_group
            and case.family_group == context.current_family_group
        ):
            problems.append("family group matches the current case")
        if (
            context.current_campaign_id
            and case.campaign_id
            and case.campaign_id == context.current_campaign_id
        ):
            problems.append("campaign matches the current case")
        if problems:
            issues.append(
                _issue(
                    "rag_contamination",
                    "critical",
                    source,
                    case.case_id,
                    "RAG case is not admissible: " + "; ".join(problems),
                )
            )
    for observable_id, observable in observable_registry.items():
        if observable.provenance == "INFERENCE":
            # Already excluded by V03; V15 records the contamination reading.
            issues.append(
                _issue(
                    "rag_contamination",
                    "critical",
                    source,
                    observable_id,
                    "a RAG neighbour observable was propagated into the current "
                    "message registry",
                )
            )

    # --- V16: run/tool/fallback/timing/usage consistency --------------------
    if has_context:
        if context.final_source not in FINAL_SOURCES:
            issues.append(
                _issue(
                    "run_inconsistency",
                    "error",
                    "runtime",
                    None,
                    f"final_source {context.final_source!r} is not a contract value",
                )
            )
        if phase == "final" and context.final_source == "internal_fallback":
            issues.append(
                _issue(
                    "final_fallback_internal_copy",
                    "warning",
                    "runtime",
                    None,
                    "FINAL assessment fell back to a copy of the valid internal "
                    "assessment; AUTO is blocked",
                )
            )
        if phase == "final" and context.final_source == "none" and model is not None:
            issues.append(
                _issue(
                    "run_inconsistency",
                    "error",
                    "runtime",
                    None,
                    "an accepted final assessment exists while final_source is 'none'",
                )
            )
    for record, expected_phase in (
        (context.internal_call, "internal"),
        (context.final_call, "final"),
    ):
        if record is None:
            continue
        if record.phase != expected_phase:
            issues.append(
                _issue(
                    "run_inconsistency",
                    "error",
                    "runtime",
                    None,
                    f"call record for {expected_phase} declares phase {record.phase!r}",
                )
            )
        if record.status == "ok" and not record.returned_model:
            issues.append(
                _issue(
                    "run_inconsistency",
                    "error",
                    "runtime",
                    None,
                    f"{expected_phase} call is ok without a returned model",
                )
            )
    if (
        phase == "final"
        and context.final_call is not None
        and context.final_call.status == "error"
        and model is not None
    ):
        issues.append(
            _issue(
                "run_inconsistency",
                "error",
                "runtime",
                None,
                "an accepted final assessment exists while the final call "
                "record is an error",
            )
        )
    if context.timings is not None:
        import math

        timing_values = (
            context.timings.model_dump()
            if isinstance(context.timings, Timings)
            else dict(context.timings)
        )
        for name, value in timing_values.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                issues.append(
                    _issue(
                        "run_inconsistency",
                        "error",
                        "runtime",
                        None,
                        f"timing {name}={value!r} is not a finite non-negative value",
                    )
                )
    if results is not None:
        for result in results:
            if result.status == "ok":
                if result.mode not in ("live", "recorded"):
                    issues.append(
                        _issue(
                            "run_inconsistency",
                            "error",
                            "runtime",
                            result.query_observable_id,
                            f"{result.tool} ok result declares mode {result.mode!r}",
                        )
                    )
                if not result.response_ref or not result.response_sha256:
                    issues.append(
                        _issue(
                            "run_inconsistency",
                            "error",
                            "runtime",
                            result.query_observable_id,
                            f"{result.tool} ok result has no archived response "
                            "reference/fingerprint",
                        )
                    )
                if not _is_iso_datetime(result.collected_at):
                    issues.append(
                        _issue(
                            "run_inconsistency",
                            "error",
                            "runtime",
                            result.query_observable_id,
                            f"{result.tool} ok result has no valid collected_at "
                            "timestamp",
                        )
                    )
            elif result.evidence or result.observables:
                issues.append(
                    _issue(
                        "run_inconsistency",
                        "error",
                        "runtime",
                        result.query_observable_id,
                        f"{result.tool} {result.status} result carries positive "
                        "evidence/observables",
                    )
                )

    # --- accepted observable list (unsupported items removed) ---------------
    accepted_observables = [
        observable
        for observable_id, observable in observable_registry.items()
        if observable_id not in excluded_set
    ]
    excluded_observables = [
        observable
        for observable_id, observable in observable_registry.items()
        if observable_id in excluded_set
    ]
    blocking_codes: list[str] = []
    for issue in issues:
        if issue.severity in BLOCKING_SEVERITIES and issue.code not in blocking_codes:
            blocking_codes.append(issue.code)

    return VerificationResult(
        phase=phase,
        accepted=accepted,
        issues=issues,
        accepted_observables=accepted_observables,
        excluded_observables=excluded_observables,
        verdict=verdict,
        confidence=confidence,
        margin=margin,
        verdict_changed=verdict_changed,
        blocking_codes=blocking_codes,
    )

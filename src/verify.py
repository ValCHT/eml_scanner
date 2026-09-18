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
import time
from typing import Any

from pydantic import ValidationError

from .prompts import ContextLimits, build_internal_messages, envelope_has_useful_content
from .state import Assessment, CallRecord, ParsedEmail, TAXONOMY_ORDER

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
            if provenance in ("OSINT", "SANDBOX"):
                issues.append(
                    f"{where}: evidence {evidence_id!r} has provenance {provenance}; "
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
    "MAX_DECISIVE_EVIDENCE_IDS",
    "MAX_INFERENCES",
    "MAX_INFERENCE_SUMMARY_CHARS",
    "PROBABILITY_SUM_TOLERANCE",
    "assess_internal",
    "compute_verdict_confidence",
    "validate_assessment_shape_and_refs",
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

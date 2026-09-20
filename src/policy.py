"""Deterministic policy (docs/decisions.md §4.3, TICKET-10).

``decide_policy(inputs, config)`` applies the frozen priority order exactly
and returns one of the three actions ``AUTO`` / ``REVIEW`` / ``ESCALATE``
with auditable reason codes. It performs no network call and takes no real
email action: the action is a SOC recommendation only.

Priority order (stop at the first applicable rule):

1. critical evidence/integrity violation → ESCALATE, technical reason,
   never transformed into a phishing verdict;
2. admissible exact malicious confirmation not contradicted by same-scope
   evidence → ESCALATE, even when the model proposes benign; the
   contradiction is preserved;
3. no valid assessment, parser/LLM error, material gap, fallback, validation
   error, unresolved material limit → REVIEW;
4. malicious-family verdict with p ≥ ``escalate_malicious_min_confidence``
   → ESCALATE; below the threshold → REVIEW;
5. legime/spam with p ≥ ``auto_min_confidence``, margin ≥ ``auto_min_margin``,
   no blocking warning, no material missing information and no required
   unavailable enrichment → AUTO;
6. everything else → REVIEW.

Thresholds live in ``configs/policy.yaml`` (frozen initial values, never
calibrated here). A tool outage without a relevant target/material dependency
is not a blocking reason by itself; an outage on required enrichment forbids
AUTO. A missing detection / ``not_found`` never yields a benign verdict: the
verifier records the coded contradiction (V12) and policy reviews it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .config import PolicyConfig, load_yaml_config
from .state import Assessment, ToolResult, VerificationIssue
from .verify import (
    MALICIOUS_VERDICTS,
    compute_verdict_confidence,
    confidence_margin,
)

#: The only three allowed recommendations.
Action = Literal["AUTO", "REVIEW", "ESCALATE"]
ACTIONS: tuple[Action, ...] = ("AUTO", "REVIEW", "ESCALATE")

#: Missing-information codes that are material for AUTO (docs/decisions.md
#: §4.3): destination to verify for a reasoning-bearing link, suspicious
#: attachment not inspected, essential visual content unread, truncated
#: content, required context. ``authentication_untrusted`` alone is NOT
#: material: it is a coverage limit whose materiality depends on scenario.
MATERIAL_MISSING_INFORMATION: tuple[str, ...] = (
    "destination_unverified",
    "attachment_not_inspected",
    "essential_visual_unread",
    "content_truncated",
    "insufficient_context",
)

#: Default configuration path (frozen thresholds, docs/decisions.md §4.3).
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "configs" / "policy.yaml"


@dataclass
class PolicyInputs:
    """Everything the policy may use; no field is a free-form verdict.

    ``verification_issues`` are the deterministic verifier issues (a
    ``VerificationResult.issues`` list fits directly). ``errors`` carries
    parser/LLM phase errors. ``material_gap`` and
    ``required_enrichment_unavailable`` may be provided explicitly; when
    left at ``None`` they are derived from the assessment's typed
    ``missing_information`` and the tool results, so a tool outage without a
    relevant target/material dependency never becomes an artificial REVIEW.
    """

    assessment: Assessment | None = None
    verification_issues: Sequence[VerificationIssue | Mapping[str, Any]] = field(
        default_factory=tuple
    )
    errors: Sequence[VerificationIssue | Mapping[str, Any]] = field(default_factory=tuple)
    final_source: str = "none"
    parser_error: bool = False
    llm_error: bool = False
    material_gap: bool | None = None
    required_enrichment_unavailable: bool | None = None
    tool_results: Sequence[ToolResult | Mapping[str, Any]] = field(default_factory=tuple)
    admissible_confirmation: bool = False
    confirmation_contradicted: bool = False


@dataclass
class PolicyDecision:
    """Recommendation plus auditable reason codes (no real email action)."""

    action: Action
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "reasons": list(self.reasons)}


def load_policy_config(path: Path | str | None = None) -> PolicyConfig:
    """Load and strictly validate ``configs/policy.yaml`` (frozen values)."""

    config_path = Path(path) if path is not None else DEFAULT_POLICY_PATH
    loaded = load_yaml_config(config_path, PolicyConfig)
    assert isinstance(loaded, PolicyConfig)
    return loaded


def _coerce_config(value: PolicyConfig | Mapping[str, Any]) -> PolicyConfig:
    if isinstance(value, PolicyConfig):
        return value
    if isinstance(value, Mapping):
        return PolicyConfig.model_validate(dict(value))
    raise TypeError(f"config: expected PolicyConfig or mapping, got {type(value).__name__}")


def _coerce_inputs(value: PolicyInputs | Mapping[str, Any]) -> PolicyInputs:
    if isinstance(value, PolicyInputs):
        return value
    if isinstance(value, Mapping):
        allowed = set(PolicyInputs.__dataclass_fields__)
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(f"inputs: unknown fields {unknown}")
        return PolicyInputs(**dict(value))
    raise TypeError(f"inputs: expected PolicyInputs or mapping, got {type(value).__name__}")


def _coerce_issues(value: Sequence[VerificationIssue | Mapping[str, Any]] | None) -> list[VerificationIssue]:
    if value is None:
        return []
    return [
        item if isinstance(item, VerificationIssue) else VerificationIssue.model_validate(item)
        for item in value
    ]


def _coerce_tool_results(
    value: Sequence[ToolResult | Mapping[str, Any]] | Any | None,
) -> list[ToolResult]:
    if value is None:
        return []
    if all(hasattr(value, name) for name in ("virustotal", "opencti", "urlscan")):
        items: list[Any] = [*value.virustotal, *value.opencti, *value.urlscan]
    else:
        items = list(value)
    results: list[ToolResult] = []
    for item in items:
        results.append(item if isinstance(item, ToolResult) else ToolResult.model_validate(item))
    return results


def material_missing_information(assessment: Assessment | None) -> list[str]:
    """Material typed gaps of the assessment, frozen order (docs/decisions.md §4.3)."""

    if assessment is None:
        return []
    return [
        code
        for code in assessment.missing_information
        if code in MATERIAL_MISSING_INFORMATION
    ]


def has_required_unavailable_enrichment(
    assessment: Assessment | None,
    tool_results: Sequence[ToolResult | Mapping[str, Any]] | None,
) -> bool:
    """True when an unavailable tool hit a RELEVANT target the assessment needs.

    ``tool_unavailable`` must be a declared gap and at least one unavailable
    result must carry a real query observable (the deterministic plan had a
    relevant target). An unavailable tool without any relevant target is not
    a blocking reason on its own.
    """

    if assessment is None or "tool_unavailable" not in assessment.missing_information:
        return False
    return any(
        result.status == "unavailable" and result.query_observable_id
        for result in _coerce_tool_results(tool_results)
    )


def _dedup(values: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def _number(value: float | None) -> str:
    return "null" if value is None else f"{value:.6f}"


def decide_policy(
    inputs: PolicyInputs | Mapping[str, Any],
    config: PolicyConfig | Mapping[str, Any],
) -> PolicyDecision:
    """Apply the frozen priority order (docs/decisions.md §4.3)."""

    data = _coerce_inputs(inputs)
    cfg = _coerce_config(config)
    issues = [
        *_coerce_issues(data.verification_issues),
        *_coerce_issues(data.errors),
    ]

    # --- Priority 1: critical evidence/integrity violation → ESCALATE.
    critical = [issue for issue in issues if issue.severity == "critical"]
    if critical:
        return PolicyDecision(
            "ESCALATE",
            _dedup(
                [f"critical_integrity_violation:{issue.code}" for issue in critical]
            ),
        )

    # --- Priority 2: admissible exact malicious confirmation → ESCALATE.
    if data.admissible_confirmation and not data.confirmation_contradicted:
        return PolicyDecision(
            "ESCALATE",
            ["admissible_exact_malicious_confirmation"],
        )

    # --- Priority 3: invalid/missing assessment or blocking facts → REVIEW.
    review: list[str] = []
    if data.parser_error:
        review.append("parser_error")
    if data.llm_error:
        review.append("llm_error")
    if data.final_source == "internal_fallback":
        review.append("final_fallback_internal_copy")
    if data.assessment is None:
        review.append("invalid_or_missing_assessment")
    for issue in issues:
        if issue.severity == "error":
            review.append(f"validation_error:{issue.code}")
    material = material_missing_information(data.assessment)
    if data.material_gap is True:
        material.append("declared_material_gap")
    if material:
        review.append("material_missing_information:" + ",".join(_dedup(material)))
    required = data.required_enrichment_unavailable
    if required is None:
        required = has_required_unavailable_enrichment(data.assessment, data.tool_results)
    if required:
        review.append("required_enrichment_unavailable")
    if review:
        return PolicyDecision("REVIEW", _dedup(review))

    # --- verdict/confidence/margin are computed locally from the vector.
    verdict: str | None = None
    confidence: float | None = None
    margin: float | None = None
    if data.assessment is not None:
        vector = data.assessment.model_dump()["probabilities"]
        verdict, confidence = compute_verdict_confidence(vector)
        margin = confidence_margin(vector)

    # --- Priority 4: malicious-family verdict at/above threshold → ESCALATE.
    if verdict in MALICIOUS_VERDICTS:
        assert confidence is not None
        if confidence >= cfg.escalate_malicious_min_confidence:
            return PolicyDecision(
                "ESCALATE",
                [f"malicious_verdict_escalation:{verdict}@{_number(confidence)}"],
            )
        return PolicyDecision(
            "REVIEW",
            [
                "malicious_verdict_below_escalation_threshold:"
                f"{verdict}@{_number(confidence)}<{_number(cfg.escalate_malicious_min_confidence)}"
            ],
        )

    # --- Priority 5: confident legime/spam in the AUTO labels → AUTO.
    if verdict in cfg.auto_labels:
        blocks: list[str] = []
        for issue in issues:
            if issue.severity in ("warning", "error", "critical"):
                blocks.append(f"blocking_warning:{issue.code}")
        if confidence is None or confidence < cfg.auto_min_confidence:
            blocks.append(
                "confidence_below_auto_min:"
                f"{_number(confidence)}<{_number(cfg.auto_min_confidence)}"
            )
        if margin is None or margin < cfg.auto_min_margin:
            blocks.append(
                f"margin_below_auto_min:{_number(margin)}<{_number(cfg.auto_min_margin)}"
            )
        if not blocks:
            return PolicyDecision(
                "AUTO",
                [
                    "auto_eligible:"
                    f"{verdict}@{_number(confidence)}:margin={_number(margin)}"
                ],
            )
        return PolicyDecision("REVIEW", _dedup(blocks))

    # --- Priority 6: everything else → REVIEW.
    if verdict is None:
        return PolicyDecision("REVIEW", ["no_valid_verdict"])
    return PolicyDecision("REVIEW", [f"default_review:{verdict}"])


__all__ = [
    "ACTIONS",
    "Action",
    "DEFAULT_POLICY_PATH",
    "MATERIAL_MISSING_INFORMATION",
    "PolicyDecision",
    "PolicyInputs",
    "decide_policy",
    "has_required_unavailable_enrichment",
    "load_policy_config",
    "material_missing_information",
]

"""Deterministic policy tests (TICKET-10, docs/decisions.md §4.3).

Non-live only. Boundaries (0.85 / 0.97 / margin 0.50) are exercised with
controlled assessment vectors; the real TICKET-09 FINAL result feeds the
end-to-end case. Thresholds are NOT calibrated here: ``configs/policy.yaml``
is asserted frozen, and the margin comparison-operator test uses an explicit
in-memory config because the frozen ``p >= 0.97`` value makes the margin
threshold unreachable at that confidence (p >= 0.97 implies margin >= 0.94).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.config import PolicyConfig
from src.parsing import ParseLimits, parse_email
from src.policy import (
    ACTIONS,
    PolicyInputs,
    decide_policy,
    load_policy_config,
)
from src.state import Assessment, TAXONOMY_ORDER, VerificationIssue
from src.verify import RunContext, verify_assessment

pytestmark = pytest.mark.g5

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
G5_FINAL = PROJECT_ROOT / "runs" / "gates" / "G5" / "final"


def _probabilities(**weights: float) -> dict[str, float]:
    values = {label: 0.0 for label in TAXONOMY_ORDER}
    for label, value in weights.items():
        values[label] = float(value)
    return values


def _assessment(
    probabilities: dict[str, float],
    *,
    observations: list[str] | None = None,
    inferences: list[dict[str, object]] | None = None,
    observable_assessments: list[dict[str, object]] | None = None,
    needs_enrichment: bool = False,
    missing_information: list[str] | None = None,
    decisive_evidence_ids: list[str] | None = None,
) -> Assessment:
    return Assessment.model_validate(
        {
            "probabilities": probabilities,
            "observations": observations or [],
            "inferences": inferences or [],
            "observable_assessments": observable_assessments or [],
            "needs_enrichment": needs_enrichment,
            "missing_information": missing_information or [],
            "decisive_evidence_ids": decisive_evidence_ids or [],
        }
    )


def _benign(confidence: float = 0.97) -> Assessment:
    return _assessment(_probabilities(legitime=confidence, spam=1.0 - confidence))


def _error(code: str) -> VerificationIssue:
    return VerificationIssue(code=code, severity="error", source="final", message="controlled")


def _warning(code: str) -> VerificationIssue:
    return VerificationIssue(code=code, severity="warning", source="final", message="controlled")


def _critical(code: str) -> VerificationIssue:
    return VerificationIssue(code=code, severity="critical", source="final", message="controlled")


# ---------------------------------------------------------------------------
# Frozen configuration
# ---------------------------------------------------------------------------


def test_policy_config_frozen_initial_values() -> None:
    config = load_policy_config()
    assert config.auto_min_confidence == 0.97
    assert config.auto_min_margin == 0.50
    assert config.escalate_malicious_min_confidence == 0.85
    assert config.auto_labels == ["legitime", "spam"]
    assert config.version == 1


def test_policy_actions_are_exactly_three() -> None:
    assert ACTIONS == ("AUTO", "REVIEW", "ESCALATE")


# ---------------------------------------------------------------------------
# Priority 1 — critical integrity violation over any verdict
# ---------------------------------------------------------------------------


def test_critical_violation_has_priority_over_benign_verdict() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_benign(0.99),
            verification_issues=[_critical("fabricated_ioc")],
        ),
        load_policy_config(),
    )
    assert decision.action == "ESCALATE"
    assert decision.reasons == ["critical_integrity_violation:fabricated_ioc"]


def test_critical_violation_overrides_malicious_below_threshold() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(_probabilities(phishing=0.60, legitime=0.40)),
            verification_issues=[_critical("recipient_as_ioc")],
        ),
        load_policy_config(),
    )
    assert decision.action == "ESCALATE"
    assert decision.reasons[0].startswith("critical_integrity_violation:")


# ---------------------------------------------------------------------------
# Priority 2 — admissible exact malicious confirmation
# ---------------------------------------------------------------------------


def test_admissible_confirmation_escalates_even_with_benign_verdict() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_benign(0.99), admissible_confirmation=True),
        load_policy_config(),
    )
    assert decision.action == "ESCALATE"
    assert decision.reasons == ["admissible_exact_malicious_confirmation"]


def test_contradicted_confirmation_defers_to_the_remaining_rules() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_benign(0.99),
            admissible_confirmation=True,
            confirmation_contradicted=True,
        ),
        load_policy_config(),
    )
    # priority 2 no longer applies; a clean confident benign assessment may AUTO
    assert decision.action == "AUTO"


# ---------------------------------------------------------------------------
# Priority 3 — invalid/missing, errors, material gaps, fallback
# ---------------------------------------------------------------------------


def test_missing_or_invalid_assessment_is_review() -> None:
    decision = decide_policy(PolicyInputs(assessment=None), load_policy_config())
    assert decision.action == "REVIEW"
    assert "invalid_or_missing_assessment" in decision.reasons


def test_parser_and_llm_errors_are_review() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_benign(0.99), parser_error=True, llm_error=True),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert {"parser_error", "llm_error"} <= set(decision.reasons)


def test_fallback_always_prevents_auto_even_for_confident_benign() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_benign(0.99), final_source="internal_fallback"),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert "final_fallback_internal_copy" in decision.reasons


def test_fallback_prevents_escalate_of_confident_malicious() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(_probabilities(phishing=0.99, legitime=0.01)),
            final_source="internal_fallback",
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"


def test_material_missing_information_prevents_auto() -> None:
    for code in (
        "destination_unverified",
        "attachment_not_inspected",
        "essential_visual_unread",
        "content_truncated",
        "insufficient_context",
    ):
        decision = decide_policy(
            PolicyInputs(
                assessment=_assessment(
                    _probabilities(legitime=0.99, spam=0.01),
                    missing_information=[code],
                )
            ),
            load_policy_config(),
        )
        assert decision.action == "REVIEW", code
        assert f"material_missing_information:{code}" in decision.reasons


def test_authentication_untrusted_alone_is_not_material() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(
                _probabilities(legitime=0.99, spam=0.01),
                missing_information=["authentication_untrusted"],
            )
        ),
        load_policy_config(),
    )
    assert decision.action == "AUTO"


def test_validation_error_prevents_auto() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_benign(0.99), verification_issues=[_error("false_exact_match")]),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert "validation_error:false_exact_match" in decision.reasons


# ---------------------------------------------------------------------------
# Unavailable enrichment: material only with a relevant target
# ---------------------------------------------------------------------------


def test_unavailable_without_relevant_target_is_not_blocking() -> None:
    from src.state import ToolResult

    unavailable = ToolResult(
        tool="virustotal",
        query_observable_id=None,
        status="unavailable",
        reason="not_configured",
        mode="none",
    )
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(
                _probabilities(legitime=0.99, spam=0.01),
                missing_information=["tool_unavailable"],
            ),
            tool_results=[unavailable],
        ),
        load_policy_config(),
    )
    assert decision.action == "AUTO"


def test_unavailable_required_enrichment_prevents_auto() -> None:
    from src.state import ToolResult

    unavailable = ToolResult(
        tool="urlscan",
        query_observable_id="obs_url_target",
        status="unavailable",
        reason="timeout",
        mode="none",
    )
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(
                _probabilities(legitime=0.99, spam=0.01),
                missing_information=["tool_unavailable"],
            ),
            tool_results=[unavailable],
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert "required_enrichment_unavailable" in decision.reasons


def test_explicit_required_unavailable_flag_prevents_auto() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_benign(0.99),
            required_enrichment_unavailable=True,
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"


# ---------------------------------------------------------------------------
# Priority 4 — malicious-family verdict boundaries
# ---------------------------------------------------------------------------


def test_malicious_confidence_boundary_at_085_escalates() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(
                _probabilities(phishing=0.85, legitime=0.10, spam=0.05)
            )
        ),
        load_policy_config(),
    )
    assert decision.action == "ESCALATE"
    assert decision.reasons == ["malicious_verdict_escalation:phishing@0.850000"]


def test_malicious_just_below_085_reviews() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(
                _probabilities(
                    phishing=0.849999, legitime=0.100001, spam=0.05
                )
            )
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert decision.reasons[0].startswith(
        "malicious_verdict_below_escalation_threshold:phishing@0.849999<0.850000"
    )


def test_each_malicious_family_label_can_escalate() -> None:
    cases = {
        "spear_phishing": _probabilities(spear_phishing=0.90, legitime=0.10),
        "fraude": _probabilities(fraude=0.90, legitime=0.10),
        "menace": _probabilities(menace=0.90, legitime=0.10),
    }
    for label, vector in cases.items():
        decision = decide_policy(
            PolicyInputs(assessment=_assessment(vector)), load_policy_config()
        )
        assert decision.action == "ESCALATE", label


# ---------------------------------------------------------------------------
# Priority 5 — AUTO boundaries
# ---------------------------------------------------------------------------


def test_auto_confidence_boundary_at_097_autos() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_benign(0.97)), load_policy_config()
    )
    assert decision.action == "AUTO"
    assert decision.reasons == ["auto_eligible:legitime@0.970000:margin=0.940000"]


def test_auto_just_below_097_reviews() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_benign(0.969999)), load_policy_config()
    )
    assert decision.action == "REVIEW"
    assert any(reason.startswith("confidence_below_auto_min") for reason in decision.reasons)


def test_auto_margin_boundary_comparison_operator() -> None:
    """Margin >= 0.50 comparison, exercised with an explicit test config.

    The frozen AUTO confidence (0.97) mathematically implies a margin above
    0.94, so the frozen pair cannot isolate the margin rule. The in-memory
    config below only tests the comparison operator; ``configs/policy.yaml``
    is untouched (asserted frozen elsewhere).
    """

    config = PolicyConfig(
        version=1,
        auto_min_confidence=0.50,
        auto_min_margin=0.50,
        escalate_malicious_min_confidence=0.85,
        auto_labels=["legitime", "spam"],
        blocked_reason_codes={},
    )
    at_boundary = _assessment(_probabilities(legitime=0.75, spam=0.25))
    assert decide_policy(PolicyInputs(assessment=at_boundary), config).action == "AUTO"

    below = _assessment(_probabilities(legitime=0.749999, spam=0.250001))
    decision = decide_policy(PolicyInputs(assessment=below), config)
    assert decision.action == "REVIEW"
    assert any(reason.startswith("margin_below_auto_min") for reason in decision.reasons)


def test_v14_warning_blocks_auto() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_benign(0.99),
            verification_issues=[_warning("confidence_rise_without_new_evidence")],
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert (
        "blocking_warning:confidence_rise_without_new_evidence" in decision.reasons
    )


def test_spam_label_is_auto_eligible() -> None:
    decision = decide_policy(
        PolicyInputs(assessment=_assessment(_probabilities(spam=0.98, legitime=0.02))),
        load_policy_config(),
    )
    assert decision.action == "AUTO"


# ---------------------------------------------------------------------------
# Priority 6 / absence-of-detection contradictions
# ---------------------------------------------------------------------------


def test_not_found_or_no_detection_contradiction_reviews() -> None:
    """V12 (benign_insufficient_basis) is an error: never an independent benign."""

    decision = decide_policy(
        PolicyInputs(
            assessment=_benign(0.99),
            verification_issues=[_error("benign_insufficient_basis")],
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert "validation_error:benign_insufficient_basis" in decision.reasons


def test_default_review_for_unmatched_verdict() -> None:
    decision = decide_policy(
        PolicyInputs(
            assessment=_assessment(_probabilities(menace=0.10, legitime=0.60, spam=0.30))
        ),
        load_policy_config(),
    )
    assert decision.action == "REVIEW"
    assert decision.reasons  # always auditable


def test_decision_and_reasons_are_deterministic() -> None:
    inputs = PolicyInputs(
        assessment=_benign(0.97),
        verification_issues=[_warning("confidence_rise_without_new_evidence")],
    )
    config = load_policy_config()
    first = decide_policy(inputs, config)
    again = decide_policy(inputs, config)
    assert first.to_dict() == again.to_dict()


def test_policy_rejects_unknown_input_fields() -> None:
    with pytest.raises(ValueError):
        decide_policy({"assessment": None, "bogus": 1}, load_policy_config())


# ---------------------------------------------------------------------------
# End-to-end with the real TICKET-09 FINAL capture
# ---------------------------------------------------------------------------


def test_real_t09_final_policy_is_review_due_to_material_destination_gap() -> None:
    request = json.loads(
        (G5_FINAL / "malicious_url_redirect" / "final_attempt_1.request.json").read_text(
            encoding="utf-8"
        )
    )
    envelope = json.loads(request["messages"][1]["content"])
    rows = [
        json.loads(line)
        for line in (G5_FINAL / "final_runs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    row = next(row for row in rows if row["fixture"] == "malicious_url_redirect.eml")
    final = Assessment.model_validate(row["final_assessment"])
    internal = Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"])
    parsed = parse_email(FIXTURES / "malicious_url_redirect.eml", ParseLimits())
    assert not isinstance(parsed, str)

    result = verify_assessment(
        final,
        "final",
        {
            "evidence": envelope["EVIDENCE_REGISTRY"],
            "observables": envelope["OBSERVABLE_REGISTRY"],
        },
        tool_results=[],
        parsed=parsed,
        rag_context=[],
        internal=internal,
        run_context=RunContext(
            final_source="final_llm",
            external_evidence_count_sent=row["external_evidence_count_sent"],
        ),
    )
    decision = decide_policy(
        PolicyInputs(
            assessment=result.accepted,
            verification_issues=result.issues,
            final_source="final_llm",
        ),
        load_policy_config(),
    )
    # phishing 0.88: no admissible confirmation (no external evidence), the
    # V14 warning blocks AUTO, and the material destination gap keeps it at
    # REVIEW per the frozen priority 3 before the rule-4 escalation.
    assert decision.action == "REVIEW"
    assert any(
        reason.startswith("material_missing_information:destination_unverified")
        for reason in decision.reasons
    )
    assert "confidence_rise_without_new_evidence" in result.blocking_codes

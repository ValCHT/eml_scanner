"""TICKET-14 metric tests (docs/evaluation.md §8.2, docs/tickets/TICKET-14.md).

Deterministic arithmetic on small synthetic tables/objects — no benchmark
result is simulated here and no provider call is possible (the autouse
fixture refuses every network access). Fixture data is test-input only.
"""

from __future__ import annotations

import pytest

from src.metrics import (
    LABELS,
    PRICING_SNAPSHOT,
    abc_block,
    classification_block,
    compare_internal_final,
    estimate_cost_usd,
    evaluate,
    fpr_block,
    latency_stats,
    paired_variant_block,
    sample_cost,
    validate_control_audits,
)

pytestmark = pytest.mark.g6


def _make_report(
    sample_id: str,
    sha: str,
    *,
    gate: str = "complex",
    internal_verdict: str | None = "phishing",
    final_verdict: str | None = "phishing",
    final_source: str = "final_llm",
    action: str = "AUTO",
    llm_calls: list[dict] | None = None,
    tools: dict[str, list[dict]] | None = None,
    evidence: list[dict] | None = None,
    unsupported: list[dict] | None = None,
) -> dict:
    """Minimal synthetic TriageReport for metric plumbing tests."""

    return {
        "sample_id": sample_id,
        "email_sha256": sha,
        "gate_decision": gate,
        "gate_reasons": [],
        "internal_verdict": internal_verdict,
        "internal_confidence": 0.9 if internal_verdict else None,
        "final_verdict": final_verdict,
        "final_confidence": 0.95 if final_verdict else None,
        "final_source": final_source,
        "run_status": "ok" if final_verdict else "error",
        "verdict_changed": None,
        "recommended_action": action,
        "policy_reasons": [],
        "timings": {
            "parse_ms": 1.0, "internal_llm_ms": 10.0, "gate_ms": 1.0,
            "vt_ms": 1.0, "opencti_ms": 1.0, "urlscan_ms": 1.0, "rag_ms": 0.0,
            "merge_ms": 1.0, "final_llm_ms": 10.0, "verify_ms": 1.0,
            "policy_ms": 1.0, "report_ms": 1.0, "total_ms": 40.0,
        },
        "llm_calls": llm_calls
        or [
            {
                "phase": "internal", "status": "ok", "attempts": 1,
                "first_attempt_schema_valid": True,
                "input_tokens": 1000, "cached_input_tokens": 100,
                "output_tokens": 500, "reasoning_tokens": 300,
                "cost_usd": None, "cost_status": "unknown",
            }
        ],
        "enrichment": {
            "virustotal": (tools or {}).get("virustotal", []),
            "opencti": (tools or {}).get("opencti", []),
            "urlscan": (tools or {}).get("urlscan", []),
            "rag": [],
        },
        "evidence": evidence or [],
        "unsupported_claims": unsupported or [],
        "verification_warnings": [],
    }


def _make_row(sample_id: str, sha: str, label: str) -> dict:
    return {
        "sample_id": sample_id,
        "normalized_label": label,
        "raw_sha256": sha,
        "family_group": sample_id,
        "source_dataset": "test",
    }


# ---------------------------------------------------------------------------
# Manual arithmetic on a small table (hand-computed, not benchmark data)
# ---------------------------------------------------------------------------


def test_manual_macro_f1_small_table():
    labels = [
        "phishing", "phishing", "legitime", "legitime",
        "spam", "spam", "spam", "spam",
    ]
    predictions = [
        "phishing", "legitime", "legitime", "phishing",
        "spam", "spam", "legitime", None,
    ]
    block = classification_block(labels, predictions)
    # Hand arithmetic (7 valid predictions + 1 abstention):
    #   phishing: tp=1, fp=1, fn=1 -> p=0.5, r=0.5, f1=0.5
    #   legitime: tp=1, fp=2, fn=1 -> p=1/3, r=0.5, f1=0.4
    #   spam:     tp=2, fp=0, fn=2 (one abstention) -> p=1.0, r=0.5, f1=2/3
    assert block["n_total"] == 8
    assert block["n_valid_predictions"] == 7
    assert block["n_abstentions"] == 1
    assert block["support"]["spam"] == 4
    assert block["per_class"]["phishing"]["precision"] == pytest.approx(0.5)
    assert block["per_class"]["phishing"]["recall"] == pytest.approx(0.5)
    assert block["per_class"]["phishing"]["f1"] == pytest.approx(0.5)
    assert block["per_class"]["legitime"]["precision"] == pytest.approx(1 / 3)
    assert block["per_class"]["legitime"]["recall"] == pytest.approx(0.5)
    assert block["per_class"]["legitime"]["f1"] == pytest.approx(0.4)
    assert block["per_class"]["spam"]["precision"] == pytest.approx(1.0)
    assert block["per_class"]["spam"]["recall"] == pytest.approx(0.5)
    assert block["per_class"]["spam"]["f1"] == pytest.approx(2 / 3)
    assert block["macro_f1"]["value"] == pytest.approx((0.5 + 0.4 + 2 / 3) / 3)
    assert block["macro_f1"]["classes_with_support"] == 3
    # spear_phishing, fraude and menace have zero support here: the
    # six-class Macro-F1 is non-conclusive and the supported-classes macro
    # must never be presented as the six-class Macro-F1.
    assert block["macro_f1_six_class"]["value"] is None
    assert block["macro_f1_six_class"]["status"] == "non_conclusive_zero_support_class"
    confusion = block["confusion"]
    assert confusion["labels"] == list(LABELS)
    assert confusion["rows_true_cols_predicted"] == [
        [0, 0, 0, 0, 0, 0],  # spear_phishing (no support)
        [0, 1, 0, 0, 0, 1],  # phishing: tp=1, predicted legitime=1
        [0, 0, 0, 0, 0, 0],  # fraude
        [0, 0, 0, 0, 0, 0],  # menace
        [0, 0, 0, 0, 2, 1],  # spam: tp=2, predicted legitime=1
        [0, 1, 0, 0, 0, 1],  # legitime: tp=1, predicted phishing=1
    ]
    assert confusion["abstention_by_true_class"]["spam"] == 1
    assert sum(sum(row) for row in confusion["rows_true_cols_predicted"]) == 7


def test_class_never_predicted_precision_defined_zero():
    # A class WITH support that is never predicted: precision is DEFINED at
    # 0 (documented convention), never silently perfect, never removed.
    labels = ["fraude", "fraude", "legitime"]
    predictions = ["legitime", "legitime", "legitime"]
    block = classification_block(labels, predictions)
    fraude = block["per_class"]["fraude"]
    assert fraude["support"] == 2
    assert fraude["predicted"] == 0
    assert fraude["precision"] == 0.0
    assert fraude["precision_status"] == "defined_zero_no_prediction"
    assert fraude["recall"] == 0.0
    assert fraude["f1"] == 0.0


def test_zero_support_class_not_perfect():
    block = classification_block(["spam", "spam"], ["spam", "spam"])
    menace = block["per_class"]["menace"]
    assert menace["support"] == 0
    assert menace["recall"] is None
    assert menace["recall_status"] == "not_estimable_zero_support"
    assert menace["precision"] is None
    assert menace["f1"] is None
    assert block["macro_f1_six_class"]["status"] == "non_conclusive_zero_support_class"
    # The supported-classes macro (1.0 over spam only) is NOT a six-class
    # Macro-F1 and must never be reported as one.
    assert block["macro_f1"]["value"] == pytest.approx(1.0)
    assert block["macro_f1"]["status"] == "estimable_supported_classes"


def test_abstention_and_null_stay_in_denominators():
    labels = ["legitime", "legitime", "phishing"]
    predictions = [None, "legitime", None]
    block = classification_block(labels, predictions)
    assert block["n_total"] == 3
    assert block["n_valid_predictions"] == 1
    assert block["n_abstentions"] == 2
    # null counts as a false negative for the true class (never removed).
    assert block["per_class"]["legitime"]["recall"] == pytest.approx(0.5)
    fpr = fpr_block(labels, predictions)
    # Strict FPR EXCLUDES the null prediction; the abstention rate is
    # reported separately (never merged into an FPR).
    assert fpr["legitime_support"] == 2
    assert fpr["strict_legitime_fpr"] == 0.0
    assert fpr["legitime_abstention_rate"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Paired comparison buckets (§8.3)
# ---------------------------------------------------------------------------


def test_paired_buckets_and_denominators():
    labels = ["phishing", "legitime", "spam", "fraude", "legitime"]
    # A: correct, correct, wrong, null(failure), right
    # B: wrong,  right,   wrong, null,          right
    preds_a = ["phishing", "legitime", "legitime", None, "legitime"]
    preds_b = ["legitime", "legitime", "legitime", None, "legitime"]
    result = compare_internal_final(labels, preds_a, preds_b)
    assert result["n_comparable"] == 5
    # Hand buckets:
    #   s1: A right (phishing) -> B wrong (legitime) = right_to_wrong
    #   s2: A right            -> B right            = right_to_right
    #   s3: A wrong (label spam) -> B wrong           = wrong_to_wrong
    #   s4: A null(failure)    -> B null(failure)    = wrong_to_wrong
    #   s5: A right (legitime) -> B right            = right_to_right
    assert result["buckets"] == {
        "right_to_right": 2,
        "wrong_to_right": 0,
        "right_to_wrong": 1,
        "wrong_to_wrong": 2,
    }
    assert result["n_changed_verdict"] == 1
    assert result["a_technical_failures"] == 1
    assert result["b_technical_failures"] == 1
    assert result["denominators_paired"] is True
    # per-class recall delta where BOTH sides are estimable
    phishing = result["per_class_recall_delta"]["phishing"]
    assert phishing["a"] == pytest.approx(1.0) and phishing["b"] == 0.0
    assert phishing["delta"] == pytest.approx(-1.0)
    # menace has zero support on both sides: not estimable, not fabricated.
    menace = result["per_class_recall_delta"]["menace"]
    assert menace["status"] == "not_estimable" and menace["delta"] is None


def test_confidence_changes_separate_from_verdicts():
    # Reported through abc_block: confidence deltas counted independently.
    report = _make_report("s1", "sha1", gate="complex", internal_verdict="phishing", final_verdict="phishing")
    control = {
        "excluded_technical": False,
        "a": {"verdict": "phishing", "confidence": 0.80},
        "b": {"verdict": "phishing", "confidence": 0.97},
        "c": {"verdict": "phishing", "confidence": 0.99},
        "audit": {"valid": True, "problems": [], "no_new_external_evidence": True, "bundle_external_evidence": 0},
        "b_cost_usd": 0.001,
        "b_latency_ms": 1000.0,
    }
    block = abc_block(["phishing"], ["phishing"], ["complex"], [report], [control])
    changes = block["confidence_changes"]
    assert changes["A_to_B"]["n"] == 1
    assert changes["A_to_B"]["mean_delta"] == pytest.approx(0.17)
    assert changes["B_to_C"]["mean_delta"] == pytest.approx(0.02)
    assert changes["same_verdict_confidence_changed_A_to_B"] == 1


# ---------------------------------------------------------------------------
# Cost accounting: reasoning never double-counted, unknown never zero
# ---------------------------------------------------------------------------


def test_reasoning_tokens_not_double_counted():
    call = {
        "input_tokens": 1000,
        "cached_input_tokens": 100,
        "output_tokens": 500,
        "reasoning_tokens": 300,
        "cost_usd": None,
        "cost_status": "unknown",
    }
    cost, status = estimate_cost_usd(call, PRICING_SNAPSHOT)
    # (900*0.25 + 100*0.05 + 500*2.2) / 1e6 = 0.00133 USD
    assert status == "estimated"
    assert cost == pytest.approx((900 * 0.25 + 100 * 0.05 + 500 * 2.2) / 1_000_000)
    # If reasoning tokens (300) were billed a SECOND time the cost would be
    # 300*2.2/1e6 = 0.00066 higher: assert the double-counted value differs.
    double_counted = cost + 300 * 2.2 / 1_000_000
    assert not math_close(cost, double_counted)


def math_close(a: float, b: float) -> bool:
    return abs(a - b) < 1e-12


def test_cost_unknown_when_usage_missing():
    call = {"input_tokens": None, "output_tokens": None, "cost_usd": None, "cost_status": "unknown"}
    cost, status = estimate_cost_usd(call, PRICING_SNAPSHOT)
    assert cost is None and status == "unknown"
    report = {
        "llm_calls": [call],
        "timings": {"total_ms": 5.0},
    }
    block = sample_cost(report)
    # An unknown cost is NEVER turned into zero.
    assert block["total_usd"] is None
    assert block["status"] == "unknown"
    assert block["unknown_call_count"] == 1


def test_cost_partial_when_one_call_has_usage():
    report = {
        "llm_calls": [
            {"phase": "internal", "status": "ok", "input_tokens": 1000, "cached_input_tokens": 0,
             "output_tokens": 500, "reasoning_tokens": 0, "cost_usd": None, "cost_status": "unknown"},
            {"phase": "final", "status": "error", "input_tokens": None, "output_tokens": None,
             "cost_usd": None, "cost_status": "unknown"},
        ],
        "timings": {"total_ms": 5.0},
    }
    block = sample_cost(report)
    assert block["status"] == "partial"
    assert block["unknown_call_count"] == 1
    # Only the attempt with real usage contributes.
    assert block["total_usd"] == pytest.approx((1000 * 0.25 + 500 * 2.2) / 1_000_000)


def test_provider_billed_value_takes_precedence():
    call = {
        "input_tokens": 1000, "cached_input_tokens": 0, "output_tokens": 500,
        "reasoning_tokens": 0,
        "cost_usd": 0.5, "cost_status": "provider_reported",
    }
    cost, status = estimate_cost_usd(call, PRICING_SNAPSHOT)
    assert status == "provider_reported"
    assert cost == 0.5
    block = sample_cost({"llm_calls": [call], "timings": {}})
    assert block["provider_reported_usd"] == 0.5
    assert block["provider_status"] == "provider_reported"


def test_reasoning_aggregation_preserved_for_audit():
    report = {
        "llm_calls": [
            {"phase": "internal", "status": "ok", "input_tokens": 100, "cached_input_tokens": 0,
             "output_tokens": 50, "reasoning_tokens": 20, "cost_usd": None, "cost_status": "unknown"},
        ],
        "timings": {"total_ms": 1.0},
    }
    block = sample_cost(report)
    assert block["usage_tokens"]["reasoning_tokens"] == 20
    assert block["usage_tokens"]["output_tokens"] == 50


# ---------------------------------------------------------------------------
# Latency statistics (documented nearest-rank p95)
# ---------------------------------------------------------------------------


def test_latency_stats_p95_nearest_rank():
    values = [float(i) for i in range(1, 101)]  # 1..100
    stats = latency_stats(values)
    assert stats["n"] == 100
    assert stats["mean_ms"] == pytest.approx(50.5)
    assert stats["median_ms"] == pytest.approx(50.5)
    assert stats["p95_ms"] == pytest.approx(95.0)
    assert stats["max_ms"] == pytest.approx(100.0)
    assert stats["total_ms"] == pytest.approx(5050.0)


def test_latency_stats_empty_is_none_not_zero():
    stats = latency_stats([])
    assert stats["mean_ms"] is None and stats["p95_ms"] is None and stats["total_ms"] is None


# ---------------------------------------------------------------------------
# A/B/C audit invariants (docs/contracts.md §2.6.1)
# ---------------------------------------------------------------------------


def _b_audit(**overrides: object) -> dict:
    audit = {
        "phase": "final",
        "external_evidence_count_sent": 0,
        "internal_evidence_count_sent": 4,
        "evidence_count_sent": 4,
        "rag_case_count_sent": 0,
        "visual_count_sent": 0,
        "tool_status_digest": "d" * 64,
    }
    audit.update(overrides)
    return audit


def _c_audit(**overrides: object) -> dict:
    audit = {
        "phase": "final",
        "external_evidence_count_sent": 3,
        "internal_evidence_count_sent": 4,
        "evidence_count_sent": 7,
        "rag_case_count_sent": 0,
        "visual_count_sent": 0,
        "tool_status_digest": "e" * 64,
    }
    audit.update(overrides)
    return audit


def test_b_audit_with_external_evidence_invalidates():
    valid, problems, _ = validate_control_audits(
        [_b_audit(external_evidence_count_sent=2)], [_c_audit()], bundle_external_evidence=3
    )
    assert not valid
    assert any("external_evidence_count_sent" in problem for problem in problems)


def test_b_audit_with_rag_or_visual_invalidates():
    for override in ({"rag_case_count_sent": 1}, {"visual_count_sent": 2}):
        valid, problems, _ = validate_control_audits(
            [_b_audit(**override)], [_c_audit()], bundle_external_evidence=0
        )
        assert not valid
        assert problems


def test_b_audit_evidence_internal_mismatch_invalidates():
    valid, problems, _ = validate_control_audits(
        [_b_audit(evidence_count_sent=5, internal_evidence_count_sent=4)],
        [_c_audit()],
        bundle_external_evidence=0,
    )
    assert not valid
    assert any("evidence_count_sent" in problem for problem in problems)


def test_c_dropping_admissible_external_evidence_invalidates():
    # The bundle produced external evidence but C sent none: invalid.
    valid, problems, no_new = validate_control_audits(
        [_b_audit()], [_c_audit(external_evidence_count_sent=0)], bundle_external_evidence=3
    )
    assert not valid
    assert any("dropped admissible evidence" in problem for problem in problems)
    assert no_new is False


def test_c_without_external_bundle_is_valid_with_limitation():
    valid, problems, no_new = validate_control_audits(
        [_b_audit()], [_c_audit(external_evidence_count_sent=0)], bundle_external_evidence=0
    )
    assert valid
    assert not problems
    assert no_new is True


def test_missing_audits_are_unprovable():
    valid, problems, _ = validate_control_audits([], [], bundle_external_evidence=0)
    assert not valid
    assert any("unprovable" in problem for problem in problems)


# ---------------------------------------------------------------------------
# Contract entry point: evaluate(rows, reports)
# ---------------------------------------------------------------------------


def test_evaluate_contract_core_metrics():
    rows = [
        _make_row("s1", "sha1", "phishing"),
        _make_row("s2", "sha2", "legitime"),
        _make_row("s3", "sha3", "spam"),
    ]
    reports = [
        _make_report("s1", "sha1", gate="complex", internal_verdict="phishing",
                     final_verdict="phishing", action="AUTO",
                     tools={"virustotal": [{"tool": "virustotal", "status": "unavailable",
                                            "reason": "access_not_authorized", "requests_sent": 0,
                                            "query_observable_id": None, "mode": "live"}]},
                     evidence=[{"id": "ev1", "provenance": "OSINT"}]),
        _make_report("s2", "sha2", gate="simple", internal_verdict="legitime",
                     final_verdict="legitime", final_source="internal_copy", action="AUTO"),
        _make_report("s3", "sha3", gate="complex", internal_verdict="legitime",
                     final_verdict="spam", action="AUTO"),
    ]
    metrics = evaluate(rows, reports)
    assert metrics["n_total"] == 3
    assert metrics["n_valid_predictions"] == 3
    assert metrics["delivered"]["support"]["spam"] == 1
    assert metrics["paths"]["simple"]["n"] == 1
    assert metrics["paths"]["complex"]["n"] == 2
    assert metrics["policy"]["coverage"]["AUTO"]["count"] == 3
    assert metrics["policy"]["malicious_auto_count"] == 1
    assert metrics["policy"]["benign_auto"]["support"] == 3
    assert metrics["tool_coverage"]["tools"]["virustotal"]["statuses"] == {"unavailable": 1}
    assert metrics["tool_coverage"]["external_evidence_new"]["OSINT"] == 1
    assert metrics["fpr"]["legitime_support"] == 1
    assert metrics["delivered"]["macro_f1_six_class"]["status"] == "non_conclusive_zero_support_class"


def test_evaluate_loud_hash_mismatch():
    rows = [_make_row("s1", "gold_sha", "phishing")]
    reports = [_make_report("s1", "different_sha")]
    with pytest.raises(ValueError):
        evaluate(rows, reports)


def test_technical_failure_remains_in_denominator():
    rows = [
        _make_row("s1", "sha1", "fraude"),
        _make_row("s2", "sha2", "spam"),
    ]
    reports = [
        # provider failure: no valid prediction at all (both phases failed)
        _make_report("s1", "sha1", gate="complex", internal_verdict=None,
                     final_verdict=None, final_source="none"),
        _make_report("s2", "sha2", gate="complex", internal_verdict="spam", final_verdict="spam"),
    ]
    metrics = evaluate(rows, reports)
    # The failed sample stays in every denominator as an abstention.
    assert metrics["n_total"] == 2
    assert metrics["n_valid_predictions"] == 1
    assert metrics["n_abstentions"] == 1
    assert metrics["delivered"]["per_class"]["fraude"]["recall"] == 0.0
    assert metrics["delivered"]["confusion"]["abstention_by_true_class"]["fraude"] == 1


# ---------------------------------------------------------------------------
# IOC proposal counting (before verifier / delivered after verifier)
# ---------------------------------------------------------------------------


def test_ioc_counters_before_and_after_verifier():
    rows = [_make_row("s1", "sha1", "phishing")]
    reports = [
        _make_report(
            "s1", "sha1", gate="complex",
            unsupported=[
                {"code": "fabricated_ioc", "severity": "critical", "source": "final",
                 "object_id": "obs_x", "message": "delivered violation"},
            ],
        )
    ]
    extras = [{"proposals_total": 10, "proposals_invalid": 2, "refusals": 0}]
    metrics = evaluate(rows, reports, sample_extras=extras)
    assert metrics["ioc"]["proposals_total"] == 10
    assert metrics["ioc"]["proposals_invalid"] == 2
    assert metrics["ioc"]["fabricated_rate_before_verifier"] == pytest.approx(0.2)
    assert metrics["ioc"]["delivered_violations_after_verifier"] == 1
    assert metrics["schema"]["refusals"] == 0


def test_ioc_rate_null_when_denominator_zero():
    rows = [_make_row("s1", "sha1", "phishing")]
    reports = [_make_report("s1", "sha1", gate="simple")]
    metrics = evaluate(rows, reports, sample_extras=[{"proposals_total": 0, "proposals_invalid": 0}])
    assert metrics["ioc"]["fabricated_rate_before_verifier"] is None
    assert metrics["ioc"]["proposals_total"] == 0


# ---------------------------------------------------------------------------
# Paired baseline -> variant block (TICKET-15, docs/evaluation.md §8.7)
# ---------------------------------------------------------------------------


def test_paired_variant_block_stays_paired_and_diagnostic():
    labels = ["phishing", "legitime", "spam"]
    baseline = ["phishing", "legitime", "spam"]
    rag = ["phishing", None, "spam"]  # one technical failure on legitime
    block = paired_variant_block(
        labels, baseline, rag, baseline_variant="baseline", variant="rag"
    )
    assert block["n_comparable"] == 3
    assert block["buckets"] == {
        "right_to_right": 2,
        "wrong_to_right": 0,
        "right_to_wrong": 1,
        "wrong_to_wrong": 0,
    }
    assert block["n_changed_verdict"] == 1
    assert block["b_technical_failures"] == 1
    assert block["a_technical_failures"] == 0
    assert block["denominators_paired"] is True
    assert block["a_role"] == "baseline"
    assert block["b_role"] == "variant"
    assert block["baseline_variant"] == "baseline"
    assert block["variant"] == "rag"
    assert block["diagnostic_only"] is True
    assert block["performance_claims_allowed"] is False


def test_paired_variant_block_improvement_and_regression_buckets():
    labels = ["phishing", "legitime"]
    baseline = [None, "legitime"]  # one baseline failure, one baseline hit
    rag = ["phishing", "spam"]  # corrected one, broke the other
    block = paired_variant_block(labels, baseline, rag)
    assert block["buckets"]["wrong_to_right"] == 1
    assert block["buckets"]["right_to_wrong"] == 1
    assert block["a_technical_failures"] == 1
    assert block["delta_macro_f1"] is not None


def test_paired_variant_block_refuses_length_mismatch():
    with pytest.raises(ValueError):
        paired_variant_block(["phishing"], ["phishing", "spam"], ["phishing"])

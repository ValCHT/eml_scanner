"""Evaluation metrics for the real dev baseline (TICKET-14, docs/evaluation.md §8).

Pure, deterministic, offline arithmetic over three inputs:

- gold rows: closed-schema ``GoldRecord`` dicts (docs/contracts.md §2.8) —
  label metadata only, already validated by the loader;
- triage reports: the archived ``TriageReport`` dicts actually produced by the
  frozen pipeline (``src.reporting.build_report``);
- optional per-sample control payloads for the A/B/C experiment (variant
  ``baseline`` on COMPLEX gold_dev emails: A=INTERNAL medium shared,
  B=XHIGH internal-only ablation control, C=XHIGH real enriched FINAL).

Contract (docs/tickets/TICKET-14.md INTERFACES):

    evaluate(rows: list[GoldRecord], reports: list[TriageReport]) -> Metrics
    compare_internal_final(...)

Fixed label order everywhere: spear_phishing, phishing, fraude, menace,
spam, legitime. ``pred=null`` (technical failure/refusal/abstention) stays in
every denominator, counts as an abstention and a false negative for the true
class, and is never silently removed.

Documented metric conventions (docs/evaluation.md §8.2):

- a class with zero support has non-estimable recall/F1 (never perfect);
- a class with support but zero predictions gets precision defined at 0,
  explicitly documented — never silently perfect;
- six-class Macro-F1 is ``non_conclusive`` whenever any class has zero
  support; the macro over supported classes is reported separately and is
  never presented as the six-class Macro-F1;
- FPR strict/malicious/abstention are reported separately for legitime
  (spam is never mixed with malveillance);
- cost never invents 0 for unknown usage: missing usage makes the record
  ``unknown``/``partial`` and the cost stays explicitly unknown;
- reasoning tokens are already counted inside ``output_tokens`` by the
  provider convention: they are NEVER added a second time.

No wall-clock time, hostname or absolute path enters a metric value: the
same archived inputs always produce byte-identical metrics, which is what
the offline ``--mode recompute`` equality check relies on.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

#: Fixed taxonomy order (docs/contracts.md §2.1 / src.state.TAXONOMY_ORDER).
LABELS: tuple[str, ...] = (
    "spear_phishing",
    "phishing",
    "fraude",
    "menace",
    "spam",
    "legitime",
)

#: Malicious classes (policy/FPR semantics; spam is NOT malicious, §8.2).
MALICIOUS_LABELS: tuple[str, ...] = ("spear_phishing", "phishing", "fraude", "menace")

#: Benign classes for AUTO-precision reporting (legitime + spam, reported
#: separately so the spam/malveillance distinction stays visible).
BENIGN_LABELS: tuple[str, ...] = ("legitime", "spam")

#: Documented AkashML pricing snapshot (USD per 1M tokens, 19/09/2026,
#: docs/evaluation.md §8.2). Reasoning tokens are inside completion tokens.
PRICING_SNAPSHOT: dict[str, Any] = {
    "model": "Qwen/Qwen3.8-27B",
    "provider": "AkashML OpenAI-compatible endpoint",
    "input_usd_per_1m": 0.25,
    "cache_read_usd_per_1m": 0.05,
    "output_usd_per_1m": 2.20,
    "currency": "USD",
    "observed_on": "2026-09-19",
    "source": "docs/evaluation.md §8.2 AkashML metadata snapshot",
}


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def latency_stats(values: Sequence[float]) -> dict[str, Any]:
    """Mean/median/p95/max/total with the documented nearest-rank p95.

    p95 uses the nearest-rank method on ascending order:
    ``sorted[ceil(0.95 * n) - 1]`` (0-based). Median is the classic mean of
    the two central values for even ``n``. Empty input yields ``None``
    statistics (never a fake zero).
    """

    clean = [float(value) for value in values if _finite(value) and value >= 0]
    if not clean:
        return {
            "n": 0,
            "mean_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "max_ms": None,
            "total_ms": None,
        }
    ordered = sorted(clean)
    count = len(ordered)
    p95_index = max(0, math.ceil(0.95 * count) - 1)
    middle = count // 2
    median = (
        ordered[middle]
        if count % 2 == 1
        else (ordered[middle - 1] + ordered[middle]) / 2.0
    )
    return {
        "n": count,
        "mean_ms": sum(ordered) / count,
        "median_ms": median,
        "p95_ms": ordered[p95_index],
        "max_ms": ordered[-1],
        "total_ms": sum(ordered),
    }


def estimate_cost_usd(
    call: Mapping[str, Any], pricing: Mapping[str, Any]
) -> tuple[float | None, str]:
    """Estimated cost of ONE call record from its real usage metadata.

    ``(cost, status)``: the cost is ``None`` when the usage is missing — an
    unknown cost is never replaced by a fake zero (§8.2). The provider-billed
    value (``cost_usd`` with ``cost_status=provider_reported``) takes
    precedence when exposed; otherwise the documented snapshot is applied:

    ``(input - cached) * input_rate + cached * cache_rate + output * output_rate``.

    Reasoning tokens are already part of ``output_tokens`` (completion
    tokens) per the provider convention: they are counted exactly once.
    """

    provider_cost = call.get("cost_usd")
    if provider_cost is not None and call.get("cost_status") == "provider_reported":
        return float(provider_cost), "provider_reported"
    input_tokens = call.get("input_tokens")
    output_tokens = call.get("output_tokens")
    if not _finite(input_tokens) or not _finite(output_tokens):
        return None, "unknown"
    cached = call.get("cached_input_tokens")
    cached_value = float(cached) if _finite(cached) else 0.0
    # Defensive clamp: cached tokens can never exceed the prompt tokens.
    cached_value = min(max(cached_value, 0.0), float(input_tokens))
    input_rate = float(pricing.get("input_usd_per_1m", 0.0))
    cache_rate = float(pricing.get("cache_read_usd_per_1m", 0.0))
    output_rate = float(pricing.get("output_usd_per_1m", 0.0))
    cost = (
        (float(input_tokens) - cached_value) * input_rate / 1_000_000.0
        + cached_value * cache_rate / 1_000_000.0
        + float(output_tokens) * output_rate / 1_000_000.0
    )
    return cost, "estimated"


# ---------------------------------------------------------------------------
# Per-sample cost projection from a TriageReport
# ---------------------------------------------------------------------------


def sample_cost(
    report: Mapping[str, Any], pricing: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Cost projection of one sample from its real call records (§8.2).

    Every entry of ``llm_calls`` is a billable phase attempt set (retries are
    already included in the usage of the attempts that ran). The cost is
    estimated from the pricing snapshot when the provider exposes no billed
    value; missing usage keeps the sample cost explicitly unknown, never a
    fake zero. Provider-billed and estimated values are preserved
    separately.
    """

    pricing = pricing or PRICING_SNAPSHOT
    records = [
        record
        for record in (report.get("llm_calls") or [])
        if isinstance(record, Mapping)
    ]
    per_call: list[dict[str, Any]] = []
    estimated_total = 0.0
    estimated_known = 0
    provider_total = 0.0
    provider_known = 0
    unknown = 0
    statuses: set[str] = set()
    usage = {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0}
    usage_known = {"input_tokens": False, "cached_input_tokens": False, "output_tokens": False, "reasoning_tokens": False}
    for record in records:
        cost, status = estimate_cost_usd(record, pricing)
        entry: dict[str, Any] = {
            "phase": record.get("phase"),
            "phase_status": record.get("status"),
            "attempts": record.get("attempts"),
            "cost_status": status,
            # Provider convention: reasoning tokens are already inside
            # output_tokens (completion tokens) — counted exactly once.
            "reasoning_double_count_guard": "reasoning tokens are inside output_tokens; counted once",
        }
        for token_field in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens"):
            value = record.get(token_field)
            if _finite(value):
                usage[token_field] += int(value)  # type: ignore[arg-type]
                usage_known[token_field] = True
            entry[token_field] = value if _finite(value) else None
        if cost is not None:
            entry["estimated_usd"] = cost
            estimated_total += cost
            estimated_known += 1
            statuses.add(status)
        else:
            statuses.add("unknown")
            unknown += 1
        if record.get("cost_usd") is not None and record.get("cost_status") == "provider_reported":
            provider_total += float(record["cost_usd"])
            provider_known += 1
            entry["provider_reported_usd"] = float(record["cost_usd"])
        per_call.append(entry)
    if not records:
        status = "unknown"
        total_value: float | None = None
    elif unknown == len(records):
        status = "unknown"
        total_value = None
    elif unknown > 0 or len(statuses) > 1:
        status = "partial"
        total_value = estimated_total if estimated_known else None
    else:
        status = next(iter(statuses))
        total_value = estimated_total
    if provider_known == 0:
        provider_value: float | None = None
        provider_status = "not_exposed"
    elif provider_known < len(records):
        provider_value = provider_total
        provider_status = "partial"
    else:
        provider_value = provider_total
        provider_status = "provider_reported"
    usage_out = {
        field: (usage[field] if usage_known[field] else None)
        for field in usage
    }
    return {
        "total_usd": total_value,
        "status": status,
        "provider_reported_usd": provider_value,
        "provider_status": provider_status,
        "estimated_total_usd": estimated_total if estimated_known else None,
        "unknown_call_count": unknown,
        "call_count": len(records),
        "usage_tokens": usage_out,
        "per_call": per_call,
        "pricing_snapshot": dict(pricing),
    }


# ---------------------------------------------------------------------------
# Classification metrics (fixed label order, abstentions explicit)
# ---------------------------------------------------------------------------


def classification_block(
    labels: Sequence[str | None], predictions: Sequence[str | None]
) -> dict[str, Any]:
    """Full classification block for paired gold/prediction sequences.

    ``predictions`` may contain ``None`` (technical failure / abstention):
    such samples stay in every denominator, are counted in the abstention
    vector, and count as a false negative for their true class. A ``None``
    gold label is not possible for validated GoldRecords; if one appears it
    raises (fail-closed, never a silent sample drop).
    """

    if len(labels) != len(predictions):
        raise ValueError("labels/predictions length mismatch")
    for label in labels:
        if label is not None and label not in LABELS:
            raise ValueError(f"unknown gold label {label!r}")
    for prediction in predictions:
        if prediction is not None and prediction not in LABELS:
            raise ValueError(f"unknown prediction {prediction!r}")

    support = {label: 0 for label in LABELS}
    for label in labels:
        if label is not None:
            support[label] += 1

    predicted_count = {label: 0 for label in LABELS}
    true_positive = {label: 0 for label in LABELS}
    confusion = [[0] * len(LABELS) for _ in LABELS]
    abstention_by_true_class = {label: 0 for label in LABELS}
    for label, prediction in zip(labels, predictions):
        if label is None:
            continue  # cannot happen for validated gold; defensive no-op
        if prediction is None:
            abstention_by_true_class[label] += 1
            continue
        predicted_count[prediction] += 1
        confusion[LABELS.index(label)][LABELS.index(prediction)] += 1
        if prediction == label:
            true_positive[label] += 1

    n_total = len(labels)
    n_valid = sum(predicted_count.values())
    n_abstentions = sum(abstention_by_true_class.values())

    per_class: dict[str, dict[str, Any]] = {}
    f1_supported: list[float] = []
    classes_with_support = 0
    for index, label in enumerate(LABELS):
        class_support = support[label]
        class_predicted = predicted_count[label]
        tp = true_positive[label]
        # --- precision -----------------------------------------------------
        if class_predicted == 0:
            if class_support > 0:
                # Documented §8.2 convention: a class with support that is
                # never predicted gets precision DEFINED at 0 (explicitly
                # documented, never silently perfect).
                precision = 0.0
                precision_status = "defined_zero_no_prediction"
            else:
                precision = None
                precision_status = "not_estimable_no_prediction_no_support"
        else:
            precision = tp / class_predicted
            precision_status = "estimable"
        # --- recall ---------------------------------------------------------
        if class_support == 0:
            recall = None
            recall_status = "not_estimable_zero_support"
        else:
            recall = tp / class_support
            recall_status = "estimable"
        # --- F1 ---------------------------------------------------------------
        if precision is None or recall is None:
            f1 = None
            f1_status = "not_estimable"
        elif precision + recall == 0:
            f1 = 0.0
            f1_status = "defined_zero"
        else:
            f1 = 2 * precision * recall / (precision + recall)
            f1_status = "estimable"
        if class_support > 0:
            classes_with_support += 1
            if f1 is not None:
                f1_supported.append(f1)
        per_class[label] = {
            "support": class_support,
            "predicted": class_predicted,
            "true_positive": tp,
            "precision": precision,
            "precision_status": precision_status,
            "recall": recall,
            "recall_status": recall_status,
            "f1": f1,
            "f1_status": f1_status,
        }

    macro_supported = (
        sum(f1_supported) / len(f1_supported) if f1_supported else None
    )
    six_conclusive = classes_with_support == len(LABELS)
    six_value = (
        sum(float(per_class[label]["f1"]) for label in LABELS) / len(LABELS)
        if six_conclusive
        else None
    )
    matrix = {
        "labels": list(LABELS),
        "rows_true_cols_predicted": confusion,
        "abstention_by_true_class": abstention_by_true_class,
        "with_abstention_column": [
            confusion[index] + [abstention_by_true_class[label]]
            for index, label in enumerate(LABELS)
        ],
    }
    return {
        "n_total": n_total,
        "n_valid_predictions": n_valid,
        "n_abstentions": n_abstentions,
        "support": support,
        "per_class": per_class,
        "macro_f1": {
            "value": macro_supported,
            "status": (
                "estimable_supported_classes"
                if macro_supported is not None
                else "not_estimable_no_supported_class"
            ),
            "classes_with_support": classes_with_support,
        },
        "macro_f1_six_class": {
            "value": six_value,
            "status": (
                "estimable"
                if six_conclusive
                else "non_conclusive_zero_support_class"
            ),
            "reason": (
                None
                if six_conclusive
                else "at least one class has zero reference support "
                "(menace=0 in this POC); the six-class Macro-F1 is not "
                "estimable and the supported-classes macro must never be "
                "presented as a six-class Macro-F1"
            ),
        },
        "confusion": matrix,
    }


# ---------------------------------------------------------------------------
# FPR block (legitime reference class, §8.2)
# ---------------------------------------------------------------------------


def fpr_block(labels: Sequence[str | None], predictions: Sequence[str | None]) -> dict[str, Any]:
    """FPR metrics on the legitime reference class (spam never mixed in).

    - strict: legitime predicted as any other class with a NON-null
      prediction, divided by the legitime support;
    - malicious: legitime predicted as one of the malicious classes;
    - abstention: legitime samples whose prediction is null (reported
      separately, never merged into an FPR).
    """

    pairs = [
        (label, prediction)
        for label, prediction in zip(labels, predictions)
        if label == "legitime"
    ]
    support = len(pairs)
    strict = sum(
        1
        for _, prediction in pairs
        if prediction is not None and prediction != "legitime"
    )
    malicious = sum(
        1
        for _, prediction in pairs
        if prediction is not None and prediction in MALICIOUS_LABELS
    )
    abstentions = sum(1 for _, prediction in pairs if prediction is None)
    return {
        "legitime_support": support,
        "strict_legitime_fpr": _ratio(strict, support),
        "malicious_legitime_fpr": _ratio(malicious, support),
        "legitime_abstention_rate": _ratio(abstentions, support),
        "strict_errors": strict,
        "malicious_errors": malicious,
        "abstentions": abstentions,
        "status": "estimable" if support > 0 else "not_estimable_zero_support",
    }


# ---------------------------------------------------------------------------
# Report -> metric inputs (TriageReport is a plain JSON dict, §2.6)
# ---------------------------------------------------------------------------


def _report_field(report: Mapping[str, Any], name: str) -> Any:
    value = report.get(name)
    return value if isinstance(value, str) or value is None else None


def delivered_prediction(report: Mapping[str, Any]) -> str | None:
    """Delivered verdict of one report (``final_validated`` projection)."""

    verdict = report.get("final_verdict")
    return verdict if isinstance(verdict, str) and verdict in LABELS else None


def internal_prediction(report: Mapping[str, Any]) -> str | None:
    """INTERNAL (A) verdict of one report."""

    verdict = report.get("internal_verdict")
    return verdict if isinstance(verdict, str) and verdict in LABELS else None


def _confidence(report: Mapping[str, Any], key: str) -> float | None:
    value = report.get(key)
    return float(value) if _finite(value) else None


def align_rows_reports(
    rows: Sequence[Mapping[str, Any]], reports: Sequence[Mapping[str, Any]]
) -> None:
    """Loud alignment check: gold row <-> report must describe the same email.

    When a report parsed the message, its ``email_sha256`` is the hash of the
    bytes actually analysed; the validated GoldRecord ``raw_sha256`` is the
    hash of the exact local bytes. Any mismatch raises (never silently
    dropped). A null ``email_sha256`` means the parse failed — a real
    technical outcome that stays in the denominators.
    """

    if len(rows) != len(reports):
        raise ValueError(
            f"gold rows ({len(rows)}) and reports ({len(reports)}) counts differ"
        )
    for row, report in zip(rows, reports):
        gold_hash = str(row.get("raw_sha256", ""))
        report_hash = report.get("email_sha256")
        if report_hash is not None and str(report_hash) != gold_hash:
            raise ValueError(
                f"report/gold hash mismatch for sample {row.get('sample_id')!r}: "
                f"gold raw_sha256={gold_hash} vs report email_sha256={report_hash}"
            )


def _evidence_provenance_counts(report: Mapping[str, Any]) -> dict[str, int]:
    counts = {"INTERNE": 0, "OSINT": 0, "SANDBOX": 0, "INFERENCE": 0}
    for entry in report.get("evidence") or []:
        if isinstance(entry, Mapping):
            provenance = entry.get("provenance")
            if isinstance(provenance, str) and provenance in counts:
                counts[provenance] += 1
    return counts


def _tool_coverage(report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Per-tool coverage rows from one report's enrichment (statuses kept)."""

    enrichment = report.get("enrichment")
    coverage: dict[str, dict[str, Any]] = {}
    for tool in ("virustotal", "opencti", "urlscan"):
        rows = (enrichment or {}).get(tool) or []
        if not isinstance(rows, Sequence):
            rows = []
        statuses: dict[str, int] = {}
        reasons: dict[str, int] = {}
        requests = 0
        for result in rows:
            if not isinstance(result, Mapping):
                continue
            status = str(result.get("status"))
            statuses[status] = statuses.get(status, 0) + 1
            reason = str(result.get("reason"))
            reasons[reason] = reasons.get(reason, 0) + 1
            count = result.get("requests_sent")
            if _finite(count):
                requests += int(count)  # type: ignore[arg-type]
        coverage[tool] = {
            "candidates": len(rows),
            "statuses": statuses,
            "reasons": reasons,
            "requests_sent": requests,
            "ok_results": statuses.get("ok", 0),
        }
    return coverage


def _call_schema_validity(report: Mapping[str, Any]) -> dict[str, Any]:
    """First-attempt schema validity / after-retry / retries per phase (§8.2)."""

    by_phase: dict[str, dict[str, Any]] = {}
    for record in report.get("llm_calls") or []:
        if not isinstance(record, Mapping):
            continue
        phase = str(record.get("phase"))
        first = record.get("first_attempt_schema_valid")
        attempts = record.get("attempts")
        attempts_value = int(attempts) if _finite(attempts) else 0
        status = str(record.get("status"))
        by_phase[phase] = {
            "first_attempt_schema_valid": (
                bool(first) if isinstance(first, bool) else None
            ),
            "valid_after_retry": status == "ok",
            "status": status,
            "attempts": attempts_value,
            "retries": max(0, attempts_value - 1) if attempts_value else 0,
        }
    return by_phase


def _critical_issue_codes(report: Mapping[str, Any]) -> dict[str, int]:
    """Critical (unsupported/delivered) issue code counts of one report."""

    counts: dict[str, int] = {}
    for issue in report.get("unsupported_claims") or []:
        if isinstance(issue, Mapping):
            code = str(issue.get("code"))
            counts[code] = counts.get(code, 0) + 1
    return counts


_IOC_DELIVERED_CODES = (
    "unsupported_claim",
    "unsupported_external_claim",
    "unsupported_external_fact",
    "fabricated_ioc",
)


# ---------------------------------------------------------------------------
# Contract entry point: evaluate(rows, reports) -> Metrics
# ---------------------------------------------------------------------------


def evaluate(
    rows: Sequence[Mapping[str, Any]],
    reports: Sequence[Mapping[str, Any]],
    *,
    sample_extras: Sequence[Mapping[str, Any]] | None = None,
    controls: Sequence[Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Gold metrics of one evaluation run (docs/evaluation.md §8.2).

    ``rows`` are validated GoldRecords (label metadata only); ``reports`` are
    the archived TriageReport dicts of the SAME samples, in the same order.
    ``sample_extras`` (optional, aligned) carries per-sample live-observed
    counters that are not part of the report schema: the pre-verifier IOC
    proposal counters (from the archived FINAL validation rejects) and the
    refusal count (from the archived attempt error artifacts). ``controls``
    (optional, aligned) carries the A/B/C payloads of the ``baseline``
    variant for COMPLEX samples.

    The delivered prediction is the report's ``final_verdict`` (the
    ``final_validated`` assessment: the real FINAL result for COMPLEX, the
    documented internal copy for SIMPLE, null when no valid assessment
    survives). ``null`` predictions stay in every denominator.
    """

    align_rows_reports(rows, reports)
    labels = [str(row["normalized_label"]) for row in rows]
    delivered = [delivered_prediction(report) for report in reports]
    internal = [internal_prediction(report) for report in reports]
    gate_decisions = [
        (report.get("gate_decision") if isinstance(report.get("gate_decision"), str) else None)
        for report in reports
    ]
    actions = [
        (report.get("recommended_action") if isinstance(report.get("recommended_action"), str) else None)
        for report in reports
    ]
    extras = [dict(extra) if isinstance(extra, Mapping) else {} for extra in (sample_extras or [])]
    if len(extras) < len(rows):
        extras = extras + [{} for _ in range(len(rows) - len(extras))]

    overall = classification_block(labels, delivered)
    internal_block = classification_block(labels, internal)

    # --- SIMPLE / COMPLEX paths ------------------------------------------------
    paths: dict[str, Any] = {}
    for path_name in ("simple", "complex"):
        indexes = [i for i, decision in enumerate(gate_decisions) if decision == path_name]
        path_labels = [labels[i] for i in indexes]
        path_preds = [delivered[i] for i in indexes]
        path_costs = [sample_cost(reports[i]) for i in indexes]
        path_latencies = [
            float(reports[i]["timings"]["total_ms"])
            for i in indexes
            if isinstance(reports[i].get("timings"), Mapping)
            and _finite(reports[i]["timings"].get("total_ms"))
        ]
        path_block = classification_block(path_labels, path_preds)
        paths[path_name] = {
            "n": len(indexes),
            "pct": _ratio(len(indexes), len(rows)),
            "quality": {
                "support": path_block["support"],
                "per_class": path_block["per_class"],
                "macro_f1": path_block["macro_f1"],
                "macro_f1_six_class": path_block["macro_f1_six_class"],
                "n_abstentions": path_block["n_abstentions"],
            },
            "cost": _path_cost(path_costs, len(indexes)),
            "latency": latency_stats(path_latencies),
        }

    # --- cost -------------------------------------------------------------------
    all_costs = [sample_cost(report) for report in reports]
    cost_block = _aggregate_cost(all_costs, len(rows))
    cost_block["by_path"] = {}
    for path_name in ("simple", "complex"):
        path_indexes = [i for i, decision in enumerate(gate_decisions) if decision == path_name]
        cost_block["by_path"][path_name] = _path_cost(
            [sample_cost(reports[i]) for i in path_indexes], len(path_indexes)
        )

    # --- latency ------------------------------------------------------------------
    phase_names = (
        "parse_ms", "internal_llm_ms", "gate_ms", "vt_ms", "opencti_ms",
        "urlscan_ms", "rag_ms", "merge_ms", "final_llm_ms", "verify_ms",
        "policy_ms", "report_ms", "total_ms",
    )
    by_phase: dict[str, Any] = {}
    for phase_name in phase_names:
        values = [
            float(report["timings"][phase_name])
            for report in reports
            if isinstance(report.get("timings"), Mapping)
            and _finite(report["timings"].get(phase_name))
        ]
        by_phase[phase_name] = latency_stats(values)
    latency_block = {
        "overall": by_phase["total_ms"],
        "by_phase": by_phase,
        "by_path": {
            path_name: {
                phase: latency_stats([
                    float(reports[i]["timings"][phase])
                    for i, decision in enumerate(gate_decisions)
                    if decision == path_name
                    and isinstance(reports[i].get("timings"), Mapping)
                    and _finite(reports[i]["timings"].get(phase))
                ])
                for phase in ("total_ms", "internal_llm_ms", "final_llm_ms")
            }
            for path_name in ("simple", "complex")
        },
    }

    # --- schema validity ---------------------------------------------------------
    first_attempt = {"internal": [0, 0], "final": [0, 0]}  # [valid, total_known]
    after_retry = {"internal": 0, "final": 0}
    phase_status_errors = {"internal": 0, "final": 0}
    retries = 0
    for report in reports:
        by_phase_call = _call_schema_validity(report)
        for phase, stats in by_phase_call.items():
            if phase not in ("internal", "final"):
                continue
            if stats["first_attempt_schema_valid"] is not None:
                first_attempt[phase][1] += 1
                if stats["first_attempt_schema_valid"]:
                    first_attempt[phase][0] += 1
            if stats["valid_after_retry"]:
                after_retry[phase] += 1
            retries += stats["retries"]
            if stats["status"] == "error":
                phase_status_errors[phase] += 1
    refusals = sum(int(extra.get("refusals", 0) or 0) for extra in extras)

    # --- IOC / fabricated-proposal counters (§8.2) ------------------------------
    proposals_total = sum(int(extra.get("proposals_total", 0) or 0) for extra in extras)
    proposals_invalid = sum(int(extra.get("proposals_invalid", 0) or 0) for extra in extras)
    emails_with_invalid = sum(
        1
        for extra, report in zip(extras, reports)
        if int(extra.get("proposals_invalid", 0) or 0) > 0
        or any(code in _IOC_DELIVERED_CODES for code in _critical_issue_codes(report))
    )
    delivered_violations = sum(
        sum(count for code, count in _critical_issue_codes(report).items() if code in _IOC_DELIVERED_CODES)
        for report in reports
    )
    ioc_block = {
        "proposals_total": proposals_total,
        "proposals_invalid": proposals_invalid,
        "fabricated_rate_before_verifier": _ratio(proposals_invalid, proposals_total),
        "emails_with_invalid_proposal_or_delivered_violation": emails_with_invalid,
        "delivered_violations_after_verifier": delivered_violations,
        "note": (
            "proposals are counted BEFORE verifier filtering (archived FINAL "
            "validation rejects); delivered violations are counted AFTER the "
            "deterministic verifier; 'zero delivered' never means the model "
            "never proposed an IOC"
        ),
    }

    # --- policy coverage (§8.2) ----------------------------------------------------
    policy_counts = {action: 0 for action in ("AUTO", "REVIEW", "ESCALATE")}
    auto_by_true_label = {label: dict.fromkeys(("AUTO", "REVIEW", "ESCALATE"), 0) for label in LABELS}
    for label, action in zip(labels, actions):
        if action in policy_counts:
            policy_counts[action] += 1
        if action == "AUTO" and label in LABELS:
            auto_by_true_label[label]["AUTO"] += 1
        elif label in LABELS and action in ("REVIEW", "ESCALATE"):
            auto_by_true_label[label][action] += 1  # type: ignore[index]
    malicious_auto = sum(auto_by_true_label[label]["AUTO"] for label in MALICIOUS_LABELS)
    legitime_escalate = auto_by_true_label["legitime"]["ESCALATE"]
    benign_auto = sum(auto_by_true_label[label]["AUTO"] for label in BENIGN_LABELS)
    legitime_auto = auto_by_true_label["legitime"]["AUTO"]
    policy_block = {
        "coverage": {
            action: {"count": policy_counts[action], "pct": _ratio(policy_counts[action], len(rows))}
            for action in ("AUTO", "REVIEW", "ESCALATE")
        },
        "auto_by_true_label": auto_by_true_label,
        "malicious_auto_count": malicious_auto,
        "legitime_escalate_count": legitime_escalate,
        "benign_auto": {
            "definition": "true label in {legitime, spam} (non-malicious)",
            "precision": _ratio(benign_auto, policy_counts["AUTO"]),
            "support": policy_counts["AUTO"],
            "legitime_only_precision": _ratio(legitime_auto, policy_counts["AUTO"]),
        },
        "note": (
            "errors and coverage are reported simultaneously: an all-REVIEW "
            "policy can never be mistaken for automation success"
        ),
    }

    # --- external tool coverage -------------------------------------------------------
    coverage_total: dict[str, dict[str, Any]] = {}
    external_evidence_counts = {"OSINT": 0, "SANDBOX": 0}
    samples_with_external = 0
    for report in reports:
        for tool, stats in _tool_coverage(report).items():
            bucket = coverage_total.setdefault(
                tool,
                {"candidates": 0, "statuses": {}, "reasons": {}, "requests_sent": 0, "ok_results": 0},
            )
            bucket["candidates"] += stats["candidates"]
            for status, count in stats["statuses"].items():
                bucket["statuses"][status] = bucket["statuses"].get(status, 0) + count
            for reason, count in stats["reasons"].items():
                bucket["reasons"][reason] = bucket["reasons"].get(reason, 0) + count
            bucket["requests_sent"] += stats["requests_sent"]
            bucket["ok_results"] += stats["ok_results"]
        counts = _evidence_provenance_counts(report)
        external_evidence_counts["OSINT"] += counts["OSINT"]
        external_evidence_counts["SANDBOX"] += counts["SANDBOX"]
        if counts["OSINT"] + counts["SANDBOX"] > 0:
            samples_with_external += 1
    tool_block = {
        "n_samples": len(rows),
        "tools": coverage_total,
        "external_evidence_new": external_evidence_counts,
        "samples_with_new_external_evidence": samples_with_external,
        "note": (
            "unavailable/not_found/skipped statuses are preserved with their "
            "cause; an unavailable provider is never removed from the "
            "coverage denominators and never counted as benign evidence"
        ),
    }

    # --- internal -> final (§8.3, all samples and COMPLEX-only) -------------------
    internal_to_final_all = compare_internal_final(labels, internal, delivered)
    complex_indexes = [i for i, decision in enumerate(gate_decisions) if decision == "complex"]
    internal_to_final_complex = compare_internal_final(
        [labels[i] for i in complex_indexes],
        [internal[i] for i in complex_indexes],
        [delivered[i] for i in complex_indexes],
    )

    metrics: dict[str, Any] = {
        "schema_version": "metrics-1.0",
        "labels": list(LABELS),
        "n_total": overall["n_total"],
        "n_valid_predictions": overall["n_valid_predictions"],
        "n_abstentions": overall["n_abstentions"],
        "delivered": overall,
        "internal_phase": internal_block,
        "internal_to_final": {
            "all": internal_to_final_all,
            "complex_only": internal_to_final_complex,
        },
        "fpr": fpr_block(labels, delivered),
        "fpr_internal_phase": fpr_block(labels, internal),
        "paths": paths,
        "cost": cost_block,
        "latency": latency_block,
        "schema": {
            "first_attempt_valid": {
                phase: {"valid": first_attempt[phase][0], "known": first_attempt[phase][1]}
                for phase in ("internal", "final")
            },
            "valid_after_retry": after_retry,
            "phase_status_error_count": phase_status_errors,
            "retries": retries,
            "refusals": refusals,
        },
        "ioc": ioc_block,
        "policy": policy_block,
        "tool_coverage": tool_block,
        "limitations": _limitations_block(overall["support"]),
    }
    if controls is not None:
        control_values = list(controls) + [None] * (len(rows) - len(controls))
        metrics["abc"] = abc_block(labels, delivered, gate_decisions, reports, control_values)
    return metrics


def _limitations_block(support: Mapping[str, int]) -> list[str]:
    """Truthful, auto-generated metric limitations (never hidden)."""

    limitations = []
    zero_support = [label for label in LABELS if support.get(label, 0) == 0]
    if zero_support:
        limitations.append(
            "zero reference support for class(es): " + ", ".join(zero_support)
            + " — six-class Macro-F1 is non-conclusive and the class metric is "
            "not estimable (nothing fabricated)"
        )
    small = [label for label in LABELS if 0 < support.get(label, 0) < 10]
    if small:
        limitations.append(
            "very small reference support (<10) for class(es): " + ", ".join(small)
            + " — per-class metrics carry wide uncertainty"
        )
    limitations.append(
        "Gold-AI reference labels are AI-adjudicated (human_validated=false), "
        "not human analyst ground truth"
    )
    return limitations


def _path_cost(costs: Sequence[Mapping[str, Any]], n: int) -> dict[str, Any]:
    """Mean/total cost of one path; unknown costs stay explicitly unknown."""

    totals = [float(cost["total_usd"]) for cost in costs if cost.get("total_usd") is not None]
    unknown = sum(1 for cost in costs if cost.get("total_usd") is None)
    statuses = {str(cost.get("status")) for cost in costs}
    return {
        "n": n,
        "mean_usd": (sum(totals) / len(totals) if totals and len(totals) == len(costs) else (sum(totals) / len(totals) if totals else None)),
        "total_usd": sum(totals) if totals else None,
        "status": (
            "unknown" if not totals
            else ("partial" if unknown > 0 or len(statuses) > 1 else next(iter(statuses)))
        ),
        "samples_with_unknown_cost": unknown,
        "note": "unknown cost is never turned into zero",
    }


def _aggregate_cost(costs: Sequence[Mapping[str, Any]], n: int) -> dict[str, Any]:
    totals = [float(cost["total_usd"]) for cost in costs if cost.get("total_usd") is not None]
    provider = [
        float(cost["provider_reported_usd"])
        for cost in costs
        if cost.get("provider_reported_usd") is not None
    ]
    statuses = {str(cost.get("status")) for cost in costs}
    unknown_samples = sum(1 for cost in costs if cost.get("total_usd") is None)
    unknown_calls = sum(int(cost.get("unknown_call_count", 0) or 0) for cost in costs)
    if totals and unknown_samples == 0:
        status = next(iter(statuses)) if len(statuses) == 1 else "partial"
    else:
        status = "partial" if totals else "unknown"
    pricing: dict[str, Any] = {}
    for cost in costs:
        snapshot = cost.get("pricing_snapshot")
        if isinstance(snapshot, Mapping) and not pricing:
            pricing = dict(snapshot)
    return {
        "n_emails": n,
        "total_usd": sum(totals) if totals else None,
        "mean_usd": (sum(totals) / len(totals) if totals and len(totals) == len(costs) else None),
        "status": status,
        "provider_reported_total_usd": (sum(provider) if provider else None),
        "provider_status": "not_exposed" if not provider else "provider_reported",
        "estimated_and_provider_separate": True,
        "samples_with_unknown_cost": unknown_samples,
        "unknown_call_count": unknown_calls,
        "external_license_cost": "excluded from variable inference cost (separate VT/licence budget)",
        "pricing_snapshot": pricing or dict(PRICING_SNAPSHOT),
    }


# ---------------------------------------------------------------------------
# A/B/C FINAL-audit invariants (docs/contracts.md §2.6.1, §8.3)
# ---------------------------------------------------------------------------


def validate_control_audits(
    b_audits: Sequence[Mapping[str, Any]],
    c_audits: Sequence[Mapping[str, Any]],
    bundle_external_evidence: int,
) -> tuple[bool, list[str], bool]:
    """Validate the §2.6.1 A/B/C audit invariants BEFORE any delta.

    B (every emitted attempt): ``external_evidence_count_sent == 0``,
    ``evidence_count_sent == internal_evidence_count_sent``,
    ``rag_case_count_sent == 0``, ``visual_count_sent == 0``.
    C: when the merged bundle contains at least one admissible
    OSINT/SANDBOX evidence, ``external_evidence_count_sent > 0``; when the
    bundle produced none, zero is kept and ``no_new_external_evidence`` is
    recorded (never a fabricated proof). Missing audits make the comparison
    UNPROVABLE (invalid) — a different request SHA alone is not evidence.
    """

    problems: list[str] = []
    no_new_external_evidence = False
    if not b_audits:
        problems.append("B: no archived FINAL input audit found (ablation unprovable)")
    for audit in b_audits:
        attempt = audit.get("attempt", "?")
        if audit.get("external_evidence_count_sent") != 0:
            problems.append(
                f"B attempt {attempt}: external_evidence_count_sent="
                f"{audit.get('external_evidence_count_sent')!r} (must be 0)"
            )
        if audit.get("evidence_count_sent") != audit.get("internal_evidence_count_sent"):
            problems.append(
                f"B attempt {attempt}: evidence_count_sent="
                f"{audit.get('evidence_count_sent')!r} != "
                f"internal_evidence_count_sent="
                f"{audit.get('internal_evidence_count_sent')!r}"
            )
        if audit.get("rag_case_count_sent") != 0:
            problems.append(f"B attempt {attempt}: rag_case_count_sent must be 0")
        if audit.get("visual_count_sent") != 0:
            problems.append(f"B attempt {attempt}: visual_count_sent must be 0")
    if not c_audits:
        problems.append("C: no archived FINAL input audit found (comparison unprovable)")
    c_external_values: list[int] = []
    for audit in c_audits:
        raw = audit.get("external_evidence_count_sent")
        c_external_values.append(
            int(raw) if isinstance(raw, int) and not isinstance(raw, bool) else -1
        )
    if bundle_external_evidence > 0:
        if not c_audits or any(value <= 0 for value in c_external_values):
            problems.append(
                "C: bundle contains "
                f"{bundle_external_evidence} admissible external evidence "
                "entries but external_evidence_count_sent is "
                f"{c_external_values!r} (dropped admissible evidence)"
            )
    else:
        if c_audits and all(value == 0 for value in c_external_values):
            no_new_external_evidence = True
    return (not problems), problems, no_new_external_evidence


# ---------------------------------------------------------------------------
# Paired comparison (§8.3) — used for internal→final and for the A/B/C controls
# ---------------------------------------------------------------------------


def compare_internal_final(
    labels: Sequence[str | None],
    predictions_a: Sequence[str | None],
    predictions_b: Sequence[str | None],
) -> dict[str, Any]:
    """Paired two-prediction comparison on the SAME samples (§8.3).

    Bucket semantics (a technical failure/null prediction counts as "wrong",
    and is additionally counted in the explicit failure counters):

    - ``right_to_right``: both predictions equal the label;
    - ``wrong_to_right``: improvement (A wrong/null → B right);
    - ``right_to_wrong``: degradation (A right → B wrong/null);
    - ``wrong_to_wrong``: no correction (both wrong or null; each null side
      is counted in the failure counters).

    Verdict changes and confidence changes are reported separately. The
    Δmetrics block compares the classification of the two prediction lists
    (ΔMacro-F1 over supported classes, Δrecall per class where both sides
    are estimable). Denominators stay paired: every sample appears in
    exactly one bucket.
    """

    if not (len(labels) == len(predictions_a) == len(predictions_b)):
        raise ValueError("paired comparison length mismatch")
    buckets = {
        "right_to_right": 0,
        "wrong_to_right": 0,
        "right_to_wrong": 0,
        "wrong_to_wrong": 0,
    }
    a_failures = 0
    b_failures = 0
    confidence_pairs: list[tuple[float, float]] = []
    confidence_changed = 0
    labels_aligned: list[str | None] = []
    preds_a_aligned: list[str | None] = []
    preds_b_aligned: list[str | None] = []
    for label, pred_a, pred_b in zip(labels, predictions_a, predictions_b):
        a_right = pred_a == label and pred_a is not None
        b_right = pred_b == label and pred_b is not None
        if pred_a is None:
            a_failures += 1
        if pred_b is None:
            b_failures += 1
        if a_right and b_right:
            buckets["right_to_right"] += 1
        elif not a_right and b_right:
            buckets["wrong_to_right"] += 1
        elif a_right and not b_right:
            buckets["right_to_wrong"] += 1
        else:
            buckets["wrong_to_wrong"] += 1
        labels_aligned.append(label)
        preds_a_aligned.append(pred_a)
        preds_b_aligned.append(pred_b)
    block_a = classification_block(labels_aligned, preds_a_aligned)
    block_b = classification_block(labels_aligned, preds_b_aligned)
    recall_delta: dict[str, Any] = {}
    for label in LABELS:
        recall_a = block_a["per_class"][label]["recall"]
        recall_b = block_b["per_class"][label]["recall"]
        if recall_a is None or recall_b is None:
            recall_delta[label] = {"a": recall_a, "b": recall_b, "delta": None,
                                   "status": "not_estimable"}
        else:
            recall_delta[label] = {
                "a": recall_a,
                "b": recall_b,
                "delta": recall_b - recall_a,
                "status": "estimable",
            }
    macro_a = block_a["macro_f1"]["value"]
    macro_b = block_b["macro_f1"]["value"]
    n_changed = buckets["wrong_to_right"] + buckets["right_to_wrong"]
    return {
        "n_comparable": len(labels),
        "n_changed_verdict": n_changed,
        "buckets": buckets,
        "a_technical_failures": a_failures,
        "b_technical_failures": b_failures,
        "macro_f1_a": macro_a,
        "macro_f1_b": macro_b,
        "delta_macro_f1": (
            macro_b - macro_a if macro_a is not None and macro_b is not None else None
        ),
        "per_class_recall_delta": recall_delta,
        "abstentions_a": block_a["n_abstentions"],
        "abstentions_b": block_b["n_abstentions"],
        "denominators_paired": True,
        "note": (
            "null predictions count as failures and stay in the paired "
            "denominators; they are never removed"
        ),
    }


# --- block_a_value accessor removed: direct dict access is clearer ---------


def paired_variant_block(
    labels: Sequence[str | None],
    baseline_predictions: Sequence[str | None],
    variant_predictions: Sequence[str | None],
    *,
    baseline_variant: str = "baseline",
    variant: str = "rag",
) -> dict[str, Any]:
    """Paired baseline→variant comparison on the SAME archived samples (§8.7).

    Diagnostic smoke scope only: the block never authorizes a performance
    claim (``performance_claims_allowed=false``) and INCONCLUSIVE stays a
    valid outcome. Denominators stay paired: the evaluator verifies the
    exact ``sample_id`` identity of the two archived series BEFORE calling
    this (missing/extra row = FAIL), every sample then appears in exactly
    one bucket, and a null prediction counts as a failure — never removed.
    """

    block = compare_internal_final(labels, baseline_predictions, variant_predictions)
    block["a_role"] = "baseline"
    block["b_role"] = "variant"
    block["baseline_variant"] = baseline_variant
    block["variant"] = variant
    block["diagnostic_only"] = True
    block["performance_claims_allowed"] = False
    block["scope_note"] = (
        "bounded smoke paired ablation (docs/evaluation.md §8.7): diagnostic "
        "only, feeds T19C; the first full benchmark including the variant is "
        "TICKET-19E"
    )
    return block


# ---------------------------------------------------------------------------
# A/B/C block (variant baseline, COMPLEX samples, docs/evaluation.md §8.3)
# ---------------------------------------------------------------------------


def abc_block(
    labels: Sequence[str | None],
    delivered: Sequence[str | None],
    gate_decisions: Sequence[str | None],
    reports: Sequence[Mapping[str, Any]],
    controls: Sequence[Mapping[str, Any] | None],
) -> dict[str, Any]:
    """A/B/C control comparison over the COMPLEX dev samples.

    ``controls[i]`` is the per-sample payload produced by the runner for
    COMPLEX samples (``None`` for SIMPLE samples): shared A (the INTERNAL of
    the nominal run), the B ablation control (XHIGH, internal evidence only,
    TOOL_STATUS explicitly marked as ablation), C (the nominal FINAL with
    the real external bundle), and the FINAL input-audit validation result.
    An invalid audit marks the comparison INVALID — the deltas are still
    reported but explicitly flagged invalid, never silently repaired.
    """

    complex_indexes = [
        i for i, decision in enumerate(gate_decisions) if decision == "complex"
    ]
    audit_problems: list[str] = []
    invalid_samples = 0
    no_new_external = 0
    with_external_bundle = 0
    excluded_technical: list[int] = []
    b_costs: list[float] = []
    b_latencies: list[float] = []
    operational_costs: list[float] = []
    operational_latencies: list[float] = []
    for i in complex_indexes:
        control = controls[i]
        if not isinstance(control, Mapping):
            audit_problems.append(f"sample {rows_sample_id(reports, i)}: missing A/B/C control payload")
            invalid_samples += 1
            continue
        if control.get("excluded_technical"):
            excluded_technical.append(i)
            continue
        audit = control.get("audit")
        if not isinstance(audit, Mapping) or not audit.get("valid", False):
            invalid_samples += 1
            for problem in (audit.get("problems") if isinstance(audit, Mapping) else None) or []:
                audit_problems.append(f"sample {rows_sample_id(reports, i)}: {problem}")
            continue
        if audit.get("no_new_external_evidence"):
            no_new_external += 1
        if int(audit.get("bundle_external_evidence", 0) or 0) > 0:
            with_external_bundle += 1
        b_cost = control.get("b_cost_usd")
        if _finite(b_cost):
            b_costs.append(float(b_cost))  # type: ignore[arg-type]
        b_latency = control.get("b_latency_ms")
        if _finite(b_latency):
            b_latencies.append(float(b_latency))  # type: ignore[arg-type]
        cost = sample_cost(reports[i]).get("total_usd")
        if _finite(cost):
            operational_costs.append(float(cost))  # type: ignore[arg-type]
        timings = reports[i].get("timings")
        if isinstance(timings, Mapping) and _finite(timings.get("total_ms")):
            operational_latencies.append(float(timings["total_ms"]))

    included = [
        i for i in complex_indexes
        if not (isinstance(controls[i], Mapping) and controls[i].get("excluded_technical"))
    ]
    labels_c = [labels[i] for i in included]
    a_predictions = [internal_prediction(reports[i]) for i in included]
    b_predictions = [
        _control_prediction(controls[i], "b") for i in included
    ]
    c_predictions = [delivered[i] for i in included]

    a_to_b = compare_internal_final(labels_c, a_predictions, b_predictions)
    b_to_c = compare_internal_final(labels_c, b_predictions, c_predictions)
    audit_valid = invalid_samples == 0
    return {
        "variant": "baseline",
        "complex_n": len(complex_indexes),
        "comparable_n": len(included),
        "excluded_technical_n": len(excluded_technical),
        "audit": {
            "valid": audit_valid,
            "invalid_samples": invalid_samples,
            "problems": audit_problems,
            "samples_with_external_evidence_bundle": with_external_bundle,
            "samples_no_new_external_evidence": no_new_external,
            "note": (
                "B must show external_evidence_count_sent=0, "
                "evidence_count_sent=internal_evidence_count_sent, "
                "rag_case_count_sent=0, visual_count_sent=0; C must transmit "
                "the admissible OSINT/SANDBOX evidence when the bundle "
                "produced one, otherwise keep zero with "
                "no_new_external_evidence; a different request SHA alone "
                "never proves the ablation"
            ),
        },
        "A_to_B": a_to_b,
        "B_to_C": b_to_c,
        "confidence_changes": _abc_confidence_changes(
            controls, included, a_predictions, b_predictions, c_predictions, labels_c
        ),
        "cost_delta": {
            "operational_mean_usd": (
                sum(operational_costs) / len(operational_costs) if operational_costs else None
            ),
            "control_b_mean_usd": (sum(b_costs) / len(b_costs) if b_costs else None),
            "experiment_total_mean_usd": (
                sum(operational_costs) / len(operational_costs)
                + sum(b_costs) / len(b_costs)
                if operational_costs and b_costs
                else None
            ),
            "note": (
                "B cost/time is the extra control experiment; the nominal "
                "operational path cost is A (SIMPLE) or A+tools+C (COMPLEX); "
                "all attempts stay in the total experiment budget and every "
                "unknown cost is explicitly unknown, never zero"
            ),
        },
        "latency_delta": {
            "operational_mean_ms": (
                sum(operational_latencies) / len(operational_latencies)
                if operational_latencies
                else None
            ),
            "control_b_mean_ms": (sum(b_latencies) / len(b_latencies) if b_latencies else None),
            "note": (
                "operational = the nominal COMPLEX path (A + tools + C); the "
                "B control call time is separated from it and both are "
                "archived"
            ),
        },
        "interpretation": (
            "B−A estimates the effect of the second (xhigh) reasoning pass; "
            "C−B estimates the effect of the actually collected external "
            "bundle; comparing only A and C never proves the value of "
            "external tools; individual VT/OpenCTI/urlscan attribution "
            "requires a separately pre-registered ablation (G7-D, optional)"
        ),
    }


def rows_sample_id(reports: Sequence[Mapping[str, Any]], index: int) -> Any:
    """Best-effort sample identification for audit problem messages."""

    run_id = reports[index].get("run_id") if isinstance(reports[index], Mapping) else None
    return run_id if run_id is not None else f"#{index}"


def _control_prediction(control: Mapping[str, Any] | None, which: str) -> str | None:
    if not isinstance(control, Mapping):
        return None
    verdict = (control.get(which) or {}).get("verdict") if isinstance(control.get(which), Mapping) else None
    return verdict if isinstance(verdict, str) and verdict in LABELS else None


def _stats_for(values: Sequence[float]) -> dict[str, Any]:
    """Mean/max/min of a delta list; empty lists stay explicitly empty."""

    if not values:
        return {"n": 0, "mean_delta": None, "max_increase": None, "max_decrease": None}
    return {
        "n": len(values),
        "mean_delta": sum(values) / len(values),
        "max_increase": max(values),
        "max_decrease": min(values),
    }


def _abc_confidence_changes(
    controls: Sequence[Mapping[str, Any] | None],
    complex_indexes: Sequence[int],
    a_predictions: Sequence[str | None],
    b_predictions: Sequence[str | None],
    c_predictions: Sequence[str | None],
    labels_c: Sequence[str | None],
) -> dict[str, Any]:
    """Confidence changes reported separately from verdict changes (§8.3)."""

    deltas_ab: list[float] = []
    deltas_bc: list[float] = []
    same_verdict_confidence_changed_ab = 0
    for position, i in enumerate(complex_indexes):
        control = controls[i]
        if not isinstance(control, Mapping):
            continue
        a_conf = ((control.get("a") or {}).get("confidence") if isinstance(control.get("a"), Mapping) else None)
        b_conf = ((control.get("b") or {}).get("confidence") if isinstance(control.get("b"), Mapping) else None)
        c_conf = ((control.get("c") or {}).get("confidence") if isinstance(control.get("c"), Mapping) else None)
        if _finite(a_conf) and _finite(b_conf):
            delta_ab = float(b_conf) - float(a_conf)  # type: ignore[arg-type]
            deltas_ab.append(delta_ab)
            if (
                a_predictions[position] == b_predictions[position]
                and a_predictions[position] is not None
                and abs(delta_ab) > 1e-12
            ):
                same_verdict_confidence_changed_ab += 1
        if _finite(b_conf) and _finite(c_conf):
            deltas_bc.append(float(c_conf) - float(b_conf))  # type: ignore[arg-type]

    return {
        "A_to_B": _stats_for(deltas_ab),
        "B_to_C": _stats_for(deltas_bc),
        "same_verdict_confidence_changed_A_to_B": same_verdict_confidence_changed_ab,
        "note": "confidence changes are reported separately from verdict changes",
    }


__all__ = [
    "BENIGN_LABELS",
    "LABELS",
    "MALICIOUS_LABELS",
    "PRICING_SNAPSHOT",
    "abc_block",
    "align_rows_reports",
    "classification_block",
    "compare_internal_final",
    "delivered_prediction",
    "estimate_cost_usd",
    "evaluate",
    "fpr_block",
    "internal_prediction",
    "latency_stats",
    "paired_variant_block",
    "sample_cost",
    "validate_control_audits",
]

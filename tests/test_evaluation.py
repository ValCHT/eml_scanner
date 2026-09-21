"""TICKET-14 evaluation workflow tests (offline, deterministic).

These tests verify the CONTRACT of the dev baseline workflow — gold input
validation, gold_test refusal, A/B/C audit invalidation through the row
plumbing, frozen-input lock drift, and exact offline recompute — using
synthetic small artifacts labeled as test fixtures. No provider response is
simulated and no benchmark result is claimed: the network is refused for
the whole module (autouse fixture).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.g6

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
PROJECT_ROOT = SCRIPTS_DIR.parent


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The evaluation contract tests never touch the network."""

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in an evaluation workflow test")

    import socket

    monkeypatch.setattr(socket, "socket", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)


def _load_evaluate_module():
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("evaluate_script", SCRIPTS_DIR / "evaluate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register before exec: pydantic resolves forward annotations through
    # sys.modules[module.__name__] when rebuilding strict models.
    sys.modules["evaluate_script"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def evaluate_script():
    return _load_evaluate_module()


def _load_check_gate_module():
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("check_gate_script", SCRIPTS_DIR / "check_gate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["check_gate_script"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# gold_test is NEVER opened by the TICKET-14 dev workflow
# ---------------------------------------------------------------------------


def test_gold_test_split_refused(evaluate_script):
    config = evaluate_script.load_evaluation_config(PROJECT_ROOT / "configs" / "evaluation.yaml")
    with pytest.raises(evaluate_script.GoldTestAccessRefused):
        evaluate_script.gold_path_for_split(config, "test")
    # The refusal happens BEFORE any file access: the returned path for dev
    # is the dev partition only.
    path = evaluate_script.gold_path_for_split(config, "dev")
    assert path.name == "gold_dev.jsonl"
    assert path.name != "gold_test.jsonl"


def test_dev_loader_never_touches_gold_test_bytes(evaluate_script, monkeypatch):
    """Track every file the dev loading/validation reads; gold_test never appears.

    Path.open / read_bytes / read_text are wrapped (still calling the
    originals) so any attempted access to gold_test.jsonl would be recorded.
    """

    touched: list[str] = []

    original_open = Path.open
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def _record(original, self_path: Path, *args: object, **kwargs: object):
        touched.append(str(self_path))
        return original(self_path, *args, **kwargs)

    monkeypatch.setattr(
        Path, "open", lambda self, *a, **k: _record(original_open, self, *a, **k)
    )
    monkeypatch.setattr(
        Path, "read_bytes", lambda self, *a, **k: _record(original_read_bytes, self, *a, **k)
    )
    monkeypatch.setattr(
        Path, "read_text", lambda self, *a, **k: _record(original_read_text, self, *a, **k)
    )

    config = evaluate_script.load_evaluation_config(PROJECT_ROOT / "configs" / "evaluation.yaml")
    rows, path = evaluate_script.load_gold_records(config, "dev")
    evaluate_script.validate_gold_raw_files(rows)

    assert any(str(candidate).endswith("gold_dev.jsonl") for candidate in touched)
    assert not any("gold_test" in str(candidate) for candidate in touched)


def test_split_test_cli_refused(evaluate_script, tmp_path):
    args = evaluate_script.build_parser().parse_args(
        ["--split", "test", "--mode", "live", "--variant", "baseline",
         "--out", str(tmp_path / "out")]
    )
    config = evaluate_script.load_evaluation_config(PROJECT_ROOT / "configs" / "evaluation.yaml")
    result = evaluate_script.run_live(args, config, {})
    assert result == evaluate_script.EXIT_BLOCKED


# ---------------------------------------------------------------------------
# Gold validation: forbidden content / missing raw / hash mismatch
# ---------------------------------------------------------------------------


def _write_gold(tmp_root: Path, rows: list[dict]) -> Path:
    gold = tmp_root / "corpus" / "gold" / "gold_dev.jsonl"
    gold.parent.mkdir(parents=True, exist_ok=True)
    gold.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return gold


def _valid_row(sha: str, raw_path: str = "corpus/raw/x/m.eml") -> dict:
    return {
        "sample_id": "sample_ok",
        "raw_sha256": sha,
        "email_sha256": sha,
        "raw_path": raw_path,
        "source_dataset": "unit_test",
        "input_format": "rfc822",
        "normalized_label": "phishing",
        "label_status": "confirmed",
        "reviewer_ref": "astra_gold_ai_v1",
        "label_rationale": "unit test row",
        "public_source": True,
        "is_synthetic": None,
        "campaign_id": None,
        "duplicate_group": "g",
        "family_group": "g",
        "tags": ["unit_test"],
        "split": "dev",
    }


def _patched_config(evaluate_script, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = evaluate_script.EvaluationConfig(
        version=1,
        label_order=list(evaluate_script.LABELS),
        split_files={"dev": "corpus/gold/gold_dev.jsonl"},
        split_policy={},
        source_profile_mapping={"public_source_true": "public_corpus",
                                "public_source_false": "private_authorized"},
        pricing_snapshot=evaluate_script.PRICING_SNAPSHOT,
        latency={},
        abc={"variant": "baseline"},
        published_limitations=[],
    )
    return config


def test_gold_with_forbidden_content_rejected(evaluate_script, monkeypatch, tmp_path):
    """A forbidden content key (even deeply nested) makes the loader fail."""

    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = _make_cfg(evaluate_script, tmp_path)
    row = _valid_row("a" * 64)
    row["body"] = {"hidden": "embedded content"}  # forbidden key, non-empty
    _write_gold(tmp_path, [row])
    with pytest.raises(evaluate_script.build_corpus.GoldValidationError):
        evaluate_script.load_gold_records(config, "dev")


def test_gold_with_null_forbidden_content_key_rejected(evaluate_script, monkeypatch, tmp_path):
    """The forbidden key is refused even when its value is null/empty."""

    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = _make_cfg(evaluate_script, tmp_path)
    row = _valid_row("a" * 64)
    row["raw_email"] = None
    _write_gold(tmp_path, [row])
    with pytest.raises(evaluate_script.build_corpus.GoldValidationError):
        evaluate_script.load_gold_records(config, "dev")


def test_raw_file_absent_rejected_before_provider_call(evaluate_script, monkeypatch, tmp_path):
    """A missing raw file fails the pre-call validation (loud, no call)."""

    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = _make_cfg(evaluate_script, tmp_path)
    _write_gold(tmp_path, [_valid_row("a" * 64)])  # no corpus/raw/x/m.eml written
    rows, _path = evaluate_script.load_gold_records(config, "dev")

    def _fail_pipeline(*args: object, **kwargs: object) -> None:
        pytest.fail("the pipeline must never run when raw validation fails")

    monkeypatch.setattr(evaluate_script, "run_nominal_pipeline", _fail_pipeline)
    failures = evaluate_script.validate_gold_raw_files(rows)[1]
    assert failures, "missing raw file must be a loud validation failure"


def test_raw_hash_mismatch_rejected_before_provider_call(evaluate_script, monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = _make_cfg(evaluate_script, tmp_path)
    raw = tmp_path / "corpus" / "raw" / "x" / "m.eml"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_bytes(b"From: a@example.com\r\n\r\nhello\r\n")
    actual_sha = hashlib.sha256(raw.read_bytes()).hexdigest()
    wrong_sha = "b" * 64
    assert actual_sha != wrong_sha
    _write_gold(tmp_path, [_valid_row(wrong_sha)])
    rows, _path = evaluate_script.load_gold_records(config, "dev")

    def _fail_pipeline(*args: object, **kwargs: object) -> None:
        pytest.fail("the pipeline must never run when raw_sha256 mismatches")

    monkeypatch.setattr(evaluate_script, "run_nominal_pipeline", _fail_pipeline)
    failures = evaluate_script.validate_gold_raw_files(rows)[1]
    assert any("raw_sha256 mismatch" in failure for failure in failures)


def test_raw_path_escaping_corpus_raw_rejected(evaluate_script, monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = _make_cfg(evaluate_script, tmp_path)
    row = _valid_row("a" * 64, raw_path="corpus/raw/../outside/m.eml")
    _write_gold(tmp_path, [row])
    rows, _path = evaluate_script.load_gold_records(config, "dev")
    failures = evaluate_script.validate_gold_raw_files(rows)[1]
    assert any("escapes" in failure for failure in failures)


def test_valid_gold_passes_full_validation(evaluate_script, monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    config = _make_cfg(evaluate_script, tmp_path)
    raw = tmp_path / "corpus" / "raw" / "x" / "m.eml"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_bytes(b"From: a@example.com\r\nSubject: ok\r\n\r\nbody\r\n")
    sha = hashlib.sha256(raw.read_bytes()).hexdigest()
    _write_gold(tmp_path, [_valid_row(sha)])
    rows, _path = evaluate_script.load_gold_records(config, "dev")
    verified, failures = evaluate_script.validate_gold_raw_files(rows)
    assert not failures
    assert verified["sample_ok"] == raw.read_bytes()


def _make_cfg(evaluate_script, tmp_path: Path):
    from src.metrics import PRICING_SNAPSHOT

    return evaluate_script.EvaluationConfig(
        version=1,
        label_order=list(evaluate_script.LABELS),
        split_files={"dev": "corpus/gold/gold_dev.jsonl"},
        split_policy={},
        source_profile_mapping={
            "public_source_true": "public_corpus",
            "public_source_false": "private_authorized",
        },
        pricing_snapshot=PRICING_SNAPSHOT,
        latency={},
        abc={"variant": "baseline"},
        published_limitations=[],
    )


# ---------------------------------------------------------------------------
# A/B/C audit invalidation through the ROW plumbing
# ---------------------------------------------------------------------------


def _control_row(
    sample_id: str,
    sha: str,
    *,
    b_audits: list[dict],
    c_audits: list[dict],
    bundle_external: int = 0,
    gate: str = "complex",
    parse_ok: bool = True,
) -> dict:
    """Synthetic archived row shaped exactly like the live runner output."""

    b_payload = {
        "attempted": parse_ok,
        "reason_not_attempted": None if parse_ok else "parsed_none_nominal_parse_failed",
        "verdict": "phishing" if parse_ok else None,
        "confidence": 0.9 if parse_ok else None,
        "probabilities": None,
        "call": {"phase": "final", "status": "ok", "attempts": 1,
                 "input_tokens": 10, "cached_input_tokens": 0, "output_tokens": 5,
                 "reasoning_tokens": 2, "cost_usd": None, "cost_status": "unknown"},
        "latency_ms": 1200.0 if parse_ok else None,
        "capture_dir": "responses_control_b",
        "cost_usd": 0.0001 if parse_ok else None,
        "cost_status": "estimated" if parse_ok else "unknown",
    }
    return {
        "sample_id": sample_id,
        "split": "dev",
        "variant": "baseline",
        "source_dataset": "unit_test",
        "family_group": sample_id,
        "raw_path": "corpus/raw/x/m.eml",
        "raw_sha256": sha,
        "input_format": "rfc822",
        "public_source": True,
        "label": "phishing",
        "run_id": "run_" + sample_id,
        "report_dir": "runs/synthetic/" + sample_id,
        "report_path": "runs/synthetic/" + sample_id + "/report.json",
        "report_sha256": "0" * 64,
        "started_at": "2026-09-20T00:00:00Z",
        "runtime_config_sha256": "1" * 64,
        "gate_decision": gate,
        "gate_reasons": [],
        "final_source": "final_llm" if parse_ok else "none",
        "run_status": "ok" if parse_ok else "error",
        "predicted": "phishing" if parse_ok else None,
        "predicted_valid": bool(parse_ok),
        "final_confidence": 0.95 if parse_ok else None,
        "final_probabilities": None,
        "internal_verdict": "phishing",
        "internal_confidence": 0.9,
        "verdict_changed": False,
        "recommended_action": "REVIEW",
        "policy_reasons": [],
        "timings": {"total_ms": 1000.0, "internal_llm_ms": 300.0, "final_llm_ms": 500.0},
        "llm_calls": [
            {"phase": "internal", "status": "ok", "attempts": 1,
             "first_attempt_schema_valid": True, "input_tokens": 10,
             "cached_input_tokens": 0, "output_tokens": 5, "reasoning_tokens": 2,
             "cost_usd": None, "cost_status": "unknown"},
            {"phase": "final", "status": "ok", "attempts": 1,
             "first_attempt_schema_valid": True, "input_tokens": 20,
             "cached_input_tokens": 0, "output_tokens": 8, "reasoning_tokens": 3,
             "cost_usd": None, "cost_status": "unknown"},
        ],
        "control_b": b_payload,
        "internal_assessment_sha256": "2" * 64,
        "untrusted_email_sha256_b": "3" * 64,
        "untrusted_email_sha256_c": "3" * 64,
        "tool_status_digest_b": "4" * 64,
        "tool_status_digest_c": "5" * 64,
        "evidence_provenance_counts": {"INTERNE": 4, "OSINT": bundle_external, "SANDBOX": 0},
        "bundle_external_evidence": bundle_external,
        "extras": {"rejected_final_candidates": 0, "proposals_total": 0,
                   "proposals_invalid": 0, "refusals": 0},
        "abc_audit": {
            "applicable": gate == "complex",
            "valid": False,
            "problems": [],
            "no_new_external_evidence": False,
            "b_attempt_audits": b_audits,
            "c_attempt_audits": c_audits,
        },
        "notes": [] if parse_ok else ["parse_failed_technical_failure_stays_in_denominator"],
    }


def _b_audit(**overrides: object) -> dict:
    audit = {
        "phase": "final", "external_evidence_count_sent": 0,
        "internal_evidence_count_sent": 4, "evidence_count_sent": 4,
        "rag_case_count_sent": 0, "visual_count_sent": 0,
        "tool_status_digest": "d" * 64,
    }
    audit.update(overrides)
    return audit


def _c_audit(**overrides: object) -> dict:
    audit = {
        "phase": "final", "external_evidence_count_sent": 0,
        "internal_evidence_count_sent": 4, "evidence_count_sent": 4,
        "rag_case_count_sent": 0, "visual_count_sent": 0,
        "tool_status_digest": "e" * 64,
    }
    audit.update(overrides)
    return audit


def _finish_abc_audit(row: dict) -> dict:
    """Recompute the row audit exactly like the runner (post-hoc validation)."""

    from src.metrics import validate_control_audits

    valid, problems, no_new = validate_control_audits(
        row["abc_audit"]["b_attempt_audits"],
        row["abc_audit"]["c_attempt_audits"],
        row["bundle_external_evidence"],
    )
    row["abc_audit"]["valid"] = valid
    row["abc_audit"]["problems"] = problems
    row["abc_audit"]["no_new_external_evidence"] = no_new
    return row


def test_abc_row_with_external_evidence_in_b_invalidates(evaluate_script):
    from src.metrics import abc_block

    row = _finish_abc_audit(_control_row(
        "s1", "a" * 64,
        b_audits=[_b_audit(external_evidence_count_sent=2)],
        c_audits=[_c_audit(external_evidence_count_sent=2)],
        bundle_external=2,
    ))
    assert not row["abc_audit"]["valid"]
    controls = evaluate_script.controls_from_rows([row])
    report = {
        "sample_id": "s1", "email_sha256": row["raw_sha256"], "gate_decision": "complex",
        "internal_verdict": "phishing", "final_verdict": "phishing", "final_source": "final_llm",
        "run_status": "ok", "recommended_action": "REVIEW", "llm_calls": [],
        "timings": {"total_ms": 1000.0}, "evidence": [], "unsupported_claims": [],
    }
    abc = abc_block(["phishing"], ["phishing"], ["complex"], [report], controls)
    assert abc["audit"]["valid"] is False
    assert abc["audit"]["problems"], "B containing external evidence must invalidate"


def test_abc_row_c_dropping_admissible_evidence_invalidates(evaluate_script):
    from src.metrics import abc_block

    row = _finish_abc_audit(_control_row(
        "s1", "a" * 64,
        b_audits=[_b_audit()],
        c_audits=[_c_audit(external_evidence_count_sent=0)],
        bundle_external=4,  # the bundle produced external evidence...
    ))
    assert not row["abc_audit"]["valid"]
    controls = evaluate_script.controls_from_rows([row])
    report = {
        "sample_id": "s1", "email_sha256": row["raw_sha256"], "gate_decision": "complex",
        "internal_verdict": "phishing", "final_verdict": "phishing", "final_source": "final_llm",
        "run_status": "ok", "recommended_action": "REVIEW", "llm_calls": [],
        "timings": {"total_ms": 1000.0}, "evidence": [], "unsupported_claims": [],
    }
    abc = abc_block(["phishing"], ["phishing"], ["complex"], [report], controls)
    assert abc["audit"]["valid"] is False
    assert any("dropped admissible evidence" in problem for problem in abc["audit"]["problems"])


def test_abc_row_valid_without_external_bundle(evaluate_script):
    from src.metrics import abc_block

    row = _finish_abc_audit(_control_row(
        "s1", "a" * 64,
        b_audits=[_b_audit()],
        c_audits=[_c_audit(external_evidence_count_sent=0)],
        bundle_external=0,
    ))
    assert row["abc_audit"]["valid"]
    assert row["abc_audit"]["no_new_external_evidence"] is True
    controls = evaluate_script.controls_from_rows([row])
    report = {
        "sample_id": "s1", "email_sha256": row["raw_sha256"], "gate_decision": "complex",
        "internal_verdict": "phishing", "final_verdict": "phishing", "final_source": "final_llm",
        "run_status": "ok", "recommended_action": "REVIEW", "llm_calls": [],
        "timings": {"total_ms": 1000.0}, "evidence": [], "unsupported_claims": [],
    }
    abc = abc_block(["phishing"], ["phishing"], ["complex"], [report], controls)
    assert abc["audit"]["valid"] is True
    assert abc["audit"]["samples_no_new_external_evidence"] == 1
    assert abc["comparable_n"] == 1


def test_abc_row_parse_failure_excluded_technical(evaluate_script):
    from src.metrics import abc_block

    row = _control_row(
        "s1", "a" * 64,
        b_audits=[], c_audits=[], gate="complex", parse_ok=False,
    )
    row["notes"] = ["parse_failed_technical_failure_stays_in_denominator"]
    controls = evaluate_script.controls_from_rows([row])
    report = {
        "sample_id": "s1", "email_sha256": row["raw_sha256"], "gate_decision": "complex",
        "internal_verdict": None, "final_verdict": None, "final_source": "none",
        "run_status": "error", "recommended_action": "REVIEW", "llm_calls": [],
        "timings": {"total_ms": 1000.0}, "evidence": [], "unsupported_claims": [],
    }
    abc = abc_block(["phishing"], [None], ["complex"], [report], controls)
    assert abc["audit"]["valid"] is True  # technical exclusion, not an audit failure
    assert abc["excluded_technical_n"] == 1
    assert abc["comparable_n"] == 0


# ---------------------------------------------------------------------------
# Experiment lock
# ---------------------------------------------------------------------------


def test_lock_hash_drift_fails(evaluate_script):
    lock = evaluate_script.load_experiment_lock(PROJECT_ROOT / "configs" / "experiment_lock.json")
    assert evaluate_script.verify_experiment_lock(lock) == []
    tampered = json.loads(json.dumps(lock))
    tampered["hashes"]["config_gate"] = "0" * 64
    problems = evaluate_script.verify_experiment_lock(tampered)
    assert any("config_gate" in problem for problem in problems)


def test_lock_model_drift_detected(evaluate_script):
    lock = evaluate_script.load_experiment_lock(PROJECT_ROOT / "configs" / "experiment_lock.json")
    tampered = dict(lock)
    tampered["runtime"] = {**lock["runtime"], "model": "Other/Model"}
    problems = evaluate_script.verify_experiment_lock(tampered)
    assert any("model" in problem for problem in problems)


def test_evaluation_config_strict(evaluate_script, tmp_path):
    config_text = (PROJECT_ROOT / "configs" / "evaluation.yaml").read_text(encoding="utf-8")
    bad = tmp_path / "evaluation.yaml"
    bad.write_text(config_text + "\nunknown_key: true\n", encoding="utf-8")
    with pytest.raises(Exception):
        evaluate_script.load_evaluation_config(bad)
    good = tmp_path / "evaluation_ok.yaml"
    good.write_text(config_text, encoding="utf-8")
    config = evaluate_script.load_evaluation_config(good)
    assert tuple(config.label_order) == evaluate_script.LABELS


# ---------------------------------------------------------------------------
# Recompute mode: exact equality with the captured (archived) results
# ---------------------------------------------------------------------------


def _synthetic_report(sample_id: str, sha: str, *, gate: str, final_verdict: str | None,
                      internal_verdict: str | None, action: str) -> dict:
    llm_calls = [
        {"phase": "internal", "status": "ok" if internal_verdict else "error", "attempts": 1,
         "requested_model": "Qwen/Qwen3.8-27B", "returned_model": "Qwen/Qwen3.8-27B",
         "reasoning_effort": "medium", "first_attempt_schema_valid": bool(internal_verdict),
         "input_tokens": 1500, "cached_input_tokens": 100, "output_tokens": 400,
         "reasoning_tokens": 150, "cost_usd": None, "cost_status": "unknown",
         "response_refs": [], "request_sha256": "r" * 64},
    ]
    if gate == "complex":
        llm_calls.append(
            {"phase": "final", "status": "ok" if final_verdict else "error", "attempts": 1,
             "requested_model": "Qwen/Qwen3.8-27B", "returned_model": "Qwen/Qwen3.8-27B",
             "reasoning_effort": "xhigh", "first_attempt_schema_valid": bool(final_verdict),
             "input_tokens": 2500, "cached_input_tokens": 0, "output_tokens": 600,
             "reasoning_tokens": 200, "cost_usd": None, "cost_status": "unknown",
             "response_refs": [], "request_sha256": "f" * 64},
        )
    timings = {
        "parse_ms": 2.0, "internal_llm_ms": 1000.0, "gate_ms": 1.0,
        "vt_ms": 1.0, "opencti_ms": 1.0, "urlscan_ms": 1.0, "rag_ms": 0.0,
        "merge_ms": 1.0, "final_llm_ms": 2000.0 if gate == "complex" else 0.0,
        "verify_ms": 2.0, "policy_ms": 1.0, "report_ms": 1.0, "total_ms": 3010.0,
    }
    return {
        "schema_version": "1.0",
        "run_id": "run_" + sample_id,
        "email_sha256": sha,
        "run_status": "ok" if final_verdict else "error",
        "internal_verdict": internal_verdict,
        "internal_confidence": 0.91 if internal_verdict else None,
        "internal_probabilities": None,
        "gate_decision": gate,
        "gate_reasons": [],
        "enrichment": {
            "virustotal": [
                {"tool": "virustotal", "query_observable_id": None, "status": "unavailable",
                 "reason": "access_not_authorized", "evidence": [], "observables": [],
                 "response_sha256": None, "response_ref": None, "collected_at": None,
                 "mode": "live", "elapsed_ms": 1.0, "requests_sent": 0,
                 "visibility": None, "scan_id": None}
            ],
            "opencti": [
                {"tool": "opencti", "query_observable_id": None, "status": "skipped",
                 "reason": "service_not_approved_in_egress", "evidence": [], "observables": [],
                 "response_sha256": None, "response_ref": None, "collected_at": None,
                 "mode": "none", "elapsed_ms": 1.0, "requests_sent": 0,
                 "visibility": None, "scan_id": None}
            ],
            "urlscan": [],
            "rag": [],
        },
        "visual_evidence": [],
        "final_verdict": final_verdict,
        "final_confidence": 0.97 if final_verdict else None,
        "final_probabilities": None,
        "final_source": "final_llm" if (gate == "complex" and final_verdict)
        else ("internal_copy" if gate == "simple" and final_verdict else "none"),
        "verdict_changed": None,
        "decisive_evidence": [],
        "decisive_evidence_ids": [],
        "evidence": [{"id": "ev_1", "provenance": "INTERNE", "source_kind": "parser",
                      "observable_id": None, "predicate": "header_value",
                      "value": "unit", "source_ref": "header:0", "observed_at": None,
                      "match_level": "NONE", "source_group": ""}],
        "observables": [],
        "inferences": [],
        "unsupported_claims": [],
        "verification_warnings": [],
        "recommended_action": action,
        "policy_reasons": [],
        "analyst_summary": "Verdict indéterminé. (unit synthetic)",
        "timings": timings,
        "llm_calls": llm_calls,
        "cost_usd": None,
        "cost_status": "unknown",
        "reproducibility": {
            "code_commit": None, "python_version": "3.11.10",
            "dependencies_sha256": "d" * 64, "prompt_internal_sha256": "p" * 64,
            "prompt_final_sha256": "q" * 64, "assessment_schema_sha256": "s" * 64,
            "config_sha256": "c" * 64, "corpus_split_sha256": None,
            "mode": "live", "started_at": "2026-09-20T00:00:00Z",
        },
    }


def _gold_row(sample_id: str, sha: str, label: str) -> dict:
    return {
        "sample_id": sample_id,
        "raw_sha256": sha,
        "email_sha256": sha,
        "raw_path": "corpus/raw/unit/" + sample_id + ".eml",
        "source_dataset": "unit_test",
        "input_format": "rfc822",
        "normalized_label": label,
        "label_status": "confirmed",
        "reviewer_ref": "astra_gold_ai_v1",
        "label_rationale": "synthetic unit row",
        "public_source": True,
        "is_synthetic": None,
        "campaign_id": None,
        "duplicate_group": sample_id,
        "family_group": sample_id,
        "tags": ["unit_test"],
        "split": "dev",
    }


def _write_synthetic_run(
    evaluate_script, root: Path
) -> tuple[Path, dict]:
    """Archive a small synthetic run (predictions + reports + metrics).

    Clearly a TEST FIXTURE: synthetic rows/reports used to verify the
    recompute machinery, never presented as a benchmark measurement. The
    matching synthetic gold partition is written under ``root.parent`` so a
    patched ``evaluate_script.PROJECT_ROOT`` resolves it.
    """

    from src.metrics import evaluate as evaluate_metrics

    gold = [
        _gold_row("u1", "a" * 64, "phishing"),
        _gold_row("u2", "b" * 64, "legitime"),
        _gold_row("u3", "c" * 64, "spam"),
    ]
    _write_gold(root.parent, gold)
    specs = [
        ("u1", "complex", "phishing", "phishing", "AUTO"),
        ("u2", "simple", "legitime", "legitime", "AUTO"),
        ("u3", "complex", "legitime", "spam", "AUTO"),
    ]
    rows: list[dict] = []
    reports: list[dict] = []
    for sample_id, gate, internal_v, final_v, action in specs:
        sha = next(row["raw_sha256"] for row in gold if row["sample_id"] == sample_id)
        report = _synthetic_report(sample_id, sha, gate=gate, final_verdict=final_v,
                                   internal_verdict=internal_v, action=action)
        report_dir = root / ("run_" + sample_id)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_bytes = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
        (report_dir / "report.json").write_bytes(report_bytes)
        row = {
            "sample_id": sample_id,
            "split": "dev",
            "variant": "baseline",
            "source_dataset": "unit_test",
            "family_group": sample_id,
            "raw_path": "corpus/raw/unit/" + sample_id + ".eml",
            "raw_sha256": sha,
            "input_format": "rfc822",
            "public_source": True,
            "label": next(row["normalized_label"] for row in gold if row["sample_id"] == sample_id),
            "run_id": report["run_id"],
            "report_dir": str(report_dir.relative_to(root)),
            "report_path": str((report_dir / "report.json").relative_to(root)),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "started_at": report["reproducibility"]["started_at"],
            "runtime_config_sha256": "c" * 64,
            "gate_decision": gate,
            "gate_reasons": [],
            "final_source": report["final_source"],
            "run_status": report["run_status"],
            "predicted": final_v,
            "predicted_valid": final_v is not None,
            "final_confidence": report["final_confidence"],
            "final_probabilities": None,
            "internal_verdict": internal_v,
            "internal_confidence": report["internal_confidence"],
            "verdict_changed": None,
            "recommended_action": action,
            "policy_reasons": [],
            "timings": report["timings"],
            "llm_calls": report["llm_calls"],
            "control_b": {
                "attempted": True, "reason_not_attempted": None,
                "verdict": "phishing" if sample_id == "u1" else None,
                "confidence": 0.9 if sample_id == "u1" else None,
                "probabilities": None,
                "call": {"phase": "final", "status": "ok", "attempts": 1,
                         "input_tokens": 2200, "cached_input_tokens": 0,
                         "output_tokens": 500, "reasoning_tokens": 180,
                         "cost_usd": None, "cost_status": "unknown"},
                "latency_ms": 1500.0 if sample_id == "u1" else None,
                "capture_dir": "responses_control_b",
                "cost_usd": 0.0002 if sample_id == "u1" else None,
                "cost_status": "estimated" if sample_id == "u1" else "unknown",
            },
            "internal_assessment_sha256": "i" * 64,
            "untrusted_email_sha256_b": "m" * 64,
            "untrusted_email_sha256_c": "m" * 64,
            "tool_status_digest_b": "t" * 64,
            "tool_status_digest_c": "s" * 64,
            "evidence_provenance_counts": {"INTERNE": 1, "OSINT": 0, "SANDBOX": 0},
            "bundle_external_evidence": 0,
            "extras": {"rejected_final_candidates": 0, "proposals_total": 6,
                       "proposals_invalid": 0, "refusals": 0},
            "abc_audit": {
                "applicable": gate == "complex",
                "valid": True,
                "problems": [],
                "no_new_external_evidence": True,
                "b_attempt_audits": [{
                    "phase": "final", "external_evidence_count_sent": 0,
                    "internal_evidence_count_sent": 1, "evidence_count_sent": 1,
                    "rag_case_count_sent": 0, "visual_count_sent": 0,
                    "tool_status_digest": "t" * 64,
                }],
                "c_attempt_audits": [{
                    "phase": "final", "external_evidence_count_sent": 0,
                    "internal_evidence_count_sent": 1, "evidence_count_sent": 1,
                    "rag_case_count_sent": 0, "visual_count_sent": 0,
                    "tool_status_digest": "s" * 64,
                }],
            },
            "notes": [],
        }
        rows.append(row)
        reports.append(report)
    metrics = evaluate_metrics(
        gold, reports,
        sample_extras=evaluate_script.extras_from_rows(rows),
        controls=evaluate_script.controls_from_rows(rows),
    )
    manifest = {
        "run_id": root.name,
        "date_time_utc": "2026-09-20T00:00:00Z",
        "git_commit": None,
        "model": "Qwen/Qwen3.8-27B",
        "variant": "baseline",
        "split": "dev",
        "sample_count": len(rows),
        "measurement_scope": "smoke",
        "performance_claims_allowed": False,
        "sample_selection_rule": evaluate_script.SAMPLE_SELECTION_RULE,
        "selected_sample_ids": sorted(str(row["sample_id"]) for row in rows),
        "full_dev_label_support": {"spear_phishing": 8, "phishing": 25, "fraude": 15,
                                   "menace": 0, "spam": 15, "legitime": 20},
    }
    evaluate_script.write_predictions_atomic(root / "predictions.jsonl", rows)
    evaluate_script.write_json_atomic(root / "metrics.json", metrics)
    evaluate_script.write_json_atomic(root / "manifest.json", manifest)
    return root, metrics


def test_recompute_equals_archived_live_metrics(evaluate_script, monkeypatch, tmp_path):
    """recompute MUST reproduce the captured metrics exactly."""

    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    from_run = tmp_path / "from_run"
    from_run.mkdir()
    _from_run, live_metrics = _write_synthetic_run(evaluate_script, from_run)

    out = tmp_path / "recomputed"
    args = evaluate_script.build_parser().parse_args(
        ["--mode", "recompute", "--from-run", str(from_run), "--out", str(out)]
    )
    config = _make_cfg(evaluate_script, tmp_path)
    exit_code = evaluate_script.run_recompute(args, config)
    assert exit_code == evaluate_script.EXIT_OK
    recomputed = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert evaluate_script.diff_metrics(live_metrics, recomputed) == []
    assert (out / "manifest.json").is_file()
    recompute_manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert recompute_manifest["provider_calls"] == 0
    assert recompute_manifest["observation_timestamps_preserved"] is True


def test_recompute_detects_tampered_report(evaluate_script, monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    from_run = tmp_path / "from_run"
    from_run.mkdir()
    _write_synthetic_run(evaluate_script, from_run)
    victim = from_run / "run_u1" / "report.json"
    report = json.loads(victim.read_text(encoding="utf-8"))
    report["final_verdict"] = "legitime"  # tampering with an archived report
    victim.write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    out = tmp_path / "out"
    args = evaluate_script.build_parser().parse_args(
        ["--mode", "recompute", "--from-run", str(from_run), "--out", str(out)]
    )
    config = _make_cfg(evaluate_script, tmp_path)
    exit_code = evaluate_script.run_recompute(args, config)
    assert exit_code == evaluate_script.EXIT_FAIL  # provenance hash mismatch


def test_recompute_missing_predictions_fail(evaluate_script, monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    from_run = tmp_path / "from_run"
    from_run.mkdir()
    (from_run / "manifest.json").write_text("{}", encoding="utf-8")
    args = evaluate_script.build_parser().parse_args(
        ["--mode", "recompute", "--from-run", str(from_run), "--out", str(tmp_path / "out")]
    )
    config = _make_cfg(evaluate_script, tmp_path)
    exit_code = evaluate_script.run_recompute(args, config)
    assert exit_code == evaluate_script.EXIT_FAIL


def test_metrics_from_rows_plumbing_consistent(evaluate_script, monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    """The row → controls/extras plumbing keeps the paired denominators."""
    from src.metrics import abc_block

    from_run = tmp_path / "from_run"
    from_run.mkdir()
    _write_synthetic_run(evaluate_script, from_run)
    rows = [
        json.loads(line)
        for line in (from_run / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    controls = evaluate_script.controls_from_rows(rows)
    assert len(controls) == 3
    complex_controls = [control for control in controls if control is not None]
    assert len(complex_controls) == 2  # u1, u3 complex; u2 simple
    report_stub = {
        "sample_id": "x", "email_sha256": "z" * 64, "gate_decision": "complex",
        "internal_verdict": "phishing", "final_verdict": "phishing",
        "final_source": "final_llm", "run_status": "ok",
        "recommended_action": "AUTO", "llm_calls": [], "timings": {},
        "evidence": [], "unsupported_claims": [],
    }
    abc = abc_block(
        ["phishing"], ["phishing"], ["complex"], [report_stub], [controls[0]]
    )
    assert abc["comparable_n"] == 1
    assert abc["audit"]["valid"] is True


# ---------------------------------------------------------------------------
# Smoke scope (operator amendment 2026-09-21): deterministic 5-record sample
# ---------------------------------------------------------------------------


def test_smoke_selection_is_deterministic_and_label_stratified(evaluate_script):
    """Exactly one lexicographically first sample per dev label with support>0."""
    config = evaluate_script.load_evaluation_config(PROJECT_ROOT / "configs" / "evaluation.yaml")
    rows, _path = evaluate_script.load_gold_records(config, "dev")
    selected = evaluate_script.select_smoke_sample(rows)
    ids = [str(row["sample_id"]) for row in selected]
    labels = [str(row["normalized_label"]) for row in selected]
    assert labels == ["spear_phishing", "phishing", "fraude", "spam", "legitime"]
    # Exact deterministic selection (lexicographically first per label):
    assert ids == [
        "nazario_phishing_2025_00116",   # spear_phishing (lexicographically first)
        "nazario_phishing_2025_00020",   # phishing
        "nazario_phishing_2025_00112",   # fraude
        "spamassassin_hard_ham_00192",   # spam
        "nazario_phishing_2025_00404",   # legitime
    ]
    assert "menace" not in labels  # support=0: nothing fabricated
    # idempotent
    assert ids == [str(row["sample_id"]) for row in evaluate_script.select_smoke_sample(rows)]


def test_live_requires_explicit_sample_profile(evaluate_script, tmp_path):
    args = evaluate_script.build_parser().parse_args(
        ["--split", "dev", "--mode", "live", "--variant", "baseline",
         "--out", str(tmp_path / "out")]
    )
    config = evaluate_script.load_evaluation_config(PROJECT_ROOT / "configs" / "evaluation.yaml")
    exit_code = evaluate_script.main(
        ["--split", "dev", "--mode", "live", "--variant", "baseline",
         "--out", str(tmp_path / "out")]
    )
    assert exit_code == evaluate_script.EXIT_FAIL


def test_evaluation_config_declares_t19e_terminal_ticket(evaluate_script):
    """Operator trajectory 2026-09-21: the terminal benchmark ticket is T19E.

    The full-corpus capability stays refused as development validation and the
    terminal test run is owned by TICKET-19E (first full benchmark with a
    simultaneous rerun of the fixed V1).
    """
    config = evaluate_script.load_evaluation_config(PROJECT_ROOT / "configs" / "evaluation.yaml")
    assert config.split_policy.get("terminal_test_command_ticket") == "TICKET-19E"
    assert config.split_policy.get("gold_test_readable_by_ticket_14") is False


def test_check_gate_g6_commands_are_smoke_scoped():
    """G6 must run the bounded smoke, not the 83-email benchmark."""
    module = _load_check_gate_module()
    commands = module.GATE_COMMANDS["G6"]
    assert " ".join(commands[1][1:]) == (
        "scripts/evaluate.py --split dev --mode live --variant baseline "
        "--sample-profile smoke --out runs/eval/dev_smoke"
    )
    assert " ".join(commands[2][1:]) == (
        "scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke "
        "--out runs/eval/dev_smoke_recomputed"
    )
    assert not any("--out runs/eval/dev_baseline" in " ".join(command) for command in commands)
    # The gate record must archive those exact output dirs before re-running.
    assert module.GATE_ARTIFACT_DIRS["G6"] == [
        "runs/eval/dev_smoke",
        "runs/eval/dev_smoke_recomputed",
    ]


def test_check_gate_g7c_targets_t19e_artifacts():
    """T17/G7-C is post-T19E: it recomputes the T19E full-dev run, not the smoke."""
    module = _load_check_gate_module()
    command = module.GATE_COMMANDS["G7-C"][0]
    assert " ".join(command[1:]) == (
        "scripts/evaluate.py --mode recompute --from-run runs/eval/t19e_dev "
        "--out runs/eval/t19e_for_ft_decision"
    )
    assert not any("dev_smoke" in " ".join(entry) for entry in module.GATE_COMMANDS["G7-C"])


def test_check_gate_g6_record_is_rerunnable_without_manual_cleanup(monkeypatch, tmp_path):
    """PR #15 finding 2: --record must archive preserved runs, never fail on them.

    The evaluator refuses a non-empty --out; the controller therefore MOVES
    any existing gate output under runs/eval/_archive/<stamp>_<name> before
    executing its fixed commands (non-destructive, deterministic, repeatable).
    """
    module = _load_check_gate_module()
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    smoke = tmp_path / "runs" / "eval" / "dev_smoke"
    recomputed = tmp_path / "runs" / "eval" / "dev_smoke_recomputed"
    (smoke / "run-1").mkdir(parents=True)
    (smoke / "predictions.jsonl").write_text("{}\n", encoding="utf-8")
    recomputed.mkdir(parents=True)
    (recomputed / "metrics.json").write_text("{}\n", encoding="utf-8")

    archived = module.archive_gate_artifacts("G6", stamp="20260921T000000Z")
    assert [entry["path"] for entry in archived] == [
        "runs/eval/dev_smoke",
        "runs/eval/dev_smoke_recomputed",
    ]
    assert not smoke.exists()
    assert (
        tmp_path / "runs" / "eval" / "_archive" / "20260921T000000Z_dev_smoke"
        / "predictions.jsonl"
    ).is_file()
    assert (
        tmp_path / "runs" / "eval" / "_archive" / "20260921T000000Z_dev_smoke_recomputed"
        / "metrics.json"
    ).is_file()

    # Re-runnable: a later record archives the new outputs instead of failing.
    (smoke / "run-2").mkdir(parents=True)
    (smoke / "run-2" / "report.json").write_text("{}", encoding="utf-8")
    archived_again = module.archive_gate_artifacts("G6", stamp="20260921T010000Z")
    assert [entry["path"] for entry in archived_again] == ["runs/eval/dev_smoke"]
    assert archived_again[0]["archived_to"].endswith("20260921T010000Z_dev_smoke")

    # Nothing to archive -> no-op; unaffected gates stay untouched.
    assert module.archive_gate_artifacts("G6", stamp="20260921T020000Z") == []
    assert module.archive_gate_artifacts("G1") == []


def test_recompute_smoke_requires_exact_selection_identity(evaluate_script, monkeypatch, tmp_path):
    """A smoke run missing/adding a selected row FAILS (identity check)."""
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    from_run = tmp_path / "from_run"
    from_run.mkdir()
    _write_synthetic_run(evaluate_script, from_run)
    lines = [
        json.loads(line)
        for line in (from_run / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # Drop one archived row: the smoke must reproduce the selection EXACTLY.
    reduced_rows = lines[:-1]
    evaluate_script.write_predictions_atomic(from_run / "predictions.jsonl", reduced_rows)
    args = evaluate_script.build_parser().parse_args(
        ["--mode", "recompute", "--from-run", str(from_run), "--out", str(tmp_path / "out")]
    )
    config = _make_cfg(evaluate_script, tmp_path)
    exit_code = evaluate_script.run_recompute(args, config)
    assert exit_code == evaluate_script.EXIT_FAIL


# ---------------------------------------------------------------------------
# Provider outcomes in the bounded smoke (PR #15 finding 4)
# ---------------------------------------------------------------------------


def test_bounded_smoke_never_aborts_on_provider_outcomes(evaluate_script):
    """Five genuine INTERNAL timeouts are honest rows, never a smoke FAIL.

    The consecutive-failure abort is reserved to a FULL-corpus run (T19E)
    that never saw one successful INTERNAL call; the bounded smoke never
    aborts on provider outcomes (operator amendment 2026-09-21).
    """

    smoke = evaluate_script.SMOKE_PROFILE
    full = evaluate_script.FULL_PROFILE
    assert evaluate_script._abort_on_systematic_outage(smoke, 5, False) is False
    assert evaluate_script._abort_on_systematic_outage(smoke, 50, False) is False
    assert evaluate_script._abort_on_systematic_outage(smoke, 5, True) is False
    assert evaluate_script._abort_on_systematic_outage(full, 4, False) is False
    assert evaluate_script._abort_on_systematic_outage(full, 5, False) is True
    assert evaluate_script._abort_on_systematic_outage(full, 9, False) is True
    assert evaluate_script._abort_on_systematic_outage(full, 5, True) is False


class _StubSettings:
    """Minimal Settings stand-in for the offline run_live contract tests."""

    LITELLM_API_KEY = "unit-test-key-not-a-secret"
    LITELLM_MODEL = "Qwen/Qwen3.8-27B"
    LITELLM_CHAT_URL = "https://unit.invalid/v1/chat/completions"

    def model_copy(self, update: dict) -> "_StubSettings":
        clone = _StubSettings()
        for key, value in update.items():
            setattr(clone, key, value)
        return clone


def _stub_offline_run_live(evaluate_script, monkeypatch, tmp_path, gold_rows):
    """Wire run_live offline with a provider that fails on every record.

    Only the guard/denominator behaviour is under test. The report shape is
    the same synthetic fixture used by the recompute tests (clearly labeled
    a unit fixture, never a benchmark measurement); the network is denied
    module-wide and every provider call is stubbed out.
    """

    import types

    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(evaluate_script, "load_settings", lambda: _StubSettings())
    monkeypatch.setattr(evaluate_script, "verify_experiment_lock", lambda lock: [])
    monkeypatch.setattr(evaluate_script, "check_runtime_ready", lambda settings, lock: [])
    monkeypatch.setattr(
        evaluate_script, "load_gold_records",
        lambda config, split: (gold_rows, tmp_path / "corpus" / "gold" / "gold_dev.jsonl"),
    )
    monkeypatch.setattr(
        evaluate_script, "validate_gold_raw_files",
        lambda rows: ({row["sample_id"]: b"raw email bytes" for row in rows}, []),
    )
    monkeypatch.setattr(
        evaluate_script, "build_manifest",
        lambda **kwargs: {
            "run_id": kwargs["out_dir"].name,
            "date_time_utc": kwargs["started_at"],
            "git_commit": None,
            "variant": kwargs["variant"],
            "split": kwargs["split"],
            "sample_count": len(kwargs["rows"]),
            "measurement_scope": kwargs["measurement_scope"],
            "performance_claims_allowed": kwargs["performance_claims_allowed"],
            "sample_selection_rule": kwargs["sample_selection_rule"],
            "selected_sample_ids": kwargs["selected_ids"],
            "full_dev_label_support": kwargs["full_support"],
        },
    )
    monkeypatch.setattr(
        evaluate_script, "write_human_report",
        lambda path, metrics, manifest: path.write_text("stub report", encoding="utf-8"),
    )
    monkeypatch.setattr(
        evaluate_script, "write_matrix_csv",
        lambda path, metrics: path.write_text("stub matrix", encoding="utf-8"),
    )
    stub_audits = [{
        "attempt": 1, "phase": "final", "external_evidence_count_sent": 0,
        "internal_evidence_count_sent": 1, "evidence_count_sent": 1,
        "rag_case_count_sent": 0, "visual_count_sent": 0,
        "tool_status_digest": "d" * 64,
    }]
    monkeypatch.setattr(evaluate_script, "read_final_audits", lambda capture_dir: list(stub_audits))
    monkeypatch.setattr(
        evaluate_script, "run_control_b",
        lambda settings, final_state, capture_dir, pricing: {
            "attempted": True, "reason_not_attempted": None, "verdict": None,
            "confidence": None, "probabilities": None,
            "call": {"phase": "final", "status": "error", "attempts": 1,
                     "input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0,
                     "reasoning_tokens": 0, "cost_usd": None, "cost_status": "unknown"},
            "latency_ms": None, "capture_dir": "responses_control_b",
            "cost_usd": None, "cost_status": "unknown",
        },
    )

    order: dict[str, object] = {"rows": []}

    def _fake_pipeline(settings, email_file, profile, **kwargs):
        # The frozen baseline call site must not pass any ablation override.
        assert kwargs.get("tools_override") is None
        assert kwargs.get("rag_adapter") is None
        done = order.setdefault("done", [])
        rows = order["rows"]
        assert isinstance(rows, list) and len(done) < len(rows)
        row = rows[len(done)]
        done.append(row["sample_id"])
        report = _synthetic_report(
            row["sample_id"], row["raw_sha256"], gate="complex",
            final_verdict=None, internal_verdict=None, action="REVIEW",
        )
        report_dir = tmp_path / "stubbed_reports" / row["sample_id"]
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / "report.json"
        report_file.write_text(
            json.dumps(report, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        final_state = {
            "parsed": types.SimpleNamespace(email_sha256=row["raw_sha256"]),
            "internal": None,
            "final_validated": None,
            "evidence": {},
            "report_path": str(report_file),
        }
        return report, final_state

    monkeypatch.setattr(evaluate_script, "run_nominal_pipeline", _fake_pipeline)
    return order


def test_run_live_smoke_keeps_all_provider_failures_in_denominators(
    evaluate_script, monkeypatch, tmp_path
):
    """Finding 4 regression: a smoke whose every INTERNAL call fails still
    completes with honest rows, exact recompute inputs and exit 0."""

    gold = [
        _gold_row("u1", "a" * 64, "phishing"),
        _gold_row("u2", "b" * 64, "spam"),
        _gold_row("u3", "c" * 64, "legitime"),
    ]
    config = _make_cfg(evaluate_script, tmp_path)
    order = _stub_offline_run_live(evaluate_script, monkeypatch, tmp_path, gold)
    order["rows"] = evaluate_script.select_smoke_sample(gold)

    out = tmp_path / "dev_smoke"
    args = evaluate_script.build_parser().parse_args(
        ["--split", "dev", "--mode", "live", "--variant", "baseline",
         "--sample-profile", "smoke", "--out", str(out)]
    )
    exit_code = evaluate_script.run_live(args, config, {})
    assert exit_code == evaluate_script.EXIT_OK
    rows = [
        json.loads(line)
        for line in (out / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 3  # complete denominator, no silent drop
    assert all(row["predicted"] is None for row in rows)
    assert all(row["internal_verdict"] is None for row in rows)
    assert (out / "metrics.json").is_file()


def test_run_live_full_profile_keeps_the_systematic_outage_abort(
    evaluate_script, monkeypatch, tmp_path
):
    """The full-corpus T19E scope still refuses to burn 5 records on a dead
    endpoint when no INTERNAL call ever succeeded."""

    gold = [
        _gold_row("u1", "a" * 64, "phishing"),
        _gold_row("u2", "b" * 64, "phishing"),
        _gold_row("u3", "c" * 64, "spam"),
        _gold_row("u4", "d" * 64, "legitime"),
        _gold_row("u5", "e" * 64, "fraude"),
    ]
    config = _make_cfg(evaluate_script, tmp_path)
    order = _stub_offline_run_live(evaluate_script, monkeypatch, tmp_path, gold)
    order["rows"] = list(gold)

    out = tmp_path / "dev_full"
    args = evaluate_script.build_parser().parse_args(
        ["--split", "dev", "--mode", "live", "--variant", "baseline",
         "--sample-profile", "full", "--out", str(out)]
    )
    exit_code = evaluate_script.run_live(args, config, {})
    assert exit_code == evaluate_script.EXIT_FAIL
    assert not (out / "predictions.jsonl").exists()


# ---------------------------------------------------------------------------
# TICKET-15 paired RAG interface (offline, docs/evaluation.md §8.7)
# ---------------------------------------------------------------------------


def _rag_gold_rows() -> list[dict]:
    return [
        _gold_row("u1", "a" * 64, "phishing"),
        _gold_row("u2", "b" * 64, "legitime"),
        _gold_row("u3", "c" * 64, "spam"),
    ]


def _write_paired_baseline_run(
    evaluate_script,
    root: Path,
    gold_rows: list[dict],
    predictions: dict[str, str | None],
) -> Path:
    """Archive a minimal baseline run used as the read-only paired reference."""

    root.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for gold in gold_rows:
        sample_id = str(gold["sample_id"])
        report = _synthetic_report(
            sample_id,
            str(gold["raw_sha256"]),
            gate="complex",
            final_verdict=predictions[sample_id],
            internal_verdict="phishing",
            action="AUTO",
        )
        report_dir = root / ("run_" + sample_id)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_bytes = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
        (report_dir / "report.json").write_bytes(report_bytes)
        rows.append(
            {
                "sample_id": sample_id,
                "split": "dev",
                "variant": "baseline",
                "measurement_scope": "smoke",
                "label": gold["normalized_label"],
                "raw_sha256": gold["raw_sha256"],
                "predicted": predictions[sample_id],
                "gate_decision": "complex",
                "report_dir": str(report_dir.relative_to(root)),
                "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            }
        )
    evaluate_script.write_predictions_atomic(root / "predictions.jsonl", rows)
    manifest = {
        "run_id": root.name,
        "variant": "baseline",
        "split": "dev",
        "sample_count": len(rows),
        "measurement_scope": "smoke",
        "performance_claims_allowed": False,
        "sample_selection_rule": evaluate_script.SAMPLE_SELECTION_RULE,
        "selected_sample_ids": sorted(predictions),
        "full_dev_label_support": {},
    }
    evaluate_script.write_json_atomic(root / "manifest.json", manifest)
    return root


def _rag_variant_args(evaluate_script, tmp_path: Path, paired_dir: Path | None):
    argv = [
        "--split", "dev",
        "--mode", "live",
        "--variant", "rag",
        "--sample-profile", "smoke",
        "--out", str(tmp_path / "dev_rag_smoke"),
    ]
    if paired_dir is not None:
        argv += ["--paired-with", str(paired_dir)]
    return evaluate_script.build_parser().parse_args(argv)


def test_rag_variant_requires_paired_with(evaluate_script, monkeypatch, tmp_path):
    """--variant rag without --paired-with is a FAIL before anything runs."""

    def _never(*args: object, **kwargs: object) -> None:
        pytest.fail("no pipeline call without --paired-with")

    monkeypatch.setattr(evaluate_script, "run_nominal_pipeline", _never)
    args = _rag_variant_args(evaluate_script, tmp_path, None)
    config = _make_cfg(evaluate_script, tmp_path)
    assert evaluate_script.run_live(args, config, {}) == evaluate_script.EXIT_FAIL
    assert not (tmp_path / "dev_rag_smoke").exists()


def test_paired_with_refused_for_the_baseline_variant(evaluate_script, tmp_path):
    args = evaluate_script.build_parser().parse_args(
        [
            "--split", "dev",
            "--mode", "live",
            "--variant", "baseline",
            "--sample-profile", "smoke",
            "--paired-with", str(tmp_path),
            "--out", str(tmp_path / "out"),
        ]
    )
    config = _make_cfg(evaluate_script, tmp_path)
    assert evaluate_script.run_live(args, config, {}) == evaluate_script.EXIT_FAIL


def test_paired_run_with_missing_row_fails_before_any_call(
    evaluate_script, monkeypatch, tmp_path
):
    """A paired run whose rows miss its own selection is refused (no call)."""

    gold = _rag_gold_rows()
    config = _make_cfg(evaluate_script, tmp_path)
    _stub_offline_run_live(evaluate_script, monkeypatch, tmp_path, gold)
    monkeypatch.setattr(
        evaluate_script,
        "run_nominal_pipeline",
        lambda *args, **kwargs: pytest.fail("no pipeline call for an invalid paired run"),
    )
    paired_dir = _write_paired_baseline_run(
        evaluate_script,
        tmp_path / "paired",
        gold,
        {"u1": "phishing", "u2": "legitime", "u3": "spam"},
    )
    lines = [
        json.loads(line)
        for line in (paired_dir / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    evaluate_script.write_predictions_atomic(paired_dir / "predictions.jsonl", lines[:-1])
    args = _rag_variant_args(evaluate_script, tmp_path, paired_dir)
    assert evaluate_script.run_live(args, config, {}) == evaluate_script.EXIT_FAIL
    assert not (tmp_path / "dev_rag_smoke").exists()


def test_paired_selection_mismatch_fails_before_any_call(
    evaluate_script, monkeypatch, tmp_path
):
    """Different sample ids between the two runs: FAIL, no provider call."""

    gold = _rag_gold_rows()  # deterministic selection: u1, u2, u3
    other_gold = [
        _gold_row("u1", "a" * 64, "phishing"),
        _gold_row("u2", "b" * 64, "legitime"),
        _gold_row("u4", "d" * 64, "spam"),
    ]
    config = _make_cfg(evaluate_script, tmp_path)
    _stub_offline_run_live(evaluate_script, monkeypatch, tmp_path, gold)
    monkeypatch.setattr(
        evaluate_script,
        "run_nominal_pipeline",
        lambda *args, **kwargs: pytest.fail("no pipeline call on a selection mismatch"),
    )
    paired_dir = _write_paired_baseline_run(
        evaluate_script,
        tmp_path / "paired",
        other_gold,
        {"u1": "phishing", "u2": "legitime", "u4": "spam"},
    )
    args = _rag_variant_args(evaluate_script, tmp_path, paired_dir)
    assert evaluate_script.run_live(args, config, {}) == evaluate_script.EXIT_FAIL


def _stub_offline_rag_run(
    evaluate_script,
    monkeypatch,
    tmp_path,
    gold_rows,
    *,
    verdicts: dict[str, str | None],
    rag_context: dict[str, list[dict]],
    index_count: int = 2,
) -> dict[str, list]:
    """Offline paired-RAG wiring: no network, no chromadb, no ONNX weights.

    The REAL effective-config construction runs (``prepare_rag_ablation``);
    only the adapter factory is replaced by a stub that records the
    effective flags and returns a fake adapter. The real manifest/report
    writers run against a copied config/prompts/schemas fixture so the
    archived artifacts are exercised end to end.
    """

    import shutil
    import types

    from pydantic import SecretStr

    from src.config import load_settings as real_load_settings

    real_root = SCRIPTS_DIR.parent
    monkeypatch.setattr(evaluate_script, "PROJECT_ROOT", tmp_path)
    for relative in ("prompts", "schemas", "configs"):
        shutil.copytree(real_root / relative, tmp_path / relative, dirs_exist_ok=True)
    gold_path = tmp_path / "corpus" / "gold" / "gold_dev.jsonl"
    gold_path.parent.mkdir(parents=True, exist_ok=True)
    gold_path.write_text("", encoding="utf-8")

    settings = real_load_settings(None).model_copy(
        update={
            "RUNS_DIR": tmp_path / "runs",
            "CONFIG_DIR": real_root / "configs",
            "RAG_ENABLED": False,
            "RAG_DIR": tmp_path / "chroma",
            "LITELLM_API_KEY": SecretStr("placeholder-key-not-a-real-credential"),
        }
    )
    monkeypatch.setattr(evaluate_script, "load_settings", lambda: settings)
    monkeypatch.setattr(evaluate_script, "verify_experiment_lock", lambda lock: [])
    monkeypatch.setattr(evaluate_script, "check_runtime_ready", lambda settings, lock: [])
    monkeypatch.setattr(
        evaluate_script, "load_gold_records", lambda config, split: (gold_rows, gold_path)
    )
    monkeypatch.setattr(
        evaluate_script,
        "validate_gold_raw_files",
        lambda rows: ({row["sample_id"]: b"raw email bytes" for row in rows}, []),
    )
    stub_audit = {
        "attempt": 1,
        "phase": "final",
        "external_evidence_count_sent": 0,
        "internal_evidence_count_sent": 1,
        "evidence_count_sent": 1,
        "rag_case_count_sent": 0,
        "visual_count_sent": 0,
        "tool_status_digest": "d" * 64,
    }
    monkeypatch.setattr(
        evaluate_script, "read_final_audits", lambda capture_dir: [dict(stub_audit)]
    )
    monkeypatch.setattr(
        evaluate_script,
        "run_control_b",
        lambda settings, final_state, capture_dir, pricing: {
            "attempted": True,
            "reason_not_attempted": None,
            "verdict": None,
            "confidence": None,
            "probabilities": None,
            "call": {
                "phase": "final",
                "status": "error",
                "attempts": 1,
                "input_tokens": 0,
                "cached_input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "cost_usd": None,
                "cost_status": "unknown",
            },
            "latency_ms": None,
            "capture_dir": "responses_control_b",
            "cost_usd": None,
            "cost_status": "unknown",
        },
    )

    factory_calls: list[dict] = []

    class _FakeAdapter:
        def count(self) -> int:
            return index_count

        def describe(self) -> dict:
            return {
                "collection": "public_rag_reference",
                "index_dir": str(tmp_path / "chroma"),
                "count": index_count,
                "distance_space": "cosine",
                "embedding_model_id": "all-MiniLM-L6-v2@sha256:" + "a" * 16,
                "embedding_model_sha256": "a" * 64,
                "max_cases": 150,
                "k": 3,
                "max_distance": 0.4,
            }

    def _factory(effective_settings, rag_config):
        factory_calls.append(
            {
                "rag_enabled": bool(effective_settings.RAG_ENABLED),
                "tools_rag_enabled": bool(rag_config.enabled),
                "rag_dir": str(effective_settings.RAG_DIR),
            }
        )
        return _FakeAdapter()

    monkeypatch.setattr(evaluate_script, "create_rag_adapter_if_enabled", _factory)

    pipeline_calls: list[dict] = []

    def _fake_pipeline(settings, email_file, profile, **kwargs):
        assert kwargs.get("tools_override") is not None, "the ablation must pass the effective tools"
        assert kwargs["tools_override"].rag.enabled is True
        assert kwargs.get("rag_adapter") is not None, "the validated adapter must be reused"
        assert settings.RAG_ENABLED is True
        sample_id = Path(email_file).stem.split("_", 1)[1]
        pipeline_calls.append({"sample_id": sample_id, "profile": profile})
        verdict = verdicts[sample_id]
        sha = next(
            str(row["raw_sha256"]) for row in gold_rows if row["sample_id"] == sample_id
        )
        report = _synthetic_report(
            sample_id,
            sha,
            gate="complex",
            final_verdict=verdict,
            internal_verdict="phishing",
            action="AUTO",
        )
        cases = [dict(case) for case in rag_context.get(sample_id, [])]
        report["enrichment"]["rag"] = cases
        report_dir = tmp_path / "rag_reports" / sample_id
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / "report.json"
        report_file.write_text(
            json.dumps(report, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        final_state = {
            "parsed": types.SimpleNamespace(email_sha256=sha),
            "internal": None,
            "final_validated": None,
            "evidence": {},
            "enrichment": types.SimpleNamespace(
                rag=[types.SimpleNamespace(**case) for case in cases]
            ),
            "report_path": str(report_file),
        }
        return report, final_state

    monkeypatch.setattr(evaluate_script, "run_nominal_pipeline", _fake_pipeline)
    return {"factory": factory_calls, "pipeline": pipeline_calls}


def test_rag_variant_refuses_an_empty_public_index(
    evaluate_script, monkeypatch, tmp_path
):
    """An empty index is refused: never a silently always-empty ablation."""

    gold = _rag_gold_rows()
    config = _make_cfg(evaluate_script, tmp_path)
    state = _stub_offline_rag_run(
        evaluate_script,
        monkeypatch,
        tmp_path,
        gold,
        verdicts={"u1": "phishing", "u2": "legitime", "u3": "spam"},
        rag_context={},
        index_count=0,
    )
    paired_dir = _write_paired_baseline_run(
        evaluate_script,
        tmp_path / "paired",
        gold,
        {"u1": "phishing", "u2": "legitime", "u3": "spam"},
    )
    args = _rag_variant_args(evaluate_script, tmp_path, paired_dir)
    assert evaluate_script.run_live(args, config, {}) == evaluate_script.EXIT_FAIL
    assert state["factory"], "the effective factory is still probed"
    assert state["pipeline"] == []
    assert not (tmp_path / "dev_rag_smoke").exists()


def test_paired_rag_run_pairs_read_only_and_archives_diagnostics(
    evaluate_script, monkeypatch, tmp_path
):
    """Happy path: exact pairing, read-only baseline, diagnostic artifacts."""

    gold = _rag_gold_rows()
    config = _make_cfg(evaluate_script, tmp_path)
    paired_dir = _write_paired_baseline_run(
        evaluate_script,
        tmp_path / "paired",
        gold,
        {"u1": "phishing", "u2": "legitime", "u3": "spam"},
    )
    before = {
        str(path.relative_to(paired_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paired_dir.rglob("*"))
        if path.is_file()
    }
    embedding_id = "all-MiniLM-L6-v2@sha256:" + "a" * 16
    rag_context = {
        "u1": [
            {
                "case_id": "rag_public_1",
                "family_group": "fam:rag_1",
                "distance": 0.12,
                "embedding_model_id": embedding_id,
            }
        ],
        "u2": [],
        "u3": [
            {
                "case_id": "rag_public_2",
                "family_group": "fam:rag_2",
                "distance": 0.2,
                "embedding_model_id": embedding_id,
            },
            {
                "case_id": "rag_public_3",
                "family_group": "fam:rag_3",
                "distance": 0.31,
                "embedding_model_id": embedding_id,
            },
        ],
    }
    state = _stub_offline_rag_run(
        evaluate_script,
        monkeypatch,
        tmp_path,
        gold,
        verdicts={"u1": "phishing", "u2": None, "u3": "spam"},
        rag_context=rag_context,
    )
    args = _rag_variant_args(evaluate_script, tmp_path, paired_dir)
    assert evaluate_script.run_live(args, config, {}) == evaluate_script.EXIT_OK

    out = tmp_path / "dev_rag_smoke"
    # The effective configuration is built in memory; the frozen tools.yaml
    # (copied fixture) still says rag.enabled=false.
    assert state["factory"] == [
        {
            "rag_enabled": True,
            "tools_rag_enabled": True,
            "rag_dir": str(tmp_path / "chroma"),
        }
    ]
    tools_yaml = (tmp_path / "configs" / "tools.yaml").read_text(encoding="utf-8")
    assert "rag:\n  # Globally piloted by RAG_ENABLED (default false); inactive before G7-A.\n  enabled: false" in tools_yaml
    assert len(state["pipeline"]) == 3

    rows = [
        json.loads(line)
        for line in (out / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert sorted(row["sample_id"] for row in rows) == ["u1", "u2", "u3"]
    assert all(row["variant"] == "rag" for row in rows)
    assert next(row for row in rows if row["sample_id"] == "u3")["rag_cases"]
    assert next(row for row in rows if row["sample_id"] == "u2")["rag_cases"] == []

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["variant"] == "rag"
    assert manifest["measurement_scope"] == "smoke"
    assert manifest["performance_claims_allowed"] is False
    assert manifest["rag_ablation"]["capability"]["in_memory_overrides"] == [
        "tools.rag.enabled=true",
        "RAG_ENABLED=true",
    ]
    assert manifest["rag_ablation"]["capability"]["frozen_tools_yaml_unchanged"] is True
    assert manifest["rag_ablation"]["index"]["count"] == 2
    assert manifest["rag_ablation"]["paired_with"] == "paired"
    assert manifest["rag_ablation"]["paired_baseline_artifact"] == "paired_baseline.json"
    assert manifest["paired_baseline"]["comparison"]["performance_claims_allowed"] is False

    paired = json.loads((out / "paired_baseline.json").read_text(encoding="utf-8"))
    assert paired["paired_variant"] == "baseline"
    assert paired["paired_with"] == "paired"
    assert paired["selection_identity"]["sample_ids"] == ["u1", "u2", "u3"]
    assert paired["denominators"] == {
        "current_run": 3,
        "paired_run": 3,
        "selection": 3,
        "identical": True,
    }
    comparison = paired["comparison"]
    assert comparison["n_comparable"] == 3
    assert comparison["buckets"]["right_to_right"] == 2
    assert comparison["buckets"]["right_to_wrong"] == 1
    assert comparison["denominators_paired"] is True
    assert paired["rag_usage"]["samples_with_neighbour"] == 2
    assert paired["rag_usage"]["samples_without_neighbour"] == 1
    assert paired["rag_usage"]["total_neighbours"] == 3
    per_sample = {entry["sample_id"]: entry for entry in paired["per_sample"]}
    assert per_sample["u2"]["baseline_predicted"] == "legitime"
    assert per_sample["u2"]["rag_predicted"] is None
    assert per_sample["u2"]["prediction_changed"] is True
    report = (out / "report.md").read_text(encoding="utf-8")
    assert "Paired baseline" in report
    assert "performance_claims_allowed=false" in report

    # The paired baseline run was never modified.
    after = {
        str(path.relative_to(paired_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paired_dir.rglob("*"))
        if path.is_file()
    }
    assert before == after

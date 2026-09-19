"""TICKET-11 reporting tests: summary templates, schema validation, writing.

Controlled states are local plumbing objects; they never claim a provider
observation. The report shape itself is checked against the frozen
``schemas/triage_report.schema.json`` plus the documented invariants.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from src.reporting import (
    SUMMARY_MAX_WORDS,
    ReportWriteError,
    build_events,
    build_report,
    render_summary,
    validate_report,
    write_report,
)
from src.state import (
    Assessment,
    EmailTriageState,
    Evidence,
    GateResult,
    Inference,
    ParsedEmail,
    VerificationIssue,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class _StubServices:
    """Minimal harness the report projection actually reads."""

    def __init__(self, *, mode: str = "live") -> None:
        self.clock = time.monotonic
        # Started 50 ms ago so the measured total_ms really covers the
        # controlled phase timings of the test state.
        self.started_monotonic = time.monotonic() - 0.05
        self.mode = mode


def _assessment(vector: dict[str, float] | None = None) -> Assessment:
    values = {
        "spear_phishing": 0.01,
        "phishing": 0.9,
        "fraude": 0.02,
        "menace": 0.02,
        "spam": 0.02,
        "legitime": 0.03,
    }
    values.update(vector or {})
    return Assessment(
        probabilities=values,
        observations=[],
        inferences=[
            Inference(
                id="inf_cred",
                code="credential_collection",
                summary="Collecte d'identifiants.",
                evidence_ids=[],
                rag_case_ids=[],
            )
        ],
        observable_assessments=[],
        needs_enrichment=True,
        missing_information=["destination_unverified"],
        decisive_evidence_ids=["ev_" + "1" * 8],
    )


def _state(tmp_path: Path, **overrides: Any) -> EmailTriageState:
    evidence = Evidence(
        id="ev_" + "1" * 8,
        provenance="SANDBOX",
        source_kind="urlscan",
        observable_id=None,
        predicate="sandbox_final_url",
        value="https://evil.test/collecte?token=abc",
        source_ref="urlscan_capture.poll_1.json#/page/url",
        observed_at="2026-09-19T10:00:00+00:00",
        match_level="EXACT",
        source_group="urlscan",
    )
    parsed = ParsedEmail(
        email_sha256="d" * 64,
        raw_size_bytes=512,
        input_format="rfc822",
        subject="<script>URGENT</script> remboursement",
        from_addresses=["attacker@evil.example"],
        to_addresses=["victime@example.org"],
    )
    state = EmailTriageState(
        input_path=str((tmp_path / "sample.eml").resolve()),
        source_profile="fixture",
        started_at="2026-09-19T10:00:00+00:00",
        config_sha256="a" * 64,
        parsed=parsed,
        evidence={evidence.id: evidence},
        internal=_assessment({"phishing": 0.70, "legitime": 0.23}),
        final_candidate=_assessment(),
        final_validated=_assessment(),
        final_source="final_llm",
        verification=[
            VerificationIssue(
                code="confidence_rise_without_new_evidence",
                severity="warning",
                source="final",
                object_id=None,
                message="warning de test",
            )
        ],
        action="REVIEW",
        policy_reasons=["material_missing_information:destination_unverified"],
        timings={"parse_ms": 1.0, "internal_llm_ms": 2.0, "total_ms": 3.0},
        gate=GateResult(
            decision="complex",
            reasons=["urls_present"],
            rule_hits={"R1": False, "R2": True, "R3": False},
        ),
    )
    return state.model_copy(update=overrides) if overrides else state


def test_render_summary_is_bounded_escaped_and_defanged(tmp_path: Path) -> None:
    summary = render_summary(_state(tmp_path))
    assert len(summary.split()) <= SUMMARY_MAX_WORDS
    assert "<script" not in summary.lower()
    assert "&lt;script&gt;" in summary
    assert "https://evil.test" not in summary
    assert "hxxps://evil[.]test" in summary
    assert "credential_collection" in summary
    assert "Action recommandée : REVIEW" in summary
    assert "destination_unverified" in summary


def test_render_summary_is_deterministic(tmp_path: Path) -> None:
    state = _state(tmp_path)
    assert render_summary(state) == render_summary(state)


def test_build_report_matches_schema_and_records_unknown_cost(tmp_path: Path) -> None:
    services = _StubServices()
    report = build_report(_state(tmp_path), services, report_started_monotonic=time.monotonic())
    assert validate_report(report) == []
    assert report["run_status"] == "ok"
    assert report["verdict_changed"] == (
        report["internal_verdict"] != report["final_verdict"]
    )
    assert report["cost_usd"] is None and report["cost_status"] == "unknown"
    assert report["timings"]["total_ms"] >= 3.0 - 0.02
    assert report["reproducibility"]["mode"] == "live"
    assert report["decisive_evidence"] and "sandbox_final_url" in report["decisive_evidence"][0]
    assert report["gate_decision"] == "complex"
    assert report["unsupported_claims"] == []
    assert [issue["code"] for issue in report["verification_warnings"]] == [
        "confidence_rise_without_new_evidence"
    ]


def test_write_report_writes_three_atomic_artifacts(tmp_path: Path) -> None:
    services = _StubServices()
    state = _state(tmp_path)
    report = build_report(state, services, report_started_monotonic=time.monotonic())
    events = build_events(state, str(tmp_path / "out" / "report.json"))
    path = write_report(report, tmp_path / "out", events=events)

    assert path == tmp_path / "out" / "report.json"
    assert json.loads(path.read_text(encoding="utf-8"))["run_id"] == report["run_id"]
    assert (tmp_path / "out" / "summary.txt").read_text(encoding="utf-8") == (
        report["analyst_summary"] + "\n"
    )
    lines = (tmp_path / "out" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["node"] for line in lines] == [
        "parse_email",
        "internal_assessment",
        "complexity_gate",
        "virustotal",
        "opencti",
        "urlscan",
        "rag_lookup",
        "merge_evidence",
        "final_assessment",
        "verify",
        "policy",
        "write_report",
    ]
    assert not list((tmp_path / "out").glob("*.tmp"))


def test_write_report_refuses_silent_overwrite(tmp_path: Path) -> None:
    services = _StubServices()
    report = build_report(_state(tmp_path), services, report_started_monotonic=time.monotonic())
    write_report(report, tmp_path / "out")
    before = (tmp_path / "out" / "report.json").read_bytes()

    with pytest.raises(ReportWriteError):
        write_report(report, tmp_path / "out")
    assert (tmp_path / "out" / "report.json").read_bytes() == before


def test_write_report_rejects_invalid_document_without_partial_files(tmp_path: Path) -> None:
    services = _StubServices()
    report = build_report(_state(tmp_path), services, report_started_monotonic=time.monotonic())
    del report["run_id"]

    with pytest.raises(ReportWriteError):
        write_report(report, tmp_path / "out")
    assert not (tmp_path / "out" / "report.json").exists()


def test_write_report_wraps_unwritable_target(tmp_path: Path) -> None:
    services = _StubServices()
    report = build_report(_state(tmp_path), services, report_started_monotonic=time.monotonic())
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ReportWriteError):
        write_report(report, blocker / "sub")


def test_validate_report_detects_semantic_tampering(tmp_path: Path) -> None:
    services = _StubServices()
    report = build_report(_state(tmp_path), services, report_started_monotonic=time.monotonic())
    assert validate_report(report) == []

    for mutate in (
        lambda doc: doc.__setitem__(
            "verdict_changed",
            not doc["verdict_changed"] if doc["verdict_changed"] is not None else True,
        ),
        lambda doc: doc.__setitem__("run_status", "error"),
        lambda doc: doc["timings"].__setitem__("total_ms", -1.0),
        lambda doc: doc.__setitem__("analyst_summary", "mot " * 150),
        lambda doc: doc.__setitem__("recommended_action", "DELETE"),
    ):
        tampered = json.loads(json.dumps(report))
        mutate(tampered)
        assert validate_report(tampered), "tampering was not detected"


def test_report_text_is_expurgated_before_writing(tmp_path: Path) -> None:
    canary = "Authorization: Bearer sk-canary-0123456789abcdef"
    evidence = Evidence(
        id="ev_" + "2" * 8,
        provenance="OSINT",
        source_kind="opencti",
        observable_id=None,
        predicate="cti_label",
        value=canary,
        source_ref="cti_capture.json#/label",
        observed_at="2026-09-19T10:00:00+00:00",
        match_level="EXACT",
        source_group="opencti",
    )
    final = _assessment().model_copy(update={"decisive_evidence_ids": [evidence.id]})
    state = _state(
        tmp_path,
        evidence={evidence.id: evidence},
        final_validated=final,
        final_candidate=final,
    )
    report = build_report(
        state, _StubServices(), report_started_monotonic=time.monotonic()
    )
    write_report(report, tmp_path / "out")

    for name in ("report.json", "summary.txt"):
        text = (tmp_path / "out" / name).read_text(encoding="utf-8")
        assert canary not in text, name
        assert "sk-canary" not in text, name

"""Contract tests (TICKET-01): the six model classes and their exact rules.

These are minimal local contract objects, not API responses. No simulated
Luna/VT/OpenCTI/urlscan observation is fabricated here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.config import GateConfig, PolicyConfig, ToolsConfig, load_yaml_config
from src.state import (
    Assessment,
    EmailTriageState,
    Evidence,
    Inference,
    Observable,
    ObservableAssessment,
    ParsedEmail,
    Probabilities,
    Timings,
    new_state,
)

pytestmark = pytest.mark.g0


def make_probabilities(**overrides: float) -> Probabilities:
    values = dict.fromkeys(
        ("spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"), 0.0
    )
    values["legitime"] = 1.0
    values.update(overrides)
    return Probabilities(**values)


def make_parsed_email() -> ParsedEmail:
    return ParsedEmail(
        email_sha256="a" * 64,
        raw_size_bytes=10,
        input_format="rfc822",
    )


def make_assessment() -> Assessment:
    """Minimal valid Assessment — all schema-required fields provided explicitly."""

    return Assessment(
        probabilities=make_probabilities(),
        observations=[],
        inferences=[],
        observable_assessments=[],
        needs_enrichment=False,
        missing_information=[],
        decisive_evidence_ids=[],
    )


def test_six_exact_classes() -> None:
    """Exactly the six contract classes exist with the required fields."""

    assert set(Probabilities.model_fields) == {
        "spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"
    }
    assert set(ParsedEmail.model_fields) >= {"email_sha256", "raw_size_bytes", "input_format"}
    assert set(Assessment.model_fields) == {
        "probabilities",
        "observations",
        "inferences",
        "observable_assessments",
        "needs_enrichment",
        "missing_information",
        "decisive_evidence_ids",
    }
    assert set(EmailTriageState.model_fields) == {
        "schema_version",
        "run_id",
        "input_path",
        "source_profile",
        "started_at",
        "config_sha256",
        "parsed",
        "observable_registry",
        "evidence",
        "visual_evidence",
        "internal",
        "internal_call",
        "gate",
        "enrichment",
        "final_candidate",
        "final_call",
        "final_source",
        "final_validated",
        "verification",
        "accepted_observables",
        "errors",
        "action",
        "policy_reasons",
        "timings",
        "report_path",
    }
    assert set(Timings.model_fields) == {
        "parse_ms", "internal_llm_ms", "gate_ms", "vt_ms", "opencti_ms",
        "urlscan_ms", "rag_ms", "merge_ms", "final_llm_ms", "verify_ms",
        "policy_ms", "report_ms", "total_ms",
    }


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        Probabilities(**{**{k: 0.0 for k in (
            "spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"
        )}, "unknown_field": 1})


def test_nan_and_inf_rejected() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError):
            make_probabilities(legitime=bad)
        with pytest.raises(ValidationError):
            Timings(parse_ms=bad)


def test_probability_sum_tolerance() -> None:
    with pytest.raises(ValidationError):
        make_probabilities(legitime=0.9)  # sums to 0.9
    # within tolerance ±0.000001
    make_probabilities(phishing=0.0000005, legitime=0.9999995)


def test_nullable_distinct_from_empty() -> None:
    parsed = make_parsed_email()
    assert parsed.subject is None
    assert parsed.headers == []
    assert parsed.essential_visual_content is False
    assessment = make_assessment()
    assert assessment.observations == []


def test_minimal_valid_assessment_and_json_roundtrip() -> None:
    assessment = make_assessment()
    data = json.loads(assessment.model_dump_json())
    assert Assessment.model_validate(data) == assessment


def test_state_json_serialization(tmp_path: Path) -> None:
    state = new_state(tmp_path / "x.eml", "fixture", "0" * 64)
    data = json.loads(state.model_dump_json())
    assert data["schema_version"] == "1.0"
    assert data["action"] == "REVIEW"
    assert data["final_source"] == "none"
    assert data["parsed"] is None
    assert data["timings"]["total_ms"] == 0.0
    again = EmailTriageState.model_validate(data)
    assert again.run_id == state.run_id


def test_invalid_enums_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Evidence(
            id="ev_x", provenance="MAGIE", source_kind="parser", observable_id=None,
            predicate="header_value", value="v", source_ref="r",
            observed_at=None, match_level="EXACT", source_group="",
        )
    with pytest.raises(ValidationError):
        new_state(tmp_path / "x.eml", "guessed_profile", "0" * 64)  # type: ignore[arg-method]
    with pytest.raises(ValidationError):
        Evidence(
            id="ev_x", provenance="INTERNE", source_kind="parser", observable_id=None,
            predicate="not_a_predicate", value="v", source_ref="r",
            observed_at=None, match_level="EXACT", source_group="",
        )


def test_valid_observable_minimal() -> None:
    obs = Observable(
        id="obs_" + "0" * 8,
        value="https://example.org/a",
        normalized_value="https://example.org/a",
        type="url",
        provenance="INTERNE",
        source_ref="part:1",
    )
    assert obs.category is None
    assert obs.roles == []
    assert obs.justification == ""


def test_invalid_observable_category_rejected() -> None:
    with pytest.raises(ValidationError):
        Observable(
            id="obs_" + "0" * 8,
            value="https://example.org/a",
            normalized_value="https://example.org/a",
            type="url",
            provenance="INTERNE",
            source_ref="part:1",
            category="X",
        )


def test_gate_and_policy_configs(configs_dir: Path) -> None:
    gate = load_yaml_config(configs_dir / "gate.yaml", GateConfig)
    assert gate.version == 1
    assert gate.min_confidence == 0.90
    assert gate.min_margin == 0.20
    assert gate.enrich_http_urls is True
    assert gate.enrich_non_inline_attachments is True
    assert gate.enrich_on_material_coverage_gap is True

    policy = load_yaml_config(configs_dir / "policy.yaml", PolicyConfig)
    assert policy.auto_min_confidence == 0.97
    assert policy.auto_min_margin == 0.50
    assert policy.escalate_malicious_min_confidence == 0.85
    assert policy.auto_labels == ["legitime", "spam"]


def test_tools_config_exact_sections(configs_dir: Path) -> None:
    tools = load_yaml_config(configs_dir / "tools.yaml", ToolsConfig)
    assert set(ToolsConfig.model_fields) == {
        "virustotal", "opencti", "urlscan", "rag", "vision", "egress", "parse_limits"
    }
    assert tools.virustotal.max_targets == 4
    assert tools.virustotal.phase_timeout_s == 20
    assert tools.virustotal.requests_per_minute == 4
    assert tools.virustotal.requests_per_day == 500
    assert tools.opencti.first == 10
    assert tools.urlscan.max_urls == 1
    assert tools.urlscan.visibility_real == "private"
    assert tools.urlscan.visibility_fixture == "private"
    assert tools.urlscan.first_poll_s == 10
    assert tools.urlscan.poll_interval_s == 5
    assert tools.urlscan.phase_timeout_s == 45
    assert tools.rag.max_cases == 150
    assert tools.rag.k == 3
    assert tools.rag.max_distance == 0.40
    assert tools.rag.max_case_chars == 1200
    assert tools.rag.embedding_model == "all-MiniLM-L6-v2"
    assert tools.vision.max_images == 4
    assert tools.vision.max_image_bytes == 4194304
    assert tools.vision.max_total_bytes == 8388608
    assert tools.vision.max_pixels == 16000000
    assert tools.egress.allow_real_urls is False
    assert tools.egress.approved_services == []
    assert tools.parse_limits.max_eml_bytes == 25 * 1024 * 1024
    assert tools.parse_limits.max_mime_parts == 200
    assert tools.parse_limits.max_mime_depth == 20
    assert tools.parse_limits.max_attachments == 20
    assert tools.parse_limits.max_decoded_bytes_per_part == 20 * 1024 * 1024
    assert tools.parse_limits.max_decoded_bytes_total == 40 * 1024 * 1024


def test_tools_config_rejects_unknown_section(configs_dir: Path, tmp_path: Path) -> None:
    raw = (configs_dir / "tools.yaml").read_text(encoding="utf-8")
    bad = tmp_path / "tools_bad.yaml"
    bad.write_text(raw + "\nunknown_section:\n  foo: 1\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_yaml_config(bad, ToolsConfig)


def test_gate_config_rejects_invalid_boolean(configs_dir: Path, tmp_path: Path) -> None:
    raw = (configs_dir / "gate.yaml").read_text(encoding="utf-8")
    bad = tmp_path / "gate_bad.yaml"
    bad.write_text(raw.replace("enrich_http_urls: true", "enrich_http_urls: yes-please"), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_yaml_config(bad, GateConfig)


def test_gate_result_decision_mandatory() -> None:
    """GateResult always has a decision; 'not yet decided' is state.gate=None."""

    from src.state import GateResult

    gate = GateResult(decision="simple")
    assert gate.reasons == []
    assert gate.rule_hits == {"R1": False, "R2": False, "R3": False}
    gate_complex = GateResult(decision="complex", reasons=["urls_present"])
    assert gate_complex.decision == "complex"
    with pytest.raises(ValidationError):
        GateResult()  # decision is mandatory, never null


def test_assessment_defaults_not_shared() -> None:
    a1, a2 = make_assessment(), make_assessment()
    a1.observations.append("ev_1")
    assert a2.observations == []
    a1.missing_information.append("tool_unavailable")
    assert a2.missing_information == []


def test_nested_required_fields_have_no_defaults() -> None:
    """Inference and ObservableAssessment: nested list fields are required,
    matching schemas/assessment.schema.json (no default_factory)."""

    with pytest.raises(ValidationError):  # Inference.evidence_ids required
        Inference(id="inf_1", code="link_mismatch", summary="s", rag_case_ids=[])
    with pytest.raises(ValidationError):  # Inference.rag_case_ids required
        Inference(id="inf_1", code="link_mismatch", summary="s", evidence_ids=[])
    with pytest.raises(ValidationError):  # ObservableAssessment.evidence_ids required
        ObservableAssessment(observable_id="obs_1", category="B", reason_code="unconfirmed")
    # explicit empty lists are valid (empty != missing)
    Inference(id="inf_1", code="link_mismatch", summary="s", evidence_ids=[], rag_case_ids=[])
    ObservableAssessment(observable_id="obs_1", category="B", evidence_ids=[], reason_code="unconfirmed")


def test_assessment_rejects_more_than_six_inferences() -> None:
    """Schema: at most six inferences."""

    base = dict(make_assessment().model_dump())
    inferences = [
        Inference(id=f"inf_{i}", code="insufficient_information", summary="s", evidence_ids=[], rag_case_ids=[])
        for i in range(7)
    ]
    with pytest.raises(ValidationError):
        Assessment(**{**base, "inferences": inferences})
    Assessment(**{**base, "inferences": inferences[:6]})  # exactly 6 is valid


def test_assessment_rejects_more_than_three_decisive_ids() -> None:
    """Schema: at most three decisive_evidence_ids."""

    base = dict(make_assessment().model_dump())
    with pytest.raises(ValidationError):
        Assessment(**{**base, "decisive_evidence_ids": ["ev_1", "ev_2", "ev_3", "ev_4"]})
    Assessment(**{**base, "decisive_evidence_ids": ["ev_1", "ev_2", "ev_3"]})  # 3 is valid


def test_assessment_rejects_missing_top_level_fields() -> None:
    """Schema-required top-level fields cannot be omitted via defaults."""

    required_fields = set(Assessment.model_fields)
    for omitted in required_fields:
        partial = {k: v for k, v in make_assessment().model_dump().items() if k != omitted}
        with pytest.raises(ValidationError):
            Assessment(**partial)

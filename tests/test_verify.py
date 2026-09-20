"""Deterministic verifier tests (TICKET-10, docs/decisions.md §4.2 V01–V16).

Non-live only. The nominal cases are the REAL archived TICKET-09 captures:

- INTERNAL: ``runs/gates/G2/assessments.jsonl`` (accepted Qwen3.8 assessments);
- FINAL: ``runs/gates/G5/final/`` (accepted xhigh assessment, timeout
  fallback, per-attempt input audits);
- external facts: the real G4 adapter captures (``runs/gates/G4``).

Negative cases deep-copy those real objects and introduce exactly one
controlled violation: they are validator attack tests, never simulated POC
provider responses and never archived. Where no real capture exists (the G4
VT result is ``unavailable/access_not_authorized`` and carries no counter;
no screenshot was downloaded; RAG is inactive), a clearly labelled
controlled verifier input exercises the frozen branch without ever being
counted as a provider observation.
"""

from __future__ import annotations

import copy
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from src.evidence import merge_evidence, signals_gain_without_external_evidence
from src.parsing import ParseLimits, parse_email
from src.prompts import canonical_bytes
from src.state import (
    Assessment,
    Evidence,
    Observable,
    ParsedEmail,
    RagCase,
    TAXONOMY_ORDER,
    ToolResult,
    VerificationIssue,
)
from src.verify import (
    RunContext,
    is_admissible_malicious_confirmation,
    verify_assessment,
)

pytestmark = pytest.mark.g5

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
G2 = PROJECT_ROOT / "runs" / "gates" / "G2"
G4 = PROJECT_ROOT / "runs" / "gates" / "G4"
G5_FINAL = PROJECT_ROOT / "runs" / "gates" / "G5" / "final"

FINAL_MALICIOUS = "malicious_url_redirect"
FINAL_NEWSLETTER = "legitimate_newsletter"


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """The deterministic verifier must never perform network access."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in a verifier test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


# ---------------------------------------------------------------------------
# Real archived captures
# ---------------------------------------------------------------------------


def _internal_rows() -> dict[str, dict[str, Any]]:
    path = G2 / "assessments.jsonl"
    if not path.is_file():
        pytest.fail("real INTERNAL captures missing (TICKET-09 precondition)")
    return {
        json.loads(line)["sample_id"]: json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def _final_rows() -> dict[str, dict[str, Any]]:
    path = G5_FINAL / "final_runs.jsonl"
    if not path.is_file():
        pytest.fail("real FINAL captures missing (TICKET-09 precondition)")
    return {
        json.loads(line)["fixture"]: json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def _final_envelope(name: str) -> dict[str, Any]:
    path = G5_FINAL / name / "final_attempt_1.request.json"
    if not path.is_file():
        pytest.fail(f"real FINAL request capture missing: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    return json.loads(document["messages"][1]["content"])


def _final_assessment(name: str) -> Assessment:
    row = _final_rows()[f"{name}.eml"]
    assert row["final_accepted"] is True, row
    return Assessment.model_validate(row["final_assessment"])


def _parsed(fixture: str) -> ParsedEmail:
    result = parse_email(FIXTURES / fixture, ParseLimits())
    assert isinstance(result, ParsedEmail), f"{fixture}: structured failure {result}"
    return result


def _registry_from_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence": copy.deepcopy(envelope["EVIDENCE_REGISTRY"]),
        "observables": copy.deepcopy(envelope["OBSERVABLE_REGISTRY"]),
    }


def _observable_models(registry: dict[str, Any]) -> dict[str, Observable]:
    return {
        observable_id: Observable.model_validate(observable)
        for observable_id, observable in registry["observables"].items()
    }


def _evidence_models(registry: dict[str, Any]) -> dict[str, Evidence]:
    return {
        evidence_id: Evidence.model_validate(evidence)
        for evidence_id, evidence in registry["evidence"].items()
    }


def _registry_from_parsed(parsed: ParsedEmail) -> dict[str, Any]:
    return {
        "evidence": {entry.id: entry.model_copy(deep=True) for entry in parsed.evidence},
        "observables": {
            entry.id: entry.model_copy(deep=True) for entry in parsed.observables
        },
    }


def _internal_case(sample_id: str) -> tuple[Assessment, dict[str, Any], ParsedEmail]:
    row = _internal_rows()[sample_id]
    parsed = _parsed(row["fixture"])
    assessment = Assessment.model_validate(row["assessment"])
    return assessment, _registry_from_parsed(parsed), parsed


def _codes(result: Any) -> list[str]:
    return [issue.code for issue in result.issues]


def _issues_with(result: Any, code: str) -> list[VerificationIssue]:
    return [issue for issue in result.issues if issue.code == code]


def _assessment_dict(model_or_dict: Any) -> dict[str, Any]:
    if isinstance(model_or_dict, Assessment):
        return model_or_dict.model_dump(mode="json")
    return copy.deepcopy(model_or_dict)


# ---------------------------------------------------------------------------
# Real G4 external evidence (same reconstruction as tests/test_evidence.py)
# ---------------------------------------------------------------------------


def real_g4_tool_results() -> list[ToolResult]:
    files = [
        ("results", G4 / "opencti" / "live_result.json", "results"),
        ("results", G4 / "urlscan" / "live_private_benign_result.json", "results"),
        ("result", G4 / "urlscan" / "live_private_redirect_result.json", "result"),
        ("direct", G4 / "virustotal" / "live_unconfigured_result.json", "direct"),
    ]
    missing = [str(path.relative_to(PROJECT_ROOT)) for _, path, _ in files if not path.is_file()]
    if missing:
        pytest.fail("G4 live captures missing (TICKET-10 precondition): " + ", ".join(missing))
    results: list[ToolResult] = []
    for _kind, path, extraction in files:
        document = json.loads(path.read_text(encoding="utf-8"))
        if extraction == "direct":
            items = [document]
        else:
            value = document.get(extraction)
            items = value if isinstance(value, list) else [value]
        for item in items:
            results.append(ToolResult.model_validate(item))
    return results


def _query_observables_from_captures(observable_ids: set[str]) -> list[Observable]:
    reconstructed: list[Observable] = []
    seen: set[str] = set()
    for meta in sorted(G4.rglob("*.meta.json")):
        try:
            document = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        query = document.get("query")
        if not isinstance(query, dict):
            continue
        observable_id = query.get("observable_id")
        normalized = query.get("normalized_value")
        observable_type = query.get("type")
        if (
            observable_id in observable_ids
            and observable_id not in seen
            and isinstance(normalized, str)
            and isinstance(observable_type, str)
        ):
            seen.add(observable_id)
            reconstructed.append(
                Observable(
                    id=observable_id,
                    value=normalized,
                    normalized_value=normalized,
                    type=observable_type,  # type: ignore[arg-type]
                    roles=[],
                    provenance="INTERNE",
                    source_ref=str(meta.relative_to(PROJECT_ROOT)),
                )
            )
    missing = observable_ids - seen
    if missing:
        pytest.fail(f"no archived query metadata for G4 observables: {sorted(missing)}")
    return reconstructed


def merged_g4_registry(
    fixture: str = "phishing_simple.eml",
) -> tuple[dict[str, Any], list[ToolResult]]:
    """(registry, tool_results) merging a fixture with the real G4 captures."""

    results = real_g4_tool_results()
    parsed = _parsed(fixture)
    query_ids = {
        result.query_observable_id
        for result in results
        if result.query_observable_id is not None and (result.evidence or result.observables)
    }
    reconstructed = _query_observables_from_captures(query_ids)
    parsed = parsed.model_copy(
        update={"observables": [*parsed.observables, *reconstructed]}
    )
    evidence, observables, _visuals = merge_evidence(parsed, results)
    return {"evidence": evidence, "observables": observables}, results


def _external_evidence_id(registry: dict[str, Any], predicate: str) -> str:
    for evidence_id, evidence in registry["evidence"].items():
        if evidence.predicate == predicate and evidence.provenance in ("OSINT", "SANDBOX"):
            return evidence_id
    pytest.fail(f"real G4 captures expose no {predicate!r} evidence")


# ---------------------------------------------------------------------------
# Controlled verifier inputs (documented; never provider observations)
# ---------------------------------------------------------------------------


def _probabilities(**weights: float) -> dict[str, float]:
    values = {label: 0.0 for label in TAXONOMY_ORDER}
    for label, value in weights.items():
        values[label] = float(value)
    return values


def _assessment(
    probabilities: dict[str, float],
    *,
    observations: list[str] | None = None,
    inferences: list[dict[str, Any]] | None = None,
    observable_assessments: list[dict[str, Any]] | None = None,
    needs_enrichment: bool = False,
    missing_information: list[str] | None = None,
    decisive_evidence_ids: list[str] | None = None,
) -> Assessment:
    """Controlled assessment shape for policy/verifier branch inputs."""

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


def _controlled_vt_zero(
    value: float = 0.0,
) -> tuple[dict[str, Any], list[ToolResult], str, str]:
    """Controlled VT counter input (the real G4 VT result is unavailable).

    Exercises the VT-counter branches of V05/V09/V12 only. Never archived,
    never counted as a provider observation.
    """

    digest = "a" * 64
    evidence = Evidence(
        id="ev_controlled_vt_counter",
        provenance="OSINT",
        source_kind="virustotal",
        observable_id="obs_controlled_sha256",
        predicate="vt_malicious_count",
        value=value,
        source_ref="controlled/vt.json#/data/attributes/last_analysis_stats/malicious",
        observed_at="2026-09-19T00:00:00+00:00",
        match_level="EXACT",
    )
    observable = Observable(
        id="obs_controlled_sha256",
        value=digest,
        normalized_value=digest,
        type="sha256",
        roles=["attachment"],
        provenance="INTERNE",
        source_ref="controlled",
        evidence_ids=[evidence.id],
    )
    result = ToolResult(
        tool="virustotal",
        query_observable_id=observable.id,
        status="ok",
        evidence=[evidence],
        observables=[observable],
        response_sha256="b" * 64,
        response_ref="controlled/vt.json",
        collected_at="2026-09-19T00:00:00+00:00",
        mode="live",
        elapsed_ms=1.0,
        requests_sent=1,
    )
    registry = {
        "evidence": {evidence.id: evidence.model_copy(deep=True)},
        "observables": {observable.id: observable.model_copy(deep=True)},
    }
    return registry, [result], evidence.id, observable.id


def _controlled_rag_case(**overrides: Any) -> RagCase:
    base: dict[str, Any] = {
        "case_id": "rag_case_controlled",
        "public_source_url": "https://example.org/public/case",
        "dataset": "controlled_public",
        "record_sha256": "c" * 64,
        "validated_label": "phishing",
        "analyst_validation_ref": "review:controlled",
        "campaign_id": None,
        "duplicate_group": "dg_controlled",
        "family_group": "fg_controlled",
        "text_excerpt": "controlled RAG excerpt",
        "analyst_rationale": "controlled",
        "distance": 0.10,
        "embedding_model_id": "all-MiniLM-L6-v2",
    }
    base.update(overrides)
    return RagCase.model_validate(base)


# ---------------------------------------------------------------------------
# Nominal paths on the real TICKET-09 captures
# ---------------------------------------------------------------------------


def test_nominal_final_real_t09_case_clean_except_v14() -> None:
    """The accepted real xhigh FINAL produces exactly the V14 warning."""

    envelope = _final_envelope(FINAL_MALICIOUS)
    assessment = _final_assessment(FINAL_MALICIOUS)
    internal = Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"])
    parsed = _parsed("malicious_url_redirect.eml")
    result = verify_assessment(
        assessment,
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=parsed,
        rag_context=[],
        internal=internal,
        run_context=RunContext(
            final_source="final_llm",
            external_evidence_count_sent=0,
            visual_count_sent=0,
        ),
    )
    assert result.accepted is not None
    assert _codes(result) == ["confidence_rise_without_new_evidence"]
    assert result.issues[0].severity == "warning"
    assert result.verdict == "phishing"
    assert result.confidence == pytest.approx(0.88)
    assert result.verdict_changed is False
    assert result.blocking_codes == ["confidence_rise_without_new_evidence"]
    # The recipient actor is never part of the accepted IOC list.
    assert all("victime@example.org" != observable.normalized_value for observable in result.accepted_observables)
    assert any("victime@example.org" == observable.normalized_value for observable in result.excluded_observables)
    assert not result.unsupported_claims


def test_nominal_internal_real_newsletter_is_clean() -> None:
    assessment, registry, parsed = _internal_case("legitimate_newsletter_rep1")
    result = verify_assessment(
        assessment, "internal", registry, tool_results=[], parsed=parsed, rag_context=[]
    )
    assert result.issues == []
    assert result.accepted is not None
    assert result.verdict == "legitime"


def test_verifier_output_is_deterministic_and_stable() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    assessment = _final_assessment(FINAL_MALICIOUS)
    internal = Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"])
    parsed = _parsed("malicious_url_redirect.eml")
    registry = _registry_from_envelope(envelope)
    context = RunContext(final_source="final_llm", external_evidence_count_sent=0)

    first = verify_assessment(
        assessment, "final", registry, [], parsed, [], internal=internal, run_context=context
    )
    again = verify_assessment(
        assessment, "final", registry, [], parsed, [], internal=internal, run_context=context
    )
    assert canonical_bytes(first.to_dict()) == canonical_bytes(again.to_dict())
    assert _codes(first) == _codes(again)
    assert [issue.severity for issue in first.issues] == [
        issue.severity for issue in again.issues
    ]


# ---------------------------------------------------------------------------
# V01 — strict schema / probabilities / argmax
# ---------------------------------------------------------------------------


def test_v01_invalid_probabilities_reject_without_repair() -> None:
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    corrupted = _assessment_dict(row["final_assessment"])
    corrupted["probabilities"]["legitime"] = 0.5  # sum no longer 1
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        corrupted, "final", _registry_from_envelope(envelope), [], None, []
    )
    assert result.accepted is None
    issues = _issues_with(result, "invalid_assessment")
    assert issues and issues[0].severity == "error"
    # never renormalized / repaired
    assert corrupted["probabilities"]["legitime"] == 0.5


def test_v01_missing_assessment_is_explicit() -> None:
    result = verify_assessment(None, "final", None, [], None, [])
    assert result.accepted is None
    issues = _issues_with(result, "missing_assessment")
    assert issues and issues[0].severity == "error"


def test_v01_extra_field_is_rejected() -> None:
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    corrupted = _assessment_dict(row["final_assessment"])
    corrupted["free_form_verdict"] = "benign"
    result = verify_assessment(corrupted, "final", None, [], None, [])
    assert result.accepted is None
    assert _issues_with(result, "invalid_assessment")


# ---------------------------------------------------------------------------
# V02 — references exist in the input actually provided
# ---------------------------------------------------------------------------


def test_v02_unknown_evidence_reference_is_critical_unsupported_claim() -> None:
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    corrupted = _assessment_dict(row["final_assessment"])
    corrupted["observations"][0] = "ev_does_not_exist"
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        corrupted, "final", _registry_from_envelope(envelope), [], None, []
    )
    assert result.accepted is not None  # structurally valid, kept for audit
    issues = _issues_with(result, "unsupported_claim")
    assert issues and issues[0].severity == "critical"
    assert "ev_does_not_exist" in issues[0].message


def test_v02_unknown_observable_and_rag_references_are_critical() -> None:
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    corrupted = _assessment_dict(row["final_assessment"])
    corrupted["observable_assessments"][0]["observable_id"] = "obs_does_not_exist"
    corrupted["inferences"][0]["rag_case_ids"] = ["rag_does_not_exist"]
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        corrupted, "final", _registry_from_envelope(envelope), [], None, []
    )
    issues = _issues_with(result, "unsupported_claim")
    assert len(issues) == 2
    assert all(issue.severity == "critical" for issue in issues)


# ---------------------------------------------------------------------------
# V03 — LLM cannot create or alter an Observable
# ---------------------------------------------------------------------------


def test_v03_fabricated_observable_is_excluded_from_accepted() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    fabricated = Observable(
        id="obs_fabricated_attacker",
        value="attacker.example",
        normalized_value="attacker.example",
        type="domain",
        roles=["sender"],
        provenance="INTERNE",
        source_ref="headers:from",
    )
    registry["observables"][fabricated.id] = fabricated
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        registry,
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    issues = _issues_with(result, "fabricated_ioc")
    assert issues and issues[0].severity == "critical"
    assert fabricated.id not in {o.id for o in result.accepted_observables}
    assert fabricated.id in {o.id for o in result.excluded_observables}
    assert "attacker.example" not in {
        o.normalized_value for o in result.accepted_observables
    }


def test_v03_altered_observable_is_excluded() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    victim = next(iter(registry["observables"]))
    registry["observables"][victim]["normalized_value"] = "attacker.example"
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        registry,
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    issues = _issues_with(result, "fabricated_ioc")
    assert issues and "differs from its real producer" in issues[0].message
    assert victim in {o.id for o in result.excluded_observables}


# ---------------------------------------------------------------------------
# V04 — provenance must match the producer
# ---------------------------------------------------------------------------


def test_v04_parser_evidence_claiming_osint_is_critical() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    evidence_id = next(iter(registry["evidence"]))
    registry["evidence"][evidence_id]["provenance"] = "OSINT"
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        registry,
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    issues = _issues_with(result, "impossible_provenance")
    assert issues and issues[0].severity == "critical"


def test_v04_interpretation_cannot_become_fact() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    evidence_id = next(iter(registry["evidence"]))
    registry["evidence"][evidence_id]["provenance"] = "INFERENCE"
    result = verify_assessment(
        Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"]),
        "internal",
        {"evidence": registry["evidence"], "observables": registry["observables"]},
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    assert _issues_with(result, "impossible_provenance")


# ---------------------------------------------------------------------------
# V05 — external facts must match a real ok archived response
# ---------------------------------------------------------------------------


def _assessment_citing(evidence_id: str) -> Assessment:
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    corrupted = _assessment_dict(row["final_assessment"])
    corrupted["observations"][0] = evidence_id
    return Assessment.model_validate(corrupted)


def test_v05_real_external_fact_is_supported() -> None:
    registry, results = merged_g4_registry()
    external_id = _external_evidence_id(registry, "cti_exact_match")
    result = verify_assessment(
        _assessment_citing(external_id),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    assert not _issues_with(result, "unsupported_external_fact")


def test_v05_false_external_counter_is_critical() -> None:
    """False counter/URL/UUID: registry copy altered, archived result intact."""

    registry, results = merged_g4_registry()
    registry = copy.deepcopy(registry)
    external_id = _external_evidence_id(registry, "cti_score")
    registry["evidence"][external_id].value = 99.0
    result = verify_assessment(
        _assessment_citing(external_id),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "unsupported_external_fact")
    assert issues and issues[0].severity == "critical"
    assert "false counter" in issues[0].message


def test_v05_external_fact_from_non_ok_result_is_critical() -> None:
    registry, results = merged_g4_registry()
    external_id = _external_evidence_id(registry, "cti_exact_match")
    corrupted_results = copy.deepcopy(results)
    for tool_result in corrupted_results:
        if any(entry.id == external_id for entry in tool_result.evidence):
            tool_result.status = "not_found"
    result = verify_assessment(
        _assessment_citing(external_id),
        "final",
        registry,
        tool_results=corrupted_results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "unsupported_external_fact")
    assert issues and "non-ok or unarchived" in issues[0].message


def test_v05_external_fact_without_tool_results_fails_closed() -> None:
    registry, _results = merged_g4_registry()
    external_id = _external_evidence_id(registry, "cti_exact_match")
    result = verify_assessment(
        _assessment_citing(external_id),
        "final",
        registry,
        tool_results=None,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "unsupported_external_fact")
    assert issues and issues[0].severity == "critical"


def test_v05_false_vt_counter_is_critical() -> None:
    """Direct false VT counter: the registry copy says 1, the tool result 0."""

    registry, results, evidence_id, _observable_id = _controlled_vt_zero()
    registry["evidence"][evidence_id].value = 1.0
    result = verify_assessment(
        _assessment(
            _probabilities(phishing=0.9, legitime=0.1),
            observations=[evidence_id],
        ),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "unsupported_external_fact")
    assert issues and issues[0].severity == "critical"
    assert "false counter" in issues[0].message


def test_v05_invented_sandbox_redirect_chain_is_critical() -> None:
    registry, results = merged_g4_registry()
    registry = copy.deepcopy(registry)
    redirect_id = _external_evidence_id(registry, "sandbox_redirect")
    original = registry["evidence"][redirect_id].value
    registry["evidence"][redirect_id].value = "https://invented.invalid/step"
    assert registry["evidence"][redirect_id].value != original
    result = verify_assessment(
        _assessment_citing(redirect_id),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "unsupported_external_fact")
    assert issues and issues[0].severity == "critical"


def test_v05_controlled_vt_counter_matches_its_archived_shape() -> None:
    """Controlled VT counter (real G4 VT is unavailable): no false positive."""

    registry, results, evidence_id, _observable_id = _controlled_vt_zero()
    result = verify_assessment(
        _assessment(  # controlled benign shape citing the counter
            _probabilities(legitime=0.99, spam=0.01),
            observations=[evidence_id],
        ),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    assert not _issues_with(result, "unsupported_external_fact")


# ---------------------------------------------------------------------------
# V06 — exact evidence applies to the exact same observable
# ---------------------------------------------------------------------------


def test_v06_url_evidence_on_parent_domain_is_false_exact_match() -> None:
    registry, results = merged_g4_registry()
    registry = copy.deepcopy(registry)
    url_evidence_id = _external_evidence_id(registry, "sandbox_final_url")
    parsed = _parsed("phishing_simple.eml")
    domain = next(o for o in parsed.observables if o.type == "domain")
    registry["evidence"][url_evidence_id].observable_id = domain.id
    result = verify_assessment(
        _assessment_citing(url_evidence_id),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "false_exact_match")
    assert issues and issues[0].severity == "error"


def test_v06_exact_evidence_for_another_query_is_false_exact_match() -> None:
    registry, results = merged_g4_registry()
    registry = copy.deepcopy(registry)
    external_id = _external_evidence_id(registry, "cti_exact_match")
    other = next(
        observable.id
        for observable in registry["observables"].values()
        if observable.id != registry["evidence"][external_id].observable_id
    )
    registry["evidence"][external_id].observable_id = other
    result = verify_assessment(
        _assessment_citing(external_id),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "false_exact_match")
    assert issues and "produced for observable" in issues[0].message


# ---------------------------------------------------------------------------
# V07 — recipients never become IOCs
# ---------------------------------------------------------------------------


def test_v07_real_recipient_is_excluded_without_false_alarm() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    parsed = _parsed("malicious_url_redirect.eml")
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=parsed,
        rag_context=[],
    )
    assert not _issues_with(result, "recipient_as_ioc")
    assert all(
        observable.normalized_value.lower() not in parsed.to_addresses
        for observable in result.accepted_observables
    )


def test_v07_recipient_smuggled_as_ioc_is_critical() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    parsed = _parsed("malicious_url_redirect.eml")
    recipient_id = next(
        observable_id
        for observable_id, observable in _observable_models(registry).items()
        if observable.type == "email"
        and observable.normalized_value.lower() in parsed.to_addresses
    )
    registry["observables"][recipient_id]["roles"] = ["link_target"]
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        registry,
        tool_results=[],
        parsed=parsed,
        rag_context=[],
    )
    issues = _issues_with(result, "recipient_as_ioc")
    assert issues and issues[0].severity == "critical"
    assert recipient_id in {o.id for o in result.excluded_observables}


def test_v07_model_proposing_recipient_as_ioc_is_critical() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    parsed = _parsed("malicious_url_redirect.eml")
    registry = _registry_from_envelope(envelope)
    recipient_id = next(
        observable_id
        for observable_id, observable in _observable_models(registry).items()
        if observable.type == "email"
        and observable.normalized_value.lower() in parsed.to_addresses
    )
    corrupted = _assessment_dict(_final_assessment(FINAL_MALICIOUS))
    corrupted["observable_assessments"].append(
        {
            "observable_id": recipient_id,
            "category": "S",
            "evidence_ids": [],
            "reason_code": "unconfirmed",
        }
    )
    result = verify_assessment(
        corrupted, "final", registry, [], parsed, []
    )
    issues = _issues_with(result, "recipient_as_ioc")
    assert issues and issues[0].severity == "critical"


# ---------------------------------------------------------------------------
# V08 — protected roles / hosts cannot inherit M/S
# ---------------------------------------------------------------------------


def test_v08_shared_host_cannot_inherit_url_category() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    parsed = _parsed("malicious_url_redirect.eml")
    host_id = next(
        observable_id
        for observable_id, observable in _observable_models(registry).items()
        if observable.type == "domain"
    )
    url_evidence_id = next(
        evidence_id
        for evidence_id, evidence in _evidence_models(registry).items()
        if evidence.predicate == "url_found"
    )
    registry["observables"][host_id]["roles"] = ["shared_host"]
    corrupted = _assessment_dict(_final_assessment(FINAL_MALICIOUS))
    for entry in corrupted["observable_assessments"]:
        if entry["observable_id"] == host_id:
            entry["category"] = "S"
            entry["evidence_ids"] = [url_evidence_id]
    result = verify_assessment(corrupted, "final", registry, [], parsed, [])
    issues = _issues_with(result, "unjustified_global_attribution")
    assert issues and issues[0].severity == "error"


def test_v08_brand_without_precise_evidence_is_error() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    parsed = _parsed("malicious_url_redirect.eml")
    sender_id = next(
        observable_id
        for observable_id, observable in _observable_models(registry).items()
        if observable.type == "email" and "sender" in observable.roles
    )
    header_evidence_id = next(
        evidence_id
        for evidence_id, evidence in _evidence_models(registry).items()
        if evidence.predicate == "header_value"
    )
    registry["observables"][sender_id]["roles"] = ["displayed_brand"]
    corrupted = _assessment_dict(_final_assessment(FINAL_MALICIOUS))
    for entry in corrupted["observable_assessments"]:
        if entry["observable_id"] == sender_id:
            entry["category"] = "M"
            entry["evidence_ids"] = [header_evidence_id]
    result = verify_assessment(corrupted, "final", registry, [], parsed, [])
    assert _issues_with(result, "unjustified_global_attribution")
    # and the M proposal is also refused by V09
    assert _issues_with(result, "insufficient_malicious_confirmation")


# ---------------------------------------------------------------------------
# V09 — M requires the admissible exact confirmation
# ---------------------------------------------------------------------------


def test_v09_real_internal_m_without_confirmation_is_rejected() -> None:
    """Real TICKET-09-relevant case: the internal URL proposal is M with only
    INTERNAL evidence; V09 refuses it (the FINAL later revised it to S)."""

    assessment, registry, parsed = _internal_case("malicious_url_redirect_rep1")
    result = verify_assessment(assessment, "internal", registry, [], parsed, [])
    issues = _issues_with(result, "insufficient_malicious_confirmation")
    assert issues and issues[0].severity == "error"


def test_v09_cti_presence_and_labels_are_not_confirmations() -> None:
    registry, results = merged_g4_registry()
    exact_id = _external_evidence_id(registry, "cti_exact_match")
    label_id = _external_evidence_id(registry, "cti_label")
    observable_id = registry["evidence"][exact_id].observable_id
    result = verify_assessment(
        _assessment(
            _probabilities(phishing=0.9, legitime=0.1),
            observable_assessments=[
                {
                    "observable_id": observable_id,
                    "category": "M",
                    "evidence_ids": [exact_id, label_id],
                    "reason_code": "attack_artifact",
                }
            ],
        ),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "insufficient_malicious_confirmation")
    assert issues and issues[0].severity == "error"


def test_v09_zero_vt_counter_is_not_a_confirmation() -> None:
    registry, results, evidence_id, observable_id = _controlled_vt_zero()
    result = verify_assessment(
        _assessment(
            _probabilities(phishing=0.9, legitime=0.1),
            observable_assessments=[
                {
                    "observable_id": observable_id,
                    "category": "M",
                    "evidence_ids": [evidence_id],
                    "reason_code": "attack_artifact",
                }
            ],
        ),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    assert _issues_with(result, "insufficient_malicious_confirmation")


def test_v09_admissible_sandbox_confirmation_shape_is_recognized() -> None:
    """Controlled corrupt copy (validator attack inverse): flipping the real
    urlscan provider assertion to True exercises the V09 branch; never
    archived, never a provider observation."""

    registry, results = merged_g4_registry()
    malicious_id = _external_evidence_id(registry, "sandbox_provider_malicious")
    evidence = registry["evidence"][malicious_id]
    assert is_admissible_malicious_confirmation(evidence, evidence.observable_id) is False
    corrupted = evidence.model_copy(deep=True, update={"value": True})
    assert is_admissible_malicious_confirmation(corrupted, corrupted.observable_id) is True


# ---------------------------------------------------------------------------
# V10 — sandbox assertions / screenshot evidence
# ---------------------------------------------------------------------------


def _merged_with_screenshot() -> tuple[dict[str, Any], list[ToolResult], str, str]:
    """Corrupt copy of a real urlscan result carrying a screenshot assertion."""

    results = real_g4_tool_results()
    parsed = _parsed("phishing_simple.eml")
    urlscan_ok = next(
        result for result in results if result.tool == "urlscan" and result.status == "ok"
    )
    screenshot = Evidence(
        id="ev_controlled_sandbox_screenshot",
        provenance="SANDBOX",
        source_kind="urlscan",
        observable_id=urlscan_ok.query_observable_id,
        predicate="sandbox_screenshot",
        value="d" * 64,
        source_ref=f"{urlscan_ok.response_ref}#/screenshot",
        observed_at=urlscan_ok.collected_at,
        match_level="EXACT",
    )
    corrupted_result = urlscan_ok.model_copy(deep=True)
    corrupted_result.evidence = [*corrupted_result.evidence, screenshot]
    query_ids = {
        result.query_observable_id
        for result in results
        if result.query_observable_id is not None and (result.evidence or result.observables)
    }
    reconstructed = _query_observables_from_captures(query_ids)
    parsed = parsed.model_copy(update={"observables": [*parsed.observables, *reconstructed]})
    merged_results = [corrupted_result if result is urlscan_ok else result for result in results]
    evidence, observables, _visuals = merge_evidence(parsed, merged_results)
    return (
        {"evidence": evidence, "observables": observables},
        merged_results,
        screenshot.id,
        urlscan_ok.query_observable_id,
    )


def test_v10_screenshot_assertion_without_pixels_is_error() -> None:
    registry, results, screenshot_id, observable_id = _merged_with_screenshot()
    result = verify_assessment(
        _assessment(
            _probabilities(phishing=0.9, legitime=0.1),
            observations=[screenshot_id],
            observable_assessments=[
                {
                    "observable_id": observable_id,
                    "category": "S",
                    "evidence_ids": [screenshot_id],
                    "reason_code": "unconfirmed",
                }
            ],
        ),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
        run_context=RunContext(visual_count_sent=0),
    )
    issues = _issues_with(result, "screenshot_not_provided")
    assert issues and issues[0].severity == "error"


def test_v10_sandbox_assertion_without_archived_scan_is_critical() -> None:
    registry, results = merged_g4_registry()
    registry = copy.deepcopy(registry)
    sandbox_id = _external_evidence_id(registry, "sandbox_final_url")
    corrupted_results = copy.deepcopy(results)
    for tool_result in corrupted_results:
        if any(entry.id == sandbox_id for entry in tool_result.evidence):
            tool_result.scan_id = None
    result = verify_assessment(
        _assessment_citing(sandbox_id),
        "final",
        registry,
        tool_results=corrupted_results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "invented_sandbox_assertion")
    assert issues and issues[0].severity == "critical"


# ---------------------------------------------------------------------------
# V11 — external reasons / targeting support
# ---------------------------------------------------------------------------


def test_v11_real_internal_external_support_without_osint_is_error() -> None:
    assessment, registry, parsed = _internal_case("shared_infra_benign_rep1")
    result = verify_assessment(assessment, "internal", registry, [], parsed, [])
    issues = _issues_with(result, "unsupported_external_claim")
    assert issues and issues[0].severity == "error"


def test_v11_targeting_with_only_actor_header_is_error() -> None:
    assessment, registry, parsed = _internal_case("spear_phishing_targeted_rep1")
    recipient_evidence = next(
        evidence_id
        for evidence_id, evidence in registry["evidence"].items()
        if evidence.predicate == "header_value"
        and any(address in str(evidence.value).lower() for address in parsed.to_addresses)
    )
    corrupted = _assessment_dict(assessment)
    for inference in corrupted["inferences"]:
        if inference["code"] == "targeted_context":
            inference["evidence_ids"] = [recipient_evidence]
    result = verify_assessment(corrupted, "internal", registry, [], parsed, [])
    issues = _issues_with(result, "targeting_without_context")
    assert issues and issues[0].severity == "error"


def test_v11_real_targeting_with_subject_context_is_clean() -> None:
    assessment, registry, parsed = _internal_case("spear_phishing_targeted_rep1")
    result = verify_assessment(assessment, "internal", registry, [], parsed, [])
    assert not _issues_with(result, "targeting_without_context")
    assert not _issues_with(result, "unsupported_external_claim")


# ---------------------------------------------------------------------------
# V12 — benignity cannot rest on absence of detection
# ---------------------------------------------------------------------------


def test_v12_real_benign_with_substantive_evidence_is_clean() -> None:
    assessment, registry, parsed = _internal_case("legitimate_newsletter_rep1")
    result = verify_assessment(assessment, "internal", registry, [], parsed, [])
    assert not _issues_with(result, "benign_insufficient_basis")


def test_v12_auth_pass_alone_is_not_a_benign_basis() -> None:
    parsed = _parsed("phishing_auth_pass.eml")
    registry = _registry_from_parsed(parsed)
    auth_evidence = next(
        evidence
        for evidence in parsed.evidence
        if evidence.predicate == "auth_reported" and "pass" in str(evidence.value).lower()
    )
    result = verify_assessment(
        _assessment(
            _probabilities(legitime=0.99, spam=0.01),
            observations=[auth_evidence.id],
        ),
        "internal",
        registry,
        tool_results=[],
        parsed=parsed,
        rag_context=[],
    )
    issues = _issues_with(result, "benign_insufficient_basis")
    assert issues and issues[0].severity == "error"


def test_v12_no_evidence_at_all_is_not_a_benign_basis() -> None:
    result = verify_assessment(
        _assessment(_probabilities(legitime=0.99, spam=0.01)),
        "internal",
        None,
        [],
        None,
        [],
    )
    assert _issues_with(result, "benign_insufficient_basis")


def test_v12_zero_vt_detection_alone_is_not_a_benign_basis() -> None:
    registry, results, evidence_id, _observable_id = _controlled_vt_zero()
    result = verify_assessment(
        _assessment(
            _probabilities(legitime=0.99, spam=0.01),
            observations=[evidence_id],
        ),
        "final",
        registry,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "benign_insufficient_basis")
    assert issues and issues[0].severity == "error"


# ---------------------------------------------------------------------------
# V13 — explicit malicious evidence / material reasons vs benign verdict
# ---------------------------------------------------------------------------


def test_v13_admissible_confirmation_with_benign_verdict_conflicts() -> None:
    registry, results = merged_g4_registry()
    malicious_id = _external_evidence_id(registry, "sandbox_provider_malicious")
    corrupted = copy.deepcopy(registry)
    corrupted["evidence"][malicious_id].value = True
    result = verify_assessment(
        _assessment(
            _probabilities(legitime=0.99, spam=0.01),
            observations=[malicious_id],
        ),
        "final",
        corrupted,
        tool_results=results,
        parsed=None,
        rag_context=[],
    )
    issues = _issues_with(result, "verdict_evidence_conflict")
    assert issues and issues[0].severity == "error"


def test_v13_credential_collection_with_benign_verdict_conflicts() -> None:
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    corrupted = _assessment_dict(row["final_assessment"])
    corrupted["probabilities"] = _probabilities(legitime=0.90, spam=0.05, phishing=0.03, fraude=0.01, menace=0.01)
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        corrupted,
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    issues = _issues_with(result, "verdict_evidence_conflict")
    assert issues and issues[0].severity == "error"


# ---------------------------------------------------------------------------
# V14 — verdict/confidence gain without new evidence (real T09 case)
# ---------------------------------------------------------------------------


def test_v14_real_t09_case_confidence_rise_without_external_evidence() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    row = _final_rows()[f"{FINAL_MALICIOUS}.eml"]
    internal = Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"])
    final = _final_assessment(FINAL_MALICIOUS)
    assert row["internal_confidence"] == pytest.approx(0.82)
    assert row["final_confidence"] == pytest.approx(0.88)
    assert row["external_evidence_count_sent"] == 0

    result = verify_assessment(
        final,
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
        internal=internal,
        run_context=RunContext(
            final_source="final_llm",
            external_evidence_count_sent=row["external_evidence_count_sent"],
        ),
    )
    issues = _issues_with(result, "confidence_rise_without_new_evidence")
    assert issues and issues[0].severity == "warning"
    assert issues[0].code in result.blocking_codes
    assert not _issues_with(result, "invalid_assessment")
    # the frozen T09 signal agrees with V14
    assert signals_gain_without_external_evidence(
        internal, final, row["external_evidence_count_sent"]
    )


def test_v14_new_external_evidence_does_not_flag() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    internal = Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"])
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
        internal=internal,
        run_context=RunContext(
            final_source="final_llm",
            external_evidence_count_sent=2,
        ),
    )
    assert not _issues_with(result, "confidence_rise_without_new_evidence")


def test_v14_identical_vectors_do_not_flag() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    internal = Assessment.model_validate(envelope["INTERNAL_ASSESSMENT"])
    result = verify_assessment(
        internal,
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
        internal=internal,
        run_context=RunContext(
            final_source="internal_copy",
            external_evidence_count_sent=0,
        ),
    )
    assert not _issues_with(result, "confidence_rise_without_new_evidence")
    assert result.verdict_changed is False


# ---------------------------------------------------------------------------
# V15 — RAG contamination controls
# ---------------------------------------------------------------------------


def test_v15_rag_inactive_baseline_has_no_rag_issue() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    assert not [code for code in _codes(result) if code.startswith("rag")]


def test_v15_related_group_case_is_contamination() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    case = _controlled_rag_case(duplicate_group="dg_current")
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[case],
        run_context=RunContext(current_duplicate_group="dg_current"),
    )
    issues = _issues_with(result, "rag_contamination")
    assert issues and issues[0].severity == "critical"


def test_v15_family_and_campaign_groups_are_contamination() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    case = _controlled_rag_case(family_group="fg_current", campaign_id="camp_current")
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[case],
        run_context=RunContext(
            current_family_group="fg_current", current_campaign_id="camp_current"
        ),
    )
    assert _issues_with(result, "rag_contamination")


def test_v15_neighbour_observable_in_registry_is_contamination() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    registry = _registry_from_envelope(envelope)
    neighbour = Observable(
        id="obs_rag_neighbour",
        value="neighbour.example",
        normalized_value="neighbour.example",
        type="domain",
        roles=["shared_host"],
        provenance="INFERENCE",
        source_ref="rag:rag_case_controlled",
    )
    registry["observables"][neighbour.id] = neighbour
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        registry,
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    assert _issues_with(result, "rag_contamination")
    assert _issues_with(result, "fabricated_ioc")
    assert neighbour.id in {o.id for o in result.excluded_observables}


# ---------------------------------------------------------------------------
# V16 — run/tool/fallback/timing/usage consistency
# ---------------------------------------------------------------------------


def test_v16_real_fallback_blocks_auto_without_technical_error() -> None:
    assessment, registry, parsed = _internal_case("legitimate_newsletter_rep1")
    result = verify_assessment(
        assessment,
        "final",
        registry,
        tool_results=[],
        parsed=parsed,
        rag_context=[],
        run_context=RunContext(final_source="internal_fallback"),
    )
    issues = _issues_with(result, "final_fallback_internal_copy")
    assert issues and issues[0].severity == "warning"
    assert not _issues_with(result, "run_inconsistency")


def test_v16_negative_timing_is_a_technical_error() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
        run_context={"final_source": "final_llm", "timings": {"total_ms": -1.0}},
    )
    assert _issues_with(result, "run_inconsistency")


def test_v16_ok_tool_without_archive_is_an_error() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    results = real_g4_tool_results()
    corrupted = copy.deepcopy(results)
    ok_result = next(result for result in corrupted if result.status == "ok")
    ok_result.response_ref = None
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=corrupted,
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    assert _issues_with(result, "run_inconsistency")


def test_v16_verdict_comparison_is_nullable_without_internal() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
    )
    assert result.verdict_changed is None  # never False when comparison is impossible


def test_v16_final_source_none_with_assessment_is_an_error() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
        run_context=RunContext(final_source="none"),
    )
    assert _issues_with(result, "run_inconsistency")


def test_v16_invalid_final_source_is_an_error() -> None:
    envelope = _final_envelope(FINAL_MALICIOUS)
    result = verify_assessment(
        _final_assessment(FINAL_MALICIOUS),
        "final",
        _registry_from_envelope(envelope),
        tool_results=[],
        parsed=_parsed("malicious_url_redirect.eml"),
        rag_context=[],
        run_context=RunContext(final_source="not_a_source"),
    )
    assert _issues_with(result, "run_inconsistency")

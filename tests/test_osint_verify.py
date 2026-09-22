"""TICKET-19D-OSINT §30/§37 — controlled verifier observations for OSINT evidence.

Offline only: every provider observation below is a CONTROLLED test object
fed to the deterministic verifier (``src.verify.verify_assessment``), never
presented as a live provider response. No network, no ``gold_test``.

Status after U1 (``IMPLEMENTED_OSINT_VERIFIER_UNBLOCKED``): the verifier maps
``source_kind="osint"`` to provenance ``OSINT`` (one entry in
``PROVENANCE_BY_PRODUCER``; V09 strictly unchanged), i.e.
``verifier_osint_behavior=compatible_not_confirming``:

- cases A/B (an assessment citing REAL OSINT evidence with
  ``source_kind="osint"``): NO ``impossible_provenance`` anymore, no
  exception, ``accepted`` kept. Case A additionally keeps
  ``insufficient_malicious_confirmation`` (V09 only admits
  ``sandbox_provider_malicious``): a ThreatFox hit is visible context, never
  an admissible malicious confirmation. The ticket declares this NON
  BLOQUANT.
- case C (benign verdict, ``ToolResult(osint)`` ``not_found``, no positive
  evidence): ``benign_insufficient_basis`` (V12) — the absence is treated as
  an absence of confirmation, never as positive proof of legitimacy.
- case D (citing a nonexistent OSINT evidence ID): ``unsupported_claim``
  (V02), exactly like any other unknown evidence ID.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.parsing import ParseLimits, parse_email
from src.state import Evidence, Observable, ParsedEmail, ToolResult
from src.verify import verify_assessment

OBSERVED_AT = "2026-09-22T12:00:00+00:00"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _parsed() -> ParsedEmail:
    result = parse_email(PROJECT_ROOT / "tests" / "fixtures" / "phishing_simple.eml", ParseLimits())
    assert isinstance(result, ParsedEmail)
    return result


def _domain_observable(parsed: ParsedEmail) -> Observable:
    for observable in parsed.observables:
        if observable.type == "domain":
            return observable
    raise AssertionError("fixture has no domain observable")


def _osint_evidence(
    predicate: str,
    observable_id: str,
    value: Any,
    source_group: str,
    suffix: str,
) -> Evidence:
    return Evidence(
        id=f"ev_osint_{suffix}",
        provenance="OSINT",
        source_kind="osint",
        observable_id=observable_id,
        predicate=predicate,  # type: ignore[arg-type]
        value=value,
        source_ref=f"osint_bundle_abcd.json#/{source_group}/{suffix}",
        observed_at=OBSERVED_AT,
        match_level="EXACT",
        source_group=source_group,
    )


def _osint_tool_result(
    observable_id: str,
    evidence: list[Evidence],
    *,
    status: str = "ok",
) -> ToolResult:
    return ToolResult(
        tool="osint",
        query_observable_id=observable_id,
        status=status,  # type: ignore[arg-type]
        evidence=evidence,
        observables=[],
        response_sha256="b" * 64 if status == "ok" else None,
        response_ref="osint_bundle_abcd.json" if status == "ok" else None,
        collected_at=OBSERVED_AT,
        mode="live",
        elapsed_ms=3.0,
        requests_sent=3 if status == "ok" else 2,
    )


def _assessment(
    *,
    verdict_phishing: bool,
    observations: list[str],
    inferences: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "probabilities": {
            "spear_phishing": 0.0,
            "phishing": 0.9 if verdict_phishing else 0.0,
            "fraude": 0.0,
            "menace": 0.0,
            "spam": 0.0,
            "legitime": 0.1 if verdict_phishing else 1.0,
        },
        "observations": observations,
        "inferences": inferences,
        "observable_assessments": [],
        "needs_enrichment": False,
        "missing_information": [],
        "decisive_evidence_ids": [],
    }


def _codes(result: Any) -> list[str]:
    return [issue.code for issue in result.issues]


# ---------------------------------------------------------------------------
# Case A — malicious assessment citing osint_threatfox_match
# ---------------------------------------------------------------------------


def test_case_a_threatfox_match_compatible_not_confirming() -> None:
    parsed = _parsed()
    observable = _domain_observable(parsed)
    evidence = _osint_evidence(
        "osint_threatfox_match", observable.id, True, "threatfox", "tf_match"
    )
    tool_result = _osint_tool_result(observable.id, [evidence])
    registries = {
        "evidence": {entry.id: entry for entry in [*parsed.evidence, evidence]},
        "observables": {entry.id: entry for entry in parsed.observables},
    }
    candidate = _assessment(
        verdict_phishing=True,
        observations=[evidence.id],
        inferences=[
            {
                "id": "inf_1",
                "code": "external_support",
                "summary": "threatfox hit on the exact domain",
                "evidence_ids": [evidence.id],
                "rag_case_ids": [],
            }
        ],
    )
    candidate["observable_assessments"] = [
        {
            "observable_id": observable.id,
            "category": "M",
            "evidence_ids": [evidence.id],
            "reason_code": "attack_artifact",
        }
    ]
    result = verify_assessment(
        candidate,
        "final",
        registry=registries,
        tool_results=[tool_result],
        parsed=parsed,
        rag_context=[],
    )
    # No exception: the verifier answers deterministically and keeps the
    # structurally valid assessment for audit.
    assert result.accepted is not None
    # U1 structural compatibility: source_kind="osint" maps to provenance
    # OSINT, so V04 no longer refuses the OSINT evidence.
    assert "impossible_provenance" not in _codes(result)
    # V09 strictly unchanged (U1 §4): a ThreatFox hit is NOT an admissible
    # malicious confirmation (only sandbox_provider_malicious admits M), so
    # the M proposal is refused as insufficiently confirmed. Expected and
    # NON BLOQUANT (compatible_not_confirming).
    assert "insufficient_malicious_confirmation" in _codes(result)


# ---------------------------------------------------------------------------
# Case B — RDAP / DNS / CT evidence used as context
# ---------------------------------------------------------------------------


def test_case_b_rdap_dns_ct_context_compatible() -> None:
    parsed = _parsed()
    observable = _domain_observable(parsed)
    evidences = [
        _osint_evidence(
            "osint_rdap_registration_date",
            observable.id,
            "2019-04-12T00:00:00+00:00",
            "rdap",
            "rdap_reg",
        ),
        _osint_evidence("osint_dns_a", observable.id, "93.184.216.34", "dns", "dns_a"),
        _osint_evidence(
            "osint_ct_certificate_count", observable.id, 4.0, "certificate_transparency", "ct_n"
        ),
    ]
    tool_result = _osint_tool_result(observable.id, evidences)
    registries = {
        "evidence": {entry.id: entry for entry in [*parsed.evidence, *evidences]},
        "observables": {entry.id: entry for entry in parsed.observables},
    }
    candidate = _assessment(
        verdict_phishing=True,
        observations=[entry.id for entry in evidences],
        inferences=[
            {
                "id": "inf_1",
                "code": "external_support",
                "summary": "rdap/dns/ct context on the exact domain",
                "evidence_ids": [entry.id for entry in evidences],
                "rag_case_ids": [],
            }
        ],
    )
    result = verify_assessment(
        candidate,
        "final",
        registry=registries,
        tool_results=[tool_result],
        parsed=parsed,
        rag_context=[],
    )
    assert result.accepted is not None
    # U1 structural compatibility: RDAP/DNS/CT context evidence with
    # source_kind="osint" no longer triggers a V04 provenance refusal.
    assert "impossible_provenance" not in _codes(result)


# ---------------------------------------------------------------------------
# Case C — benign verdict, osint not_found, no positive evidence
# ---------------------------------------------------------------------------


def test_case_c_benign_with_osint_not_found_absence_is_not_proof() -> None:
    parsed = _parsed()
    observable = _domain_observable(parsed)
    tool_result = _osint_tool_result(observable.id, [], status="not_found")
    registries = {
        "evidence": {entry.id: entry for entry in parsed.evidence},
        "observables": {entry.id: entry for entry in parsed.observables},
    }
    candidate = _assessment(verdict_phishing=False, observations=[], inferences=[])
    result = verify_assessment(
        candidate,
        "final",
        registry=registries,
        tool_results=[tool_result],
        parsed=parsed,
        rag_context=[],
    )
    # The absence of OSINT is treated as an absence of confirmation: a benign
    # verdict on no substantive basis is flagged (V12 blocks AUTO), never
    # accepted as positively proven legitimate. No provenance rejection here
    # (no positive OSINT evidence exists) and no crash.
    assert result.accepted is not None
    assert "benign_insufficient_basis" in _codes(result)
    assert "impossible_provenance" not in _codes(result)


# ---------------------------------------------------------------------------
# Case D — citing a nonexistent OSINT evidence ID
# ---------------------------------------------------------------------------


def test_case_d_ghost_osint_evidence_id_rejected_like_any_unknown_id() -> None:
    parsed = _parsed()
    observable = _domain_observable(parsed)
    tool_result = _osint_tool_result(observable.id, [], status="not_found")
    registries = {
        "evidence": {entry.id: entry for entry in parsed.evidence},
        "observables": {entry.id: entry for entry in parsed.observables},
    }
    candidate = _assessment(
        verdict_phishing=True,
        observations=["ev_osint_ghost_zzz"],
        inferences=[],
    )
    result = verify_assessment(
        candidate,
        "final",
        registry=registries,
        tool_results=[tool_result],
        parsed=parsed,
        rag_context=[],
    )
    assert "unsupported_claim" in _codes(result)

"""Evidence merge tests (TICKET-09, docs/contracts.md §2.4, docs/gates.md G5).

Non-live only: the merge is pure and offline. Real G4 live captures
(``runs/gates/G4``) are used as tool-result inputs; the G4 query observables
are reconstructed from the archived ``*.meta.json`` query metadata so that
every reconstructed reference is faithful to the real run (test-only input
objects, never POC observations). Edge cases mutate isolated COPIES of those
real captures — validator attacks, never provider responses.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

from src.evidence import EvidenceMergeError, merge_evidence
from src.parsing import ParseLimits, parse_email
from src.prompts import canonical_bytes
from src.state import Observable, ParsedEmail, ToolResult

pytestmark = pytest.mark.g5

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
G4 = PROJECT_ROOT / "runs" / "gates" / "G4"


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """The merge must never perform network access (pure function)."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in an evidence-merge test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


def _parsed(name: str) -> ParsedEmail:
    result = parse_email(FIXTURES / name, ParseLimits())
    assert isinstance(result, ParsedEmail), f"{name}: structured failure {result}"
    return result


# ---------------------------------------------------------------------------
# Real G4 live captures as inputs
# ---------------------------------------------------------------------------


def _capture_files() -> list[tuple[str, Path, str]]:
    """(kind, path, extraction) of the real G4 receipts used by the merge."""

    return [
        ("results", G4 / "opencti" / "live_result.json", "results"),
        ("results", G4 / "urlscan" / "live_private_benign_result.json", "results"),
        ("result", G4 / "urlscan" / "live_private_redirect_result.json", "result"),
        ("direct", G4 / "virustotal" / "live_unconfigured_result.json", "direct"),
    ]


def real_g4_tool_results() -> list[ToolResult]:
    """The real G4 tool results; missing captures are an explicit refusal."""

    missing = [str(path.relative_to(PROJECT_ROOT)) for _, path, _ in _capture_files() if not path.is_file()]
    if missing:
        pytest.fail(
            "G4 live captures missing (TICKET-09 precondition): " + ", ".join(missing)
        )
    results: list[ToolResult] = []
    for _, path, extraction in _capture_files():
        document = json.loads(path.read_text(encoding="utf-8"))
        if extraction == "direct":
            items = [document]
        else:
            value = document.get(extraction)
            items = value if isinstance(value, list) else [value]
        for item in items:
            results.append(ToolResult.model_validate(item))
    return results


def _query_observables_from_captures(observable_ids: set[str]) -> dict[str, Observable]:
    """Reconstruct the G4 query observables from their archived query metadata.

    Only the exact values/types recorded in the real capture ``*.meta.json``
    files are used; the source_ref points at the capture that documents them.
    """

    reconstructed: dict[str, Observable] = {}
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
            and observable_id not in reconstructed
            and isinstance(normalized, str)
            and isinstance(observable_type, str)
        ):
            reconstructed[observable_id] = Observable(
                id=observable_id,
                value=normalized,
                normalized_value=normalized,
                type=observable_type,  # type: ignore[arg-type]
                roles=[],
                provenance="INTERNE",
                source_ref=str(meta.relative_to(PROJECT_ROOT)),
            )
    missing = observable_ids - set(reconstructed)
    if missing:
        pytest.fail(f"no archived query metadata for G4 observables: {sorted(missing)}")
    return reconstructed


def _parsed_with_tool_queries(
    fixture: str, tool_results: list[ToolResult]
) -> ParsedEmail:
    """Fixture + the G4 query observables (reconstructed from real captures).

    The reconstruction proves the merge plumbing against real evidence; it is
    a controlled test input, never a POC observation.
    """

    parsed = _parsed(fixture)
    # Only results carrying evidence/observables need their query observable:
    # an unavailable/skipped result references nothing.
    query_ids = {
        result.query_observable_id
        for result in tool_results
        if result.query_observable_id is not None
        and (result.evidence or result.observables)
    }
    reconstructed = _query_observables_from_captures(query_ids)
    return parsed.model_copy(
        update={"observables": [*parsed.observables, *reconstructed.values()]}
    )


def _canonical(registries: tuple[dict[str, Any], dict[str, Any], list[Any]]) -> bytes:
    evidence, observables, visuals = registries
    return canonical_bytes(
        {
            "evidence": {
                key: value.model_dump(mode="json") for key, value in evidence.items()
            },
            "observables": {
                key: value.model_dump(mode="json") for key, value in observables.items()
            },
            "visuals": [value.model_dump(mode="json") for value in visuals],
        }
    )


# ---------------------------------------------------------------------------
# Merge of real G4 captures
# ---------------------------------------------------------------------------


def test_merge_real_g4_captures_registries_and_provenance() -> None:
    """Real CTI/urlscan evidence enters OSINT/SANDBOX; parser facts stay INTERNE."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    evidence, observables, visuals = merge_evidence(parsed, results)

    # Parser registries first, unchanged provenance.
    for entry in parsed.evidence:
        assert evidence[entry.id].provenance == "INTERNE"
        assert evidence[entry.id].model_dump() == entry.model_dump()
    for entry in parsed.observables:
        assert observables[entry.id].provenance == "INTERNE"

    # Real tool evidence, keyed by the real capture IDs.
    opencti_ok = [r for r in results if r.tool == "opencti" and r.status == "ok"][0]
    urlscan_ok = [
        r
        for r in results
        if r.tool == "urlscan" and r.status == "ok"
    ]
    for result in (opencti_ok, *urlscan_ok):
        for entry in result.evidence:
            merged = evidence[entry.id]
            assert merged.model_dump() == entry.model_dump()
            expected = "OSINT" if result.tool in ("virustotal", "opencti") else "SANDBOX"
            assert merged.provenance == expected

    # Non-ok results contribute nothing.
    non_ok = [r for r in results if r.status != "ok"]
    assert non_ok, "G4 captures must include unavailable/not_found/skipped results"
    for result in non_ok:
        assert result.evidence == []

    assert len(evidence) == (
        len(parsed.evidence) + sum(len(r.evidence) for r in results)
    )
    assert len(observables) == len(parsed.observables)
    assert [v.model_dump() for v in visuals] == [v.model_dump() for v in parsed.images]

    # No dangling references anywhere.
    for entry in evidence.values():
        assert entry.observable_id is None or entry.observable_id in observables
    for entry in observables.values():
        for evidence_id in entry.evidence_ids:
            assert evidence_id in evidence


def test_merge_is_deterministic_and_order_independent() -> None:
    """Same inputs (any order) → byte-identical registries (stable sort)."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)

    first = _canonical(merge_evidence(parsed, results))
    again = _canonical(merge_evidence(parsed, results))
    reversed_order = _canonical(merge_evidence(parsed, list(reversed(results))))
    assert first == again == reversed_order


def test_merge_same_id_and_content_is_idempotent() -> None:
    """The same real evidence inserted twice stays a single entry."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    once = merge_evidence(parsed, results)
    doubled = merge_evidence(parsed, [*results, *results])
    assert _canonical(once) == _canonical(doubled)


def test_merge_collision_with_different_content_is_refused() -> None:
    """Same evidence ID, different content → explicit refusal (§2.4)."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = ok.model_copy(deep=True)
    corrupted.evidence[0].value = "collision-content"
    with pytest.raises(EvidenceMergeError, match="collision"):
        merge_evidence(parsed, [ok, corrupted])


def test_merge_observable_collision_is_refused() -> None:
    """Same tool-discovered observable ID with different content → refusal.

    The controlled object is built from a REAL captured value (urlscan final
    URL) and its real capture reference; it only exercises the collision
    guard and is never a POC observation.
    """

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    urlscan_ok = next(r for r in results if r.tool == "urlscan" and r.status == "ok")
    final_url_evidence = next(
        entry for entry in urlscan_ok.evidence if entry.predicate == "sandbox_final_url"
    )
    base = urlscan_ok.model_copy(deep=True)
    base.observables = [
        Observable(
            id="obs_collision_guard_check",
            value=str(final_url_evidence.value),
            normalized_value=str(final_url_evidence.value),
            type="url",
            roles=["tool_discovery"],
            provenance="SANDBOX",
            source_ref=final_url_evidence.source_ref,
            evidence_ids=[final_url_evidence.id],
        )
    ]
    merged_evidence, merged_observables, _visuals = merge_evidence(parsed, [base])
    assert "obs_collision_guard_check" in merged_observables

    corrupted = base.model_copy(deep=True)
    corrupted.observables[0].value = "https://other.invalid/"
    corrupted.observables[0].normalized_value = "https://other.invalid/"
    with pytest.raises(EvidenceMergeError, match="collision"):
        merge_evidence(parsed, [base, corrupted])


# ---------------------------------------------------------------------------
# Refusals: missing proof, raw data, provenance mismatch, dangling refs
# ---------------------------------------------------------------------------


def test_missing_source_ref_evidence_is_refused() -> None:
    """An ok result whose evidence has no source_ref is refused (preuve absente)."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = ok.model_copy(deep=True)
    corrupted.evidence[0].source_ref = ""
    with pytest.raises(EvidenceMergeError, match="source_ref"):
        merge_evidence(parsed, [corrupted])


def test_ok_result_without_archived_response_is_refused() -> None:
    """Positive evidence without a response reference/fingerprint is refused."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = ok.model_copy(deep=True)
    corrupted.response_ref = None
    with pytest.raises(EvidenceMergeError, match="archived response"):
        merge_evidence(parsed, [corrupted])

    corrupted_sha = ok.model_copy(deep=True)
    corrupted_sha.response_sha256 = None
    with pytest.raises(EvidenceMergeError, match="archived response"):
        merge_evidence(parsed, [corrupted_sha])


def test_evidence_without_timestamp_is_refused() -> None:
    """An OSINT/SANDBOX evidence without observed_at is refused (§2.4)."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = ok.model_copy(deep=True)
    corrupted.evidence[0].observed_at = None
    with pytest.raises(EvidenceMergeError, match="observed_at"):
        merge_evidence(parsed, [corrupted])


def test_non_ok_result_with_evidence_is_refused() -> None:
    """An unavailable/not_found/skipped result carrying evidence is refused."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    unavailable = next(r for r in results if r.status == "unavailable")
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = unavailable.model_copy(deep=True)
    corrupted.evidence = [ok.evidence[0].model_copy(deep=True)]
    with pytest.raises(EvidenceMergeError, match="positive"):
        merge_evidence(parsed, [corrupted])


def test_provenance_mismatch_is_refused() -> None:
    """urlscan evidence claimed as OSINT (or CTI as SANDBOX) is refused (V04)."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.tool == "urlscan" and r.status == "ok")
    corrupted = ok.model_copy(deep=True)
    corrupted.evidence[0].provenance = "OSINT"
    with pytest.raises(EvidenceMergeError, match="provenance"):
        merge_evidence(parsed, [corrupted])


def test_source_kind_mismatch_is_refused() -> None:
    """Evidence whose source_kind does not match its tool result is refused."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = ok.model_copy(deep=True)
    corrupted.evidence[0].source_kind = "parser"
    with pytest.raises(EvidenceMergeError, match="source_kind"):
        merge_evidence(parsed, [corrupted])


def test_dangling_observable_reference_is_refused() -> None:
    """Evidence referencing an absent observable is refused, never dropped silently."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    ok = next(r for r in results if r.status == "ok" and r.evidence)
    corrupted = ok.model_copy(deep=True)
    corrupted.evidence[0].observable_id = "obs_unknown_reference"
    with pytest.raises(EvidenceMergeError, match="unknown observable"):
        merge_evidence(parsed, [corrupted])


def test_parser_provenance_is_preserved_and_osint_is_separate() -> None:
    """The internal hash evidence is kept INTERNE; an OSINT assertion is a
    SEPARATE evidence entry (never an overwrite of the local hash fact)."""

    parsed = _parsed("attachment_suspicious.eml")
    internal_hash_evidence = [
        ev for ev in parsed.evidence if ev.predicate == "attachment_hash"
    ]
    assert internal_hash_evidence, "fixture must carry attachment hash evidence"

    attachment_observable = next(
        obs for obs in parsed.observables if obs.type == "sha256"
    )
    # Controlled capture copy: a real CTI evidence re-pointed at this exact
    # artifact to prove separation; never used as a provider observation.
    real_results = real_g4_tool_results()
    cti_ok = next(r for r in real_results if r.tool == "opencti" and r.status == "ok")
    injected = cti_ok.model_copy(deep=True)
    injected.query_observable_id = attachment_observable.id
    for entry in injected.evidence:
        entry.observable_id = attachment_observable.id

    evidence, _observables, _visuals = merge_evidence(parsed, [injected])

    for entry in internal_hash_evidence:
        merged = evidence[entry.id]
        assert merged.provenance == "INTERNE"
        assert merged.predicate == "attachment_hash"
    external = [e for e in injected.evidence if e.id in evidence]
    assert external
    for entry in external:
        assert evidence[entry.id].provenance == "OSINT"
        assert evidence[entry.id].id != internal_hash_evidence[0].id


def test_merged_entries_carry_only_normalized_contract_fields() -> None:
    """No raw provider JSON ever enters the registries (§2.6/§2.7)."""

    results = real_g4_tool_results()
    parsed = _parsed_with_tool_queries("phishing_simple.eml", results)
    evidence, observables, _visuals = merge_evidence(parsed, results)

    allowed_evidence = {
        "id",
        "provenance",
        "source_kind",
        "observable_id",
        "predicate",
        "value",
        "source_ref",
        "observed_at",
        "match_level",
        "source_group",
    }
    allowed_observables = {
        "id",
        "value",
        "normalized_value",
        "type",
        "roles",
        "provenance",
        "source_ref",
        "evidence_ids",
        "category",
        "justification",
    }
    for entry in evidence.values():
        assert set(entry.model_dump().keys()) == allowed_evidence
    for entry in observables.values():
        assert set(entry.model_dump().keys()) == allowed_observables
    serialized = _canonical((evidence, observables, []))
    for raw_key in (b'"data"', b'"attributes"', b'"verdicts"', b'"meta"'):
        assert raw_key not in serialized


def test_merge_without_tool_results_is_parser_only() -> None:
    """No tool result = no external evidence; visuals are the parsed images."""

    parsed = _parsed("legitimate_newsletter.eml")
    evidence, observables, visuals = merge_evidence(parsed, None)
    assert set(evidence) == {entry.id for entry in parsed.evidence}
    assert set(observables) == {entry.id for entry in parsed.observables}
    assert all(entry.provenance == "INTERNE" for entry in evidence.values())
    assert [v.model_dump() for v in visuals] == [v.model_dump() for v in parsed.images]


def test_real_capture_tool_results_validate_against_state_contract() -> None:
    """The capture files used by every merge test are real normalized outputs."""

    results = real_g4_tool_results()
    assert {r.tool for r in results} == {"virustotal", "opencti", "urlscan"}
    assert any(r.status == "unavailable" for r in results)
    assert any(r.status == "not_found" for r in results)
    assert any(r.status == "skipped" for r in results)
    assert any(r.status == "ok" for r in results)

"""FINAL assessment tests (TICKET-09, docs/prompt_integration.md §3, gates §5.1.2).

Non-live coverage (no network, fake transport only where the harness plumbing
itself is under test): envelope fields and TOOL_STATUS, exact-bytes FINAL
audit with the §2.6.1 counters/digests, minimization for non-fixture source
profiles, reference rejection, honest absence, documented fallback and the
V14 signal.

Live coverage (explicit ``--live``): real FINAL xhigh calls on fixtures whose
valid INTERNAL assessment was really produced by the official runtime
(``runs/gates/G2/assessments.jsonl``, docs/fixtures.md: authentic archived
responses are the regression input). Real captures are archived under
``runs/gates/G5/final/`` with the per-attempt audit; no result is simulated.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import time
from pathlib import Path
from typing import Any

import pytest

from src.config import load_settings
from src.evidence import (
    EvidenceMergeError,
    assess_final,
    final_selection,
    merge_evidence,
    signals_gain_without_external_evidence,
    validate_final_candidate,
)
from src.llm import LunaClient
from src.parsing import ParseLimits, parse_email
from src.prompts import (
    RAG_MAX_CASE_CHARS,
    ContextLimits,
    build_final_messages,
    build_internal_envelope,
    canonical_bytes,
    envelope_has_useful_content,
    load_final_prompt,
    rag_context_entries,
)
from src.state import Assessment, CallRecord, ParsedEmail, RagCase, ToolResult

pytestmark = pytest.mark.g5

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
G4 = PROJECT_ROOT / "runs" / "gates" / "G4"
G2_ASSESSMENTS = PROJECT_ROOT / "runs" / "gates" / "G2" / "assessments.jsonl"
G5_FINAL = PROJECT_ROOT / "runs" / "gates" / "G5" / "final"

#: FINAL audit field set (docs/contracts.md §2.6.1): 7 common + 5 FINAL.
COMMON_AUDIT_FIELDS = {
    "phase",
    "input_payload_sha256",
    "untrusted_email_sha256",
    "body_chars_sent",
    "headers_chars_sent",
    "evidence_count_sent",
    "observable_count_sent",
}
FINAL_AUDIT_FIELDS = COMMON_AUDIT_FIELDS | {
    "internal_evidence_count_sent",
    "external_evidence_count_sent",
    "tool_status_digest",
    "rag_case_count_sent",
    "visual_count_sent",
}

EXPECTED_RUNTIME_MODEL = "Qwen/Qwen3.8-27B"

#: Fixtures whose REAL INTERNAL assessment is archived (G2) and used for the
#: real FINAL regression calls. One benign, one phishing mechanism.
LIVE_FIXTURES = ("legitimate_newsletter.eml", "malicious_url_redirect.eml")


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-live tests must not perform any network access."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in a non-live FINAL test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


def _parsed(name: str) -> ParsedEmail:
    result = parse_email(FIXTURES / name, ParseLimits())
    assert isinstance(result, ParsedEmail), f"{name}: structured failure {result}"
    return result


def _valid_assessment_dict(
    evidence_id: str | None = None,
    observable_id: str | None = None,
    phishing: float = 0.60,
) -> dict[str, Any]:
    """A schema-valid Assessment used ONLY as a controlled function input.

    The four non-leading classes stay at 0.05; ``legitime`` absorbs the rest,
    so ``phishing`` must stay ≤ 0.80 for a valid probability vector.
    """

    rest = 0.05 * 4
    legitime = round(1.0 - rest - phishing, 6)
    assert legitime >= 0, "test helper: phishing too high for a valid vector"
    return {
        "probabilities": {
            "spear_phishing": 0.05,
            "phishing": phishing,
            "fraude": 0.05,
            "menace": 0.05,
            "spam": 0.05,
            "legitime": legitime,
        },
        "observations": [evidence_id] if evidence_id else [],
        "inferences": (
            [
                {
                    "id": "inf_1",
                    "code": "link_mismatch",
                    "summary": "controlled test inference",
                    "evidence_ids": [evidence_id],
                    "rag_case_ids": [],
                }
            ]
            if evidence_id
            else []
        ),
        "observable_assessments": (
            [
                {
                    "observable_id": observable_id,
                    "category": "S",
                    "evidence_ids": [evidence_id],
                    "reason_code": "unconfirmed",
                }
            ]
            if evidence_id and observable_id
            else []
        ),
        "needs_enrichment": False,
        "missing_information": [],
        "decisive_evidence_ids": [evidence_id] if evidence_id else [],
    }


def _assessment_bytes(candidate: dict[str, Any], model: str) -> bytes:
    body = {
        "model": model,
        "choices": [
            {"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(candidate)}}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    return json.dumps(body).encode("utf-8")


# ---------------------------------------------------------------------------
# Real G4 captures as FINAL inputs (same extraction rules as test_evidence)
# ---------------------------------------------------------------------------


def _real_g4_tool_results() -> list[ToolResult]:
    files = [
        (G4 / "opencti" / "live_result.json", "results"),
        (G4 / "urlscan" / "live_private_benign_result.json", "results"),
        (G4 / "urlscan" / "live_private_redirect_result.json", "result"),
        (G4 / "virustotal" / "live_unconfigured_result.json", "direct"),
    ]
    missing = [str(path.relative_to(PROJECT_ROOT)) for path, _ in files if not path.is_file()]
    if missing:
        pytest.fail("G4 live captures missing (TICKET-09 precondition): " + ", ".join(missing))
    results: list[ToolResult] = []
    for path, extraction in files:
        document = json.loads(path.read_text(encoding="utf-8"))
        if extraction == "direct":
            items = [document]
        else:
            value = document.get(extraction)
            items = value if isinstance(value, list) else [value]
        for item in items:
            results.append(ToolResult.model_validate(item))
    return results


def _query_observables(observable_ids: set[str]):
    from src.state import Observable

    reconstructed = {}
    for meta in sorted(G4.rglob("*.meta.json")):
        try:
            document = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        query = document.get("query")
        if not isinstance(query, dict):
            continue
        observable_id = query.get("observable_id")
        if (
            observable_id in observable_ids
            and observable_id not in reconstructed
            and isinstance(query.get("normalized_value"), str)
            and isinstance(query.get("type"), str)
        ):
            reconstructed[observable_id] = Observable(
                id=observable_id,
                value=query["normalized_value"],
                normalized_value=query["normalized_value"],
                type=query["type"],  # type: ignore[arg-type]
                roles=[],
                provenance="INTERNE",
                source_ref=str(meta.relative_to(PROJECT_ROOT)),
            )
    if observable_ids - set(reconstructed):
        pytest.fail(
            f"no archived query metadata for G4 observables: "
            f"{sorted(observable_ids - set(reconstructed))}"
        )
    return reconstructed


def _fixture_with_merged_real_captures(
    fixture: str = "phishing_simple.eml",
) -> tuple[ParsedEmail, list[ToolResult], dict[str, Any], dict[str, Any], list[Any]]:
    """Fixture + real G4 captures merged into registries (test input objects)."""

    results = _real_g4_tool_results()
    parsed = _parsed(fixture)
    query_ids = {
        r.query_observable_id
        for r in results
        if r.query_observable_id is not None and (r.evidence or r.observables)
    }
    reconstructed = _query_observables(query_ids)
    parsed = parsed.model_copy(
        update={"observables": [*parsed.observables, *reconstructed.values()]}
    )
    evidence, observables, visuals = merge_evidence(parsed, results)
    return parsed, results, evidence, observables, visuals


def _captured_final_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response_body: bytes,
    persist_request_body: bool,
) -> tuple[LunaClient, dict[str, bytes]]:
    """Real client, real serialization/audit path, transport recorded locally."""

    monkeypatch.setenv("LITELLM_API_KEY", "sk-canary-0123456789abcdef")
    monkeypatch.setenv("LITELLM_CHAT_URL", "https://endpoint.invalid/v1/chat/completions")
    monkeypatch.setenv("LITELLM_MODEL", "openai/gpt-oss-20b")
    settings = load_settings(None)
    client = LunaClient(
        settings,
        phase="final",
        capture_dir=tmp_path / "captures",
        persist_request_body=persist_request_body,
    )
    captured: dict[str, bytes] = {}

    def _fake_post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
        captured["body"] = body
        return 200, response_body

    client._post_bytes = _fake_post  # type: ignore[method-assign]
    return client, captured


# ---------------------------------------------------------------------------
# Envelope: fields, TOOL_STATUS, budgets
# ---------------------------------------------------------------------------


def test_final_envelope_has_exactly_the_documented_fields() -> None:
    """Mêmes champs que INTERNAL + INTERNAL_ASSESSMENT, TOOL_STATUS, RAG_CONTEXT."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    internal = Assessment.model_validate(_valid_assessment_dict())
    messages, envelope = build_final_messages(
        parsed, internal, evidence, observables, results, [], ContextLimits()
    )

    assert set(envelope.keys()) == {
        "UNTRUSTED_EMAIL",
        "EVIDENCE_REGISTRY",
        "OBSERVABLE_REGISTRY",
        "SUPPLIED_VISUAL_IDS",
        "INTERNAL_ASSESSMENT",
        "TOOL_STATUS",
        "RAG_CONTEXT",
    }
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert envelope["RAG_CONTEXT"] == []
    assert envelope["INTERNAL_ASSESSMENT"] == internal.model_dump(mode="json")
    assert messages[0]["content"] == load_final_prompt()
    assert envelope_has_useful_content(envelope)

    # UNTRUSTED_EMAIL is projected exactly like INTERNAL (same budgets).
    internal_envelope = build_internal_envelope(parsed, ContextLimits())
    assert envelope["UNTRUSTED_EMAIL"] == internal_envelope["UNTRUSTED_EMAIL"]

    # The merged registry is a superset of the INTERNAL registry.
    for evidence_id, entry in internal_envelope["EVIDENCE_REGISTRY"].items():
        assert evidence_id in envelope["EVIDENCE_REGISTRY"]
        assert envelope["EVIDENCE_REGISTRY"][evidence_id]["provenance"] == entry["provenance"]


def test_tool_status_transmits_every_result_including_unavailable() -> None:
    """Every normalized status, cause included, is transmitted — never raw data."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    _messages, envelope = build_final_messages(
        parsed, None, evidence, observables, results, [], ContextLimits()
    )
    statuses = envelope["TOOL_STATUS"]
    assert len(statuses) == len(results)
    by_key = {(entry["tool"], entry["status"]): entry for entry in statuses}
    assert ("virustotal", "unavailable") in by_key
    assert by_key[("virustotal", "unavailable")]["reason"] == "access_not_authorized"
    assert ("opencti", "not_found") in by_key
    assert ("urlscan", "skipped") in by_key
    assert ("urlscan", "ok") in by_key
    allowed = {
        "tool",
        "query_observable_id",
        "status",
        "reason",
        "mode",
        "collected_at",
        "requests_sent",
        "elapsed_ms",
        "response_ref",
        "response_sha256",
        "visibility",
        "scan_id",
    }
    for entry in statuses:
        assert set(entry.keys()) == allowed


def test_final_reference_consistency_under_tiny_budgets() -> None:
    """Whole-entry selection only; no dangling reference under any budget."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    tiny = ContextLimits(evidence_chars=1, urls_observables_chars=1)
    _messages, envelope = build_final_messages(
        parsed, None, evidence, observables, results, [], tiny
    )
    assert envelope["EVIDENCE_REGISTRY"] == {}
    for entry in envelope["EVIDENCE_REGISTRY"].values():
        assert entry["observable_id"] is None or entry["observable_id"] in envelope["OBSERVABLE_REGISTRY"]
    assert "evidence_truncated" in envelope["UNTRUSTED_EMAIL"]["content_limits"]
    assert "urls_truncated" in envelope["UNTRUSTED_EMAIL"]["content_limits"]


def test_final_prompt_enumerates_the_closed_lists() -> None:
    """TICKET-09 documented deviation: enums enumerated verbatim (TICKET-04 precedent)."""

    prompt = load_final_prompt()
    for value in (
        "credential_collection",
        "insufficient_information",
        "attack_artifact",
        "benign_context",
        "authentication_untrusted",
        "content_truncated",
    ):
        assert value in prompt
    assert "prend EXACTEMENT" in prompt


def test_rag_context_is_bounded_and_rejects_more_than_three_cases() -> None:
    def _case(case_id: str) -> RagCase:
        return RagCase(
            case_id=case_id,
            public_source_url="https://example.org/public/case",
            dataset="public_cases",
            record_sha256="0" * 64,
            validated_label="phishing",
            analyst_validation_ref="review-1",
            duplicate_group="dup-1",
            family_group="fam-1",
            text_excerpt="x" * (RAG_MAX_CASE_CHARS * 3),
            analyst_rationale="reviewed rationale",
            distance=0.1,
            embedding_model_id="all-MiniLM-L6-v2",
        )

    entries = rag_context_entries([_case("c1")])
    assert len(entries) == 1
    assert len(canonical_bytes(entries[0])) <= RAG_MAX_CASE_CHARS
    assert entries[0]["case_id"] == "c1"
    with pytest.raises(ValueError, match="at most 3"):
        rag_context_entries([_case(f"c{i}") for i in range(4)])


# ---------------------------------------------------------------------------
# FINAL audit: exact bytes, counters, digest, minimization
# ---------------------------------------------------------------------------


def test_final_audit_recomputed_from_exact_fixture_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """§2.6.1: audit computed on the exact transport bytes, all 12 fields."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    internal = Assessment.model_validate(_valid_assessment_dict())
    first_evidence_id = next(iter(evidence))
    first_observable_id = next(iter(observables))
    candidate = _valid_assessment_dict(first_evidence_id, first_observable_id)
    client, captured = _captured_final_client(
        monkeypatch,
        tmp_path,
        _assessment_bytes(candidate, "openai/gpt-oss-20b"),
        persist_request_body=True,
    )
    assessment, record = assess_final(
        parsed,
        internal,
        evidence,
        [],
        client,
        observables=observables,
        tool_results=results,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is not None and record.status == "ok"

    captures = tmp_path / "captures"
    request_path = captures / "final_attempt_1.request.json"
    audit_path = captures / "final_attempt_1.input_audit.json"
    assert request_path.is_file() and audit_path.is_file()
    archived = request_path.read_bytes()
    assert archived == captured["body"]  # archived == transported
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert set(audit.keys()) == FINAL_AUDIT_FIELDS
    assert audit["phase"] == "final"

    # Recompute EVERY field from the archived request itself.
    assert audit["input_payload_sha256"] == hashlib.sha256(archived).hexdigest()
    sent = json.loads(archived.decode("utf-8"))
    assert sent["reasoning_effort"] == "xhigh"
    assert sent["max_completion_tokens"] == 16384
    envelope = json.loads(sent["messages"][1]["content"])
    untrusted = envelope["UNTRUSTED_EMAIL"]
    assert audit["untrusted_email_sha256"] == hashlib.sha256(
        canonical_bytes(untrusted)
    ).hexdigest()
    assert audit["body_chars_sent"] == sum(
        len(part["text"]) for part in untrusted["text_parts"] + untrusted["html_parts"]
    )
    assert audit["headers_chars_sent"] == sum(
        len(header["name"]) + len(header["decoded_value"])
        for header in untrusted["headers"]
    )
    assert audit["evidence_count_sent"] == len(envelope["EVIDENCE_REGISTRY"])
    assert audit["observable_count_sent"] == len(envelope["OBSERVABLE_REGISTRY"])

    internal_count = sum(
        1
        for entry in envelope["EVIDENCE_REGISTRY"].values()
        if entry["provenance"] == "INTERNE"
    )
    external_count = sum(
        1
        for entry in envelope["EVIDENCE_REGISTRY"].values()
        if entry["provenance"] in ("OSINT", "SANDBOX")
    )
    assert audit["internal_evidence_count_sent"] == internal_count
    assert audit["external_evidence_count_sent"] == external_count
    assert external_count > 0  # real G4 evidence really attached
    assert audit["tool_status_digest"] == hashlib.sha256(
        canonical_bytes(envelope["TOOL_STATUS"])
    ).hexdigest()
    assert audit["rag_case_count_sent"] == 0
    assert audit["visual_count_sent"] == 0
    assert record.request_sha256 == audit["input_payload_sha256"]


def test_final_audit_is_minimized_without_the_fixture_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """public_corpus/private_authorized path: audit kept, request body never persisted."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    client, captured = _captured_final_client(
        monkeypatch,
        tmp_path,
        _assessment_bytes(_valid_assessment_dict(), "openai/gpt-oss-20b"),
        persist_request_body=False,
    )
    assessment, record = assess_final(
        parsed,
        None,
        evidence,
        [],
        client,
        observables=observables,
        tool_results=results,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is not None and record.status == "ok"
    captures = tmp_path / "captures"
    audit_path = captures / "final_attempt_1.input_audit.json"
    assert audit_path.is_file()
    assert not list(captures.glob("*_attempt_*.request.json"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    # The audit still proves the exact bytes handed to transport.
    assert audit["input_payload_sha256"] == hashlib.sha256(captured["body"]).hexdigest()


def test_external_evidence_count_matches_attached_registry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The counter equals the OSINT/SANDBOX entries really included, not a claim."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    client, captured = _captured_final_client(
        monkeypatch,
        tmp_path,
        _assessment_bytes(_valid_assessment_dict(), "openai/gpt-oss-20b"),
        persist_request_body=False,
    )
    assess_final(
        parsed,
        None,
        evidence,
        [],
        client,
        observables=observables,
        tool_results=results,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    audit = json.loads(
        (tmp_path / "captures" / "final_attempt_1.input_audit.json").read_text(
            encoding="utf-8"
        )
    )
    envelope = json.loads(
        json.loads(captured["body"].decode("utf-8"))["messages"][1]["content"]
    )
    registry = envelope["EVIDENCE_REGISTRY"]
    assert audit["external_evidence_count_sent"] == sum(
        1 for entry in registry.values() if entry["provenance"] in ("OSINT", "SANDBOX")
    )
    assert audit["internal_evidence_count_sent"] == sum(
        1 for entry in registry.values() if entry["provenance"] == "INTERNE"
    )
    assert audit["evidence_count_sent"] == len(registry)


def test_final_call_parameters_follow_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """FINAL is xhigh, 16384 max output tokens, bounded by the 90 s phase budget."""

    parsed, evidence, observables = _parsed("spam_promo.eml"), {}, {}
    monkeypatch.setenv("LITELLM_API_KEY", "sk-canary-0123456789abcdef")
    monkeypatch.setenv("LITELLM_CHAT_URL", "https://endpoint.invalid/v1/chat/completions")
    settings = load_settings(None)
    client = LunaClient(settings, phase="final", capture_dir=tmp_path / "captures")
    captured: dict[str, Any] = {}

    def _fake_complete_json(messages: Any, schema: Any, effort: str, max_output_tokens: int, deadline: float):
        captured.update(
            {
                "effort": effort,
                "max_output_tokens": max_output_tokens,
                "deadline": deadline,
                "messages": messages,
            }
        )
        return None, CallRecord(
            phase="final", status="error", requested_model=settings.LITELLM_MODEL, reasoning_effort=effort
        )

    client.complete_json = _fake_complete_json  # type: ignore[method-assign]
    before = time.monotonic()
    assessment, record = assess_final(
        parsed, None, evidence, [], client, observables=observables, tool_results=()
    )
    assert assessment is None and record.status == "error"
    assert captured["effort"] == "xhigh"
    assert captured["max_output_tokens"] == settings.FINAL_MAX_OUTPUT_TOKENS == 16384
    assert captured["deadline"] <= before + settings.FINAL_PHASE_SECONDS + 1.0
    assert captured["deadline"] >= before + settings.FINAL_PHASE_SECONDS - 1.0


# ---------------------------------------------------------------------------
# Rejections and honest absence (no fabrication)
# ---------------------------------------------------------------------------


def test_final_rejects_candidate_with_unknown_reference(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Out-of-registry reference → explicit rejection, archived, never repaired."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    candidate = _valid_assessment_dict("ev_does_not_exist", next(iter(observables)))
    client, _captured = _captured_final_client(
        monkeypatch,
        tmp_path,
        _assessment_bytes(candidate, "openai/gpt-oss-20b"),
        persist_request_body=False,
    )
    assessment, record = assess_final(
        parsed,
        None,
        evidence,
        [],
        client,
        observables=observables,
        tool_results=results,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is None
    assert record.status == "error"
    reject = tmp_path / "captures" / "final_validation_reject.json"
    assert reject.is_file()
    issues = json.loads(reject.read_text(encoding="utf-8"))["issues"]
    assert any("unknown evidence ID" in issue for issue in issues)
    assert "final_validation_reject.json" in record.response_refs


def test_missing_final_result_is_returned_honestly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Transport failure → (None, error record); no fabricated assessment."""

    parsed = _parsed("spam_promo.eml")
    client, _captured = _captured_final_client(
        monkeypatch, tmp_path, b"unused", persist_request_body=False
    )

    def _failing_post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
        return 500, b'{"error": "controlled transport failure"}'

    client._post_bytes = _failing_post  # type: ignore[method-assign]
    assessment, record = assess_final(
        parsed, None, {}, [], client, observables={}, tool_results=(),
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is None
    assert record.status == "error"
    assert record.attempts >= 1


def test_final_selection_fallback_copies_internal_and_warns() -> None:
    """FINAL failure + valid internal → documented fallback, no fabricated result."""

    internal = Assessment.model_validate(_valid_assessment_dict())
    error_record = CallRecord(
        phase="final", status="error", requested_model=EXPECTED_RUNTIME_MODEL, reasoning_effort="xhigh", attempts=2
    )
    selection = final_selection(internal, None, error_record)
    assert selection.final_source == "internal_fallback"
    assert selection.candidate is not None
    assert selection.candidate is not internal  # deep copy, no aliasing
    assert selection.candidate.model_dump() == internal.model_dump()
    assert [warning.code for warning in selection.warnings] == [
        "final_fallback_internal_copy"
    ]
    assert selection.warnings[0].severity == "warning"
    assert "AUTO is blocked" in selection.warnings[0].message

    # Mutating the copy must not alter the original internal assessment.
    selection.candidate.probabilities.phishing = 0.99
    assert internal.probabilities.phishing != 0.99

    # Success path: the real FINAL candidate wins.
    ok_record = CallRecord(
        phase="final", status="ok", requested_model=EXPECTED_RUNTIME_MODEL, reasoning_effort="xhigh", attempts=1
    )
    final_candidate = Assessment.model_validate(_valid_assessment_dict(phishing=0.75))
    success = final_selection(internal, final_candidate, ok_record)
    assert success.final_source == "final_llm"
    assert success.candidate is final_candidate
    assert success.warnings == []

    # Both unavailable: no candidate, no confidence.
    none_selection = final_selection(None, None, error_record)
    assert none_selection.final_source == "none"
    assert none_selection.candidate is None
    assert none_selection.warnings[0].code == "final_assessment_unavailable"


def test_gain_without_external_evidence_signal() -> None:
    """V14 input: a move with zero external evidence sent is signalled."""

    internal = Assessment.model_validate(_valid_assessment_dict(phishing=0.60))
    gained = Assessment.model_validate(_valid_assessment_dict(phishing=0.75))
    same = Assessment.model_validate(_valid_assessment_dict(phishing=0.62))

    assert signals_gain_without_external_evidence(internal, gained, 0) is True
    assert signals_gain_without_external_evidence(internal, gained, 3) is False
    assert signals_gain_without_external_evidence(internal, same, 0) is False
    assert signals_gain_without_external_evidence(None, gained, 0) is False

    # Verdict change alone is enough to signal, even at equal confidence.
    verdict_change = Assessment.model_validate(
        _valid_assessment_dict(phishing=0.60) | {"probabilities": {
            "spear_phishing": 0.60,
            "phishing": 0.05,
            "fraude": 0.05,
            "menace": 0.05,
            "spam": 0.05,
            "legitime": 0.20,
        }}
    )
    assert signals_gain_without_external_evidence(internal, verdict_change, 0) is True


def test_validate_final_candidate_binds_rag_ids_to_the_provided_context() -> None:
    """RAG case IDs may only cite cases really provided (all [] in G5)."""

    evidence_registry = {
        "ev_1": {"provenance": "INTERNE"},
        "ev_2": {"provenance": "OSINT"},
    }
    observable_registry = {"obs_1": {"provenance": "SANDBOX"}}
    candidate = _valid_assessment_dict("ev_2", "obs_1")
    candidate["inferences"][0]["rag_case_ids"] = ["case_9"]
    issues = validate_final_candidate(candidate, evidence_registry, observable_registry, [])
    assert any("RAG_CONTEXT" in issue for issue in issues)

    # Factual provenance and resolvable IDs are accepted.
    clean = _valid_assessment_dict("ev_1", None)
    assert validate_final_candidate(clean, evidence_registry, observable_registry, []) == []

    # INFERENCE provenance may never be presented as a fact.
    inference_only = {
        "ev_3": {"provenance": "INFERENCE"},
    }
    candidate3 = _valid_assessment_dict("ev_3", None)
    issues3 = validate_final_candidate(candidate3, inference_only, {}, [])
    assert any("INTERNE/OSINT/SANDBOX" in issue for issue in issues3)


def test_assess_final_refuses_dangling_registries_before_any_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A missing observables registry is refused BEFORE any LLM call."""

    parsed, results, evidence, _observables, _visuals = _fixture_with_merged_real_captures()
    client, captured = _captured_final_client(
        monkeypatch,
        tmp_path,
        _assessment_bytes(_valid_assessment_dict(), "openai/gpt-oss-20b"),
        persist_request_body=False,
    )
    assessment, record = assess_final(
        parsed, None, evidence, [], client, tool_results=results,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is None
    assert record.status == "error" and record.attempts == 0
    assert captured == {}  # no transport call
    assert (tmp_path / "captures" / "final_projection_error.txt").is_file()


def test_assess_final_accepts_the_merge_tuple_directly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The merge_evidence 3-tuple is a valid ``evidence`` argument (interface)."""

    parsed, results, evidence, observables, _visuals = _fixture_with_merged_real_captures()
    merged = (evidence, observables, merge_evidence(parsed, results)[2])
    first_evidence_id = next(iter(evidence))
    client, _captured = _captured_final_client(
        monkeypatch,
        tmp_path,
        _assessment_bytes(
            _valid_assessment_dict(first_evidence_id, next(iter(observables))),
            "openai/gpt-oss-20b",
        ),
        persist_request_body=False,
    )
    assessment, record = assess_final(
        parsed, None, merged, [], client, tool_results=results,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is not None and record.status == "ok"


def test_merge_error_is_reported_without_a_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Invalid registries → explicit error record, zero attempts."""

    client, captured = _captured_final_client(
        monkeypatch, tmp_path, b"unused", persist_request_body=False
    )
    assessment, record = assess_final(
        _parsed("spam_promo.eml"), None, {"ev_x": object()}, [], client,
        observables={}, tool_results=(),
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    assert assessment is None and record.status == "error"
    assert captured == {}


# ---------------------------------------------------------------------------
# LIVE: real FINAL calls on fixtures with archived real INTERNAL assessments
# ---------------------------------------------------------------------------


def _load_archived_internal(fixture: str) -> dict[str, Any]:
    if not G2_ASSESSMENTS.is_file():
        pytest.fail(
            "archived real INTERNAL assessments missing "
            "(runs/gates/G2/assessments.jsonl); FINAL requires a real internal input"
        )
    for line in G2_ASSESSMENTS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("fixture") == fixture:
            return record
    pytest.fail(f"no archived real INTERNAL assessment for {fixture}")


def _run_live_final_matrix() -> dict[str, Any]:
    """Real FINAL xhigh calls for the live fixtures; real failures archived."""

    settings = load_settings(None)
    if settings.LITELLM_MODEL != EXPECTED_RUNTIME_MODEL:
        pytest.fail(
            "official FINAL requires LITELLM_MODEL="
            f"{EXPECTED_RUNTIME_MODEL!r}; got {settings.LITELLM_MODEL!r}. "
            "Refusing before artifact mutation or network access."
        )
    if settings.LITELLM_API_KEY is None:
        pytest.fail(
            "LITELLM_API_KEY absent: FINAL requires real official-runtime calls "
            "(BLOCKED — no simulation possible)"
        )

    G5_FINAL.mkdir(parents=True, exist_ok=True)
    expected_dirs = {fixture.removesuffix(".eml") for fixture in LIVE_FIXTURES}
    for stale in G5_FINAL.iterdir():
        if stale.is_dir() and stale.name not in expected_dirs:
            shutil.rmtree(stale)

    rows: list[dict[str, Any]] = []
    for fixture in LIVE_FIXTURES:
        stem = fixture.removesuffix(".eml")
        run_dir = G5_FINAL / stem
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True)

        archived = _load_archived_internal(fixture)
        internal = Assessment.model_validate(archived["assessment"])
        parsed = _parsed(fixture)
        evidence, observables, _visuals = merge_evidence(parsed, None)
        client = LunaClient(
            settings,
            phase="final",
            capture_dir=run_dir,
            persist_request_body=True,  # fixture source profile (§2.6.1)
        )
        candidate, record = assess_final(
            parsed,
            internal,
            evidence,
            [],
            client,
            observables=observables,
            tool_results=(),
            run_artifacts={"capture_dir": run_dir},
        )
        selection = final_selection(internal, candidate, record)

        audit_path = run_dir / "final_attempt_1.input_audit.json"
        audit = (
            json.loads(audit_path.read_text(encoding="utf-8"))
            if audit_path.is_file()
            else {}
        )
        metas = sorted(run_dir.glob("attempt_*_response_meta.json"))
        meta = json.loads(metas[-1].read_text(encoding="utf-8")) if metas else {}
        internal_verdict = archived.get("verdict")
        internal_confidence = archived.get("confidence")
        final_verdict = final_confidence = None
        if candidate is not None:
            from src.verify import compute_verdict_confidence

            final_verdict, final_confidence = compute_verdict_confidence(
                candidate.model_dump()["probabilities"]
            )
        external_count = audit.get("external_evidence_count_sent", 0)

        row = {
            "sample_id": f"{stem}_final",
            "fixture": fixture,
            "internal_source": f"runs/gates/G2/assessments.jsonl#{archived.get('sample_id')}",
            "internal_verdict": internal_verdict,
            "internal_confidence": internal_confidence,
            "final_source": selection.final_source,
            "final_accepted": candidate is not None,
            "final_verdict": final_verdict,
            "final_confidence": final_confidence,
            "final_assessment": (
                candidate.model_dump(mode="json") if candidate is not None else None
            ),
            "technical_status": record.status,
            "attempts": record.attempts,
            "requested_model": record.requested_model,
            "returned_model": record.returned_model,
            "reasoning_effort": record.reasoning_effort,
            "usage": {
                "input_tokens": record.input_tokens,
                "cached_input_tokens": record.cached_input_tokens,
                "output_tokens": record.output_tokens,
                "reasoning_tokens": record.reasoning_tokens,
            },
            "input_payload_sha256": audit.get("input_payload_sha256"),
            "response_sha256": meta.get("response_sha256"),
            "internal_evidence_count_sent": audit.get("internal_evidence_count_sent"),
            "external_evidence_count_sent": external_count,
            "tool_status_digest": audit.get("tool_status_digest"),
            "rag_case_count_sent": audit.get("rag_case_count_sent"),
            "visual_count_sent": audit.get("visual_count_sent"),
            "gain_without_external_evidence": signals_gain_without_external_evidence(
                internal, candidate, external_count
            ),
            "warnings": [warning.code for warning in selection.warnings],
            "error_artifacts": record.response_refs,
        }
        rows.append(row)

    (G5_FINAL / "final_runs.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return {"rows": rows, "dir": G5_FINAL}


@pytest.fixture(scope="session")
def live_final_matrix() -> dict[str, Any]:
    """Session-scoped real FINAL matrix; runs once for all live tests."""

    return _run_live_final_matrix()


@pytest.mark.live
class TestLiveFinalMatrix:
    def test_live_real_model_identity_and_effort(self, live_final_matrix: dict[str, Any]) -> None:
        rows = live_final_matrix["rows"]
        assert len(rows) == len(LIVE_FIXTURES)
        for row in rows:
            assert row["requested_model"] == EXPECTED_RUNTIME_MODEL, row["sample_id"]
            assert row["reasoning_effort"] == "xhigh", row["sample_id"]
            if row["technical_status"] == "ok":
                assert row["returned_model"] == EXPECTED_RUNTIME_MODEL, row["sample_id"]
                assert row["attempts"] >= 1

    def test_live_at_least_one_real_structured_final(
        self, live_final_matrix: dict[str, Any]
    ) -> None:
        accepted = [row for row in live_final_matrix["rows"] if row["final_accepted"]]
        assert accepted, (
            "no real FINAL call produced an accepted Assessment; archived failures: "
            + json.dumps(live_final_matrix["rows"], ensure_ascii=False)
        )

    def test_live_audit_recomputable_from_archived_request(
        self, live_final_matrix: dict[str, Any]
    ) -> None:
        for row in live_final_matrix["rows"]:
            run_dir = G5_FINAL / row["fixture"].removesuffix(".eml")
            audits = sorted(run_dir.glob("final_attempt_*.input_audit.json"))
            requests = sorted(run_dir.glob("final_attempt_*.request.json"))
            assert audits, f"{row['sample_id']}: no archived audit"
            assert requests, f"{row['sample_id']}: no archived request body"
            for audit_path in audits:
                audit = json.loads(audit_path.read_text(encoding="utf-8"))
                assert set(audit.keys()) == FINAL_AUDIT_FIELDS, row["sample_id"]
                request_path = audit_path.with_name(
                    audit_path.name.replace(".input_audit.json", ".request.json")
                )
                assert request_path.is_file(), f"{row['sample_id']}: {request_path.name}"
                archived_bytes = request_path.read_bytes()
                assert (
                    hashlib.sha256(archived_bytes).hexdigest()
                    == audit["input_payload_sha256"]
                ), row["sample_id"]
                sent = json.loads(archived_bytes.decode("utf-8"))
                envelope = json.loads(sent["messages"][1]["content"])
                untrusted = envelope["UNTRUSTED_EMAIL"]
                assert audit["untrusted_email_sha256"] == hashlib.sha256(
                    canonical_bytes(untrusted)
                ).hexdigest(), row["sample_id"]
                assert audit["body_chars_sent"] == sum(
                    len(part["text"])
                    for part in untrusted["text_parts"] + untrusted["html_parts"]
                ), row["sample_id"]
                assert audit["headers_chars_sent"] == sum(
                    len(header["name"]) + len(header["decoded_value"])
                    for header in untrusted["headers"]
                ), row["sample_id"]
                assert audit["evidence_count_sent"] == len(
                    envelope["EVIDENCE_REGISTRY"]
                ), row["sample_id"]
                assert audit["observable_count_sent"] == len(
                    envelope["OBSERVABLE_REGISTRY"]
                ), row["sample_id"]
                assert audit["external_evidence_count_sent"] == sum(
                    1
                    for entry in envelope["EVIDENCE_REGISTRY"].values()
                    if entry["provenance"] in ("OSINT", "SANDBOX")
                ), row["sample_id"]
                assert audit["tool_status_digest"] == hashlib.sha256(
                    canonical_bytes(envelope["TOOL_STATUS"])
                ).hexdigest(), row["sample_id"]
                assert audit["rag_case_count_sent"] == 0
                assert audit["visual_count_sent"] == 0

    def test_live_accepted_candidates_revalidate_against_archived_envelope(
        self, live_final_matrix: dict[str, Any]
    ) -> None:
        """Accepted candidates are independently revalidated against the
        registries read from the ARCHIVED request — not the in-memory ones."""

        for row in live_final_matrix["rows"]:
            if not row["final_accepted"]:
                continue
            run_dir = G5_FINAL / row["fixture"].removesuffix(".eml")
            request_path = next(iter(sorted(run_dir.glob("final_attempt_*.request.json"))))
            sent = json.loads(request_path.read_bytes().decode("utf-8"))
            envelope = json.loads(sent["messages"][1]["content"])
            issues = validate_final_candidate(
                row["final_assessment"],
                envelope["EVIDENCE_REGISTRY"],
                envelope["OBSERVABLE_REGISTRY"],
                [case["case_id"] for case in envelope["RAG_CONTEXT"]],
            )
            assert issues == [], f"{row['sample_id']}: {issues}"

    def test_live_external_evidence_really_zero_and_statuses_honest(
        self, live_final_matrix: dict[str, Any]
    ) -> None:
        for row in live_final_matrix["rows"]:
            assert row["external_evidence_count_sent"] == 0, row["sample_id"]
            assert row["rag_case_count_sent"] == 0, row["sample_id"]
            assert row["visual_count_sent"] == 0, row["sample_id"]
            assert row["gain_without_external_evidence"] in (True, False)

    def test_live_artifacts_written(self, live_final_matrix: dict[str, Any]) -> None:
        assert (G5_FINAL / "final_runs.jsonl").is_file()
        rows = [
            json.loads(line)
            for line in (G5_FINAL / "final_runs.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(rows) == len(LIVE_FIXTURES)

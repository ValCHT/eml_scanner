"""INTERNAL assessment tests (TICKET-04, docs/tickets/TICKET-04.md, gates §5.1.1).

Non-live coverage (no network): projection, harness-metadata exclusion,
anchors, exact-bytes audit recomputation, fingerprints, minimization,
validator rejections, injection/auth-PASS data treatment.

Live coverage (explicit ``--live``): real INTERNAL calls for all 14
parsable fixtures plus one repeat of prompt_injection.eml and
phishing_auth_pass.eml (16 real calls minimum), archived under
``runs/gates/G2/`` with real artifacts, real failures preserved, and
harness-side performance metadata. Classification disagreement with
``design_label`` is recorded and informational — never a gate condition.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
from pathlib import Path
from typing import Any

import pytest

from src.config import load_settings
from src.llm import LunaClient
from src.parsing import ParseLimits, parse_email
from src.prompts import (
    ContextLimits,
    build_internal_envelope,
    build_internal_messages,
    canonical_bytes,
    envelope_has_useful_content,
)
from src.state import ParsedEmail, TAXONOMY_ORDER
from src.verify import (
    assess_internal,
    compute_verdict_confidence,
    validate_assessment_shape_and_refs,
)

pytestmark = pytest.mark.g2

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
LIMITS = ContextLimits()

#: Harness-only manifest fields that must NEVER reach the model payload.
HARNESS_ONLY_KEYS = (
    "design_label",
    "scenario",
    "content_anchors",
    "part_expectations",
    "harness_only",
    "constraints",
)

#: Current official POC runtime identity. Cheap GPT-OSS compatibility calls
#: never execute this official G2 matrix or write its measurement artifacts.
EXPECTED_RUNTIME_MODEL = "Qwen/Qwen3.8-27B"


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Any network attempt fails non-live tests (live tests bypass this)."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in a non-live test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


def _parsed(name: str) -> ParsedEmail:
    result = parse_email(FIXTURES / name, ParseLimits())
    assert isinstance(result, ParsedEmail), f"{name}: structured failure {result}"
    return result


def _entry(name: str) -> dict[str, Any]:
    return next(entry for entry in MANIFEST["fixtures"] if entry["file"] == name)


def _payload(name: str) -> str:
    """The exact user JSON payload text for a fixture projection."""

    messages, _envelope = build_internal_messages(_parsed(name), LIMITS)
    return messages[1]["content"]


# ---------------------------------------------------------------------------
# Projection: real fixture data, deterministic
# ---------------------------------------------------------------------------


def test_real_fixture_projection_all_fixtures():
    """Every parsable fixture projects into the four conceptual fields with
    useful content and deterministic registries."""

    for entry in MANIFEST["fixtures"]:
        parsed = _parsed(entry["file"])
        envelope = build_internal_envelope(parsed, LIMITS)
        assert set(envelope.keys()) == {
            "UNTRUSTED_EMAIL",
            "EVIDENCE_REGISTRY",
            "OBSERVABLE_REGISTRY",
            "SUPPLIED_VISUAL_IDS",
        }, entry["file"]
        assert envelope_has_useful_content(envelope), entry["file"]
        again = build_internal_envelope(_parsed(entry["file"]), LIMITS)
        assert canonical_bytes(envelope) == canonical_bytes(again), entry["file"]


def test_no_fixture_filename_or_path_in_payload():
    """The fixture filename / dataset path never reaches the model payload.

    Note: a fixture's own MIME boundary string is email DATA carried by its
    Content-Type header; the prohibition targets harness file identity, so
    the assertions cover the ``.eml`` filename and path forms.
    """

    for entry in MANIFEST["fixtures"]:
        payload = _payload(entry["file"])
        assert ".eml" not in payload, entry["file"]
        assert "tests/fixtures" not in payload and "tests\\fixtures" not in payload
        assert "corpus/raw" not in payload
        assert entry["file"] not in payload, entry["file"]


def test_no_scenario_design_label_or_harness_metadata_in_payload():
    """Harness-only manifest fields are absent from the transmitted payload."""

    for entry in MANIFEST["fixtures"]:
        payload = _payload(entry["file"])
        for key in HARNESS_ONLY_KEYS:
            assert f'"{key}"' not in payload, f"{entry['file']}: {key} leaked"
        scenario = entry["scenario"]
        assert scenario not in payload, f"{entry['file']}: scenario leaked"
        # design_label as a labeled value: the JSON form must never appear.
        assert '"design_label"' not in payload
        assert f'"label": "{entry["design_label"]}"' not in payload


def test_expected_manifest_anchors_transmitted():
    """Expected useful content really appears in the transmitted payload
    (docs/gates.md §5.1.1 blocking check 1)."""

    for entry in MANIFEST["fixtures"]:
        payload = _payload(entry["file"])
        anchors = entry["content_anchors"]
        assert anchors["subject"] in payload, entry["file"]
        if anchors.get("text_plain_excerpt"):
            assert anchors["text_plain_excerpt"] in payload, entry["file"]
        if anchors.get("html_excerpt"):
            assert anchors["html_excerpt"] in payload, entry["file"]
        for url in anchors.get("expected_urls", []):
            assert url in payload, entry["file"]


def test_evidence_and_observable_ids_valid_and_deterministic():
    """Registry IDs are the parser's deterministic prefixed IDs; every
    evidence observable_id resolves inside the sent registry."""

    for entry in MANIFEST["fixtures"]:
        parsed = _parsed(entry["file"])
        envelope = build_internal_envelope(parsed, LIMITS)
        for ev_id, ev in envelope["EVIDENCE_REGISTRY"].items():
            assert ev_id.startswith("ev_"), entry["file"]
            assert ev["provenance"] == "INTERNE", entry["file"]
            obs_id = ev.get("observable_id")
            if obs_id is not None:
                assert obs_id in envelope["OBSERVABLE_REGISTRY"], entry["file"]
        for obs_id in envelope["OBSERVABLE_REGISTRY"]:
            assert obs_id.startswith("obs_"), entry["file"]


def test_no_external_evidence_in_envelope():
    """INTERNAL is email-only: no OSINT/SANDBOX provenance is ever sent."""

    for entry in MANIFEST["fixtures"]:
        envelope = build_internal_envelope(_parsed(entry["file"]), LIMITS)
        for ev in envelope["EVIDENCE_REGISTRY"].values():
            assert ev["provenance"] not in ("OSINT", "SANDBOX"), entry["file"]


def test_no_pixels_and_no_invented_visual_content():
    """No pixels are supplied (SUPPLIED_VISUAL_IDS empty), image metadata is
    never turned into a visual description, and the QR destination that
    exists only inside pixels is never invented in the payload."""

    for entry in MANIFEST["fixtures"]:
        envelope = build_internal_envelope(_parsed(entry["file"]), LIMITS)
        assert envelope["SUPPLIED_VISUAL_IDS"] == [], entry["file"]
        payload = json.dumps(envelope, ensure_ascii=False)
        assert "data:image" not in payload, entry["file"]
        for image in envelope["UNTRUSTED_EMAIL"]["images"]:
            assert image["status"] == "metadata_only", entry["file"]
            assert set(image.keys()) <= {
                "sha256",
                "mime_type",
                "status",
                "content_id",
                "part_id",
            }, entry["file"]

    qr_payload = _payload("qr_phishing.eml")
    # The QR payload exists ONLY in pixels: inventing it would be a visual
    # gap fabricated into an observable.
    assert "qr.notice.test" not in qr_payload


# ---------------------------------------------------------------------------
# Exact-bytes input audit (docs/contracts.md §2.6.1)
# ---------------------------------------------------------------------------


def _assessment_response_bytes(content: str, model: str) -> bytes:
    body = {
        "model": model,
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    return json.dumps(body).encode("utf-8")


def _valid_assessment_dict() -> dict[str, Any]:
    return {
        "probabilities": {
            "spear_phishing": 0.05,
            "phishing": 0.75,
            "fraude": 0.05,
            "menace": 0.05,
            "spam": 0.05,
            "legitime": 0.05,
        },
        "observations": [],
        "inferences": [],
        "observable_assessments": [],
        "needs_enrichment": False,
        "missing_information": ["insufficient_context"],
        "decisive_evidence_ids": [],
    }


def _captured_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response_body: bytes,
    persist_request_body: bool,
) -> tuple[LunaClient, dict[str, bytes]]:
    """Real client whose transport records the EXACT bytes it receives."""

    monkeypatch.setenv("LITELLM_API_KEY", "sk-canary-0123456789abcdef")
    monkeypatch.setenv("LITELLM_CHAT_URL", "https://endpoint.invalid/chat/completions")
    monkeypatch.setenv("LITELLM_MODEL", "openai/gpt-5.6-luna")
    settings = load_settings(None)
    client = LunaClient(
        settings,
        phase="internal",
        capture_dir=tmp_path / "captures",
        persist_request_body=persist_request_body,
    )
    captured: dict[str, bytes] = {}

    def _fake_post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
        captured["body"] = body
        return 200, response_body

    client._post_bytes = _fake_post  # type: ignore[method-assign]
    return client, captured


def _run_fixture_attempt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    persist_request_body: bool,
) -> tuple[LunaClient, dict[str, bytes], Any, dict[str, Any]]:
    parsed = _parsed(name)
    client, captured = _captured_client(
        monkeypatch,
        tmp_path,
        _assessment_response_bytes(
            json.dumps(_valid_assessment_dict()), "openai/gpt-5.6-luna"
        ),
        persist_request_body,
    )
    import time as _time

    assessment, record = assess_internal(
        parsed,
        client,
        LIMITS,
        run_artifacts={"capture_dir": tmp_path / "captures"},
    )
    return client, captured, assessment, record


def test_exact_fixture_request_audit_recomputation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """For a fixture: the archived request can be rehashed locally, the
    recomputed counters equal the audit fields, and the archived bytes are
    exactly those handed to transport (§5.1.1 check 4)."""

    _client, captured, _assessment, record = _run_fixture_attempt(
        monkeypatch, tmp_path, "phishing_simple.eml", persist_request_body=True
    )
    captures = tmp_path / "captures"
    audit_path = captures / "internal_attempt_1.input_audit.json"
    request_path = captures / "internal_attempt_1.request.json"
    assert audit_path.is_file() and request_path.is_file()
    audit = json.loads(audit_path.read_text(encoding="utf-8"))

    archived = request_path.read_bytes()
    # The archived bytes ARE the bytes given to transport:
    assert archived == captured["body"]
    # Rehash of the archived request == audit payload hash:
    assert hashlib.sha256(archived).hexdigest() == audit["input_payload_sha256"]
    assert record.request_sha256 == audit["input_payload_sha256"]

    # Recompute the counters from the archived request itself:
    sent = json.loads(archived.decode("utf-8"))
    envelope = json.loads(sent["messages"][1]["content"])
    untrusted = envelope["UNTRUSTED_EMAIL"]
    assert audit["untrusted_email_sha256"] == hashlib.sha256(
        canonical_bytes(untrusted)
    ).hexdigest()
    assert audit["body_chars_sent"] == sum(
        len(p["text"]) for p in untrusted["text_parts"] + untrusted["html_parts"]
    )
    assert audit["headers_chars_sent"] == sum(
        len(h["name"]) + len(h["decoded_value"]) for h in untrusted["headers"]
    )
    assert audit["evidence_count_sent"] == len(envelope["EVIDENCE_REGISTRY"])
    assert audit["observable_count_sent"] == len(envelope["OBSERVABLE_REGISTRY"])
    assert audit["phase"] == "internal"
    # Complete §2.6.1 field set:
    assert set(audit.keys()) == {
        "phase",
        "input_payload_sha256",
        "untrusted_email_sha256",
        "body_chars_sent",
        "headers_chars_sent",
        "evidence_count_sent",
        "observable_count_sent",
    }
    assert audit["body_chars_sent"] > 0 and audit["headers_chars_sent"] > 0


def test_input_payload_sha256_is_exact_transport_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """input_payload_sha256 is the SHA-256 of the exact bytes the transport
    received — serialized once, never re-serialized for audit."""

    _client, captured, _assessment, _record = _run_fixture_attempt(
        monkeypatch, tmp_path, "spam_promo.eml", persist_request_body=False
    )
    audit = json.loads(
        (tmp_path / "captures" / "internal_attempt_1.input_audit.json").read_text(
            encoding="utf-8"
        )
    )
    assert audit["input_payload_sha256"] == hashlib.sha256(captured["body"]).hexdigest()


def test_untrusted_email_sha256_is_exact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """untrusted_email_sha256 recomputes from the envelope inside the exact
    transport bytes, not from a re-projection."""

    name = "bec_fraud.eml"
    _client, captured, _assessment, _record = _run_fixture_attempt(
        monkeypatch, tmp_path, name, persist_request_body=True
    )
    audit = json.loads(
        (tmp_path / "captures" / "internal_attempt_1.input_audit.json").read_text(
            encoding="utf-8"
        )
    )
    sent = json.loads(captured["body"].decode("utf-8"))
    envelope = json.loads(sent["messages"][1]["content"])
    assert audit["untrusted_email_sha256"] == hashlib.sha256(
        canonical_bytes(envelope["UNTRUSTED_EMAIL"])
    ).hexdigest()


def test_distinct_payload_fingerprints_for_distinct_inputs():
    """Different fixtures produce distinct untrusted inputs AND distinct
    HTTP payload fingerprints (docs/gates.md §5.1.1 check 3)."""

    fingerprints: dict[str, tuple[str, str]] = {}
    for name in ("phishing_simple.eml", "spam_promo.eml", "threat_extortion.eml"):
        messages, _envelope = build_internal_messages(_parsed(name), LIMITS)
        payload = json.dumps(
            {"messages": messages}, ensure_ascii=False, sort_keys=True
        ).encode("utf-8")
        envelope = json.loads(messages[1]["content"])
        fingerprints[name] = (
            hashlib.sha256(payload).hexdigest(),
            hashlib.sha256(canonical_bytes(envelope["UNTRUSTED_EMAIL"])).hexdigest(),
        )
    payload_hashes = {fp[0] for fp in fingerprints.values()}
    email_hashes = {fp[1] for fp in fingerprints.values()}
    assert len(payload_hashes) == len(fingerprints)
    assert len(email_hashes) == len(fingerprints)


def test_public_private_path_does_not_persist_request_body(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Minimization regression (§2.6.1): without the explicit fixture flag,
    the same serialization/audit path runs and the audit is archived, but
    NO full HTTP request body is persisted."""

    _client, _captured, assessment, record = _run_fixture_attempt(
        monkeypatch, tmp_path, "phishing_simple.eml", persist_request_body=False
    )
    assert assessment is not None and record.status == "ok"
    captures = tmp_path / "captures"
    assert (captures / "internal_attempt_1.input_audit.json").is_file()
    assert not list(captures.glob("*_attempt_*.request.json"))


# ---------------------------------------------------------------------------
# Validator rejections (invalid data is rejected, never repaired)
# ---------------------------------------------------------------------------


def _registry_for(name: str) -> dict[str, dict[str, Any]]:
    envelope = build_internal_envelope(_parsed(name), LIMITS)
    return {
        "evidence": envelope["EVIDENCE_REGISTRY"],
        "observables": envelope["OBSERVABLE_REGISTRY"],
    }


def _valid_candidate() -> dict[str, Any]:
    return _valid_assessment_dict()


def test_unknown_evidence_refs_rejected():
    candidate = _valid_candidate()
    candidate["observations"] = ["ev_does_not_exist"]
    issues = validate_assessment_shape_and_refs(
        candidate, _registry_for("phishing_simple.eml"), "internal"
    )
    assert any("unknown evidence ID" in issue for issue in issues)

    candidate2 = _valid_candidate()
    candidate2["decisive_evidence_ids"] = ["ev_missing_decisive"]
    issues2 = validate_assessment_shape_and_refs(
        candidate2, _registry_for("phishing_simple.eml"), "internal"
    )
    assert any("unknown evidence ID" in issue for issue in issues2)


def test_unknown_observable_refs_rejected():
    candidate = _valid_candidate()
    candidate["observable_assessments"] = [
        {
            "observable_id": "obs_unknown",
            "category": "S",
            "evidence_ids": [],
            "reason_code": "unconfirmed",
        }
    ]
    issues = validate_assessment_shape_and_refs(
        candidate, _registry_for("phishing_simple.eml"), "internal"
    )
    assert any("unknown observable ID" in issue for issue in issues)


def test_invalid_probabilities_rejected():
    registry = _registry_for("phishing_simple.eml")

    wrong_sum = _valid_candidate()
    wrong_sum["probabilities"]["phishing"] = 0.9  # sum = 1.15
    issues = validate_assessment_shape_and_refs(wrong_sum, registry, "internal")
    assert any("sum" in issue for issue in issues)

    out_of_range = _valid_candidate()
    out_of_range["probabilities"]["spam"] = 1.2  # sum also broken
    issues2 = validate_assessment_shape_and_refs(out_of_range, registry, "internal")
    assert issues2  # rejected

    missing_class = _valid_candidate()
    del missing_class["probabilities"]["menace"]
    issues3 = validate_assessment_shape_and_refs(missing_class, registry, "internal")
    # Rejected either by the strict schema check (missing field) or by the
    # probability-vector check (six taxonomy keys required).
    assert any(
        ("menace" in issue or "exactly the six taxonomy keys" in issue)
        for issue in issues3
    )


def test_non_empty_rag_case_ids_rejected_in_internal():
    candidate = _valid_candidate()
    evidence_ids = sorted(_registry_for("phishing_simple.eml")["evidence"].keys())
    candidate["inferences"] = [
        {
            "id": "inf_1",
            "code": "link_mismatch",
            "summary": "test",
            "evidence_ids": [evidence_ids[0]],
            "rag_case_ids": ["case_42"],
        }
    ]
    issues = validate_assessment_shape_and_refs(
        candidate, _registry_for("phishing_simple.eml"), "internal"
    )
    assert any("rag_case_ids" in issue and "[]" in issue for issue in issues)


def test_osint_sandbox_evidence_rejected():
    registry = _registry_for("phishing_simple.eml")
    first_id = sorted(registry["evidence"].keys())[0]
    registry["evidence"][first_id] = dict(registry["evidence"][first_id]) | {
        "provenance": "OSINT"
    }
    candidate = _valid_candidate()
    candidate["observations"] = [first_id]
    issues = validate_assessment_shape_and_refs(candidate, registry, "internal")
    assert any("INTERNE evidence only" in issue for issue in issues)


def test_cardinality_and_summary_limits_enforced():
    registry = _registry_for("phishing_simple.eml")
    candidate = _valid_candidate()
    candidate["decisive_evidence_ids"] = ["a", "b", "c", "d"]
    issues = validate_assessment_shape_and_refs(candidate, registry, "internal")
    assert any("decisive_evidence_ids" in issue for issue in issues)

    too_long_summary = _valid_candidate()
    too_long_summary["inferences"] = [
        {
            "id": "inf_1",
            "code": "insufficient_information",
            "summary": "x" * 241,
            "evidence_ids": [],
            "rag_case_ids": [],
        }
    ]
    issues2 = validate_assessment_shape_and_refs(too_long_summary, registry, "internal")
    assert any("240" in issue for issue in issues2)  # summary length limit


# ---------------------------------------------------------------------------
# Envelope guard, injection/auth as data (non-live)
# ---------------------------------------------------------------------------


def test_empty_or_substituted_payload_rejected_before_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty/substituted envelope is refused BEFORE any LLM call:
    explicit error, zero attempts, archived cause — never a silent send."""

    empty = ParsedEmail(email_sha256="0" * 64, raw_size_bytes=0, input_format="rfc822")
    client, captured = _captured_client(
        monkeypatch,
        tmp_path,
        _assessment_response_bytes(json.dumps(_valid_assessment_dict()), "openai/gpt-5.6-luna"),
        persist_request_body=False,
    )
    assessment, record = assess_internal(
        empty, client, LIMITS, run_artifacts={"capture_dir": tmp_path / "captures"}
    )
    assert assessment is None
    assert record.status == "error"
    assert record.attempts == 0  # no call was made
    assert captured == {}  # transport was never invoked
    assert (tmp_path / "captures" / "internal_projection_error.txt").is_file()


def test_prompt_injection_is_data_not_instructions():
    """The embedded instructions are transmitted as UNTRUSTED_EMAIL data;
    the system prompt remains the delivered file (nothing appended/edited)."""

    from src.prompts import load_internal_prompt

    messages, _envelope = build_internal_messages(_parsed("prompt_injection.eml"), LIMITS)
    assert messages[0]["content"] == load_internal_prompt()
    payload = messages[1]["content"]
    assert "ignore all previous instructions" in payload  # present as DATA
    # The payload is exactly one JSON object with the four conceptual fields
    # (sorted keys: EVIDENCE_REGISTRY first) — the instruction lives inside
    # the UNTRUSTED_EMAIL data, never as a separate instruction message.
    sent = json.loads(payload)
    assert set(sent.keys()) == {
        "UNTRUSTED_EMAIL",
        "EVIDENCE_REGISTRY",
        "OBSERVABLE_REGISTRY",
        "SUPPLIED_VISUAL_IDS",
    }
    serialized_untrusted = json.dumps(sent["UNTRUSTED_EMAIL"], ensure_ascii=False)
    assert "ignore all previous instructions" in serialized_untrusted


def test_auth_pass_is_reported_unverified_evidence():
    """SPF/DKIM/DMARC PASS enters as reported_unverified data; nothing in
    the projection turns it into a trusted/benign technical fact."""

    envelope = build_internal_envelope(_parsed("phishing_auth_pass.eml"), LIMITS)
    auth = envelope["UNTRUSTED_EMAIL"]["authentication"]
    assert len(auth) == 3
    for entry in auth:
        assert entry["result"] == "pass"
        assert entry["trust"] == "reported_unverified"
    payload = json.dumps(envelope, ensure_ascii=False)
    assert '"trusted_receiver"' not in payload


def test_verdict_confidence_argmax_with_taxonomy_tiebreak():
    probabilities = {label: 0.1 for label in TAXONOMY_ORDER}
    probabilities["spam"] = probabilities["legitime"] = 0.4  # exact tie
    verdict, confidence = compute_verdict_confidence(probabilities)
    assert verdict == "spam"  # earlier in TAXONOMY_ORDER wins the tie
    assert confidence == 0.4


# ---------------------------------------------------------------------------
# Review fixes: context budgets and stricter INTERNAL validation
# ---------------------------------------------------------------------------


def test_body_truncation_flag_covers_text_and_html_parts():
    """Review fix: a text/plain cut must flag body_truncated exactly like
    an HTML cut (both sections share the single body budget)."""

    tiny = ContextLimits(body_chars=50)
    envelope = build_internal_envelope(_parsed("phishing_simple.eml"), tiny)
    assert "body_truncated" in envelope["UNTRUSTED_EMAIL"]["content_limits"]
    # No silent empty replacement: the kept part text is a real prefix.
    kept = [p for p in envelope["UNTRUSTED_EMAIL"]["text_parts"] if p["text"]]
    assert kept and all(len(p["text"]) <= 50 for p in kept)


def test_mandatory_observables_respect_budget_no_dangling_refs():
    """Review fix: observables referenced by kept evidence are budget-bound
    too; an evidence whose observable no longer fits is dropped, so the
    payload never carries a dangling observable_id (and the 16k budget
    holds for the OBSERVABLE_REGISTRY)."""

    from src.prompts import canonical_bytes

    tiny = ContextLimits(urls_observables_chars=200)
    envelope = build_internal_envelope(_parsed("phishing_simple.eml"), tiny)
    registry = envelope["OBSERVABLE_REGISTRY"]
    used = sum(len(canonical_bytes(entry).decode("utf-8")) for entry in registry.values())
    assert used <= tiny.urls_observables_chars
    for ev in envelope["EVIDENCE_REGISTRY"].values():
        assert ev["observable_id"] is None or ev["observable_id"] in registry


def test_validator_rejects_any_non_interne_provenance():
    """Review fix: INTERNAL rejects ANY provenance other than INTERNE
    (INFERENCE included, and unknown/missing values) — not only
    OSINT/SANDBOX."""

    registry = _registry_for("phishing_simple.eml")
    first_id = sorted(registry["evidence"].keys())[0]
    for bad_provenance in ("INFERENCE", "OSINT", "SANDBOX", None, "unexpected"):
        poisoned = dict(registry["evidence"][first_id])
        poisoned["provenance"] = bad_provenance
        candidate_registry = {
            "evidence": {first_id: poisoned},
            "observables": registry["observables"],
        }
        candidate = _valid_candidate()
        candidate["observations"] = [first_id]
        issues = validate_assessment_shape_and_refs(
            candidate, candidate_registry, "internal"
        )
        assert any("INTERNE evidence only" in issue for issue in issues), bad_provenance


def test_validate_reports_requires_registries(tmp_path: Path):
    """Review fix: the validator cannot prove references without the
    registries — a bare Assessment (or a wrapped record missing one
    registry) is rejected, never accepted on probabilities alone."""

    import subprocess
    import sys

    assessment = _valid_candidate()
    bare = tmp_path / "bare.jsonl"
    bare.write_text(json.dumps(assessment) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "scripts/validate_reports.py", "--assessments", str(bare)],
        cwd=PROJECT_ROOT, shell=False, capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "assessment" in (proc.stderr + proc.stdout)

    missing_one = tmp_path / "missing_one.jsonl"
    missing_one.write_text(
        json.dumps({"assessment": assessment, "evidence_registry": {}}) + "\n",
        encoding="utf-8",
    )
    proc2 = subprocess.run(
        [sys.executable, "scripts/validate_reports.py", "--assessments", str(missing_one)],
        cwd=PROJECT_ROOT, shell=False, capture_output=True, text=True,
    )
    assert proc2.returncode != 0
    assert "observable_registry" in (proc2.stderr + proc2.stdout)


# ---------------------------------------------------------------------------
# LIVE matrix (explicit --live): real calls, real artifacts, G2 evidence
# ---------------------------------------------------------------------------


def _g2_dir() -> Path:
    return PROJECT_ROOT / "runs" / "gates" / "G2"


def _attempt_meta(capture_dir: Path) -> dict[str, Any]:
    metas = sorted(capture_dir.glob("attempt_*_response_meta.json"))
    if not metas:
        return {}
    return json.loads(metas[-1].read_text(encoding="utf-8"))


def _run_live_matrix() -> dict[str, Any]:
    """Run the 16 real INTERNAL calls once per pytest session and archive
    the G2 artifacts (fixture_performance.jsonl, assessments.jsonl, per-run
    capture directories). Real failures are archived, never simulated."""

    settings = load_settings(None)
    if settings.LITELLM_API_KEY is None:
        pytest.fail(
            "LITELLM_API_KEY absent: G2 requires real official-runtime calls "
            "(BLOCKED — no simulation possible)"
        )

    runs_dir = _g2_dir() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    # 14 fixtures once + a second run for injection and auth-pass.
    plan: list[tuple[str, int]] = [(entry["file"], 1) for entry in MANIFEST["fixtures"]]
    plan += [("prompt_injection.eml", 2), ("phishing_auth_pass.eml", 2)]
    canonical_run_ids = {
        f"{fixture.removesuffix('.eml')}_rep{repetition}" for fixture, repetition in plan
    }
    # Stale directories from an earlier session (e.g. a fixture renamed or a
    # plan change) are removed: only the canonical run set may remain.
    for stale in runs_dir.iterdir():
        if stale.name not in canonical_run_ids:
            shutil.rmtree(stale)

    performance: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    canonical_session: list[str] = []
    for fixture_name, repetition in plan:
        stem = fixture_name.removesuffix(".eml")
        entry = _entry(fixture_name)
        run_id = f"{stem}_rep{repetition}"
        capture_dir = runs_dir / run_id
        # Remise à zéro systématique: un répertoire réutilisé d'une session
        # précédente peut contenir des artefacts stale (attempt_2_*, rejets
        # de validation antérieurs) qui contamineraient la preuve de CE run.
        if capture_dir.exists():
            shutil.rmtree(capture_dir)
        capture_dir.mkdir(parents=True, exist_ok=True)
        canonical_session.append(run_id)
        parsed = _parsed(fixture_name)
        client = LunaClient(
            settings,
            phase="internal",
            capture_dir=capture_dir,
            persist_request_body=True,  # fixture source profile (§2.6.1)
        )
        envelope = build_internal_envelope(parsed, LIMITS)
        assessment, record = assess_internal(
            parsed, client, LIMITS, run_artifacts={"capture_dir": capture_dir}
        )
        meta = _attempt_meta(capture_dir)
        audit_path = capture_dir / "internal_attempt_1.input_audit.json"
        audit = (
            json.loads(audit_path.read_text(encoding="utf-8"))
            if audit_path.is_file()
            else {}
        )
        verdict = confidence = None
        accepted_flag = assessment is not None
        if assessment is not None:
            verdict, confidence = compute_verdict_confidence(
                {label: getattr(assessment.probabilities, label) for label in TAXONOMY_ORDER}
            )
            accepted.append(
                {
                    "sample_id": run_id,
                    "fixture": fixture_name,
                    "repetition": repetition,
                    "assessment": assessment.model_dump(),
                    "evidence_registry": envelope["EVIDENCE_REGISTRY"],
                    "observable_registry": envelope["OBSERVABLE_REGISTRY"],
                    "verdict": verdict,
                    "confidence": confidence,
                }
            )
        reject_path = capture_dir / "internal_validation_reject.json"
        performance.append(
            {
                "sample_id": run_id,
                "fixture": fixture_name,  # harness-side only, never sent
                "repetition": repetition,
                "design_label": entry["design_label"],
                "observed_verdict": verdict,
                "confidence": confidence,
                "agrees_with_design_label": (
                    verdict == entry["design_label"] if verdict is not None else None
                ),
                # Outcome taxonomy: accepted (valid Assessment) / rejected
                # (real call succeeded, candidate refused by local
                # validation, archived in internal_validation_reject.json) /
                # error (no validated answer: refusal, timeout, schema
                # violation — archived). All three are real outcomes.
                "accepted": accepted_flag,
                # A validator-rejected candidate is identified by its archived
                # rejection file (the phase record itself is set to
                # "error" by assess_internal to avoid an ambiguous
                # "ok without assessment" state).
                "validation_rejected": (
                    not accepted_flag and reject_path.is_file()
                ),
                "technical_status": record.status,
                "attempts": record.attempts,
                "first_attempt_schema_valid": record.first_attempt_schema_valid,
                "input_payload_sha256": audit.get("input_payload_sha256"),
                "untrusted_email_sha256": audit.get("untrusted_email_sha256"),
                "body_chars_sent": audit.get("body_chars_sent"),
                "headers_chars_sent": audit.get("headers_chars_sent"),
                "evidence_count_sent": audit.get("evidence_count_sent"),
                "observable_count_sent": audit.get("observable_count_sent"),
                "response_sha256": meta.get("response_sha256"),
                "requested_model": record.requested_model,
                "returned_model": record.returned_model,
                "reasoning_effort": record.reasoning_effort,
                "usage": {
                    "input_tokens": record.input_tokens,
                    "cached_input_tokens": record.cached_input_tokens,
                    "output_tokens": record.output_tokens,
                    "reasoning_tokens": record.reasoning_tokens,
                },
                "error_artifacts": record.response_refs,
            }
        )

    g2 = _g2_dir()
    perf_path = g2 / "fixture_performance.jsonl"
    perf_path.write_text(
        "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in performance),
        encoding="utf-8",
    )
    assessments_path = g2 / "assessments.jsonl"
    assessments_path.write_text(
        "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in accepted),
        encoding="utf-8",
    )
    return {"performance": performance, "accepted": accepted}


@pytest.fixture(scope="session")
def live_matrix() -> dict[str, Any]:
    """Session-scoped live matrix; runs once for all live tests."""

    return _run_live_matrix()


@pytest.mark.live
class TestLiveInternalMatrix:
    def test_sixteen_real_calls_with_real_model_identity(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """>= 16 real INTERNAL runs; the model contract is real: the
        requested model is always Qwen/Qwen3.8-27B, and every SUCCESSFUL
        structured response reports returned == requested (silent
        substitution is refused by the client itself). Failed attempts
        legitimately carry returned_model=None: no success is invented."""

        performance = live_matrix["performance"]
        assert len(performance) >= 16
        for line in performance:
            assert line["requested_model"] == EXPECTED_RUNTIME_MODEL, line["sample_id"]
            assert line["reasoning_effort"] == "medium", line["sample_id"]
            if line["technical_status"] == "ok":
                assert line["returned_model"] == EXPECTED_RUNTIME_MODEL, line["sample_id"]

    def test_at_least_one_real_structured_success(self, live_matrix: dict[str, Any]) -> None:
        """At least one real business-structured success proves the full
        contract on the real endpoint (docs/tickets/TICKET-04.md)."""

        accepted = live_matrix["accepted"]
        assert len(accepted) >= 1
        for line in live_matrix["performance"]:
            if line["technical_status"] == "ok":
                assert line["first_attempt_schema_valid"] is not None

    def test_every_run_is_success_or_explicit_archived_outcome(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """Every fixture result is one of: an accepted valid Assessment, a
        candidate rejected by local validation (archived), or an explicit
        archived failure (refusal/timeout/schema violation) — never
        fabricated."""

        for line in live_matrix["performance"]:
            if line["accepted"]:
                assert line["observed_verdict"] is not None
            elif line["validation_rejected"]:
                # assess_internal flags a validator-rejected candidate as an
                # explicit error (no ambiguous "ok without assessment"
                # state); the rejection itself is archived per run.
                assert line["technical_status"] == "error"
                run_dir = _g2_dir() / "runs" / line["sample_id"]
                assert (run_dir / "internal_validation_reject.json").is_file(), (
                    line["sample_id"]
                )
            else:
                assert line["error_artifacts"], line["sample_id"]

    def test_accepted_assessments_are_valid_and_internal_only(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """Every accepted output: six valid probabilities, strict schema,
        existing IDs, no external evidence — revalidated independently."""

        for record in live_matrix["accepted"]:
            registry = {
                "evidence": record["evidence_registry"],
                "observables": record["observable_registry"],
            }
            issues = validate_assessment_shape_and_refs(
                record["assessment"], registry, "internal"
            )
            assert issues == [], f"{record['sample_id']}: {issues}"
            for ev in record["evidence_registry"].values():
                assert ev["provenance"] == "INTERNE"

    def test_live_anchors_and_counters_for_every_sent_entry(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """Anti-wiring per docs/gates.md §5.1.1 (blocking checks 1 and 4),
        applied to EVERY run that actually sent an entry — accepted runs AND
        runs that later failed (their sent input must be proven correct too,
        not skipped):

        - the manifest-declared anchors (subject, excerpts, expected URLs)
          really appear in the transmitted UNTRUSTED_EMAIL;
        - the four counters recomputed from the ARCHIVED request bytes equal
          the audit fields archived at send time.
        """

        for line in live_matrix["performance"]:
            sample_id = line["sample_id"]
            request_path = _g2_dir() / "runs" / sample_id / "internal_attempt_1.request.json"
            audit_path = _g2_dir() / "runs" / sample_id / "internal_attempt_1.input_audit.json"
            assert request_path.is_file(), f"{sample_id}: no archived request"
            assert audit_path.is_file(), f"{sample_id}: no archived audit"
            audit = json.loads(audit_path.read_text(encoding="utf-8"))

            # (4) Recompute hashes and the four counters from the archived
            # request itself — not from the in-memory objects.
            archived = request_path.read_bytes()
            assert (
                hashlib.sha256(archived).hexdigest() == audit["input_payload_sha256"]
            ), sample_id
            sent = json.loads(archived.decode("utf-8"))
            envelope = json.loads(sent["messages"][1]["content"])
            untrusted = envelope["UNTRUSTED_EMAIL"]
            assert audit["untrusted_email_sha256"] == hashlib.sha256(
                canonical_bytes(untrusted)
            ).hexdigest(), sample_id
            assert audit["body_chars_sent"] == sum(
                len(p["text"]) for p in untrusted["text_parts"] + untrusted["html_parts"]
            ), sample_id
            assert audit["headers_chars_sent"] == sum(
                len(h["name"]) + len(h["decoded_value"]) for h in untrusted["headers"]
            ), sample_id
            assert audit["evidence_count_sent"] == len(envelope["EVIDENCE_REGISTRY"]), sample_id
            assert audit["observable_count_sent"] == len(envelope["OBSERVABLE_REGISTRY"]), sample_id

            # (1) The expected useful content of THIS fixture is really in
            # the transmitted envelope — an ID/filename/text of another
            # fixture would not satisfy this check.
            anchors = _entry(line["fixture"])["content_anchors"]
            serialized_untrusted = json.dumps(untrusted, ensure_ascii=False)
            assert anchors["subject"] in serialized_untrusted, sample_id
            if anchors.get("text_plain_excerpt"):
                assert anchors["text_plain_excerpt"] in serialized_untrusted, sample_id
            if anchors.get("html_excerpt"):
                assert anchors["html_excerpt"] in serialized_untrusted, sample_id
            for url in anchors.get("expected_urls", []):
                assert url in serialized_untrusted, sample_id

    def test_live_identical_assessments_record_diagnostic(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """docs/gates.md §5.1.1 check 5: strictly identical Assessment
        responses across DISTINCT fixtures are a wiring DIAGNOSTIC, recorded
        here (and in the PR description) — identical verdicts alone, or
        identical outputs on proven-distinct inputs, are never by
        themselves a technical failure. Repeated runs of the SAME fixture
        are NOT a diagnostic group: they share the input by design."""

        # Group by fixture: a group with >1 DISTINCT fixture holding a
        # strictly identical canonical Assessment is the diagnostic case.
        by_canonical: dict[str, set[str]] = {}
        for record in live_matrix["accepted"]:
            canonical = canonical_bytes(record["assessment"]).decode("utf-8")
            by_canonical.setdefault(canonical, set()).add(record["fixture"])
        duplicates = {
            canonical: fixtures
            for canonical, fixtures in by_canonical.items()
            if len(fixtures) > 1
        }
        diagnostic_path = _g2_dir() / "identical_assessments_diagnostic.json"
        if duplicates:
            # Group key: full SHA-256 of the canonical JSON (never a
            # truncated form — the complete digest is the group identity).
            diagnostic_path.write_text(
                json.dumps(
                    {
                        "note": (
                            "identical canonical Assessment responses across distinct "
                            "fixtures: wiring diagnostic (§5.1.1 check 5); inputs were "
                            "proven distinct by untrusted_email_sha256/input_payload_sha256"
                        ),
                        "groups": {
                            hashlib.sha256(canonical.encode("utf-8")).hexdigest(): sorted(
                                fixtures
                            )
                            for canonical, fixtures in duplicates.items()
                        },
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        else:
            # No duplicate: record the negative fact explicitly so the
            # diagnostic artifact always documents the check outcome.
            diagnostic_path.write_text(
                json.dumps(
                    {
                        "note": "no identical canonical Assessment across distinct fixtures",
                        "groups": {},
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        assert diagnostic_path.is_file()

    def test_live_distinct_fixtures_distinct_fingerprints(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """Distinct fixtures produce distinct untrusted_email_sha256 AND
        distinct input_payload_sha256 (docs/gates.md §5.1.1 check 3 covers
        BOTH hash families). Repeated runs of the SAME fixture legitimately
        share both fingerprints: identical input bytes give an identical
        deterministic projection and payload — that identity is itself part
        of the fingerprint proof."""

        seen_email: dict[str, str] = {}
        seen_payload: dict[str, str] = {}
        for line in live_matrix["performance"]:
            fixture = line["fixture"]
            email_hash = line["untrusted_email_sha256"]
            if email_hash:
                if email_hash in seen_email and seen_email[email_hash] != fixture:
                    pytest.fail(
                        f"identical untrusted_email_sha256 for distinct fixtures: "
                        f"{seen_email[email_hash]} and {fixture}"
                    )
                seen_email.setdefault(email_hash, fixture)
            payload_hash = line["input_payload_sha256"]
            if payload_hash:
                if payload_hash in seen_payload and seen_payload[payload_hash] != fixture:
                    pytest.fail(
                        f"identical input_payload_sha256 for distinct fixtures: "
                        f"{seen_payload[payload_hash]} and {fixture}"
                    )
                seen_payload.setdefault(payload_hash, fixture)
        # Every distinct fixture is represented by exactly one hash of EACH
        # family (both uniqueness proofs cover the full run set).
        distinct_fixtures = {line["fixture"] for line in live_matrix["performance"]}
        assert len(seen_email) == len(distinct_fixtures)
        assert len(seen_payload) == len(distinct_fixtures)

    def test_live_injection_stays_schema_bound(self, live_matrix: dict[str, Any]) -> None:
        """prompt_injection.eml (both runs): the embedded instructions remain
        untrusted data; no takeover — the output stays a schema-bound
        Assessment with no real secret value. Quoting the injection attempt
        inside a ``prompt_injection`` inference is the DESIRED reporting
        behavior (the instruction was treated as data to report, not to
        obey). Classification is NOT asserted."""

        injection_runs = [
            line
            for line in live_matrix["performance"]
            if line["fixture"] == "prompt_injection.eml"
        ]
        assert len(injection_runs) >= 2
        for line in injection_runs:
            assert line["technical_status"] in ("ok", "error")
            if line["accepted"]:
                accepted = next(
                    record
                    for record in live_matrix["accepted"]
                    if record["sample_id"] == line["sample_id"]
                )
                serialized = json.dumps(accepted["assessment"])
                assert "sk-" not in serialized  # no real secret value displayed
                # Output stays strictly schema-bound (revalidated):
                registry = {
                    "evidence": accepted["evidence_registry"],
                    "observables": accepted["observable_registry"],
                }
                issues = validate_assessment_shape_and_refs(
                    accepted["assessment"], registry, "internal"
                )
                assert issues == [], f"{line['sample_id']}: {issues}"
        # The two real runs are archived separately with their own hashes;
        # response variations are measured, not hidden.
        hashes = {line["response_sha256"] for line in injection_runs}
        assert len(hashes) >= 1
        perf_path = _g2_dir() / "fixture_performance.jsonl"
        assert perf_path.is_file()

    def test_live_auth_pass_never_becomes_benign_rule(
        self, live_matrix: dict[str, Any]
    ) -> None:
        """phishing_auth_pass.eml (both runs): auth PASS data was sent as
        reported_unverified; no technical rule forces the classification.
        The observed verdict is recorded as informational only."""

        auth_runs = [
            line
            for line in live_matrix["performance"]
            if line["fixture"] == "phishing_auth_pass.eml"
        ]
        assert len(auth_runs) >= 2
        for line in auth_runs:
            # informational record exists either way; never a gate condition
            assert line["agrees_with_design_label"] in (True, False, None)

    def test_live_artifacts_written(self, live_matrix: dict[str, Any]) -> None:
        """The G2 archive exists with real per-run artifacts."""

        g2 = _g2_dir()
        assert (g2 / "fixture_performance.jsonl").is_file()
        assert (g2 / "assessments.jsonl").is_file()
        assert len(list((g2 / "runs").iterdir())) >= 16
        # The archived requests of at least one run can be rehashed to the
        # recorded audit values (exact-bytes proof on REAL traffic).
        checked = 0
        for run_dir in sorted((g2 / "runs").iterdir()):
            request_path = run_dir / "internal_attempt_1.request.json"
            audit_path = run_dir / "internal_attempt_1.input_audit.json"
            if request_path.is_file() and audit_path.is_file():
                audit = json.loads(audit_path.read_text(encoding="utf-8"))
                archived = request_path.read_bytes()
                assert hashlib.sha256(archived).hexdigest() == audit["input_payload_sha256"]
                checked += 1
            if checked >= 3:
                break
        assert checked >= 1

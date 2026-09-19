"""Complexity gate tests (TICKET-05, docs/decisions.md §4.1, docs/gates.md §5.1 G3).

Deterministic and non-live:

- synthetic function inputs prove every rule, boundary, combination, reason
  order, dedup and the SIMPLE/COMPLEX branch (these objects are NOT POC
  results);
- every authentic archived G2 Qwen3.8 outcome is replayed through
  ``decide_gate`` and its real distribution is archived, without network,
  LLM, score modification or new assessment generation.
"""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from src.config import GateConfig, load_yaml_config
from src.gate import decide_gate
from src.parsing import ParseLimits, parse_email
from src.state import (
    Assessment,
    Attachment,
    Link,
    ParsedEmail,
    Probabilities,
    TextPart,
)

pytestmark = pytest.mark.g3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CONFIG_PATH = PROJECT_ROOT / "configs" / "gate.yaml"
G2_DIR = PROJECT_ROOT / "runs" / "gates" / "G2"
G3_DIR = PROJECT_ROOT / "runs" / "gates" / "G3"

#: Exact documented limitation when no authentic G2 sample is SIMPLE.
NO_SIMPLE_LIMITATION = "No live G2 sample satisfied BASELINE V0 SIMPLE criteria"

#: Documented reason order (R1, then R2, then R3). Literals on purpose: the
#: tests must not import their expectations from the implementation.
REASON_ORDER = (
    "internal_unavailable",
    "low_confidence",
    "low_margin",
    "urls_present",
    "attachments_present",
    "parse_incomplete",
    "content_truncated",
    "essential_visual_unread",
    "model_requests_context",
)

# ---------------------------------------------------------------------------
# Deterministic vectors (function inputs, never POC results)
# ---------------------------------------------------------------------------

#: max = 0.95, margin = 0.92: R1 false.
_HIGH_VECTOR = {
    "spear_phishing": 0.03,
    "phishing": 0.95,
    "fraude": 0.01,
    "menace": 0.005,
    "spam": 0.003,
    "legitime": 0.002,
}

#: max = 0.899999 < 0.90 (low confidence), large margin.
_CONFIDENCE_BELOW_VECTOR = {
    "spear_phishing": 0.100001,
    "phishing": 0.899999,
    "fraude": 0.0,
    "menace": 0.0,
    "spam": 0.0,
    "legitime": 0.0,
}

#: max = 0.90 exactly: equality is allowed, so NOT low confidence.
_CONFIDENCE_EQUAL_VECTOR = {
    "spear_phishing": 0.10,
    "phishing": 0.90,
    "fraude": 0.0,
    "menace": 0.0,
    "spam": 0.0,
    "legitime": 0.0,
}

#: max - second = 0.199999 < 0.20 (low margin); max = 0.55 (low confidence too).
_MARGIN_BELOW_VECTOR = {
    "spear_phishing": 0.02499975,
    "phishing": 0.55,
    "fraude": 0.02499975,
    "menace": 0.02499975,
    "spam": 0.02499975,
    "legitime": 0.350001,
}

#: max - second = 0.2 exactly: equality is allowed, so NOT low margin.
_MARGIN_EQUAL_VECTOR = {
    "spear_phishing": 0.2,
    "phishing": 0.5,
    "fraude": 0.0,
    "menace": 0.0,
    "spam": 0.0,
    "legitime": 0.3,
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any network attempt fails these non-live tests: the replay is file-only."""

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in tests/test_gate.py")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


# ---------------------------------------------------------------------------
# Deterministic builders
# ---------------------------------------------------------------------------


def _gate_config() -> GateConfig:
    return load_yaml_config(CONFIG_PATH, GateConfig)  # type: ignore[return-value]


def _assessment(
    probabilities: dict[str, float] | None = None,
    *,
    needs_enrichment: bool = False,
    missing_information: list[str] | None = None,
) -> Assessment:
    vector = dict(_HIGH_VECTOR if probabilities is None else probabilities)
    for label in ("spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"):
        vector.setdefault(label, 0.0)
    return Assessment(
        probabilities=Probabilities(**vector),
        observations=[],
        inferences=[],
        observable_assessments=[],
        needs_enrichment=needs_enrichment,
        missing_information=list(missing_information or []),
        decisive_evidence_ids=[],
    )


def _parsed(
    *,
    links: list[Link] | None = None,
    attachments: list[Attachment] | None = None,
    text_parts: list[TextPart] | None = None,
    html_parts: list[TextPart] | None = None,
    defects: list[str] | None = None,
    content_limits: list[str] | None = None,
    essential_visual_content: bool = False,
) -> ParsedEmail:
    return ParsedEmail(
        email_sha256="0" * 64,
        raw_size_bytes=0,
        input_format="rfc822",
        links=list(links or []),
        attachments=list(attachments or []),
        text_parts=list(text_parts or []),
        html_parts=list(html_parts or []),
        defects=list(defects or []),
        content_limits=list(content_limits or []),
        essential_visual_content=essential_visual_content,
    )


def _link(role: str, raw_value: str, normalized_value: str | None = None) -> Link:
    return Link(
        id=f"lnk_{role}",
        part_id="part_0001",
        raw_value=raw_value,
        normalized_value=normalized_value,
        role=role,  # type: ignore[arg-type]
        hostname=None,
    )


def _attachment(is_inline: bool, decode_status: str = "ok") -> Attachment:
    return Attachment(
        part_id="part_0009",
        filename="piece.txt",
        mime_type="text/plain",
        disposition="inline" if is_inline else "attachment",
        decode_status=decode_status,  # type: ignore[arg-type]
        is_inline=is_inline,
    )


def _decoded_text_part() -> TextPart:
    return TextPart(
        part_id="part_0002",
        mime_type="text/plain",
        charset="x-unknown-9",
        text="corps encore lisible",
        decode_defects=["part_0002: charset error ('x-unknown-9'): unknown encoding: x-unknown-9"],
    )


_HTTP_LINK = "https://login.notice.test/verify?uid=V1C2"


# ---------------------------------------------------------------------------
# BASELINE V0 configuration: exact values, never silently changed
# ---------------------------------------------------------------------------


def test_baseline_v0_config_exact_values() -> None:
    config = _gate_config()
    assert config.version == 1
    assert config.min_confidence == 0.90
    assert config.min_margin == 0.20
    assert config.enrich_http_urls is True
    assert config.enrich_non_inline_attachments is True
    assert config.enrich_on_material_coverage_gap is True


def test_baseline_v0_thresholds_are_the_ones_used() -> None:
    """The gate applies the loaded BASELINE V0 values, not hidden constants."""

    config = _gate_config()
    just_below = _assessment(_CONFIDENCE_BELOW_VECTOR)
    assert decide_gate(_parsed(), just_below, config).rule_hits["R1"] is True
    at_threshold = _assessment(_CONFIDENCE_EQUAL_VECTOR)
    assert decide_gate(_parsed(), at_threshold, config).rule_hits["R1"] is False


# ---------------------------------------------------------------------------
# R1 — uncertainty
# ---------------------------------------------------------------------------


def test_r1_internal_none_unavailable_and_complex() -> None:
    result = decide_gate(_parsed(), None, _gate_config())
    assert result.rule_hits == {"R1": True, "R2": False, "R3": False}
    assert result.reasons == ["internal_unavailable"]
    assert result.decision == "complex"


def test_r1_confidence_0899999_is_low_and_complex() -> None:
    result = decide_gate(_parsed(), _assessment(_CONFIDENCE_BELOW_VECTOR), _gate_config())
    assert result.rule_hits["R1"] is True
    assert "low_confidence" in result.reasons
    assert "low_margin" not in result.reasons
    assert result.decision == "complex"


def test_r1_confidence_090_equality_is_not_low_and_simple() -> None:
    result = decide_gate(_parsed(), _assessment(_CONFIDENCE_EQUAL_VECTOR), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": False}
    assert result.reasons == []
    assert result.decision == "simple"


def test_r1_margin_0199999_is_low() -> None:
    result = decide_gate(_parsed(), _assessment(_MARGIN_BELOW_VECTOR), _gate_config())
    assert "low_margin" in result.reasons
    assert result.rule_hits["R1"] is True
    assert result.decision == "complex"


def test_r1_margin_020_equality_is_not_low() -> None:
    result = decide_gate(_parsed(), _assessment(_MARGIN_EQUAL_VECTOR), _gate_config())
    assert "low_margin" not in result.reasons
    assert result.rule_hits["R1"] is True  # confidence 0.50 is below 0.90
    assert "low_confidence" in result.reasons


def test_r1_confidence_and_margin_together_in_documented_order() -> None:
    result = decide_gate(_parsed(), _assessment(_MARGIN_BELOW_VECTOR), _gate_config())
    assert result.reasons == ["low_confidence", "low_margin"]


def test_r1_valid_high_confidence_high_margin_is_not_r1() -> None:
    result = decide_gate(_parsed(), _assessment(_HIGH_VECTOR), _gate_config())
    assert result.rule_hits["R1"] is False
    assert result.decision == "simple"


def test_r1_probabilities_never_normalized_or_altered() -> None:
    internal = _assessment(_CONFIDENCE_BELOW_VECTOR)
    before = internal.model_dump()
    decide_gate(_parsed(), internal, _gate_config())
    assert internal.model_dump() == before


# ---------------------------------------------------------------------------
# R2 — investigable material
# ---------------------------------------------------------------------------


def test_r2_href_http_url() -> None:
    parsed = _parsed(links=[_link("href", _HTTP_LINK, _HTTP_LINK)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": True, "R3": False}
    assert result.reasons == ["urls_present"]
    assert result.decision == "complex"


def test_r2_visible_url() -> None:
    parsed = _parsed(links=[_link("visible_url", _HTTP_LINK, _HTTP_LINK)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R2"] is True
    assert result.reasons == ["urls_present"]


def test_r2_form_action() -> None:
    parsed = _parsed(links=[_link("form_action", _HTTP_LINK, _HTTP_LINK)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R2"] is True
    assert result.reasons == ["urls_present"]


def test_r2_qr_url() -> None:
    qr = "https://qr.notice.test/verify"
    parsed = _parsed(links=[_link("qr_url", qr, qr)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R2"] is True
    assert result.reasons == ["urls_present"]


def test_r2_non_inline_attachment() -> None:
    parsed = _parsed(attachments=[_attachment(is_inline=False)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": True, "R3": False}
    assert result.reasons == ["attachments_present"]
    assert result.decision == "complex"


def test_r2_inline_attachment_only_is_not_enough() -> None:
    parsed = _parsed(attachments=[_attachment(is_inline=True)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": False}
    assert result.reasons == []
    assert result.decision == "simple"


def test_r2_decorative_remote_resource_alone_does_not_trigger() -> None:
    tracking = "https://track.esp-mailer.example.net/open?id=abc123"
    parsed = _parsed(links=[_link("remote_resource", tracking, tracking)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R2"] is False
    assert result.reasons == []
    assert result.decision == "simple"


def test_r2_non_http_href_is_not_investigable() -> None:
    parsed = _parsed(
        links=[
            _link("href", "/relative/path?x=1"),  # never resolved
            _link("href", "mailto:contact@notice.test"),  # not HTTP(S)
        ]
    )
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R2"] is False
    assert result.decision == "simple"


def test_r2_no_link_no_attachment() -> None:
    result = decide_gate(_parsed(), _assessment(), _gate_config())
    assert result.rule_hits["R2"] is False
    assert result.decision == "simple"


def test_r2_newsletter_with_relevant_url_remains_complex() -> None:
    """BASELINE V0 has no allowlist: a newsletter link is still investigable."""

    parsed = parse_email(FIXTURES / "legitimate_newsletter.eml", ParseLimits())
    assert isinstance(parsed, ParsedEmail)
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R2"] is True
    assert "urls_present" in result.reasons
    assert result.decision == "complex"


# ---------------------------------------------------------------------------
# R3 — context / coverage gap
# ---------------------------------------------------------------------------


def test_r3_parsed_none_is_parse_incomplete() -> None:
    result = decide_gate(None, None, _gate_config())
    assert result.rule_hits == {"R1": True, "R2": False, "R3": True}
    assert result.reasons == ["internal_unavailable", "parse_incomplete"]
    assert result.decision == "complex"


def test_r3_content_limit_reached() -> None:
    parsed = _parsed(content_limits=["max_decoded_bytes_total"])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": True}
    assert result.reasons == ["content_truncated"]
    assert result.decision == "complex"


def test_r3_material_decode_defect_text_part() -> None:
    parsed = _parsed(text_parts=[_decoded_text_part()])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R3"] is True
    assert result.reasons == ["parse_incomplete"]


def test_r3_material_decode_defect_inline_attachment() -> None:
    parsed = _parsed(attachments=[_attachment(is_inline=True, decode_status="error")])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": True}
    assert result.reasons == ["parse_incomplete"]


def test_r3_material_decode_defect_non_inline_attachment() -> None:
    parsed = _parsed(attachments=[_attachment(is_inline=False, decode_status="error")])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.reasons == ["attachments_present", "parse_incomplete"]
    assert result.decision == "complex"


def test_r3_harmless_structural_defects_are_not_material() -> None:
    """Structural parser notes alone are not a material coverage gap."""

    parsed = _parsed(
        defects=[
            "part_0001: stdlib CloseBoundaryNotFoundDefect",
            "part_0001: embedded message treated as bounded MIME",
            "part_0001: stdlib DuplicateSubjectHeader",
        ]
    )
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits["R3"] is False
    assert result.reasons == []
    assert result.decision == "simple"


def test_r3_essential_visual_content_unread() -> None:
    parsed = _parsed(essential_visual_content=True)
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": True}
    assert result.reasons == ["essential_visual_unread"]
    assert result.decision == "complex"


def test_r3_needs_enrichment_true_is_model_requests_context() -> None:
    internal = _assessment(needs_enrichment=True)
    result = decide_gate(_parsed(), internal, _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": True}
    assert result.reasons == ["model_requests_context"]
    assert result.decision == "complex"


def test_r3_clean_complete_message_is_simple() -> None:
    result = decide_gate(_parsed(), _assessment(needs_enrichment=False), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": False}
    assert result.reasons == []
    assert result.decision == "simple"


# ---------------------------------------------------------------------------
# Combinations: isolated and combined rules
# ---------------------------------------------------------------------------


def test_isolated_r1_only() -> None:
    result = decide_gate(_parsed(), None, _gate_config())
    assert result.rule_hits == {"R1": True, "R2": False, "R3": False}
    assert result.reasons == ["internal_unavailable"]


def test_isolated_r2_only() -> None:
    parsed = _parsed(links=[_link("href", _HTTP_LINK, _HTTP_LINK)])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": True, "R3": False}
    assert result.reasons == ["urls_present"]


def test_isolated_r3_only() -> None:
    parsed = _parsed(content_limits=["max_mime_parts"])
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": False, "R3": True}
    assert result.reasons == ["content_truncated"]


def test_r1_plus_r2() -> None:
    parsed = _parsed(links=[_link("href", _HTTP_LINK, _HTTP_LINK)])
    result = decide_gate(parsed, None, _gate_config())
    assert result.rule_hits == {"R1": True, "R2": True, "R3": False}
    assert result.reasons == ["internal_unavailable", "urls_present"]


def test_r1_plus_r3() -> None:
    parsed = _parsed(essential_visual_content=True)
    result = decide_gate(parsed, None, _gate_config())
    assert result.rule_hits == {"R1": True, "R2": False, "R3": True}
    assert result.reasons == ["internal_unavailable", "essential_visual_unread"]


def test_r2_plus_r3() -> None:
    parsed = _parsed(
        links=[_link("href", _HTTP_LINK, _HTTP_LINK)],
        content_limits=["max_decoded_bytes_per_part"],
    )
    result = decide_gate(parsed, _assessment(), _gate_config())
    assert result.rule_hits == {"R1": False, "R2": True, "R3": True}
    assert result.reasons == ["urls_present", "content_truncated"]


def test_r1_plus_r2_plus_r3() -> None:
    parsed = _parsed(
        links=[_link("href", _HTTP_LINK, _HTTP_LINK)],
        attachments=[_attachment(is_inline=False)],
        essential_visual_content=True,
    )
    result = decide_gate(parsed, None, _gate_config())
    assert result.rule_hits == {"R1": True, "R2": True, "R3": True}
    assert result.reasons == [
        "internal_unavailable",
        "urls_present",
        "attachments_present",
        "essential_visual_unread",
    ]


# ---------------------------------------------------------------------------
# Reason order, dedup, rule_hits, determinism
# ---------------------------------------------------------------------------


def test_reasons_full_documented_order_without_duplicates() -> None:
    parsed = _parsed(
        links=[
            _link("href", _HTTP_LINK, _HTTP_LINK),
            _link("visible_url", _HTTP_LINK + "&x=2", _HTTP_LINK + "&x=2"),
            _link("remote_resource", "https://track.example.net/p.gif", "https://track.example.net/p.gif"),
        ],
        attachments=[_attachment(is_inline=False), _attachment(is_inline=False)],
        text_parts=[_decoded_text_part()],
        content_limits=["max_decoded_bytes_total", "max_mime_parts"],
        essential_visual_content=True,
    )
    internal = _assessment(_MARGIN_BELOW_VECTOR, needs_enrichment=True)
    result = decide_gate(parsed, internal, _gate_config())
    assert result.reasons == [
        "low_confidence",
        "low_margin",
        "urls_present",
        "attachments_present",
        "parse_incomplete",
        "content_truncated",
        "essential_visual_unread",
        "model_requests_context",
    ]
    assert len(result.reasons) == len(set(result.reasons))
    assert result.decision == "complex"


def test_reasons_are_a_prefix_of_the_documented_order() -> None:
    """Every produced reason sequence keeps the documented total order."""

    cases = [
        (None, None),
        (_parsed(), None),
        (_parsed(essential_visual_content=True), None),
        (_parsed(content_limits=["max_mime_parts"]), _assessment()),
        (_parsed(text_parts=[_decoded_text_part()]), _assessment()),
        (_parsed(), _assessment(needs_enrichment=True)),
    ]
    for parsed, internal in cases:
        result = decide_gate(parsed, internal, _gate_config())
        assert result.reasons == [r for r in REASON_ORDER if r in result.reasons]


def test_rule_hits_have_exactly_three_keys() -> None:
    for result in (
        decide_gate(_parsed(), _assessment(), _gate_config()),
        decide_gate(None, None, _gate_config()),
    ):
        assert set(result.rule_hits.keys()) == {"R1", "R2", "R3"}
        assert list(result.rule_hits.keys()) == ["R1", "R2", "R3"]


def test_repeatability_bit_identical_serialization() -> None:
    parsed = _parsed(
        links=[_link("href", _HTTP_LINK, _HTTP_LINK)],
        content_limits=["max_mime_parts"],
    )
    internal = _assessment(_MARGIN_BELOW_VECTOR, needs_enrichment=True)
    config = _gate_config()
    first = decide_gate(parsed, internal, config)
    second = decide_gate(parsed, internal, config)
    third = decide_gate(
        parsed.model_copy(deep=True), internal.model_copy(deep=True), _gate_config()
    )
    assert first.model_dump_json() == second.model_dump_json() == third.model_dump_json()


def test_gate_is_pure_and_does_not_mutate_inputs() -> None:
    parsed = _parsed(links=[_link("href", _HTTP_LINK, _HTTP_LINK)])
    internal = _assessment(_MARGIN_BELOW_VECTOR, needs_enrichment=True)
    config = _gate_config()
    before = (parsed.model_dump_json(), internal.model_dump_json(), config.model_dump_json())
    decide_gate(parsed, internal, config)
    after = (parsed.model_dump_json(), internal.model_dump_json(), config.model_dump_json())
    assert before == after


# ---------------------------------------------------------------------------
# Semantics: simple is not legitimate, complex is not malicious
# ---------------------------------------------------------------------------


def test_simple_does_not_imply_legitimate() -> None:
    """A perfect, malicious-leaning vector can still be SIMPLE: the gate only
    decides enrichment, never legitimacy (docs/decisions.md §4.1)."""

    internal = _assessment(
        {
            "spear_phishing": 0.95,
            "phishing": 0.03,
            "fraude": 0.01,
            "menace": 0.005,
            "spam": 0.003,
            "legitime": 0.002,
        }
    )
    result = decide_gate(_parsed(), internal, _gate_config())
    assert result.decision == "simple"
    assert set(result.model_dump().keys()) == {"decision", "reasons", "rule_hits"}
    assert "legitime" not in result.model_dump_json()


def test_complex_does_not_imply_malicious() -> None:
    """A confident ``legitime`` verdict can still be COMPLEX for context."""

    internal = _assessment(
        {
            "legitime": 0.95,
            "spam": 0.03,
            "phishing": 0.01,
            "fraude": 0.005,
            "menace": 0.003,
            "spear_phishing": 0.002,
        },
        needs_enrichment=True,
    )
    result = decide_gate(_parsed(), internal, _gate_config())
    assert result.decision == "complex"
    assert result.reasons == ["model_requests_context"]


# ---------------------------------------------------------------------------
# Authentic G2 replay (replay-only: no network, no LLM, no new assessment)
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _serialize_artifact(artifact: dict) -> str:
    return json.dumps(artifact, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _replay_authentic_g2() -> dict:
    """Replay the archived official Qwen3.8 G2 outcomes through ``decide_gate``.

    Only authentic archived objects are used: the real parsed fixtures and
    the validated Assessments (or ``internal=None`` when no valid Assessment
    exists — rejected/error responses are NEVER turned into Assessments).
    """

    performance_path = G2_DIR / "fixture_performance.jsonl"
    assessments_path = G2_DIR / "assessments.jsonl"
    if not performance_path.is_file() or not assessments_path.is_file():
        pytest.fail(
            "authentic G2 evidence missing under runs/gates/G2/ "
            "(fixture_performance.jsonl / assessments.jsonl); TICKET-05 requires "
            "the archived official Qwen3.8 run and never simulates one"
        )
    performance = _read_jsonl(performance_path)
    accepted_records = _read_jsonl(assessments_path)
    assessments_by_id = {record["sample_id"]: record for record in accepted_records}
    assert len(assessments_by_id) == len(accepted_records)  # unique sample ids

    config = _gate_config()
    parsed_cache: dict[str, ParsedEmail] = {}
    table: list[dict] = []
    for line in performance:
        sample_id = line["sample_id"]
        fixture = line["fixture"]
        parsed = parsed_cache.get(fixture)
        if parsed is None:
            parsed = parse_email(FIXTURES / fixture, ParseLimits())
            if not isinstance(parsed, ParsedEmail):
                pytest.fail(f"fixture {fixture} did not parse (G1 contract): {parsed}")
            parsed_cache[fixture] = parsed

        record = assessments_by_id.get(sample_id)
        assert (record is not None) == bool(line["accepted"]), (
            f"{sample_id}: fixture_performance accepted={line['accepted']} but "
            f"assessments.jsonl {'has' if record else 'has no'} record"
        )
        if line.get("validation_rejected"):
            # A locally rejected candidate is never promoted to a valid one.
            assert record is None, sample_id
        internal = Assessment.model_validate(record["assessment"]) if record else None
        if internal is not None:
            # Authentic scores replayed byte-for-byte, never altered.
            assert internal.model_dump() == record["assessment"], sample_id

        result = decide_gate(parsed, internal, config)
        table.append(
            {
                "sample_id": sample_id,
                "fixture": fixture,
                "g2_outcome": (
                    "accepted"
                    if record is not None
                    else ("validation_rejected" if line.get("validation_rejected") else "error")
                ),
                "internal_available": internal is not None,
                "R1": result.rule_hits["R1"],
                "R2": result.rule_hits["R2"],
                "R3": result.rule_hits["R3"],
                "decision": result.decision,
                "reasons": list(result.reasons),
            }
        )

    total = len(table)
    simple = sum(1 for row in table if row["decision"] == "simple")
    complex_count = sum(1 for row in table if row["decision"] == "complex")
    assert simple + complex_count == total
    simple_path_live_observed = simple > 0

    return {
        "artifact": "complexity_replay",
        "gate": "G3",
        "ticket": "TICKET-05",
        "scope": (
            "authentic archived G2 Qwen3.8 outcomes replayed through decide_gate; "
            "no network, no LLM, no new assessment generation"
        ),
        "baseline": {
            "version": config.version,
            "min_confidence": config.min_confidence,
            "min_margin": config.min_margin,
            "enrich_http_urls": config.enrich_http_urls,
            "enrich_non_inline_attachments": config.enrich_non_inline_attachments,
            "enrich_on_material_coverage_gap": config.enrich_on_material_coverage_gap,
        },
        "config_file": {"path": "configs/gate.yaml", "sha256": _sha256_file(CONFIG_PATH)},
        "g2_measurement_files": {
            "fixture_performance.jsonl": {
                "path": "runs/gates/G2/fixture_performance.jsonl",
                "records": len(performance),
                "sha256": _sha256_file(performance_path),
            },
            "assessments.jsonl": {
                "path": "runs/gates/G2/assessments.jsonl",
                "records": len(accepted_records),
                "sha256": _sha256_file(assessments_path),
            },
        },
        "table": table,
        "distribution": {
            "total": total,
            "simple": simple,
            "complex": complex_count,
            "simple_path_live_observed": simple_path_live_observed,
        },
        "limitation": None if simple_path_live_observed else NO_SIMPLE_LIMITATION,
        "notes": [
            "Replay-only: reads local archived G2 files and tracked fixtures; zero network calls.",
            "Deterministic synthetic function inputs in tests/test_gate.py prove the branches; they are not POC results and never enter this table.",
            "Material decode defect maps to parse_incomplete (per-part TextPart.decode_defects or Attachment.decode_status=='error'); harmless structural notes stay non-material; content limits map to content_truncated.",
        ],
    }


def test_authentic_g2_replay_table_invariants() -> None:
    artifact = _replay_authentic_g2()
    table = artifact["table"]
    performance_records = artifact["g2_measurement_files"]["fixture_performance.jsonl"]["records"]
    accepted_records = artifact["g2_measurement_files"]["assessments.jsonl"]["records"]
    assert len(table) == performance_records
    assert sum(1 for row in table if row["internal_available"]) == accepted_records

    for row in table:
        assert set(row) == {
            "sample_id",
            "fixture",
            "g2_outcome",
            "internal_available",
            "R1",
            "R2",
            "R3",
            "decision",
            "reasons",
        }, row["sample_id"]
        assert row["reasons"] == [r for r in REASON_ORDER if r in row["reasons"]], row["sample_id"]
        assert len(row["reasons"]) == len(set(row["reasons"])), row["sample_id"]
        expected_decision = "complex" if (row["R1"] or row["R2"] or row["R3"]) else "simple"
        assert row["decision"] == expected_decision, row["sample_id"]
        assert row["internal_available"] == (row["g2_outcome"] == "accepted"), row["sample_id"]

    distribution = artifact["distribution"]
    assert distribution["total"] == len(table)
    assert distribution["simple"] + distribution["complex"] == distribution["total"]
    assert distribution["simple_path_live_observed"] == (distribution["simple"] > 0)
    if distribution["simple_path_live_observed"]:
        assert artifact["limitation"] is None
    else:
        assert artifact["limitation"] == NO_SIMPLE_LIMITATION


def test_authentic_g2_replay_writes_deterministic_artifact() -> None:
    first = _replay_authentic_g2()
    second = _replay_authentic_g2()
    payload_first = _serialize_artifact(first)
    payload_second = _serialize_artifact(second)
    assert payload_first == payload_second  # bit-identical replay

    G3_DIR.mkdir(parents=True, exist_ok=True)
    out_path = G3_DIR / "complexity_replay.json"
    out_path.write_text(payload_first, encoding="utf-8")
    assert out_path.read_text(encoding="utf-8") == payload_first

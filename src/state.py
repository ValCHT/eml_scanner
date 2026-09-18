"""Contract objects and state (docs/contracts.md §2.2–§2.5).

Strict Pydantic v2 models, ``extra='forbid'``, finite numbers, defaults via
``default_factory`` for mutable values. Nullable fields are distinct from
empty lists/dicts. No secret ever enters these objects.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .config import Label, ObservableType, Provenance, SourceProfile

FiniteNumber = Annotated[float, Field(allow_inf_nan=False)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


# ---------------------------------------------------------------------------
# §2.3 ParsedEmail and sub-models
# ---------------------------------------------------------------------------


class Header(_Strict):
    index: int
    name: str
    raw_value: str
    decoded_value: str


class TextPart(_Strict):
    part_id: str
    mime_type: str
    charset: str | None = None
    text: str = ""
    decode_defects: list[str] = Field(default_factory=list)


class Link(_Strict):
    id: str
    part_id: str
    raw_value: str
    normalized_value: str | None = None
    display_text: str | None = None
    display_url: str | None = None
    role: Literal["href", "visible_url", "form_action", "remote_resource", "qr_url"]
    hostname: str | None = None
    href_display_mismatch: bool = False
    transformation: str | None = None


class Attachment(_Strict):
    part_id: str
    filename: str | None = None
    mime_type: str
    disposition: str | None = None
    content_id: str | None = None
    decoded_size_bytes: int | None = None
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    decode_status: Literal["ok", "error", "over_limit"]
    is_inline: bool = False


class AuthObservation(_Strict):
    mechanism: Literal["spf", "dkim", "dmarc"]
    result: str
    domain: str | None = None
    authserv_id: str | None = None
    header_index: int
    trust: Literal["trusted_receiver", "reported_unverified"] = "reported_unverified"


class ParsedEmail(_Strict):
    email_sha256: str
    raw_size_bytes: int
    input_format: Literal["rfc822", "mbox_member", "structured_public_text"]
    headers: list[Header] = Field(default_factory=list)
    subject: str | None = None
    from_addresses: list[str] = Field(default_factory=list)
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    reply_to: list[str] = Field(default_factory=list)
    return_path: list[str] = Field(default_factory=list)
    date_raw: str | None = None
    message_id: str | None = None
    text_parts: list[TextPart] = Field(default_factory=list)
    html_parts: list[TextPart] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    images: list["VisualEvidence"] = Field(default_factory=list)
    authentication: list[AuthObservation] = Field(default_factory=list)
    defects: list[str] = Field(default_factory=list)
    content_limits: list[str] = Field(default_factory=list)
    essential_visual_content: bool = False
    observables: list["Observable"] = Field(default_factory=list)
    evidence: list["Evidence"] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# §2.4 Observables, evidence, visuals, tool results, RAG
# ---------------------------------------------------------------------------


class Observable(_Strict):
    id: str
    value: str
    normalized_value: str
    type: ObservableType
    roles: list[
        Literal[
            "sender",
            "return_path",
            "reply_to",
            "recipient",
            "link_target",
            "displayed_brand",
            "shared_host",
            "transport_ip",
            "attachment",
            "campaign_id",
            "tool_discovery",
        ]
    ] = Field(default_factory=list)
    provenance: Provenance
    source_ref: str
    evidence_ids: list[str] = Field(default_factory=list)
    category: Literal["M", "S", "C", "B"] | None = None
    justification: str = ""


class Evidence(_Strict):
    id: str
    provenance: Provenance
    source_kind: Literal["parser", "virustotal", "opencti", "urlscan"]
    observable_id: str | None = None
    predicate: Literal[
        "header_value",
        "body_excerpt",
        "url_found",
        "href_display_mismatch",
        "attachment_hash",
        "attachment_filename",
        "image_present",
        "auth_reported",
        "auth_trusted",
        "vt_malicious_count",
        "vt_suspicious_count",
        "vt_harmless_count",
        "vt_undetected_count",
        "vt_engine_total",
        "vt_analysis_time",
        "cti_exact_match",
        "cti_label",
        "cti_score",
        "cti_revoked",
        "cti_external_reference",
        "sandbox_redirect",
        "sandbox_final_url",
        "sandbox_page_title",
        "sandbox_form_field",
        "sandbox_provider_malicious",
        "sandbox_screenshot",
        "sandbox_dom_excerpt",
        "qr_payload",
    ]
    value: str | float | bool | None = None
    source_ref: str
    observed_at: str | None = None
    match_level: Literal["EXACT", "GENERIC", "NONE"]
    source_group: str = ""


class VisualEvidence(_Strict):
    id: str
    sha256: str
    mime_type: str
    provenance: Provenance
    part_id: str | None = None
    content_id: str | None = None
    local_ref: str
    width: int | None = None
    height: int | None = None
    status: Literal[
        "metadata_only", "supplied_to_model", "unsupported", "over_limit", "unavailable"
    ]
    qr_payloads: list[str] = Field(default_factory=list)


class ToolResult(_Strict):
    tool: Literal["virustotal", "opencti", "urlscan"]
    query_observable_id: str | None = None
    status: Literal["ok", "not_found", "unavailable", "skipped"]
    reason: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    response_sha256: str | None = None
    response_ref: str | None = None
    collected_at: str | None = None
    mode: Literal["live", "recorded", "none"]
    elapsed_ms: FiniteNumber = Field(default=0.0, ge=0)
    requests_sent: int = Field(default=0, ge=0)
    visibility: Literal["private", "unlisted"] | None = None
    scan_id: str | None = None


class RagCase(_Strict):
    case_id: str
    public_source_url: str
    dataset: str
    record_sha256: str
    validated_label: Label
    analyst_validation_ref: str
    campaign_id: str | None = None
    duplicate_group: str
    family_group: str
    text_excerpt: str
    analyst_rationale: str
    distance: FiniteNumber = Field(ge=0)
    embedding_model_id: str
    is_public: Literal[True] = True
    split: Literal["rag_reference"] = "rag_reference"


class Enrichment(_Strict):
    virustotal: list[ToolResult] = Field(default_factory=list)
    opencti: list[ToolResult] = Field(default_factory=list)
    urlscan: list[ToolResult] = Field(default_factory=list)
    rag: list[RagCase] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# §2.5 Assessment and its sub-models
# ---------------------------------------------------------------------------


class Inference(_Strict):
    id: str
    code: Literal[
        "credential_collection",
        "targeted_context",
        "payment_diversion",
        "extortion",
        "unsolicited_promotion",
        "coherent_transaction",
        "identity_mismatch",
        "link_mismatch",
        "prompt_injection",
        "visual_content_unread",
        "external_support",
        "external_conflict",
        "insufficient_information",
    ]
    summary: str = Field(max_length=240)
    evidence_ids: list[str] = Field(default_factory=list)
    rag_case_ids: list[str] = Field(default_factory=list)


class ObservableAssessment(_Strict):
    observable_id: str
    category: Literal["M", "S", "C", "B"] | None
    evidence_ids: list[str] = Field(default_factory=list)
    reason_code: Literal[
        "attack_artifact",
        "context_only",
        "shared_infrastructure",
        "spoofed_identity",
        "unconfirmed",
        "benign_context",
    ]


class Probabilities(_Strict):
    spear_phishing: FiniteNumber = Field(ge=0, le=1)
    phishing: FiniteNumber = Field(ge=0, le=1)
    fraude: FiniteNumber = Field(ge=0, le=1)
    menace: FiniteNumber = Field(ge=0, le=1)
    spam: FiniteNumber = Field(ge=0, le=1)
    legitime: FiniteNumber = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _sum_to_one(self) -> "Probabilities":
        total = (
            self.spear_phishing
            + self.phishing
            + self.fraude
            + self.menace
            + self.spam
            + self.legitime
        )
        if not math.isfinite(total) or abs(total - 1.0) > 0.000001:
            raise ValueError("probabilities must sum to 1 within ±0.000001")
        return self


#: Fixed field order of the taxonomy (argmax / tie-break order, §2.1/§2.5).
TAXONOMY_ORDER: tuple[Label, ...] = (
    "spear_phishing",
    "phishing",
    "fraude",
    "menace",
    "spam",
    "legitime",
)


class Assessment(_Strict):
    probabilities: Probabilities
    observations: list[str] = Field(default_factory=list)
    inferences: list[Inference] = Field(default_factory=list)
    observable_assessments: list[ObservableAssessment] = Field(default_factory=list)
    needs_enrichment: bool
    missing_information: list[
        Literal[
            "authentication_untrusted",
            "destination_unverified",
            "attachment_not_inspected",
            "essential_visual_unread",
            "insufficient_context",
            "tool_unavailable",
            "content_truncated",
        ]
    ] = Field(default_factory=list)
    decisive_evidence_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# §2.6 Verification, timings, call records, reproducibility
# ---------------------------------------------------------------------------


class VerificationIssue(_Strict):
    code: str
    severity: Literal["info", "warning", "error", "critical"]
    source: Literal["parse", "internal", "final", "tool", "policy", "runtime"]
    object_id: str | None = None
    message: str


class Timings(_Strict):
    parse_ms: FiniteNumber = Field(default=0.0, ge=0)
    internal_llm_ms: FiniteNumber = Field(default=0.0, ge=0)
    gate_ms: FiniteNumber = Field(default=0.0, ge=0)
    vt_ms: FiniteNumber = Field(default=0.0, ge=0)
    opencti_ms: FiniteNumber = Field(default=0.0, ge=0)
    urlscan_ms: FiniteNumber = Field(default=0.0, ge=0)
    rag_ms: FiniteNumber = Field(default=0.0, ge=0)
    merge_ms: FiniteNumber = Field(default=0.0, ge=0)
    final_llm_ms: FiniteNumber = Field(default=0.0, ge=0)
    verify_ms: FiniteNumber = Field(default=0.0, ge=0)
    policy_ms: FiniteNumber = Field(default=0.0, ge=0)
    report_ms: FiniteNumber = Field(default=0.0, ge=0)
    total_ms: FiniteNumber = Field(default=0.0, ge=0)


class CallRecord(_Strict):
    phase: Literal["internal", "final"]
    status: Literal["ok", "error", "skipped"]
    attempts: int = Field(default=0, ge=0)
    requested_model: str
    returned_model: str | None = None
    reasoning_effort: str
    input_tokens: int | None = Field(default=None, ge=0)
    cached_input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    cost_usd: FiniteNumber | None = Field(default=None, ge=0)
    cost_status: Literal["estimated", "provider_reported", "unknown", "partial"] = "unknown"
    first_attempt_schema_valid: bool | None = None
    response_refs: list[str] = Field(default_factory=list)
    request_sha256: str | None = None


class Reproducibility(_Strict):
    code_commit: str | None = None
    python_version: str
    dependencies_sha256: str
    prompt_internal_sha256: str
    prompt_final_sha256: str
    assessment_schema_sha256: str
    config_sha256: str
    corpus_split_sha256: str | None = None
    mode: Literal["live", "recorded"]
    started_at: str


# ---------------------------------------------------------------------------
# §2.2 EmailTriageState and gate result
# ---------------------------------------------------------------------------


class GateResult(_Strict):
    decision: Literal["simple", "complex"] | None = None
    reasons: list[str] = Field(default_factory=list)
    rule_hits: dict[Literal["R1", "R2", "R3"], bool] = Field(
        default_factory=lambda: {"R1": False, "R2": False, "R3": False}
    )


class EmailTriageState(_Strict):
    """Full state; every field exists from ``new_state`` (§2.2)."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    input_path: str
    source_profile: SourceProfile
    started_at: str
    config_sha256: str

    parsed: ParsedEmail | None = None
    observable_registry: dict[str, Observable] = Field(default_factory=dict)
    evidence: dict[str, Evidence] = Field(default_factory=dict)
    visual_evidence: list[VisualEvidence] = Field(default_factory=list)
    internal: Assessment | None = None
    internal_call: CallRecord | None = None
    gate: GateResult | None = None
    enrichment: Enrichment = Field(default_factory=Enrichment)
    final_candidate: Assessment | None = None
    final_call: CallRecord | None = None
    final_source: Literal["internal_copy", "final_llm", "internal_fallback", "none"] = "none"
    final_validated: Assessment | None = None
    verification: list[VerificationIssue] = Field(default_factory=list)
    accepted_observables: list[Observable] = Field(default_factory=list)
    errors: list[VerificationIssue] = Field(default_factory=list)
    action: Literal["AUTO", "REVIEW", "ESCALATE"] = "REVIEW"
    policy_reasons: list[str] = Field(default_factory=list)
    timings: Timings = Field(default_factory=Timings)
    report_path: str | None = None


def new_state(input_path: Path, source_profile: SourceProfile, config_sha256: str) -> EmailTriageState:
    """Build the initial state exactly as specified in §2.2.

    ``run_id`` is a fresh UUID4 per invocation, ``started_at`` is the UTC
    wall-clock time at creation and ``input_path`` is stored as a validated
    absolute path string.
    """

    resolved = Path(input_path)
    if not resolved.is_absolute():
        raise ValueError("input_path must be an absolute path")
    resolved = resolved.resolve()
    return EmailTriageState(
        input_path=str(resolved),
        source_profile=source_profile,
        started_at=datetime.now(UTC).isoformat(),
        config_sha256=config_sha256,
    )


__all__ = [
    "Assessment",
    "Attachment",
    "AuthObservation",
    "CallRecord",
    "EmailTriageState",
    "Enrichment",
    "Evidence",
    "GateResult",
    "Header",
    "Inference",
    "Link",
    "Observable",
    "ObservableAssessment",
    "ParsedEmail",
    "Probabilities",
    "RagCase",
    "Reproducibility",
    "TAXONOMY_ORDER",
    "TextPart",
    "Timings",
    "ToolResult",
    "VerificationIssue",
    "VisualEvidence",
    "new_state",
]

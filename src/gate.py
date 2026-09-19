"""Deterministic complexity gate (TICKET-05, docs/decisions.md §4.1).

``decide_gate(parsed, internal, config) -> GateResult`` is pure, deterministic,
network-free, LLM-free and side-effect-free. It implements exactly the three
rules R1/R2/R3 of docs/decisions.md §4.1:

- R1 — uncertainty: ``internal`` absent/invalid, ``max(p) < min_confidence``,
  or ``max(p) - second(p) < min_margin``. Boundaries are strict: equality is
  allowed (0.90 is not low confidence, 0.20 is not low margin).
- R2 — investigable material: at least one relevant HTTP(S) URL with role
  ``href``/``visible_url``/``form_action``/``qr_url``, or at least one
  non-inline attachment. Decorative ``remote_resource`` links (tracking
  pixels) never trigger R2 on their own and are never loaded.
- R3 — context/coverage gap: ``parsed`` absent, material decode defect,
  content limit reached, essential visual content unread, or
  ``internal.needs_enrichment`` true.

Reasons are complete, deduplicated, stable and emitted in the documented
cause order: R1, then R2, then R3. ``rule_hits`` carries exactly R1/R2/R3.

SIMPLE is allowed only when R1, R2 and R3 are all false; otherwise COMPLEX.
``simple`` means "no enrichment is materially required"; it never means
"legitimate" (a BEC without link can be SIMPLE and still ESCALATE).
"""

from __future__ import annotations

import math
from urllib.parse import urlparse

from .config import GateConfig
from .state import TAXONOMY_ORDER, Assessment, GateResult, Link, ParsedEmail

#: Reason codes in the fixed documented order (docs/decisions.md §4.1).
R1_REASONS: tuple[str, ...] = ("internal_unavailable", "low_confidence", "low_margin")
R2_REASONS: tuple[str, ...] = ("urls_present", "attachments_present")
R3_REASONS: tuple[str, ...] = (
    "parse_incomplete",
    "content_truncated",
    "essential_visual_unread",
    "model_requests_context",
)

#: Link roles carrying an investigable destination (R2).
_RELEVANT_LINK_ROLES = frozenset({"href", "visible_url", "form_action", "qr_url"})

_HTTP_SCHEMES = frozenset({"http", "https"})


def _is_http_url(value: str | None) -> bool:
    """True for an absolute HTTP(S) URL with a hostname; no resolution."""

    if not value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme.lower() in _HTTP_SCHEMES and bool(parsed.hostname)


def _relevant_http_url(link: Link) -> bool:
    """Relevant HTTP(S) URL: href / visible / form action / QR role.

    ``remote_resource`` (decorative remote images, tracking pixels) is
    deliberately excluded: such a resource alone never triggers R2 and is
    never fetched by the gate.
    """

    if link.role not in _RELEVANT_LINK_ROLES:
        return False
    return _is_http_url(link.normalized_value) or _is_http_url(link.raw_value)


def _has_material_decode_defect(parsed: ParsedEmail) -> bool:
    """A useful part could not be decoded (R3, docs/decisions.md §4.1).

    The parser distinguishes material decode failures from harmless
    structural notes: per-part decoding problems are recorded in
    ``TextPart.decode_defects`` and attachments whose bytes are unavailable
    carry ``decode_status == "error"``. Structural stdlib notes (e.g.
    ``CloseBoundaryNotFoundDefect``), bounded embedded messages and header
    duplication stay in ``ParsedEmail.defects`` and are NOT material here.
    Limit exhaustion is a distinct cause handled via ``content_limits``.
    """

    for part in (*parsed.text_parts, *parsed.html_parts):
        if part.decode_defects:
            return True
    for attachment in parsed.attachments:
        if attachment.decode_status == "error":
            return True
    return False


def _probability_vector(internal: Assessment) -> list[float] | None:
    """Six finite probabilities in taxonomy order, or None when unavailable.

    An invalid assessment is never repaired or normalized: it is reported as
    unavailable, exactly like a missing one (docs/contracts.md §2.5: an
    invalid candidate is rejected, never turned into a false success).
    """

    try:
        values = [getattr(internal.probabilities, label) for label in TAXONOMY_ORDER]
    except AttributeError:
        return None
    if not all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        for value in values
    ):
        return None
    return [float(value) for value in values]


def decide_gate(
    parsed: ParsedEmail | None,
    internal: Assessment | None,
    config: GateConfig,
) -> GateResult:
    """Apply R1/R2/R3 exactly; SIMPLE only when all three are false."""

    reasons: list[str] = []

    # --- R1 — uncertainty -------------------------------------------------
    r1_reasons: list[str] = []
    vector = _probability_vector(internal) if internal is not None else None
    if vector is None:
        r1_reasons.append("internal_unavailable")
    else:
        ordered = sorted(vector, reverse=True)
        max_probability = ordered[0]
        margin = max_probability - ordered[1]
        if max_probability < config.min_confidence:
            r1_reasons.append("low_confidence")
        if margin < config.min_margin:
            r1_reasons.append("low_margin")
    reasons.extend(r1_reasons)
    r1 = bool(r1_reasons)

    # --- R2 — investigable material ----------------------------------------
    r2_reasons: list[str] = []
    if parsed is not None:
        if any(_relevant_http_url(link) for link in parsed.links):
            r2_reasons.append("urls_present")
        if any(not attachment.is_inline for attachment in parsed.attachments):
            r2_reasons.append("attachments_present")
    reasons.extend(r2_reasons)
    r2 = bool(r2_reasons)

    # --- R3 — context / coverage gap ---------------------------------------
    r3_reasons: list[str] = []
    if parsed is None:
        r3_reasons.append("parse_incomplete")
    else:
        if _has_material_decode_defect(parsed):
            r3_reasons.append("parse_incomplete")
        if parsed.content_limits:
            r3_reasons.append("content_truncated")
        if parsed.essential_visual_content:
            r3_reasons.append("essential_visual_unread")
    if internal is not None and bool(internal.needs_enrichment):
        r3_reasons.append("model_requests_context")
    reasons.extend(r3_reasons)
    r3 = bool(r3_reasons)

    decision = "simple" if not (r1 or r2 or r3) else "complex"
    return GateResult(
        decision=decision,
        reasons=reasons,
        rule_hits={"R1": r1, "R2": r2, "R3": r3},
    )


__all__ = ["decide_gate"]

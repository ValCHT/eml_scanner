"""INTERNAL and FINAL prompt projections (TICKET-04/TICKET-09, docs/prompt_integration.md §3).

Builds the deterministic user envelopes from a ``ParsedEmail``:

- INTERNAL: ``UNTRUSTED_EMAIL``, ``EVIDENCE_REGISTRY``,
  ``OBSERVABLE_REGISTRY``, ``SUPPLIED_VISUAL_IDS`` — parser-produced
  registries (provenance INTERNE only by construction);
- FINAL (TICKET-09): the same four fields plus ``INTERNAL_ASSESSMENT``,
  ``TOOL_STATUS`` and ``RAG_CONTEXT``. ``TOOL_STATUS`` carries every
  normalized tool result status (including ``unavailable``/``skipped`` with
  their cause), never raw provider data.

- ``UNTRUSTED_EMAIL``: only the business-useful fields of the parsed email
  (subject, selected headers, text/HTML parts, links, attachments metadata,
  authentication as reported, image METADATA — never pixels, never an
  invented visual description);
- ``SUPPLIED_VISUAL_IDS``: empty in this POC unless actual pixels are
  supplied to the model (TICKET-16 staged visuals); metadata-only images
  never appear there.

Harness-only manifest data (fixture filename, scenario, design_label,
content_anchors, part_expectations, constraints, gold metadata, historical
X-Spam decisions) is never part of a ``ParsedEmail`` and therefore can never
enter the envelope: the projection is built exclusively from the parser
output (docs/fixtures.md, docs/contracts.md §2.8).

Context limits (docs/prompt_integration.md §3), enforced deterministically:

- body useful chars <= 24,000
- selected headers <= 8,000
- URLs/observables <= 16,000 (shared by links and extra observables)
- evidence <= 24,000
- total user text payload outside system <= 100,000 chars

Reduction is deterministic (documented order below); any truncation is
recorded in ``UNTRUSTED_EMAIL.content_limits`` and never leaves a dangling
reference: whole evidence entries are dropped, never partially quoted, and
observables referenced by kept evidence are always included.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from .state import Assessment, Observable, ParsedEmail, RagCase, ToolResult

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

#: Budgets frozen by docs/prompt_integration.md §3.
BODY_CHARS_LIMIT = 24_000
HEADERS_CHARS_LIMIT = 8_000
URLS_OBSERVABLES_CHARS_LIMIT = 16_000
EVIDENCE_CHARS_LIMIT = 24_000
TOTAL_USER_CHARS_LIMIT = 100_000

#: INTERNAL phase call parameters (docs/architecture.md §1.4; TICKET-04).
INTERNAL_EFFORT = "medium"
INTERNAL_MAX_OUTPUT_TOKENS = 8_192
INTERNAL_PHASE_SECONDS = 60.0

#: FINAL phase call parameters (docs/architecture.md §1.4; TICKET-09).
FINAL_EFFORT = "xhigh"
FINAL_MAX_OUTPUT_TOKENS = 16_384
FINAL_PHASE_SECONDS = 90.0

#: RAG_CONTEXT bounds (docs/contracts.md §2.7 tools config: k=3, 1200 chars).
RAG_MAX_CASES = 3
RAG_MAX_CASE_CHARS = 1_200

#: Canonical tool order (docs/architecture.md §1.2 pipeline order).
TOOL_ORDER: tuple[str, ...] = ("virustotal", "opencti", "urlscan")


class ContextLimits(BaseModel):
    """Deterministic projection budgets (docs/prompt_integration.md §3).

    The last two fields carry the INTERNAL call parameters so the frozen
    ``assess_internal(parsed, client, limits)`` interface needs no Settings.
    The two FINAL fields (TICKET-09) play the same role for
    ``assess_final``; the caller may override them from ``Settings``.
    """

    model_config = ConfigDict(extra="forbid")

    body_chars: int = BODY_CHARS_LIMIT
    headers_chars: int = HEADERS_CHARS_LIMIT
    urls_observables_chars: int = URLS_OBSERVABLES_CHARS_LIMIT
    evidence_chars: int = EVIDENCE_CHARS_LIMIT
    total_user_chars: int = TOTAL_USER_CHARS_LIMIT
    internal_max_output_tokens: int = INTERNAL_MAX_OUTPUT_TOKENS
    internal_phase_seconds: float = INTERNAL_PHASE_SECONDS
    final_max_output_tokens: int = FINAL_MAX_OUTPUT_TOKENS
    final_phase_seconds: float = FINAL_PHASE_SECONDS


def load_internal_prompt() -> str:
    """Load the complete delivered system prompt, unchanged (V1.2)."""

    return (PROMPTS_DIR / "internal_assessment.txt").read_text(encoding="utf-8")


def load_final_prompt() -> str:
    """Load the complete delivered FINAL system prompt (docs/prompt_integration.md §3).

    TICKET-09 mirrors the TICKET-04 documented deviation: the closed enum
    values (inference ``code``, ``reason_code``, ``missing_information``) are
    enumerated verbatim in the prompt because the observed proxy does not
    enforce ``response_format=json_schema`` for the model. The schema,
    taxonomy, business rules and user envelope are unchanged.
    """

    return (PROMPTS_DIR / "final_assessment.txt").read_text(encoding="utf-8")


def canonical_bytes(value: Any) -> bytes:
    """C(x) exactly as defined in docs/contracts.md §2.6.1 (no newline)."""

    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Deterministic section selection under budgets
# ---------------------------------------------------------------------------


def _select_headers(parsed: ParsedEmail, budget: int) -> tuple[list[dict[str, str]], bool]:
    """Headers in original order, whole-header greedy selection, ≤ budget.

    Cost of a header = len(name) + len(decoded_value) (§2.6.1 counter rule).
    Selection stops at the first header that would exceed the budget, so the
    result is a deterministic prefix of the ordered header list.
    """

    selected: list[dict[str, str]] = []
    used = 0
    truncated = False
    for header in parsed.headers:
        cost = len(header.name) + len(header.decoded_value)
        if used + cost > budget:
            truncated = True
            break
        selected.append({"name": header.name, "decoded_value": header.decoded_value})
        used += cost
    return selected, truncated


def _select_parts(parts: list[Any], budget: int) -> tuple[list[dict[str, Any]], bool]:
    """Text/HTML parts in order; a part is truncated to the remaining budget.

    A part whose text is cut, or dropped because no budget remains, is never
    silently replaced by an empty stub: it is either included with its exact
    (possibly truncated) text or absent, and the gap is flagged by the
    caller in ``content_limits``.
    """

    selected: list[dict[str, Any]] = []
    remaining = budget
    truncated = False
    for part in parts:
        if remaining <= 0:
            truncated = truncated or bool(part.text)
            continue
        text = part.text
        if len(text) > remaining:
            text = text[:remaining]
            truncated = True
        selected.append(
            {"part_id": part.part_id, "mime_type": part.mime_type, "text": text}
        )
        remaining -= len(text)
    return selected, truncated


def _select_links(parsed: ParsedEmail, budget: int) -> tuple[list[dict[str, Any]], int, bool]:
    """Links in order under the shared URLs/observables budget.

    Returns ``(links, used_chars, truncated)``; cost of a link is the length
    of its canonical JSON serialization (Unicode chars, §2.6.1).
    """

    selected: list[dict[str, Any]] = []
    used = 0
    truncated = False
    for link in parsed.links:
        entry = {
            "id": link.id,
            "part_id": link.part_id,
            "role": link.role,
            "raw_value": link.raw_value,
            "normalized_value": link.normalized_value,
            "display_text": link.display_text,
            "display_url": link.display_url,
            "href_display_mismatch": link.href_display_mismatch,
        }
        cost = len(canonical_bytes(entry).decode("utf-8"))
        if used + cost > budget:
            truncated = True
            break
        selected.append(entry)
        used += cost
    return selected, used, truncated


def _evidence_entries(parsed: ParsedEmail) -> list[dict[str, Any]]:
    """Parser evidence as registry entries (INTERNE provenance by contract)."""

    return [
        {
            "id": ev.id,
            "provenance": ev.provenance,
            "source_kind": ev.source_kind,
            "predicate": ev.predicate,
            "value": ev.value,
            "source_ref": ev.source_ref,
            "observable_id": ev.observable_id,
        }
        for ev in parsed.evidence
    ]


def _observable_entries(parsed: ParsedEmail) -> dict[str, dict[str, Any]]:
    """Parser observables keyed by id (registry form sent to the model)."""

    return {
        obs.id: {
            "id": obs.id,
            "type": obs.type,
            "value": obs.value,
            "normalized_value": obs.normalized_value,
            "roles": list(obs.roles),
            "provenance": obs.provenance,
        }
        for obs in parsed.observables
    }


def _select_evidence(
    entries: list[dict[str, Any]], budget: int
) -> tuple[list[dict[str, Any]], bool]:
    """Whole-entry greedy selection in parser order (no partial evidence)."""

    selected: list[dict[str, Any]] = []
    used = 0
    truncated = False
    for entry in entries:
        cost = len(canonical_bytes(entry).decode("utf-8"))
        if used + cost > budget:
            truncated = True
            break
        selected.append(entry)
        used += cost
    return selected, truncated


def _select_observables(
    all_observables: dict[str, dict[str, Any]],
    kept_evidence: list[dict[str, Any]],
    budget: int,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], bool]:
    """Observables under the shared budget, evidence kept reference-consistent.

    Returns ``(selected_observables, kept_evidence, truncated)``:

    - observables referenced by kept evidence are mandatory but still
      budget-bound (the 16k URLs/observables limit applies to them too);
    - an evidence entry whose observable no longer fits the budget is
      DROPPED, so the sent payload never carries a reference to an
      observable that is not in the registry (no dangling reference);
    - the remaining observables follow in registry order while the budget
      allows.
    """

    selected: dict[str, dict[str, Any]] = {}
    used = 0
    truncated = False
    mandatory_ids = {
        entry["observable_id"]
        for entry in kept_evidence
        if entry.get("observable_id") is not None
    }
    for obs_id in sorted(mandatory_ids):
        if obs_id not in all_observables:
            continue
        entry = all_observables[obs_id]
        cost = len(canonical_bytes(entry).decode("utf-8"))
        if used + cost > budget:
            truncated = True
            continue  # excluded: its evidence entries are dropped below
        selected[obs_id] = entry
        used += cost
    # Reference consistency: drop evidence entries whose observable was
    # excluded by the budget (never send a dangling observable_id).
    kept_evidence = [
        entry
        for entry in kept_evidence
        if entry.get("observable_id") is None or entry["observable_id"] in selected
    ]
    for obs_id, entry in all_observables.items():
        if obs_id in selected:
            continue
        cost = len(canonical_bytes(entry).decode("utf-8"))
        if used + cost > budget:
            truncated = True
            break
        selected[obs_id] = entry
        used += cost
    return selected, kept_evidence, truncated


# ---------------------------------------------------------------------------
# Envelope construction
# ---------------------------------------------------------------------------


def _project_untrusted_email(
    parsed: ParsedEmail, limits: ContextLimits
) -> tuple[dict[str, Any], int, bool, bool, bool]:
    """Deterministic UNTRUSTED_EMAIL projection shared by both phases.

    Section budgets are enforced in the frozen order headers → body →
    links; ``content_limits`` is intentionally NOT set here: the caller
    appends every truncation flag in one deterministic pass once all
    sections have been selected, so INTERNAL and FINAL flag identically.

    Returns ``(untrusted_email, links_chars_used, body_truncated,
    headers_truncated, links_truncated)``.
    """

    headers, headers_trunc = _select_headers(parsed, limits.headers_chars)
    # Text and HTML parts share the single body budget (docs/prompt_integration.md
    # §3: 24,000 useful body characters overall, not per MIME type). The
    # truncation flag of EACH section is kept: a text/plain cut must be
    # flagged in content_limits exactly like an HTML cut.
    text_parts, text_trunc = _select_parts(parsed.text_parts, limits.body_chars)
    text_chars_used = sum(len(part["text"]) for part in text_parts)
    html_parts, html_trunc = _select_parts(
        parsed.html_parts, max(0, limits.body_chars - text_chars_used)
    )
    body_trunc = text_trunc or html_trunc

    links, links_used, links_trunc = _select_links(parsed, limits.urls_observables_chars)

    untrusted_email = {
        "subject": parsed.subject,
        "actors": {
            "from": list(parsed.from_addresses),
            "to": list(parsed.to_addresses),
            "cc": list(parsed.cc_addresses),
            "reply_to": list(parsed.reply_to),
            "return_path": list(parsed.return_path),
        },
        "date_raw": parsed.date_raw,
        "message_id": parsed.message_id,
        "headers": headers,
        "text_parts": text_parts,
        "html_parts": html_parts,
        "links": links,
        "attachments": [
            {
                "part_id": att.part_id,
                "filename": att.filename,
                "mime_type": att.mime_type,
                "disposition": att.disposition,
                "decoded_size_bytes": att.decoded_size_bytes,
                "sha256": att.sha256,
                "decode_status": att.decode_status,
                "is_inline": att.is_inline,
            }
            for att in parsed.attachments
        ],
        "authentication": [
            {
                "mechanism": auth.mechanism,
                "result": auth.result,
                "domain": auth.domain,
                "trust": auth.trust,
            }
            for auth in parsed.authentication
        ],
        # Image METADATA only: no pixels are supplied in this POC, and a
        # metadata record must never become an invented visual description.
        # local_ref (a filesystem path) is deliberately excluded.
        "images": [
            {
                "sha256": img.sha256,
                "mime_type": img.mime_type,
                "status": img.status,
                "content_id": img.content_id,
                "part_id": img.part_id,
            }
            for img in parsed.images
        ],
        "defects": list(parsed.defects),
        "essential_visual_content": parsed.essential_visual_content,
    }
    return untrusted_email, links_used, body_trunc, headers_trunc, links_trunc


def _content_limits(
    parsed: ParsedEmail,
    body_trunc: bool,
    headers_trunc: bool,
    urls_trunc: bool,
    evidence_trunc: bool,
) -> list[str]:
    """Truncation flags in the frozen order (body → headers → urls → evidence)."""

    content_limits = list(parsed.content_limits)
    for flag, hit in (
        ("body_truncated", body_trunc),
        ("headers_truncated", headers_trunc),
        ("urls_truncated", urls_trunc),
        ("evidence_truncated", evidence_trunc),
    ):
        if hit and flag not in content_limits:
            content_limits.append(flag)
    return content_limits


def build_internal_envelope(
    parsed: ParsedEmail, limits: ContextLimits, staged: Sequence[Any] = ()
) -> dict[str, Any]:
    """Deterministic INTERNAL user envelope (docs/prompt_integration.md §3).

    Returns the four conceptual fields exactly:
    ``UNTRUSTED_EMAIL``, ``EVIDENCE_REGISTRY``, ``OBSERVABLE_REGISTRY``,
    ``SUPPLIED_VISUAL_IDS``. Without staged pixels (TICKET-16 ``staged``),
    ``SUPPLIED_VISUAL_IDS`` is empty — the G2/G5 text-only behavior.

    ``staged`` carries the ``StagedVisual`` objects of ``src/vision.py``:
    their IDs must be ``VisualEvidence`` ids of THIS parsed email and their
    data URIs must be PNG/JPEG data URIs (never a remote or local path).
    The check is strict and happens BEFORE any call: a mismatch is a
    configuration error, never a silently dropped pixel.

    Section budgets are enforced in the frozen order headers → body →
    links/observables → evidence; every truncation is flagged in
    ``UNTRUSTED_EMAIL.content_limits``. The section budgets are mutually
    consistent with the total user payload limit, which is asserted.
    """

    untrusted_email, links_used, body_trunc, headers_trunc, links_trunc = (
        _project_untrusted_email(parsed, limits)
    )

    evidence_entries = _evidence_entries(parsed)
    kept_evidence, evidence_trunc = _select_evidence(evidence_entries, limits.evidence_chars)

    all_observables = _observable_entries(parsed)
    remaining_obs_budget = max(0, limits.urls_observables_chars - links_used)
    # Mandatory observables (referenced by kept evidence) are budget-bound
    # too: one that no longer fits is excluded and the evidence entries
    # referencing it are dropped, so no dangling reference ever remains
    # (docs/prompt_integration.md §3: aucune preuve tronquée ne reste
    # référençable).
    observables, kept_evidence, obs_trunc = _select_observables(
        all_observables, kept_evidence, remaining_obs_budget
    )

    untrusted_email["content_limits"] = _content_limits(
        parsed,
        body_trunc,
        headers_trunc,
        links_trunc or obs_trunc,
        evidence_trunc,
    )

    supplied_ids = _supplied_visual_ids(parsed, staged)
    envelope = {
        "UNTRUSTED_EMAIL": untrusted_email,
        "EVIDENCE_REGISTRY": {entry["id"]: entry for entry in kept_evidence},
        "OBSERVABLE_REGISTRY": observables,
        # Exactly the IDs of images whose real pixels are attached to THIS
        # call; metadata-only images never appear here.
        "SUPPLIED_VISUAL_IDS": supplied_ids,
    }

    user_chars = len(canonical_bytes(envelope).decode("utf-8"))
    if user_chars > limits.total_user_chars:
        # Cannot happen while the section budgets hold (24k + 8k + 16k + 24k
        # + fixed keys < 100k), but the invariant stays explicit and checked.
        raise ValueError(
            f"INTERNAL user payload {user_chars} exceeds total budget "
            f"{limits.total_user_chars}; reduce section budgets deterministically"
        )
    return envelope


# ---------------------------------------------------------------------------
# FINAL envelope (TICKET-09, docs/prompt_integration.md §3)
# ---------------------------------------------------------------------------


def canonical_tool_results(tool_results: Any) -> tuple[ToolResult, ...]:
    """Deterministic tool-result order, independent of the caller's ordering.

    Accepts ``None``, an ``Enrichment``-like object (``virustotal`` /
    ``opencti`` / ``urlscan`` lists) or any iterable of ``ToolResult``. The
    order is (tool order, query observable id, canonical content) so merging
    the same set in a different order yields identical registries, TOOL_STATUS
    and therefore identical audit digests.
    """

    if tool_results is None:
        items: list[Any] = []
    elif all(hasattr(tool_results, name) for name in TOOL_ORDER):
        items = [
            *getattr(tool_results, "virustotal", ()),
            *getattr(tool_results, "opencti", ()),
            *getattr(tool_results, "urlscan", ()),
        ]
    else:
        items = list(tool_results)
    results: list[ToolResult] = []
    for item in items:
        if not isinstance(item, ToolResult):
            raise ValueError(
                f"tool_results: expected ToolResult objects, got {type(item).__name__}"
            )
        results.append(item)

    def _key(result: ToolResult) -> tuple[int, str, bytes]:
        return (
            TOOL_ORDER.index(result.tool),
            result.query_observable_id or "",
            canonical_bytes(result.model_dump(mode="json")),
        )

    return tuple(sorted(results, key=_key))


def tool_status_entries(tool_results: Any) -> list[dict[str, Any]]:
    """TOOL_STATUS included in the FINAL envelope: normalized facts only.

    Every result is transmitted, including ``not_found`` / ``unavailable`` /
    ``skipped`` with their cause, mode, date and fingerprint. Raw provider
    data is never copied here (docs/architecture.md §1.6, TICKET-09).
    """

    return [
        {
            "tool": result.tool,
            "query_observable_id": result.query_observable_id,
            "status": result.status,
            "reason": result.reason,
            "mode": result.mode,
            "collected_at": result.collected_at,
            "requests_sent": result.requests_sent,
            "elapsed_ms": result.elapsed_ms,
            "response_ref": result.response_ref,
            "response_sha256": result.response_sha256,
            "visibility": result.visibility,
            "scan_id": result.scan_id,
        }
        for result in canonical_tool_results(tool_results)
    ]


def rag_context_entries(rag_context: Any) -> list[dict[str, Any]]:
    """Bounded RAG_CONTEXT projection (max 3 cases, ≤1200 chars per case).

    Only public/validated ``RagCase`` fields are projected; the ``case_id``
    is what an inference may cite in ``rag_case_ids``. No IOC or verdict is
    propagated (docs/contracts.md §2.4/§2.7). In G5 the context is always
    empty because RAG is not active.
    """

    if rag_context is None:
        return []
    cases = list(rag_context)
    if any(not isinstance(case, RagCase) for case in cases):
        raise ValueError("rag_context: expected RagCase objects")
    if len(cases) > RAG_MAX_CASES:
        raise ValueError(
            f"rag_context: at most {RAG_MAX_CASES} cases allowed (got {len(cases)})"
        )
    entries: list[dict[str, Any]] = []
    for case in cases:
        entry: dict[str, Any] = {
            "case_id": case.case_id,
            "public_source_url": case.public_source_url,
            "dataset": case.dataset,
            "validated_label": case.validated_label,
            "text_excerpt": case.text_excerpt,
        }
        # Deterministic character bound on the whole projected case.
        while entry["text_excerpt"] and len(canonical_bytes(entry)) > RAG_MAX_CASE_CHARS:
            overflow = len(canonical_bytes(entry)) - RAG_MAX_CASE_CHARS
            entry["text_excerpt"] = entry["text_excerpt"][
                : max(0, len(entry["text_excerpt"]) - max(1, overflow))
            ]
        entries.append(entry)
    return entries


def _supplied_visual_ids(parsed: ParsedEmail, staged: Sequence[Any]) -> list[str]:
    """Validated ``SUPPLIED_VISUAL_IDS`` for the staged pixels (TICKET-16).

    Strict identity rules before any call: exactly the staged visual IDs, in
    staged order; each ID must be a ``VisualEvidence`` of this parsed email;
    only PNG/JPEG data URIs are permitted (``data:image/png;base64,`` /
    ``data:image/jpeg;base64,``) — never ``http(s)://``, ``file://`` or a
    local path. No visual ID without actual pixels, no pixels without an ID.
    """

    if not staged:
        return []
    known = {image.id for image in parsed.images}
    ids: list[str] = []
    for visual in staged:
        visual_id = getattr(visual, "visual_id", None)
        data_uri = getattr(visual, "data_uri", None)
        data_mime = getattr(visual, "data_mime_type", None)
        if visual_id is None or data_uri is None or data_mime is None:
            raise ValueError(
                f"staged visual {visual!r}: expected a vision.StagedVisual "
                "(visual_id, data_mime_type, data_uri)"
            )
        if visual_id not in known:
            raise ValueError(
                f"staged visual {visual_id!r} is not a VisualEvidence of this "
                "email: no visual ID without a matching parsed image"
            )
        expected_prefix = f"data:{data_mime};base64,"
        if data_mime not in ("image/png", "image/jpeg"):
            raise ValueError(
                f"staged visual {visual_id!r}: only PNG/JPEG data URIs are "
                f"permitted, got {data_mime!r}"
            )
        if not str(data_uri).startswith(expected_prefix):
            raise ValueError(
                f"staged visual {visual_id!r}: data URI must start with "
                f"{expected_prefix!r}"
            )
        ids.append(visual_id)
    if len(set(ids)) != len(ids):
        raise ValueError("staged visuals contain duplicate visual IDs")
    return ids


def build_final_envelope(
    parsed: ParsedEmail,
    internal: Assessment | None,
    evidence: Mapping[str, Evidence],
    observables: Mapping[str, Observable],
    tool_results: Any,
    rag_context: Any,
    limits: ContextLimits,
    staged: Sequence[Any] = (),
) -> dict[str, Any]:
    """Deterministic FINAL user envelope (docs/prompt_integration.md §3).

    Same four fields as INTERNAL plus ``INTERNAL_ASSESSMENT``,
    ``TOOL_STATUS`` and ``RAG_CONTEXT``. The registries are the MERGED ones
    (INTERNE + OSINT + SANDBOX); the selection is deterministic and never
    leaves a dangling reference: whole evidence entries only, observables
    under the shared budget, and an evidence entry whose observable no
    longer fits is dropped (truncation flagged in ``content_limits``).
    Without staged pixels ``SUPPLIED_VISUAL_IDS`` stays empty (G5).
    """

    untrusted_email, links_used, body_trunc, headers_trunc, links_trunc = (
        _project_untrusted_email(parsed, limits)
    )

    evidence_entries = [
        entry.model_dump(mode="json") for entry in evidence.values()
    ]
    kept_evidence, evidence_trunc = _select_evidence(
        evidence_entries, limits.evidence_chars
    )

    all_observables = {
        obs_id: entry.model_dump(mode="json")
        for obs_id, entry in observables.items()
    }
    remaining_obs_budget = max(0, limits.urls_observables_chars - links_used)
    observables_sent, kept_evidence, obs_trunc = _select_observables(
        all_observables, kept_evidence, remaining_obs_budget
    )

    untrusted_email["content_limits"] = _content_limits(
        parsed,
        body_trunc,
        headers_trunc,
        links_trunc or obs_trunc,
        evidence_trunc,
    )

    supplied_ids = _supplied_visual_ids(parsed, staged)
    envelope = {
        "UNTRUSTED_EMAIL": untrusted_email,
        "EVIDENCE_REGISTRY": {entry["id"]: entry for entry in kept_evidence},
        "OBSERVABLE_REGISTRY": observables_sent,
        # Exactly the IDs of the images whose pixels are attached HERE.
        "SUPPLIED_VISUAL_IDS": supplied_ids,
        # The internal assessment is unreliable data like the rest of the
        # envelope; null is honest when no valid internal result exists.
        "INTERNAL_ASSESSMENT": (
            internal.model_dump(mode="json") if internal is not None else None
        ),
        "TOOL_STATUS": tool_status_entries(tool_results),
        "RAG_CONTEXT": rag_context_entries(rag_context),
    }

    user_chars = len(canonical_bytes(envelope).decode("utf-8"))
    if user_chars > limits.total_user_chars:
        raise ValueError(
            f"FINAL user payload {user_chars} exceeds total budget "
            f"{limits.total_user_chars}; reduce section budgets deterministically"
        )
    return envelope


def envelope_has_useful_content(envelope: dict[str, Any]) -> bool:
    """False when the envelope would transmit an empty/substituted email.

    A textual fixture must always carry either useful body text or at least
    the expected headers; an envelope without any of them is rejected before
    any call (docs/gates.md §5.1.1 check 2).
    """

    untrusted = envelope["UNTRUSTED_EMAIL"]
    has_text = any(part["text"].strip() for part in untrusted["text_parts"]) or any(
        part["text"].strip() for part in untrusted["html_parts"]
    )
    has_headers = any(header["decoded_value"].strip() for header in untrusted["headers"])
    has_actors = any(
        any(address for address in addresses if address and address.strip())
        for addresses in untrusted["actors"].values()
    )
    return bool(has_text or has_headers or has_actors)


def build_internal_messages(
    parsed: ParsedEmail, limits: ContextLimits, staged: Sequence[Any] = ()
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """System prompt (delivered file, unchanged) + user JSON envelope.

    ``staged`` (TICKET-16) carries the ``StagedVisual`` pixels to attach to
    THIS call as OpenAI-compatible multipart ``image_url`` parts (PNG/JPEG
    data URIs only). Without staged pixels the user message stays the exact
    text-only string (byte-equivalent behavior when Vision is disabled).

    Returns ``(messages, envelope)`` so the caller can validate references
    against the registries ACTUALLY sent (never a rebuild).
    """

    envelope = build_internal_envelope(parsed, limits, staged)
    return _messages_from_envelope(envelope, load_internal_prompt(), staged), envelope


def build_final_messages(
    parsed: ParsedEmail,
    internal: Assessment | None,
    evidence: Mapping[str, Evidence],
    observables: Mapping[str, Observable],
    tool_results: Any,
    rag_context: Any,
    limits: ContextLimits,
    staged: Sequence[Any] = (),
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """FINAL system prompt (delivered file) + user JSON envelope.

    ``staged`` (TICKET-16) attaches the real pixels of exactly the visuals
    listed in the envelope's ``SUPPLIED_VISUAL_IDS``. Without staged pixels
    the text-only form is unchanged.

    Returns ``(messages, envelope)`` so the caller can validate references
    against the registries ACTUALLY sent, never a rebuild.
    """

    envelope = build_final_envelope(
        parsed, internal, evidence, observables, tool_results, rag_context, limits, staged
    )
    return _messages_from_envelope(envelope, load_final_prompt(), staged), envelope


def _messages_from_envelope(
    envelope: dict[str, Any], system_prompt: str, staged: Sequence[Any] = ()
) -> list[dict[str, Any]]:
    """System text + user envelope; staged pixels become multipart parts.

    Text-only (no staged pixels): the user content is the exact JSON string
    (unchanged frozen form). With staged pixels: an OpenAI-compatible
    multipart list — one ``text`` part (the same envelope JSON) followed by
    one ``image_url`` part per staged visual, using PNG/JPEG data URIs
    only. The pixels stay USER content: never system text, never a path,
    never a remote URL.
    """

    user_payload = json.dumps(
        envelope, ensure_ascii=False, sort_keys=True, allow_nan=False
    )
    if not staged:
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_payload},
        ]
    user_parts: list[dict[str, Any]] = [{"type": "text", "text": user_payload}]
    for visual in staged:
        user_parts.append(
            {
                "type": "image_url",
                "image_url": {"url": visual.data_uri},
            }
        )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_parts},
    ]


__all__ = [
    "ContextLimits",
    "FINAL_EFFORT",
    "FINAL_MAX_OUTPUT_TOKENS",
    "FINAL_PHASE_SECONDS",
    "RAG_MAX_CASES",
    "RAG_MAX_CASE_CHARS",
    "TOOL_ORDER",
    "build_final_envelope",
    "build_final_messages",
    "build_internal_envelope",
    "build_internal_messages",
    "canonical_bytes",
    "canonical_tool_results",
    "envelope_has_useful_content",
    "load_final_prompt",
    "load_internal_prompt",
    "rag_context_entries",
    "tool_status_entries",
]

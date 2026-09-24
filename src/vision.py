"""Bounded local Vision/QR capability (TICKET-16, gate G7-B) — single module.

No second pipeline and no graph integration: the StateGraph keeps its frozen
shape. This module only provides the capability the later synchronization
step will wire into the existing INTERNAL/FINAL calls (TICKET-16 parallel
branch: do not integrate here).

Public contracts (docs/contracts.md §2.7.3):

- ``prepare_visuals(parsed, limits) -> list[VisualEvidence]``: deterministic
  typed preparation of the images the parser already recorded
  (``ParsedEmail.images``). Every input visual keeps its deterministic id,
  original SHA-256, declared mime type, provenance, part/content ids and
  ``local_ref``; only ``width``/``height``, ``status`` and ``qr_payloads``
  are produced here. Statuses come from the closed vocabulary
  (``metadata_only`` / ``supplied_to_model`` / ``unsupported`` /
  ``over_limit`` / ``unavailable``) — a limit violation or a corrupt image
  becomes typed state, never an exception that escapes the analysis.
- ``decode_qr(image_bytes) -> list[str]``: local-only zxing-cpp decode.
  Exact payloads, deterministic dedup, stable (first-seen) order. A payload
  is never rewritten, never visited, never submitted to any tool.
- ``qr_contract(visuals)``: the QR payloads join the EXISTING parser
  contracts only — ``Link(role="qr_url")``, ``Observable(type="url",
  roles=["link_target"], provenance="INTERNE")`` and ``Evidence`` with
  ``predicate="qr_payload"`` (always) plus ``url_found`` (URL payloads),
  provenance INTERNE. No QR-derived value bypasses the verifier/egress
  rules; nothing is fetched, resolved or navigated.
- ``prepare_visual_bundle(...)`` returns the visuals together with the
  ``StagedVisual`` pixels for the NEXT model call: runtime-only objects,
  never persisted in state (docs/contracts.md §2.2: the state carries
  references and fingerprints only).
- ``extract_image_parts`` (src/parsing.py) loads image bytes from the MIME
  tree at the authorized call, keyed by the parser's own part ids; TICKET-20
  HTML-embedded ``data:image/png|jpeg;base64`` blobs are included under their
  synthetic parser part ids (``<html part id>:img<index>``), so this module
  enforces the same limits on them with no second pipeline.

Security invariants:

- The optional stack (Pillow, zxing-cpp) is imported lazily and only when
  actual pixels are processed: text-only analysis never imports it
  (proven by a subprocess test with the imports blocked).
- Only PNG/JPEG are processed (declared AND detected); SVG, GIF, remote
  image URLs, executable attachments, PDFs and Office files stay
  ``unsupported``.
- Limits (configs/tools.yaml ``vision``): 4 images, 4 MiB per image,
  8 MiB total, 16,000,000 decoded pixels; enforced BEFORE expensive
  processing whenever possible. ``vision.enabled`` gates the pixel staging
  ONLY: QR decoding is piloted independently by ``QR_DECODE_ENABLED`` and
  never attaches pixels by itself (``text+QR`` mode).
- The SHA-256 of the exact staged bytes is computed independently
  (``derived_sha256``) and must equal the parser's original hash; this POC
  creates no derived representation, so a mismatch is refused instead of
  sending pixels whose provenance hash would be wrong.
- Images, QR payloads and screenshots are untrusted email content, never
  instructions: staged pixels travel as user-message ``image_url`` parts
  (PNG/JPEG data URIs only) and never as system text.
"""

from __future__ import annotations

import base64
import hashlib
import io
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .config import VisionToolConfig
from .parsing import (
    _det_id,
    _hostname_of,
    _normalize_url,
)
from .state import Evidence, Link, Observable, ParsedEmail, VisualEvidence

#: Declared MIME types this capability may touch at all; everything else is
#: ``unsupported`` before any decoding (SVG/GIF/remote/PDF/Office/executable…).
SUPPORTED_IMAGE_MIME_TYPES = frozenset({"image/png", "image/jpeg"})

#: Detected Pillow formats mapped to their exact data-URI mime type. Only
#: these two formats ever produce pixels for a model call.
_DETECTED_MIME = {"PNG": "image/png", "JPEG": "image/jpeg"}


class VisionDependencyError(RuntimeError):
    """An enabled Vision/QR feature lacks its optional dependency."""


# ---------------------------------------------------------------------------
# Optional-dependency introspection (never imports the stack on the
# text-only path: only find_spec / guarded probes are used)
# ---------------------------------------------------------------------------


def vision_dependencies() -> dict[str, bool]:
    """Availability of the optional stack, WITHOUT importing it.

    ``find_spec`` reports a declared installation only; a present-but-broken
    installation may still fail at import time. The text-only path must not
    rely on this function and must never import the stack at all.
    """

    import importlib.util

    def _available(name: str) -> bool:
        try:
            return importlib.util.find_spec(name) is not None
        except (ImportError, ValueError, ModuleNotFoundError):
            return False

    return {"pillow": _available("PIL"), "zxingcpp": _available("zxingcpp")}


def _probe_zxingcpp() -> bool:
    """Explicit guarded import, allowed ONLY on the QR-enabled path."""

    try:
        import zxingcpp  # noqa: F401
    except (ImportError, ModuleNotFoundError):
        return False
    return True


def _probe_pillow() -> bool:
    """Explicit guarded import, allowed ONLY on the pixel-enabled path."""

    try:
        import PIL  # noqa: F401
    except (ImportError, ModuleNotFoundError):
        return False
    return True


# ---------------------------------------------------------------------------
# decode_qr — local-only, deterministic, no side effect
# ---------------------------------------------------------------------------


def decode_qr(image_bytes: bytes) -> list[str]:
    """Decode every QR symbol of ONE image locally (zxing-cpp only).

    - exact payloads, deterministic dedup of exact duplicates, stable
      first-seen order;
    - no image bytes leave the process, no URL is visited, resolved or
      submitted: a decoded HTTP(S) payload is returned as an exact string
      and only the caller's parser contracts may turn it into evidence;
    - undecodable/corrupt input or an image without QR → ``[]`` (typed
      absence; never an invented payload);
    - zxing-cpp missing → ``VisionDependencyError`` (QR decoding must be
      enabled only with the decoder installed).

    Deterministic on the input bytes; no OCR, no remote service, no model.
    """

    try:
        import zxingcpp
    except (ImportError, ModuleNotFoundError) as error:
        raise VisionDependencyError(
            "zxing-cpp is not installed; QR decoding is unavailable"
        ) from error

    try:
        from PIL import Image
    except (ImportError, ModuleNotFoundError) as error:
        raise VisionDependencyError(
            "Pillow is not installed; image decoding is unavailable"
        ) from error

    try:
        image = Image.open(io.BytesIO(image_bytes))
        try:
            results = zxingcpp.read_barcodes(image, zxingcpp.BarcodeFormat.QRCode)
        except (TypeError, AttributeError):
            # Binding variants without the format argument: decode then
            # filter strictly by QR format below.
            results = zxingcpp.read_barcodes(image)
    except VisionDependencyError:
        raise
    except Exception:  # noqa: BLE001 — corrupt/unsupported image: typed absence
        return []

    payloads: list[str] = []
    seen: set[str] = set()
    for result in results or ():
        try:
            is_qr = result.format == zxingcpp.BarcodeFormat.QRCode
        except AttributeError:
            is_qr = False
        if not is_qr:
            continue
        text = result.text
        if not isinstance(text, str) or text in seen:
            continue
        seen.add(text)
        payloads.append(text)
    return payloads


# ---------------------------------------------------------------------------
# Bounded byte extraction helper reusing the parser contracts
# ---------------------------------------------------------------------------


def load_image_bytes(
    raw_email: bytes,
    parsed: ParsedEmail,
    parse_limits: object | None = None,
) -> dict[str, bytes]:
    """Decoded image bytes keyed by part id, for the parser-accepted images.

    Thin adapter over ``parsing.extract_image_parts`` (same deterministic
    walk, same part ids, same decode limits). Vision limits are NOT applied
    here: :func:`prepare_visuals` enforces them with typed statuses before
    any expensive processing. Returns ``{}`` when the email cannot be read.
    """

    from .parsing import ParseLimits, extract_image_parts

    limits = parse_limits if parse_limits is not None else ParseLimits()
    if not isinstance(limits, ParseLimits):
        limits = ParseLimits(**{
            name: getattr(limits, name) for name in ParseLimits.model_fields
        })
    expected = {visual.part_id for visual in parsed.images if visual.part_id}
    if not expected:
        return {}
    extracted = extract_image_parts(raw_email, limits)
    return {part_id: extracted[part_id] for part_id in sorted(expected & extracted.keys())}


# ---------------------------------------------------------------------------
# prepare_visuals — deterministic typed preparation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StagedVisual:
    """Pixels staged for ONE model call; runtime-only, never persisted.

    ``sha256`` is the hash of the ORIGINAL image bytes (parent reference,
    never replaced). ``derived_sha256`` is the INDEPENDENT SHA-256 of the
    exact bytes embedded in the data URI, computed here and never copied
    from the parent. This POC creates no derived representation, so the two
    hashes must be equal: a mismatch means the bytes do not belong to this
    visual and the image is refused (typed ``unavailable``, never staged).
    """

    visual_id: str
    sha256: str
    mime_type: str
    part_id: str | None
    content_id: str | None
    data_mime_type: str
    data_uri: str
    width: int | None
    height: int | None
    derived_sha256: str


@dataclass(frozen=True)
class VisionPreparation:
    """Result of the bounded visual preparation (visuals + staged pixels).

    ``staged`` carries exactly the images whose pixels may be attached to
    the next model call (``SUPPLIED_VISUAL_IDS`` = their ids, in this
    order). Vision and QR are INDEPENDENT: ``limits.enabled`` controls the
    pixel staging while ``qr_enabled`` controls the local decoder, so
    ``text+QR`` decodes payloads without staging a pixel and ``text+vision``
    stages pixels without executing the decoder. ``qr_decoder_available`` is
    computed only when QR decoding is requested: ``qr_enabled=True`` without
    zxing-cpp degrades to empty ``qr_payloads`` (typed, observable — never
    fabricated).
    """

    visuals: list[VisualEvidence]
    staged: tuple[StagedVisual, ...]
    qr_decode_requested: bool
    qr_decoder_available: bool
    pixel_decoder_available: bool

    @property
    def supplied_ids(self) -> list[str]:
        return [visual.visual_id for visual in self.staged]


def prepare_visual_bundle(
    parsed: ParsedEmail,
    limits: VisionToolConfig,
    *,
    image_bytes: Mapping[str, bytes] | None = None,
    qr_enabled: bool = False,
) -> VisionPreparation:
    """Bounded preparation; every outcome is typed state (no escape).

    Order is the parser's deterministic image order. For each input visual,
    in order: parser-typed statuses are forwarded unchanged; a declared
    non-PNG/JPEG type is ``unsupported``; without ``image_bytes`` the
    metadata-only state is kept; missing bytes become ``unavailable``; the
    per-image, cumulative and pixel limits are checked BEFORE decoding and
    produce ``over_limit``; a corrupt image becomes ``unavailable``; an
    accepted image beyond ``max_images`` becomes ``over_limit``.

    Vision and QR are INDEPENDENT switches:

    - pixels are staged (``supplied_to_model``) only when ``limits.enabled``
      is true (``MODEL_SUPPORTS_VISION``);
    - QR payloads are decoded only when ``qr_enabled`` is true
      (``QR_DECODE_ENABLED``) and are attached to the visual whatever the
      vision switch: ``text+QR`` decodes without staging any pixel, and a
      disabled QR switch never executes the decoder;
    - when neither is requested, the optional stack is never imported and
      the parser's metadata-only state is forwarded unchanged.

    A staged image whose bytes hash to something other than its recorded
    ``sha256`` is refused (typed ``unavailable``, never staged): this POC
    creates no derived representation, so the hash of the exact bytes sent
    must equal the original's — a mismatch means the association is wrong.
    """

    visuals: list[VisualEvidence] = []
    staged: list[StagedVisual] = []
    staged_total = 0
    accepted = 0
    vision_enabled = bool(limits.enabled)
    qr_requested = bool(qr_enabled)
    process_bytes = (vision_enabled or qr_requested) and image_bytes is not None
    pixel_decoder_available = _probe_pillow() if process_bytes else False
    qr_decoder_available = _probe_zxingcpp() if qr_requested else False

    for original in parsed.images:
        # Forward parser-typed outcomes unchanged: nothing is re-interpreted.
        if original.status in ("unavailable", "over_limit"):
            visuals.append(original.model_copy(deep=True))
            continue
        if original.mime_type not in SUPPORTED_IMAGE_MIME_TYPES:
            visuals.append(_retype(original, status="unsupported"))
            continue
        if not process_bytes or not pixel_decoder_available:
            # Metadata-only mode (no bytes supplied, both switches off, or
            # the optional stack is broken/absent): typed degradation, never
            # a crash.
            visuals.append(original.model_copy(deep=True))
            continue
        data = image_bytes.get(original.part_id or "")
        if data is None:
            visuals.append(_retype(original, status="unavailable"))
            continue
        # Byte limits BEFORE any decode.
        if len(data) > limits.max_image_bytes:
            visuals.append(_retype(original, status="over_limit"))
            continue
        if staged_total + len(data) > limits.max_total_bytes:
            visuals.append(_retype(original, status="over_limit"))
            continue
        # Header-level decode (no pixel data is loaded, never re-encoded).
        try:
            detected = _probe_pixels(data)
        except VisionDependencyError:
            # Pillow disappeared at runtime: typed degradation for this email.
            visuals.append(original.model_copy(deep=True))
            continue
        if detected is None:
            visuals.append(_retype(original, status="unavailable"))
            continue
        detected_mime, width, height = detected
        if detected_mime is None:
            visuals.append(_retype(original, status="unsupported"))
            continue
        if width * height > limits.max_pixels:
            visuals.append(_retype(original, status="over_limit"))
            continue
        accepted += 1
        if accepted > limits.max_images:
            visuals.append(_retype(original, status="over_limit"))
            continue

        # The hash of the EXACT bytes is computed independently here; this
        # POC creates no derived representation, so a mismatch with the
        # original means the bytes do not belong to this visual: refused,
        # never staged (the parser's sha256 is never rewritten).
        derived_sha256 = hashlib.sha256(data).hexdigest()
        if derived_sha256 != original.sha256:
            visuals.append(_retype(original, status="unavailable"))
            continue

        payloads: list[str] = []
        if qr_requested and qr_decoder_available:
            try:
                payloads = decode_qr(data)
            except VisionDependencyError:
                payloads = []

        if vision_enabled:
            staged_total += len(data)
            prepared = original.model_copy(
                deep=True,
                update={
                    "width": width,
                    "height": height,
                    "status": "supplied_to_model",
                    "qr_payloads": payloads,
                },
            )
            visuals.append(prepared)
            staged.append(
                StagedVisual(
                    visual_id=original.id,
                    sha256=original.sha256,
                    mime_type=original.mime_type,
                    part_id=original.part_id,
                    content_id=original.content_id,
                    data_mime_type=detected_mime,
                    data_uri=_data_uri(detected_mime, data),
                    width=width,
                    height=height,
                    derived_sha256=derived_sha256,
                )
            )
        else:
            # QR-only mode: no pixel is staged; the exact local payloads are
            # the only produced state (the visual stays metadata_only).
            visuals.append(
                original.model_copy(deep=True, update={"qr_payloads": payloads})
            )

    return VisionPreparation(
        visuals=visuals,
        staged=tuple(staged),
        qr_decode_requested=bool(qr_enabled),
        qr_decoder_available=qr_decoder_available,
        pixel_decoder_available=pixel_decoder_available,
    )


def prepare_visuals(
    parsed: ParsedEmail,
    limits: VisionToolConfig,
    *,
    image_bytes: Mapping[str, bytes] | None = None,
    qr_enabled: bool = False,
) -> list[VisualEvidence]:
    """TICKET-16 contract: deterministic prepared visuals for one email.

    See :func:`prepare_visual_bundle` for the exact behavior; this wrapper
    returns only the ``VisualEvidence`` list.
    """

    return prepare_visual_bundle(
        parsed, limits, image_bytes=image_bytes, qr_enabled=qr_enabled
    ).visuals


def _retype(original: VisualEvidence, *, status: str) -> VisualEvidence:
    """New VisualEvidence with only ``status`` changed (validated build)."""

    data = original.model_dump()
    data["status"] = status
    return VisualEvidence.model_validate(data)


def _probe_pixels(data: bytes) -> tuple[str | None, int, int] | None:
    """Header-only probe: ``(detected_mime, width, height)``.

    ``(None, w, h)`` means a decodable image in an unsupported format
    (never touched further); ``None`` alone means corrupt/unreadable bytes.
    Pillow is imported lazily: the text-only path never reaches this.
    """

    try:
        from PIL import Image
    except (ImportError, ModuleNotFoundError) as error:
        raise VisionDependencyError(
            "Pillow is not installed; image decoding is unavailable"
        ) from error

    try:
        with Image.open(io.BytesIO(data)) as probe:
            width, height = probe.size
            detected_format = probe.format
            probe.verify()  # structural check of the declared bytes
    except Exception:  # noqa: BLE001 — corrupt/truncated image: typed unavailable
        return None
    return _DETECTED_MIME.get(detected_format or ""), width, height


def _data_uri(data_mime: str, data: bytes) -> str:
    """PNG/JPEG data URI only; the transport form of staged pixels."""

    return f"data:{data_mime};base64," + base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# QR payload → existing parser/evidence contracts
# ---------------------------------------------------------------------------


def qr_contract(
    visuals: Sequence[VisualEvidence],
) -> tuple[list[Link], list[Observable], list[Evidence]]:
    """QR payloads through the EXISTING parser contracts, nothing more.

    For every visual, for every exact payload (stable order):

    - ``Evidence(predicate="qr_payload", provenance="INTERNE")`` — the exact
      payload as text evidence (URL or not);
    - HTTP/HTTPS URL payloads additionally: ``Link(role="qr_url")``,
      ``Observable(type="url", roles=["link_target"], provenance="INTERNE")``
      and ``Evidence(predicate="url_found")`` — the same deterministic id
      scheme and normalization as the parser (no new contract, no visiting,
      no reputation inference, no automatic urlscan submission).

    Every list is deduplicated by deterministic id (first occurrence kept);
    provenance stays INTERNE because the payload is local email content.
    """

    links: list[Link] = []
    observables: list[Observable] = []
    evidence: list[Evidence] = []
    seen_links: set[str] = set()
    seen_observables: set[str] = set()
    seen_evidence: set[str] = set()

    def _add_evidence(entry: Evidence) -> None:
        if entry.id in seen_evidence:
            return
        seen_evidence.add(entry.id)
        evidence.append(entry)

    for visual in visuals:
        part_id = visual.part_id or ""
        visual_ref = f"{part_id}:image:{visual.id[:16]}"
        for index, payload in enumerate(visual.qr_payloads):
            qr_ref = f"{visual_ref}:qr:{index}"
            _add_evidence(
                Evidence(
                    id=_det_id("ev", "qr_payload", payload, qr_ref),
                    provenance="INTERNE",
                    source_kind="parser",
                    observable_id=None,
                    predicate="qr_payload",
                    value=payload,
                    source_ref=qr_ref,
                    match_level="EXACT",
                )
            )
            hostname = _hostname_of(payload)
            if hostname is None:
                continue  # non-URL payload stays text evidence, never reinterpreted
            link_id = _det_id("lnk", part_id, "qr_url", payload)
            if link_id in seen_links:
                continue
            seen_links.add(link_id)
            normalized = _normalize_url(payload)
            link = Link(
                id=link_id,
                part_id=part_id,
                raw_value=payload,
                normalized_value=normalized,
                role="qr_url",
                hostname=hostname,
            )
            links.append(link)
            observable_ref = f"{part_id}:link:{link_id[:16]}"
            observable = Observable(
                id=_det_id("obs", "url", normalized, observable_ref),
                value=payload,
                normalized_value=normalized,
                type="url",
                roles=["link_target"],
                provenance="INTERNE",
                source_ref=observable_ref,
            )
            if observable.id in seen_observables:
                continue
            seen_observables.add(observable.id)
            observables.append(observable)
            _add_evidence(
                Evidence(
                    id=_det_id("ev", "url_found", payload, observable_ref),
                    provenance="INTERNE",
                    source_kind="parser",
                    observable_id=observable.id,
                    predicate="url_found",
                    value=payload,
                    source_ref=observable_ref,
                    match_level="EXACT",
                )
            )
    return links, observables, evidence


__all__ = [
    "SUPPORTED_IMAGE_MIME_TYPES",
    "StagedVisual",
    "VisionDependencyError",
    "VisionPreparation",
    "decode_qr",
    "load_image_bytes",
    "prepare_visual_bundle",
    "prepare_visuals",
    "qr_contract",
    "vision_dependencies",
]

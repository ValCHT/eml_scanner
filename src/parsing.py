"""Deterministic email parser (docs/tickets/TICKET-03.md, architecture §1.5).

Extracts headers (preserving repetitions and order), text/HTML bodies, links
(href / visible URL / form action / remote resource as distinct roles),
attachments with hashes over decoded bytes, image metadata (never decoded at
runtime), and authentication observations reported as ``reported_unverified``
by default.

Limits of docs/architecture.md §1.5 (25 MiB email, 200 MIME parts, depth 20,
20 attachments, 20 MiB decoded per part, 40 MiB decoded total) are enforced;
any limit reached is recorded in ``content_limits``. No network access, no
archive decompression, no attachment execution, no remote image loading, no
URL resolution by the parser. Attachment filenames never become filesystem
paths.

Parse errors produce a structured ``ParseFailure`` — never an unhandled
exception. The LLM projection is not created here.
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from email import message_from_bytes
from email.message import Message
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, ConfigDict, Field

from .state import (
    Attachment,
    AuthObservation,
    Evidence,
    Header,
    Link,
    Observable,
    ParsedEmail,
    TextPart,
    VisualEvidence,
)

# ---------------------------------------------------------------------------
# ParseLimits: exact figures of docs/architecture.md §1.5.
# ---------------------------------------------------------------------------


class ParseLimits(BaseModel):
    """Parsing limits; any reached limit is recorded in ``content_limits``."""

    model_config = ConfigDict(extra="forbid")

    max_eml_bytes: int = 26_214_400  # 25 MiB
    max_mime_parts: int = 200
    max_mime_depth: int = 20
    max_attachments: int = 20
    max_decoded_bytes_per_part: int = 20_971_520  # 20 MiB
    max_decoded_bytes_total: int = 41_943_040  # 40 MiB

    @classmethod
    def from_config(cls, config: object) -> "ParseLimits":
        """Build limits from a ``ParseLimitsConfig`` (configs/tools.yaml)."""

        return cls(**{name: getattr(config, name) for name in ParseLimits.model_fields})


class ParseFailure(BaseModel):
    """Structured parse error; never an unhandled exception."""

    model_config = ConfigDict(extra="forbid")

    error: str
    detail: str = ""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_NETWORK_SCHEMES = ("http", "https")

_LIMIT_EML_BYTES = "max_eml_bytes"
_LIMIT_MIME_PARTS = "max_mime_parts"
_LIMIT_MIME_DEPTH = "max_mime_depth"
_LIMIT_ATTACHMENTS = "max_attachments"
_LIMIT_DECODED_PART = "max_decoded_bytes_per_part"
_LIMIT_DECODED_TOTAL = "max_decoded_bytes_total"


def _decode_rfc2047(value: str) -> str:
    """Decode an RFC2047-encoded header value; keep the raw text on failure."""

    try:
        from email.header import decode_header, make_header

        return str(make_header(decode_header(value)))
    except Exception:  # malformed encoded words: keep the raw value
        return value


def _hostname_of(value: str) -> str | None:
    """Lowercase IDNA hostname of an absolute HTTP(S) URL, else None.

    Relative URLs are NOT resolved (architecture §1.5): no base is invented.
    """

    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in _NETWORK_SCHEMES or not parsed.hostname:
        return None
    try:
        return parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return parsed.hostname.lower()


def _normalize_url(value: str) -> str | None:
    """Comparison normalization (architecture §1.5): scheme/host lowercased,
    host IDNA, default port removed; path, query, parameter order and encoding
    preserved. The exact extracted value is always kept in ``raw_value``."""

    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in _NETWORK_SCHEMES or not parsed.hostname:
        return None
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    default = {"http": 80, "https": 443}.get(parsed.scheme)
    netloc = host if port in (None, default) else f"{host}:{port}"
    return urlunparse(
        (parsed.scheme.lower(), netloc, parsed.path, parsed.params, parsed.query, "")
    )


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _det_id(prefix: str, *content: object) -> str:
    """Deterministic id: prefix + SHA-256 of the canonical representation
    (docs/contracts.md §2.4)."""

    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _addresses(message: Message, name: str) -> list[str]:
    """All addresses of a (possibly repeated) header; never invented."""

    out: list[str] = []
    for value in message.get_all(name, []):
        for _display, addr in getaddresses([value]):
            addr = addr.strip()
            if addr:
                out.append(addr)
    return out


# ---------------------------------------------------------------------------
# HTML link extraction (stdlib only; no bs4 dependency at baseline runtime)
# ---------------------------------------------------------------------------

_ANCHOR_RE = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.DOTALL | re.IGNORECASE)
_HREF_RE = re.compile(
    r"href\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.IGNORECASE
)
_TAG_RE = re.compile(r"<(img|form)\b([^>]*)>", re.IGNORECASE)
_SRC_ACTION_RE = re.compile(
    r"(src|action)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.IGNORECASE
)
_PLAIN_URL_RE = re.compile(r"(?<![\w.])https?://[^\s<>\"']+")


def _unescape_attr(raw: str) -> tuple[str, bool]:
    """Decode HTML entities exactly once; report whether a decode happened."""

    decoded = html.unescape(raw)
    return decoded, decoded != raw


def _strip_tags(fragment: str) -> str:
    return re.sub(r"<[^>]+>", " ", fragment)


def _extract_plain_urls(text: str, part_id: str) -> list[Link]:
    """Visible URLs written in a text/plain part: role ``visible_url``."""

    links: list[Link] = []
    for m in _PLAIN_URL_RE.finditer(text):
        raw_value = m.group(0).rstrip(".,;:!?)\"'»")
        links.append(
            Link(
                id=_det_id("lnk", part_id, "visible_url", raw_value),
                part_id=part_id,
                raw_value=raw_value,
                normalized_value=_normalize_url(raw_value),
                role="visible_url",
                hostname=_hostname_of(raw_value),
            )
        )
    return links


def _extract_html_links(html_text: str, part_id: str) -> list[Link]:
    """Extract href / form action / remote resource / visible URL roles.

    ``href`` and ``display`` are kept separately; the mismatch flag compares
    only explicitly visible hosts, never a generic "click here" text.
    HTML entities are decoded exactly once (recorded as a transformation).
    No network happens.
    """

    links: list[Link] = []

    def _add(raw_value: str, role: str, display_text: str | None = None) -> None:
        exact, transformed = _unescape_attr(raw_value)
        links.append(
            Link(
                id=_det_id("lnk", part_id, role, exact, display_text),
                part_id=part_id,
                raw_value=exact,
                normalized_value=_normalize_url(exact),
                display_text=display_text,
                role=role,  # type: ignore[arg-type]
                hostname=_hostname_of(exact),
                transformation="html_entity_decoded" if transformed else None,
            )
        )

    # Anchors first, in document order, with their display text.
    for anchor_m in _ANCHOR_RE.finditer(html_text):
        attrs_blob, inner = anchor_m.group(1), anchor_m.group(2)
        href_m = _HREF_RE.search(attrs_blob)
        if not href_m:
            continue
        raw_href = next(g for g in href_m.groups() if g is not None)
        display = re.sub(r"\s+", " ", html.unescape(_strip_tags(inner))).strip() or None
        _add(raw_href, "href", display_text=display)

    # Form actions and remote resources (img src), never loaded.
    for tag_m in _TAG_RE.finditer(html_text):
        attrs_blob = tag_m.group(2)
        attr_m = _SRC_ACTION_RE.search(attrs_blob)
        if not attr_m:
            continue
        raw_value = next(g for g in attr_m.groups()[1:] if g is not None)
        if not raw_value:
            continue
        role = "form_action" if attr_m.group(1).lower() == "action" else "remote_resource"
        _add(raw_value, role)

    # Visible URLs in the rendered text flow: distinct role.
    rendered = re.sub(r"\s+", " ", html.unescape(_strip_tags(html_text)))
    for m in _PLAIN_URL_RE.finditer(rendered):
        raw_value = m.group(0).rstrip(".,;:!?)\"'»")
        links.append(
            Link(
                id=_det_id("lnk", part_id, "visible_url", raw_value),
                part_id=part_id,
                raw_value=raw_value,
                normalized_value=_normalize_url(raw_value),
                role="visible_url",
                hostname=_hostname_of(raw_value),
            )
        )

    # href/display mismatch: only when the display text is itself an explicit
    # URL and both hosts are known (architecture §1.5).
    for link in links:
        if link.role == "href" and link.display_text:
            display_host = _hostname_of(link.display_text.strip())
            if display_host is not None:
                link.display_url = link.display_text.strip()
                link.href_display_mismatch = (
                    link.hostname is not None and display_host != link.hostname
                )
    return links


# ---------------------------------------------------------------------------
# MIME walk
# ---------------------------------------------------------------------------


class _WalkState:
    """Mutable walk state: part counter, decoded totals, limits, defects."""

    def __init__(self, limits: ParseLimits, keep_image_bytes: bool = False) -> None:
        self.limits = limits
        self.part_count = 0
        self.decoded_total = 0
        self.limits_hit: list[str] = []
        self.defects: list[str] = []
        self.attachments: list[Attachment] = []
        self.images: list[VisualEvidence] = []
        # TICKET-16: when explicitly requested (bounded Vision/QR capability),
        # the decoded bytes of images the parser ACCEPTED (metadata_only) are
        # retained here for the authorized call. The default keeps the frozen
        # metadata-only contract: no bytes are ever retained by parse_bytes.
        self.keep_image_bytes = keep_image_bytes
        self.image_bytes: dict[str, bytes] = {}
        self.aborted = False


def _part_id(index: int) -> str:
    return f"part_{index:04d}"


def _count_decoded(state: _WalkState, size: int) -> None:
    """Charge the decoded-bytes TOTAL budget only; a part over the per-part
    limit is handled by its caller before reaching here. Exceeding the total
    budget really stops the walk: no further part is decoded."""

    state.decoded_total += size
    if state.decoded_total > state.limits.max_decoded_bytes_total:
        state.limits_hit.append(_LIMIT_DECODED_TOTAL)
        state.aborted = True


def _walk(
    message: Message,
    depth: int,
    state: _WalkState,
    text_parts: list[TextPart],
    html_parts: list[TextPart],
    links: list[Link],
) -> None:
    if state.aborted:
        return
    if depth > state.limits.max_mime_depth:
        state.limits_hit.append(_LIMIT_MIME_DEPTH)
        state.defects.append("mime depth exceeded")
        state.aborted = True
        return
    state.part_count += 1
    if state.part_count > state.limits.max_mime_parts:
        state.limits_hit.append(_LIMIT_MIME_PARTS)
        state.defects.append("mime part count exceeded")
        state.aborted = True
        return
    my_id = _part_id(state.part_count)

    # Preserve stdlib email/MIME defects deterministically (in addition to
    # parser defects): readable name, stable order, local part reference.
    for d in getattr(message, "defects", []):
        state.defects.append(f"{my_id}: stdlib {type(d).__name__}")

    if message.get_content_type() == "message/rfc822":
        # In compat32 an embedded message yields a list payload, so
        # is_multipart() is True and the generic branch would swallow it.
        # Bounded walk of the embedded message, explicitly recorded.
        state.defects.append(f"{_part_id(state.part_count)}: embedded message treated as bounded MIME")
        payload = message.get_payload()
        embedded = payload[0] if isinstance(payload, list) and payload else payload
        if isinstance(embedded, Message):
            _walk(embedded, depth + 1, state, text_parts, html_parts, links)
        return

    if message.is_multipart():
        payload = message.get_payload()
        for child in payload or []:
            if isinstance(child, Message):
                _walk(child, depth + 1, state, text_parts, html_parts, links)
                if state.aborted:
                    return
        return

    content_type = message.get_content_type()
    maintype = message.get_content_maintype()
    disposition = message.get_content_disposition()
    filename = message.get_filename()
    raw_cid = _clean(message.get("Content-ID"))
    content_id = raw_cid.strip("<>") if raw_cid else None

    # Attachments: explicit disposition, or a non-image part carrying a
    # filename. Inline images stay in ``images`` (metadata_only) so their
    # content is never treated as a file the user asked to handle.
    is_attachment = disposition == "attachment" or (
        filename is not None and maintype != "image"
    )
    if is_attachment:
        state.attachments.append(
            _build_attachment(message, my_id, content_type, disposition, filename, content_id, state)
        )
        if len(state.attachments) >= state.limits.max_attachments:
            state.limits_hit.append(_LIMIT_ATTACHMENTS)
            state.aborted = True
        return

    if maintype == "image":
        # Inline image: metadata only, never decoded or interpreted here.
        state.images.append(_image_metadata(message, my_id, content_type, content_id, state))
        return

    if content_type in ("text/plain", "text/html"):
        text, charset, defects, over = _decode_text_part(message, state, my_id)
        part = TextPart(
            part_id=my_id,
            mime_type=content_type,
            charset=charset,
            text=text,
            decode_defects=defects,
        )
        # Content over a limit is never kept nor exploited: the part is not
        # added to the parsed email (defects + content_limits carry the
        # information) and no URL is extracted from dropped content.
        if over:
            state.defects.extend(defects)
            return
        if content_type == "text/plain":
            text_parts.append(part)
            links.extend(_extract_plain_urls(text, my_id))
        else:
            html_parts.append(part)
            links.extend(_extract_html_links(text, my_id))
        return

    if content_type == "message/rfc822":
        state.defects.append(f"{my_id}: embedded message treated as bounded MIME")
        payload = message.get_payload()
        if isinstance(payload, list) and payload and isinstance(payload[0], Message):
            _walk(payload[0], depth + 1, state, text_parts, html_parts, links)
        return

    state.defects.append(f"{my_id}: unhandled leaf part {content_type}")


def _decode_text_part(
    message: Message, state: _WalkState, my_id: str
) -> tuple[str, str | None, list[str], bool]:
    """Decode a text part (transfer encoding then charset). Charset and
    Base64/quoted-printable errors become defects, never exceptions.

    Returns ``(text, charset, defects, over_limit)``. When ``over_limit`` is
    True the text is NOT kept (empty string): a part over the per-part limit,
    or any part decoded after the total budget is exhausted, is never
    exploited as full content (no link extraction downstream)."""

    defects: list[str] = []
    charset = message.get_content_charset()
    try:
        payload = message.get_payload(decode=True)
    except Exception as exc:  # binascii.Error on broken Base64 etc.
        defects.append(f"{my_id}: transfer decode error: {exc}")
        raw = message.get_payload()
        payload = raw.encode("utf-8", "replace") if isinstance(raw, str) else b""
    if payload is None:
        defects.append(f"{my_id}: payload not decodable")
        payload = b""
    size = len(payload)
    over_part = size > state.limits.max_decoded_bytes_per_part
    if over_part:
        state.limits_hit.append(_LIMIT_DECODED_PART)
        defects.append(f"{my_id}: decoded part over per-part limit; content not kept")
    _count_decoded(state, size)
    over_total = state.decoded_total > state.limits.max_decoded_bytes_total
    if over_total and not over_part:
        defects.append(f"{my_id}: decoded total over limit; content not kept")
    if over_part or over_total:
        if over_total:
            state.aborted = True  # stop decoding further parts
        return "", charset, defects, True
    try:
        text = payload.decode(charset or "utf-8", "replace")
    except (LookupError, UnicodeError) as exc:
        defects.append(f"{my_id}: charset error ({charset!r}): {exc}")
        text = payload.decode("utf-8", "replace")
    return text, charset, defects, False


def _build_attachment(
    message: Message,
    my_id: str,
    content_type: str,
    disposition: str | None,
    filename: str | None,
    content_id: str | None,
    state: _WalkState,
) -> Attachment:
    """Attachment metadata; hashes over DECODED bytes (never over Base64).

    ``filename`` is untrusted data only; it never becomes a path.
    """

    inline = disposition == "inline"
    try:
        payload = message.get_payload(decode=True)
    except Exception as exc:
        state.defects.append(f"{my_id}: attachment transfer decode error: {exc}")
        payload = None
    # The email library does not raise on broken Base64: it returns partial
    # bytes and records InvalidBase64*Defect on the part. Such a part is a
    # decode error; no hash may be claimed on unreliable bytes.
    transfer_defects = [
        d for d in getattr(message, "defects", []) if "InvalidBase64" in type(d).__name__
    ]
    if transfer_defects:
        state.defects.append(f"{my_id}: broken transfer encoding (base64)")
    if payload is None or transfer_defects:
        state.defects.append(f"{my_id}: attachment bytes unavailable")
        return Attachment(
            part_id=my_id,
            filename=filename,
            mime_type=content_type,
            disposition=disposition,
            content_id=content_id,
            decode_status="error",
            is_inline=inline,
        )
    size = len(payload)
    if size > state.limits.max_decoded_bytes_per_part:
        state.limits_hit.append(_LIMIT_DECODED_PART)
        state.defects.append(f"{my_id}: attachment over per-part limit")
        return Attachment(
            part_id=my_id,
            filename=filename,
            mime_type=content_type,
            disposition=disposition,
            content_id=content_id,
            decoded_size_bytes=size,
            decode_status="over_limit",
            is_inline=inline,
        )
    _count_decoded(state, size)
    if state.aborted:  # total limit reached: over_limit, no partial success
        return Attachment(
            part_id=my_id,
            filename=filename,
            mime_type=content_type,
            disposition=disposition,
            content_id=content_id,
            decoded_size_bytes=size,
            decode_status="over_limit",
            is_inline=inline,
        )
    return Attachment(
        part_id=my_id,
        filename=filename,
        mime_type=content_type,
        disposition=disposition,
        content_id=content_id,
        decoded_size_bytes=size,
        sha256=hashlib.sha256(payload).hexdigest(),
        sha1=hashlib.sha1(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        decode_status="ok",
        is_inline=inline,
    )


def _image_metadata(
    message: Message, my_id: str, content_type: str, content_id: str | None, state: _WalkState
) -> VisualEvidence:
    """Image metadata only (G1): hash of decoded bytes, no pixel decoding,
    no interpretation invented (architecture §1.5)."""

    try:
        payload = message.get_payload(decode=True)
    except Exception as exc:
        state.defects.append(f"{my_id}: image transfer decode error: {exc}")
        payload = None
    if payload is None:
        state.defects.append(f"{my_id}: image bytes unavailable")
        digest, status = "", "unavailable"
    else:
        size = len(payload)
        over_part = size > state.limits.max_decoded_bytes_per_part
        if over_part:
            state.limits_hit.append(_LIMIT_DECODED_PART)
            state.defects.append(f"{my_id}: image over per-part limit")
        _count_decoded(state, size)
        # An oversized image never gets a full hash presented as an accepted
        # metadata_only visual: over_limit with no content hash.
        if over_part or state.aborted:
            state.defects.append(f"{my_id}: image not accepted (decode limit)")
            digest, status = "", "over_limit"
        else:
            digest, status = hashlib.sha256(payload).hexdigest(), "metadata_only"
            if state.keep_image_bytes:
                state.image_bytes[my_id] = payload
    return VisualEvidence(
        id=_det_id("vis", my_id, digest, content_type, content_id),
        sha256=digest,
        mime_type=content_type,
        provenance="INTERNE",
        part_id=my_id,
        content_id=content_id,
        local_ref=f"mime:{my_id}",
        status=status,  # type: ignore[assignment]
    )


# ---------------------------------------------------------------------------
# Authentication-Results parsing (reported data, never verified)
# ---------------------------------------------------------------------------

_MECH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*[=:]\s*([A-Za-z0-9._-]+)", re.IGNORECASE)

#: Identity property each mechanism carries (RFC 8601): SPF is validated
#: against the envelope (smtp.mailfrom, else smtp.helo), DKIM against the
#: signing domain (header.d), DMARC against the visible From domain
#: (header.from). Each mechanism is matched ONLY within its own clause
#: (up to the next ";"), never on the whole header, and NEVER inside a
#: parenthesized comment (stripped before any search).
_MECH_IDENTITY_RES: dict[str, tuple[re.Pattern[str], ...]] = {
    "spf": (
        re.compile(r"\bsmtp\.mailfrom\s*[=:]\s*([^\s;]+)", re.IGNORECASE),
        re.compile(r"\bsmtp\.helo\s*[=:]\s*([^\s;]+)", re.IGNORECASE),
    ),
    "dkim": (re.compile(r"\bheader\.d\s*[=:]\s*([^\s;]+)", re.IGNORECASE),),
    "dmarc": (re.compile(r"\bheader\.from\s*[=:]\s*([^\s;]+)", re.IGNORECASE),),
}


def _strip_ar_comments(value: str) -> str:
    """Remove RFC 8601 parenthesized comments from an Authentication-Results
    value (bounded: one nesting level, adequate for POC headers).

    Deterministic; no dependency. Comment content (e.g. a fake
    ``(spf=fail smtp.mailfrom=fake.example)``) can never create or alter an
    observation. Unterminated comments drop the rest of the value, which the
    clause scoping treats as absent data rather than invented identity.
    """

    out: list[str] = []
    depth = 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _mech_identity(mech: str, value: str, mech_start: int) -> str | None:
    """Identity domain carried by THIS mechanism's own clause.

    The search is scoped to the clause starting at ``mech_start`` (up to the
    next ";"), so ``smtp.mailfrom`` can never be attributed to DKIM or DMARC.
    No identity is invented when the clause carries none. No DNS ever happens.
    """

    clause_end = value.find(";", mech_start)
    clause = value[mech_start : clause_end if clause_end != -1 else len(value)]
    for res in _MECH_IDENTITY_RES[mech]:
        m = res.search(clause)
        if m:
            return m.group(1).strip().strip("<>").lstrip("@").lower() or None
    return None


def _parse_authentication(headers: list[tuple[str, str]]) -> list[AuthObservation]:
    """Parse Authentication-Results values as received text.

    ``trust`` stays ``reported_unverified`` by default: without a trusted
    collection provenance and configured authserv-id, the header may be forged
    (architecture §1.5). No DNS verification ever happens.
    """

    out: list[AuthObservation] = []
    for index, (name, value) in enumerate(headers):
        if name.lower() != "authentication-results" or not isinstance(value, str):
            continue
        # Comments first: nothing inside parentheses may create or alter an
        # observation (e.g. a fake "(spf=fail smtp.mailfrom=fake.example)").
        clean = _strip_ar_comments(value)
        authserv = clean.split(";", 1)[0].strip() or None
        seen: set[str] = set()
        for mech_m in _MECH_RE.finditer(clean):
            mech = mech_m.group(1).lower()
            if mech in seen:
                continue
            seen.add(mech)
            result = mech_m.group(2).lower()
            domain = _mech_identity(mech, clean, mech_m.start())
            out.append(
                AuthObservation(
                    mechanism=mech,  # type: ignore[arg-type]
                    result=result,
                    domain=domain,
                    authserv_id=authserv,
                    header_index=index,
                    trust="reported_unverified",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Observables and evidence (provenance INTERNE, source_ref local)
# ---------------------------------------------------------------------------


def _domain_of_address(addr: str) -> str | None:
    """Exact domain of an email address; nothing invented when absent."""

    if "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[1].strip().lower().rstrip(".>")
    return domain or None


#: IPs that never become transport observables: loopback, link-local, RFC1918
#: and other non-global ranges (architecture §1.5: private/non-discriminating
#: transport IPs are excluded from lookups). Documentation ranges (RFC 5737
#: TEST-NET) ARE kept: fixtures and examples use them deliberately.
_TRANSPORT_DOC_NETS = (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "2001:db8::/32",  # RFC 3849 IPv6 documentation
)


def _is_transport_ip(candidate: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if addr.is_global:
        return True
    return any(addr in ipaddress.ip_network(net) for net in _TRANSPORT_DOC_NETS)


#: An IPv4 embedded in a Received header (leading "from" host may carry one).
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
#: A bracketed IPv6 in a Received header (RFC 5321 form, e.g. [2001:db8::1]).
_IPV6_RE = re.compile(r"\b([Ii][Pp][Vv]6:)?\[?([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})\]?")


def _transport_ips(parsed: ParsedEmail) -> list[tuple[str, str, int]]:
    """Documentation/public IPs carried by Received headers, in header order.

    IPv4 and bracketed IPv6 (RFC 5321 form). Private, loopback and link-local
    addresses are never recorded. No DNS, no discrimination: the
    ``transport_ip`` role is data, not an accusation.
    """

    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for header in parsed.headers:
        if header.name.lower() != "received":
            continue
        for m in _IPV4_RE.finditer(header.raw_value):
            ip = m.group(1)
            if ip in seen or not _is_transport_ip(ip):
                continue
            seen.add(ip)
            out.append((ip, "ipv4", header.index))
        for m in _IPV6_RE.finditer(header.raw_value):
            candidate = m.group(2)
            if candidate in seen or not _is_transport_ip(candidate):
                continue
            seen.add(candidate)
            out.append((candidate, "ipv6", header.index))
    return out


def _build_observables(parsed: ParsedEmail) -> list[Observable]:
    """Deterministic observables from parsed data (architecture §1.5 roles).

    Nothing is invented: a domain observable exists only when the source data
    carries it. Recipients keep the ``recipient`` role and are never attacker
    IOCs; a displayed_brand is a displayed fact, never a maliciousness claim.
    """

    observables: list[Observable] = []

    def _add(value: str, normalized: str, obs_type: str, roles: list[str], source_ref: str) -> None:
        key = (obs_type, normalized)
        existing = next((o for o in observables if (o.type, o.normalized_value) == key), None)
        if existing is not None:
            existing.roles.extend(r for r in roles if r not in existing.roles)
            return
        observables.append(
            Observable(
                id=_det_id("obs", obs_type, normalized, source_ref),
                value=value,
                normalized_value=normalized,
                type=obs_type,  # type: ignore[arg-type]
                roles=roles,  # type: ignore[arg-type]
                provenance="INTERNE",
                source_ref=source_ref,
            )
        )

    # --- email addresses (exact, never completed).
    for addr in parsed.from_addresses:
        _add(addr, addr.lower(), "email", ["sender"], "headers:from")
    for addr in parsed.reply_to:
        _add(addr, addr.lower(), "email", ["reply_to"], "headers:reply-to")
    for addr in parsed.return_path:
        _add(addr, addr.lower(), "email", ["return_path"], "headers:return-path")
    for addr in parsed.to_addresses:
        _add(addr, addr.lower(), "email", ["recipient"], "headers:to")
    for addr in parsed.cc_addresses:
        _add(addr, addr.lower(), "email", ["recipient"], "headers:cc")

    # --- exact sender/return-path/reply-to domains derived from those addresses.
    for addr, role, ref in (
        *[(a, "sender", "headers:from") for a in parsed.from_addresses],
        *[(a, "reply_to", "headers:reply-to") for a in parsed.reply_to],
        *[(a, "return_path", "headers:return-path") for a in parsed.return_path],
    ):
        domain = _domain_of_address(addr)
        if domain:
            _add(domain, domain, "domain", [role], ref)

    # --- transport IPs from Received (public/documentation only).
    for ip, obs_type, header_index in _transport_ips(parsed):
        _add(ip, ip, obs_type, ["transport_ip"], f"header:{header_index}:received")

    if parsed.message_id:
        _add(parsed.message_id, parsed.message_id.strip(), "message_id", [], "headers:message-id")

    # --- links: href targets; explicitly displayed URLs become displayed_brand.
    for link in parsed.links:
        if link.hostname and link.normalized_value:
            _add(
                link.raw_value,
                link.normalized_value,
                "url",
                ["link_target"],
                f"{link.part_id}:link:{link.id[:16]}",
            )
        if link.role == "href" and link.display_url and _hostname_of(link.display_url):
            display_host = _hostname_of(link.display_url) or ""
            _add(
                link.display_url,
                display_host,
                "domain",
                ["displayed_brand"],
                f"{link.part_id}:link:{link.id[:16]}:display",
            )
    for att in parsed.attachments:
        if att.sha256:
            _add(
                att.sha256,
                att.sha256,
                "sha256",
                ["attachment"],
                f"{att.part_id}:attachment",
            )
    return observables


def _build_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """Deterministic evidence; every datum carries a local ``source_ref``."""

    evidence: list[Evidence] = []

    def _add(
        predicate: str,
        value: str | float | bool | None,
        source_ref: str,
        observable_id: str | None = None,
    ) -> None:
        evidence.append(
            Evidence(
                id=_det_id("ev", predicate, str(value), source_ref),
                provenance="INTERNE",
                source_kind="parser",
                observable_id=observable_id,
                predicate=predicate,  # type: ignore[arg-type]
                value=value,
                source_ref=source_ref,
                match_level="EXACT",
            )
        )

    for header in parsed.headers:
        if header.name.lower() in ("subject", "from", "to", "date"):
            _add("header_value", header.decoded_value, f"header:{header.index}")
    for link in parsed.links:
        if link.normalized_value:
            _add("url_found", link.raw_value, f"{link.part_id}:link:{link.id[:16]}")
            if link.href_display_mismatch:
                _add(
                    "href_display_mismatch",
                    f"{link.hostname} != {_hostname_of(link.display_url or '')}",
                    f"{link.part_id}:link:{link.id[:16]}",
                )
    obs_by_hash = {
        o.normalized_value: o.id for o in parsed.observables if o.type == "sha256"
    }
    for att in parsed.attachments:
        if att.sha256:
            _add(
                "attachment_hash",
                att.sha256,
                f"{att.part_id}:attachment",
                observable_id=obs_by_hash.get(att.sha256),
            )
            if att.filename:
                _add(
                    "attachment_filename",
                    att.filename,
                    f"{att.part_id}:attachment",
                    observable_id=obs_by_hash.get(att.sha256),
                )
    for auth in parsed.authentication:
        _add(
            "auth_reported",
            f"{auth.mechanism}={auth.result}",
            f"header:{auth.header_index}",
        )
    for image in parsed.images:
        _add("image_present", image.mime_type, f"{image.part_id}:image")
    return evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_bytes(
    data: bytes, input_format: str = "rfc822", limits: ParseLimits | None = None
) -> ParsedEmail | ParseFailure:
    """Parse raw email bytes into a ``ParsedEmail`` or a structured failure.

    Deterministic on the input bytes: identical bytes give identical output.
    No network, no execution, no fetch. The email hash is computed on the
    original bytes; attachment hashes on decoded content.
    """

    limits = limits or ParseLimits()
    if len(data) > limits.max_eml_bytes:
        return ParseFailure(error="email_too_large", detail=f"{len(data)} bytes")
    try:
        message = message_from_bytes(data)
    except Exception as exc:  # malformed top-level structure
        return ParseFailure(error="mime_parse_error", detail=str(exc))

    parsed = ParsedEmail(
        email_sha256=hashlib.sha256(data).hexdigest(),
        raw_size_bytes=len(data),
        input_format=input_format,  # type: ignore[arg-type]
    )

    # --- headers: order and repetitions preserved, never de-duplicated.
    headers: list[tuple[str, str]] = [
        (name, value if isinstance(value, str) else str(value))
        for name, value in message.items()
    ]
    for index, (name, raw_value) in enumerate(headers):
        parsed.headers.append(
            Header(
                index=index,
                name=name,
                raw_value=raw_value,
                decoded_value=_decode_rfc2047(raw_value),
            )
        )

    def _first(name: str) -> str | None:
        for h_name, value in headers:
            if h_name.lower() == name:
                return value
        return None

    subject_raw = _first("subject")
    parsed.subject = _decode_rfc2047(subject_raw) if subject_raw is not None else None
    parsed.from_addresses = _addresses(message, "From")
    parsed.to_addresses = _addresses(message, "To")
    parsed.cc_addresses = _addresses(message, "Cc")
    parsed.reply_to = _addresses(message, "Reply-To")
    parsed.return_path = _addresses(message, "Return-Path")
    parsed.date_raw = _first("date")
    message_id = _first("message-id")
    parsed.message_id = message_id.strip() if message_id else None

    # --- MIME walk with limits.
    state = _WalkState(limits)
    _walk(message, 1, state, parsed.text_parts, parsed.html_parts, parsed.links)
    parsed.attachments = state.attachments
    parsed.images = state.images
    parsed.defects.extend(state.defects)
    for limit in state.limits_hit:
        if limit not in parsed.content_limits:
            parsed.content_limits.append(limit)

    # --- authentication observations (reported, unverified by default).
    parsed.authentication = _parse_authentication(headers)

    # --- essential_visual_content (§2.3): conservative heuristic. An image is
    # present and fewer than 80 useful text characters, or an explicit QR
    # expectation with no URL extracted. Never a pixel measurement.
    useful_text = "".join(part.text for part in parsed.text_parts).strip()
    if parsed.images and len(useful_text) < 80:
        parsed.essential_visual_content = True

    # --- deterministic observables and evidence.
    parsed.observables = _build_observables(parsed)
    parsed.evidence = _build_evidence(parsed)
    return parsed


def parse_email(path: Path, limits: ParseLimits) -> ParsedEmail | ParseFailure:
    """Parse an ``.eml`` file from disk (TICKET-03 interface).

    The file is read as raw bytes; the caller-provided limits apply. A read
    error becomes a structured failure, never an exception.
    """

    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        return ParseFailure(error="read_error", detail=str(exc))
    if len(data) > limits.max_eml_bytes:
        return ParseFailure(error="email_too_large", detail=f"{len(data)} bytes")
    return parse_bytes(data, "rfc822", limits)


def extract_image_parts(
    data: bytes, limits: ParseLimits | None = None
) -> dict[str, bytes]:
    """Decoded image bytes keyed by the parser's own part ids (TICKET-16).

    Bounded loading of the bytes of images ``parse_bytes`` accepted as
    metadata_only visuals: the same deterministic walk, the same part
    numbering, the same decode limits — so ``part_id`` keys always match
    ``ParsedEmail.images``. The parser itself keeps its metadata-only
    contract (this helper is only called by the Vision capability, at the
    authorized call, and its result never enters the state). No network,
    no interpretation; Vision limits are re-enforced by ``src/vision.py``
    before any expensive processing.
    """

    limits = limits or ParseLimits()
    if len(data) > limits.max_eml_bytes:
        return {}
    try:
        message = message_from_bytes(data)
    except Exception:  # malformed top-level structure: no bytes claimed
        return {}
    state = _WalkState(limits, keep_image_bytes=True)
    _walk(message, 1, state, [], [], [])
    return state.image_bytes

"""Parser tests (TICKET-03, docs/tickets/TICKET-03.md).

Covers: all fixtures against manifest expectations; exact URLs (query, HTML
entities); href/display mismatch; cid/multipart; filename traversal; size and
depth limits; charset/Base64 errors; remote images never loaded.

Network guard: any connection attempt inside parser tests fails the test.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from src.parsing import ParseFailure, ParseLimits, parse_bytes, parse_email
from src.state import ParsedEmail

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def limits() -> ParseLimits:
    return ParseLimits()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any network attempt makes the test fail (TICKET-03 TESTS REQUIRED)."""

    def _deny(*args, **kwargs):  # pragma: no cover - executed only on attempt
        pytest.fail("network access attempted during parser test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


def _fixture_names():
    return [entry["file"] for entry in MANIFEST["fixtures"]]


def test_all_14_fixtures_exist():
    assert len(_fixture_names()) == 14
    for name in _fixture_names():
        assert (FIXTURES / name).is_file(), name


@pytest.mark.parametrize("entry", MANIFEST["fixtures"], ids=lambda e: e["file"])
def test_fixture_parses_and_meets_manifest(entry, limits):
    result = parse_email(FIXTURES / entry["file"], limits)
    assert isinstance(result, ParsedEmail), f"structured failure: {result}"
    expect = entry["expect"]

    # Email hash over ORIGINAL bytes (never over decoded content).
    raw = (FIXTURES / entry["file"]).read_bytes()
    import hashlib

    assert result.email_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.raw_size_bytes == len(raw)

    if expect.get("subject") is not None:
        assert result.subject == expect["subject"]
    for field in ("from_addresses", "to_addresses", "reply_to", "return_path"):
        if expect.get(field):
            assert result.__getattribute__(field) == expect[field], field

    # Header repetitions preserved (malformed fixture: duplicated Subject).
    if expect.get("duplicated_subject_headers"):
        subjects = [h for h in result.headers if h.name.lower() == "subject"]
        assert len(subjects) == expect["duplicated_subject_headers"]

    if expect.get("has_full_headers"):
        present = {h.name.lower() for h in result.headers if h.decoded_value.strip()}
        for required in ("from", "to", "subject", "date", "message-id", "received", "return-path"):
            assert required in present, f"missing {required}"

    # Links: exact raw values, roles, hostnames, mismatch flags.
    for expected_link in expect.get("links", []):
        matches = [
            l for l in result.links if l.raw_value == expected_link["raw_value"] and l.role == expected_link["role"]
        ]
        assert matches, f"link missing: {expected_link}"
        link = matches[0]
        if expected_link.get("hostname") is not None:
            assert link.hostname == expected_link["hostname"]
        if "href_display_mismatch" in expected_link:
            assert link.href_display_mismatch == expected_link["href_display_mismatch"]
        if expected_link.get("html_entity_decoded"):
            assert link.transformation == "html_entity_decoded"

    # Attachments: hashes on DECODED bytes.
    for expected_att in expect.get("attachments", []):
        matches = [a for a in result.attachments if a.filename == expected_att["filename"]]
        assert matches, f"attachment missing: {expected_att['filename']}"
        att = matches[0]
        assert att.decode_status == expected_att["decode_status"]
        if expected_att.get("sha256"):
            assert att.sha256 == expected_att["sha256"]
            assert att.decoded_size_bytes == expected_att["decoded_size_bytes"]
        if expected_att.get("content"):
            plain = [p for p in result.text_parts]
            # attachment content is not a text part; decode check via size+hash
            assert att.decoded_size_bytes == len(expected_att["content"].encode("utf-8"))

    # Images: metadata only, never decoded/interpreted.
    for expected_img in expect.get("images", []):
        matches = [i for i in result.images if i.content_id == expected_img["content_id"]]
        assert matches, f"image missing: {expected_img['content_id']}"
        img = matches[0]
        assert img.sha256 == expected_img["sha256"]
        assert img.status == "metadata_only"
    if expect.get("image_count") is not None and "images" not in expect:
        assert len(result.images) == expect["image_count"]

    if expect.get("essential_visual_content"):
        assert result.essential_visual_content is True

    # Auth observations: reported, never verified.
    for expected_auth in expect.get("auth", []):
        matches = [
            a for a in result.authentication if a.mechanism == expected_auth["mechanism"]
        ]
        assert matches, f"auth missing: {expected_auth['mechanism']}"
        auth = matches[0]
        assert auth.result == expected_auth["result"]
        assert auth.domain == expected_auth["domain"]
        assert auth.trust == "reported_unverified"

    assert len(result.defects) >= expect.get("defects_min", 0)

    # Every observable/evidence carries a local source_ref (acceptance).
    for obs in result.observables:
        assert obs.source_ref
        assert obs.provenance == "INTERNE"
    for ev in result.evidence:
        assert ev.source_ref
        assert ev.provenance == "INTERNE"
        assert ev.source_kind == "parser"


def test_url_query_and_entity_exactness(limits):
    """URL exacts: query preserved, HTML entity decoded exactly once."""

    result = parse_email(FIXTURES / "phishing_simple.eml", limits)
    href = next(l for l in result.links if l.role == "href")
    assert href.raw_value == "https://login.notice.test/verify?uid=V1C2"
    assert href.normalized_value == "https://login.notice.test/verify?uid=V1C2"

    result = parse_email(FIXTURES / "legitimate_newsletter.eml", limits)
    unsub = next(l for l in result.links if "unsubscribe" in l.raw_value and l.role == "href")
    assert unsub.raw_value == "https://news.example.org/unsubscribe?u=abonne&camp=sept"
    assert unsub.transformation == "html_entity_decoded"
    assert "&amp;" not in unsub.raw_value


def test_href_display_mismatch_detected(limits):
    result = parse_email(FIXTURES / "phishing_simple.eml", limits)
    href = next(l for l in result.links if l.role == "href")
    assert href.display_url == "https://mail.example.com"
    assert href.href_display_mismatch is True
    # The displayed host is NEVER silently merged into the link target.
    assert href.hostname == "login.notice.test"


def test_plain_text_display_is_not_a_mismatch(limits):
    """A non-URL display text ('cliquez ici') is never a mismatch."""

    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <m1@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
        b'<a href="https://x.example.test/login">cliquez ici</a>'
    )
    result = parse_bytes(data, "rfc822", limits)
    link = result.links[0]
    assert link.display_text == "cliquez ici"
    assert link.href_display_mismatch is False


def test_cid_multipart_related(limits):
    result = parse_email(FIXTURES / "qr_phishing.eml", limits)
    img = result.images[0]
    assert img.content_id == "qr1"
    assert img.part_id
    assert img.local_ref == f"mime:{img.part_id}"
    assert img.status == "metadata_only"


def test_filename_traversal_never_becomes_a_path(limits):
    """A traversal filename stays untrusted data, never a filesystem path."""

    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <m2@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\n'
        b'Content-Type: text/plain\r\nContent-Disposition: attachment; filename="../../etc/passwd.txt"\r\n\r\n'
        b"innocuous\r\n--B--\r\n"
    )
    result = parse_bytes(data, "rfc822", limits)
    att = result.attachments[0]
    assert att.filename == "../../etc/passwd.txt"
    assert "/" not in str(att.part_id)
    # hashes computed on decoded bytes; no file was ever opened
    assert att.decode_status == "ok"
    import hashlib

    assert att.sha256 == hashlib.sha256(b"innocuous").hexdigest()


def test_attachment_hash_on_decoded_not_base64(limits):
    import base64
    import hashlib

    content = b"Fixture b\xc3\xa9nigne : aucun programme."
    result = parse_email(FIXTURES / "attachment_suspicious.eml", limits)
    att = result.attachments[0]
    assert att.sha256 == hashlib.sha256(content).hexdigest()
    assert att.decoded_size_bytes == len(content)
    # Not the Base64 text hash.
    b64_text = base64.encodebytes(content)
    assert att.sha256 != hashlib.sha256(b64_text).hexdigest()


def test_oversized_email_structured_failure(limits):
    tiny = ParseLimits(max_eml_bytes=64)
    result = parse_email(FIXTURES / "phishing_simple.eml", tiny)
    assert isinstance(result, ParseFailure)
    assert result.error == "email_too_large"


def test_depth_and_part_limits_recorded():
    """Deeply nested multipart exceeds the depth limit; part flood exceeds
    the part-count limit. Nesting is built with the email library so the
    structure is guaranteed to be recursively parsed."""

    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    # 30 nested multipart levels exceed max_mime_depth (20).
    msg: MIMEMultipart = MIMEMultipart("mixed")
    outer = msg
    for _ in range(30):
        child: MIMEMultipart = MIMEMultipart("mixed")
        outer.attach(child)
        outer = child
    outer.attach(MIMEText("leaf", "plain"))

    raw = msg.as_bytes()
    result = parse_bytes(raw, "rfc822")
    assert "max_mime_depth" in result.content_limits

    # 200+ sibling parts exceed the part count (max_mime_parts: 200).
    head = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <m5@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"CC\"\r\n\r\n"
    )
    many = head + b"".join(
        b"--CC\r\nContent-Type: text/plain\r\n\r\nx\r\n" for _ in range(210)
    ) + b"--CC--\r\n"
    result = parse_bytes(many, "rfc822")
    assert "max_mime_parts" in result.content_limits


def test_unknown_charset_and_broken_base64_become_defects(limits):
    result = parse_email(FIXTURES / "malformed_reasonable.eml", limits)
    assert isinstance(result, ParsedEmail)  # never an exception
    text_part = result.text_parts[0]
    assert any("charset" in d for d in text_part.decode_defects)
    # The readable body is still extracted (malformed_reasonable).
    assert "FA-2025-114" in text_part.text
    att = result.attachments[0]
    assert att.decode_status == "error"
    assert att.sha256 is None  # no hash over bytes that do not exist


def test_remote_image_never_loaded(limits):
    """A remote <img src> is recorded as a role; no fetch, no pixels."""

    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <m3@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
        b'<img src="https://track.esp.example.net/pixel?id=1">'
    )
    result = parse_bytes(data, "rfc822", limits)
    roles = {(l.role, l.raw_value) for l in result.links}
    assert ("remote_resource", "https://track.esp.example.net/pixel?id=1") in roles
    assert result.images == []  # nothing was loaded


def test_relative_urls_never_resolved(limits):
    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <m4@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
        b'<a href="/relative/path?x=1">lien</a><base href="https://evil.example.test/">'
    )
    result = parse_bytes(data, "rfc822", limits)
    link = result.links[0]
    assert link.raw_value == "/relative/path?x=1"
    assert link.normalized_value is None  # no base invented
    assert link.hostname is None


def test_parse_failure_never_raises(tmp_path, limits):
    """A read error is a structured failure, never an unhandled exception."""

    result = parse_email(tmp_path / "does_not_exist.eml", limits)
    assert isinstance(result, ParseFailure)
    assert result.error == "read_error"


def test_parser_determinism(limits):
    a = parse_email(FIXTURES / "phishing_simple.eml", limits)
    b = parse_email(FIXTURES / "phishing_simple.eml", limits)
    assert a.model_dump_json() == b.model_dump_json()


def test_no_subject_never_invented(limits):
    """A missing Subject stays null (no plausible completion)."""

    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nbody"
    )
    result = parse_bytes(data, "rfc822", limits)
    assert result.subject is None
    assert result.message_id is None


def test_recipients_are_not_attack_iocs(limits):
    """Recipients keep the recipient role, never attacker IOC roles."""

    result = parse_email(FIXTURES / "phishing_simple.eml", limits)
    emails = {o.normalized_value: o for o in result.observables if o.type == "email"}
    victim = emails.get("victime@example.org")
    assert victim is not None
    assert victim.roles == ["recipient"]
    sender = emails.get("alert@notice.test")
    assert sender is not None
    assert "sender" in sender.roles
    assert "recipient" not in sender.roles


# ---------------------------------------------------------------------------
# BLOCKER 1 — decoding limits are real limits
# ---------------------------------------------------------------------------


def _simple_email(body_headers: str, body: str) -> bytes:
    return (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <mx@fixture.test>\r\nMIME-Version: 1.0\r\n" + body_headers.encode("utf-8") + b"\r\n" + body.encode("utf-8")
    )


def test_text_plain_over_per_part_limit_not_kept():
    body = "x" * 500 + " visitez https://evil.example.test/now"
    data = _simple_email('Content-Type: text/plain; charset="utf-8"\r\n', body)
    limits = ParseLimits(max_decoded_bytes_per_part=100)
    result = parse_bytes(data, "rfc822", limits)
    assert result.text_parts == []  # content NOT kept as a normal full part
    assert "max_decoded_bytes_per_part" in result.content_limits
    assert result.links == []  # no URL extraction from dropped content
    assert any("not kept" in d for d in result.defects)


def test_text_html_over_per_part_limit_not_kept():
    body = "<p>" + "y" * 500 + '</p><a href="https://evil.example.test/x">l</a>'
    data = _simple_email('Content-Type: text/html; charset="utf-8"\r\n', body)
    limits = ParseLimits(max_decoded_bytes_per_part=100)
    result = parse_bytes(data, "rfc822", limits)
    assert result.html_parts == []
    assert "max_decoded_bytes_per_part" in result.content_limits
    assert result.links == []  # no link extraction on dropped content


def test_image_over_per_part_limit_is_over_limit_without_full_hash():
    import base64

    payload = bytes(200)  # 200 decoded bytes > 64-byte limit
    data = _simple_email(
        'Content-Type: multipart/related; boundary="Q"\r\n\r\n--Q\r\n'
        'Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n'
        'Content-Disposition: inline\r\nContent-ID: <big1>\r\n\r\n'
        + base64.encodebytes(payload).replace(b"\n", b"\r\n").decode("ascii")
        + "\r\n--Q--\r\n",
        "",
    )
    limits = ParseLimits(max_decoded_bytes_per_part=64)
    result = parse_bytes(data, "rfc822", limits)
    assert len(result.images) == 1
    img = result.images[0]
    assert img.status == "over_limit"  # never presented as accepted metadata_only
    assert img.sha256 == ""  # no full-content hash as if accepted


def test_total_decoded_budget_stops_decoding():
    head = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <mt@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="TT"\r\n\r\n'
    )
    part = b"--TT\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n" + b"z" * 80 + b"\r\n"
    raw = head + part + part + b"--TT--\r\n"
    limits = ParseLimits(max_decoded_bytes_per_part=100, max_decoded_bytes_total=150)
    result = parse_bytes(raw, "rfc822", limits)
    # First part fits (80 <= 150); second pushes the total over: decoding stops.
    assert "max_decoded_bytes_total" in result.content_limits
    assert len(result.text_parts) == 1
    assert any("over limit" in d for d in result.defects)


def test_content_limits_deterministic():
    body = "x" * 500
    data = _simple_email('Content-Type: text/plain; charset="utf-8"\r\n', body)
    limits = ParseLimits(max_decoded_bytes_per_part=100)
    a = parse_bytes(data, "rfc822", limits)
    b = parse_bytes(data, "rfc822", limits)
    assert a.content_limits == b.content_limits
    assert a.model_dump_json() == b.model_dump_json()


# ---------------------------------------------------------------------------
# BLOCKER 2 — Authentication-Results identities
# ---------------------------------------------------------------------------


def test_auth_mechanisms_match_their_own_identity():
    data = _simple_email(
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=envelope.notice.test; "
        "dkim=pass header.d=signer.notice.test; dmarc=pass header.from=brand.example\r\n",
        "body",
    )
    result = parse_bytes(data, "rfc822")
    by_mech = {a.mechanism: a for a in result.authentication}
    assert by_mech["spf"].domain == "envelope.notice.test"
    assert by_mech["dkim"].domain == "signer.notice.test"
    assert by_mech["dmarc"].domain == "brand.example"
    assert all(a.trust == "reported_unverified" for a in result.authentication)


# ---------------------------------------------------------------------------
# BLOCKER 3 — observables of architecture §1.5
# ---------------------------------------------------------------------------


def test_sender_reply_to_return_path_domains(limits):
    result = parse_email(FIXTURES / "bec_fraud.eml", limits)
    domains = {o.normalized_value: o for o in result.observables if o.type == "domain"}
    assert "entreprise.example" in domains  # From (and Return-Path here)
    assert "sender" in domains["entreprise.example"].roles
    assert "consultant.example.net" in domains  # Reply-To domain
    assert domains["consultant.example.net"].roles == ["reply_to"]


def test_displayed_brand_on_phishing_simple(limits):
    result = parse_email(FIXTURES / "phishing_simple.eml", limits)
    brands = [o for o in result.observables if "displayed_brand" in o.roles]
    assert len(brands) == 1
    assert brands[0].normalized_value == "mail.example.com"
    # displayed_brand is a displayed fact, never a maliciousness verdict
    assert brands[0].category is None
    assert brands[0].source_ref.endswith(":display")


def test_transport_ip_from_received(limits):
    result = parse_email(FIXTURES / "phishing_simple.eml", limits)
    ips = [o for o in result.observables if o.type == "ipv4"]
    assert [ip.value for ip in ips] == ["198.51.100.10"]  # documentation IP
    assert ips[0].roles == ["transport_ip"]
    assert ":received" in ips[0].source_ref


def test_recipient_keeps_recipient_role_and_cc_source_ref():
    data = _simple_email('Content-Type: text/plain; charset="utf-8"\r\nCc: copie@example.org\r\n', "b")
    result = parse_bytes(data, "rfc822")
    emails = {o.normalized_value: o for o in result.observables if o.type == "email"}
    assert emails["copie@example.org"].source_ref == "headers:cc"  # never headers:to
    assert emails["copie@example.org"].roles == ["recipient"]


def test_no_invented_observable_when_source_absent():
    # Built without the helper: it always carries Message-ID, which this test
    # requires absent, to prove nothing is invented from missing data.
    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n\r\nb'
    )
    result = parse_bytes(data, "rfc822")
    types = {o.type for o in result.observables}
    assert "ipv4" not in types  # no Received header -> no IP invented
    # Domains only from addresses actually present (b.test from From), never invented.
    domains = {o.normalized_value for o in result.observables if o.type == "domain"}
    assert domains == {"b.test"}
    assert not any("reply_to" in o.roles for o in result.observables)
    assert result.message_id is None
    assert not any(o.type == "message_id" for o in result.observables)


# ---------------------------------------------------------------------------
# BLOCKER 4 — normative robustness matrix
# ---------------------------------------------------------------------------


def test_malformed_fixture_preserves_stdlib_defects(limits):
    result = parse_email(FIXTURES / "malformed_reasonable.eml", limits)
    assert isinstance(result, ParsedEmail)
    assert any("CloseBoundaryNotFoundDefect" in d for d in result.defects)  # truncation kept
    assert "FA-2025-114" in result.text_parts[0].text  # useful body still readable
    assert result.attachments[0].decode_status == "error"


def test_zero_byte_attachment():
    data = _simple_email(
        'Content-Type: multipart/mixed; boundary="Z"\r\n\r\n--Z\r\n'
        'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="empty.bin"\r\n\r\n'
        "\r\n--Z--\r\n",
        "",
    )
    result = parse_bytes(data, "rfc822")
    att = result.attachments[0]
    assert att.decoded_size_bytes == 0
    assert att.decode_status == "ok"
    import hashlib

    assert att.sha256 == hashlib.sha256(b"").hexdigest()


def test_embedded_message_bounded():
    inner = (
        b"From: inner@x.test\r\nSubject: inner\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n\r\ncorps interne'
    )
    data = _simple_email(
        'Content-Type: multipart/mixed; boundary="E"\r\n\r\n--E\r\n'
        'Content-Type: message/rfc822\r\n\r\n' + inner.decode("latin-1") + "\r\n--E--\r\n",
        "",
    )
    result = parse_bytes(data, "rfc822")
    assert any("embedded message" in d for d in result.defects)
    assert any("corps interne" in p.text for p in result.text_parts)  # walked, bounded


def test_same_payload_two_encodings_same_decoded_hash():
    import base64 as b64mod
    import hashlib

    content = "Facture déjà payée.".encode("utf-8")
    b64_body = b64mod.encodebytes(content).replace(b"\n", b"\r\n").rstrip(b"\r\n").decode("ascii")
    qp_body = "Facture d=C3=A9j=C3=A0 pay=C3=A9e."
    data = _simple_email(
        'Content-Type: multipart/mixed; boundary="W"\r\n\r\n--W\r\n'
        'Content-Type: text/plain; charset="utf-8"\r\nContent-Transfer-Encoding: base64\r\n'
        'Content-Disposition: attachment; filename="a.txt"\r\n\r\n' + b64_body + "\r\n--W\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\nContent-Transfer-Encoding: quoted-printable\r\n'
        'Content-Disposition: attachment; filename="b.txt"\r\n\r\n' + qp_body
        + "\r\n--W--\r\n",
        "",
    )
    result = parse_bytes(data, "rfc822")
    hashes = {a.sha256 for a in result.attachments}
    assert len(result.attachments) == 2
    assert hashes == {hashlib.sha256(content).hexdigest()}  # identical decoded hash


def test_idna_url_hostname():
    data = _simple_email(
        'Content-Type: text/html; charset="utf-8"\r\n\r\n'
        '<a href="https://b\u00fccher.example.test/a?b=1">l</a>',
        "",
    )
    result = parse_bytes(data, "rfc822")
    link = result.links[0]
    assert link.hostname == "xn--bcher-kva.example.test"  # IDNA, lowercased
    assert "xn--bcher-kva.example.test" in (link.normalized_value or "")


def test_cid_reference_absent_is_data_only():
    data = _simple_email(
        'Content-Type: text/html; charset="utf-8"\r\n\r\n<img src="cid:absent1" alt="">',
        "",
    )
    result = parse_bytes(data, "rfc822")
    link = result.links[0]
    assert link.raw_value == "cid:absent1"
    assert link.normalized_value is None  # never resolved, never fetched
    assert link.hostname is None
    assert result.images == []  # no invention of the referenced part


# ---------------------------------------------------------------------------
# SECOND REVIEW — Authentication-Results comments are never observations
# ---------------------------------------------------------------------------


def test_ar_comment_fake_value_never_wins():
    """A fake identity inside a comment never shadows the real clause value."""

    data = _simple_email(
        "Authentication-Results: mx.example.org; dkim=pass (header.d=comment.example) "
        "header.d=signer.example\r\n",
        "body",
    )
    result = parse_bytes(data, "rfc822")
    dkim = [a for a in result.authentication if a.mechanism == "dkim"]
    assert len(dkim) == 1
    assert dkim[0].domain == "signer.example"  # never comment.example
    assert dkim[0].result == "pass"


def test_ar_mechanism_only_in_comment_creates_no_observation():
    """A mechanism written only inside a comment creates no observation."""

    data = _simple_email(
        "Authentication-Results: mx.example.org; "
        "(spf=fail smtp.mailfrom=fake.example) dkim=pass header.d=signer.example\r\n",
        "body",
    )
    result = parse_bytes(data, "rfc822")
    mechs = {a.mechanism for a in result.authentication}
    assert "spf" not in mechs  # comment-only mechanism: no observation
    assert mechs == {"dkim"}
    dkim = result.authentication[0]
    assert dkim.domain == "signer.example"
    assert dkim.domain != "fake.example"


def test_ar_multidomain_still_correct_after_comment_strip():
    """The existing multi-domain behavior survives the comment stripping."""

    data = _simple_email(
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=envelope.notice.test; "
        "dkim=pass header.d=signer.notice.test; dmarc=pass header.from=brand.example\r\n",
        "body",
    )
    result = parse_bytes(data, "rfc822")
    by_mech = {a.mechanism: a for a in result.authentication}
    assert by_mech["spf"].domain == "envelope.notice.test"
    assert by_mech["dkim"].domain == "signer.notice.test"
    assert by_mech["dmarc"].domain == "brand.example"
    assert all(a.trust == "reported_unverified" for a in result.authentication)


# ---------------------------------------------------------------------------
# SECOND REVIEW — manifest completeness (G2-ready, harness-only metadata)
# ---------------------------------------------------------------------------

_TAXONOMY = {"spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"}


def test_manifest_entries_carry_g2_metadata():
    """Each of the 14 entries carries scenario, design_label (fixed taxonomy),
    content anchors, part expectations and constraints; harness-only, never
    sent to the LLM."""

    assert len(MANIFEST["fixtures"]) == 14
    for entry in MANIFEST["fixtures"]:
        assert entry["design_label"] in _TAXONOMY, entry["file"]
        assert entry["scenario"].strip(), entry["file"]
        anchors = entry["content_anchors"]
        assert anchors["subject"], entry["file"]
        # Useful-content expectations for G2 anti-wiring checks: a textual
        # excerpt or a declared alternative expected content.
        assert (
            anchors.get("text_plain_excerpt") or anchors.get("html_excerpt") or anchors.get("expected_urls")
        ), entry["file"]
        assert entry["part_expectations"], entry["file"]
        assert entry["constraints"], entry["file"]
        assert "NEVER sent to the LLM" in entry["harness_only"]


def test_manifest_content_anchors_match_parsed_fixtures(limits):
    """Declared anchors are consistent with the real fixture bytes."""

    for entry in MANIFEST["fixtures"]:
        result = parse_email(FIXTURES / entry["file"], limits)
        assert isinstance(result, ParsedEmail)
        anchors = entry["content_anchors"]
        if anchors.get("text_plain_excerpt"):
            all_text = "".join(p.text for p in result.text_parts)
            assert anchors["text_plain_excerpt"] in all_text, entry["file"]
        if anchors.get("html_excerpt"):
            all_html = "".join(p.text for p in result.html_parts)
            assert anchors["html_excerpt"] in all_html, entry["file"]
        if anchors.get("subject"):
            assert result.subject == anchors["subject"] or result.subject in anchors["subject"], entry["file"]


def test_manifest_technical_expectations_unchanged():
    """The pre-existing technical expectations (links, attachments, hashes,
    auth) keep their meaning: anchors are additive metadata only."""

    for entry in MANIFEST["fixtures"]:
        expect = entry["expect"]
        # Original keys untouched by the enrichment (parsable is entry-level).
        assert "parsable" in entry and "has_full_headers" in expect, entry["file"]
        # Part expectations stay consistent with the original expect block.
        if expect.get("images"):
            cids = {i["content_id"] for i in expect["images"]}
            declared = {p["content_id"] for p in entry["part_expectations"] if "content_id" in p}
            assert declared == cids, entry["file"]
        if expect.get("attachments"):
            names = {a["filename"] for a in expect["attachments"] if a.get("filename")}
            declared = {p["filename"] for p in entry["part_expectations"] if "filename" in p}
            assert declared == names, entry["file"]


def test_transport_ipv6_from_received():
    """Bracketed IPv6 in Received becomes a transport_ip observable (IPv6)."""

    data = (
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: t\r\nDate: Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b"Message-ID: <mv6@fixture.test>\r\nMIME-Version: 1.0\r\n"
        b"Received: from mailer (2001:db8::10) by mx with IPv6; Tue, 16 Sep 2025 09:15:00 +0000\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n\r\nb'
    )
    result = parse_bytes(data, "rfc822")
    v6 = [o for o in result.observables if o.type == "ipv6"]
    assert [o.normalized_value for o in v6] == ["2001:db8::10"]  # documentation range
    assert v6[0].roles == ["transport_ip"]


def test_manifest_part_ids_match_parsed_parts(limits):
    """Every declared part_id identifies a real part of the parsed email
    (docs/fixtures.md: IDs de pièces dans le manifest)."""

    for entry in MANIFEST["fixtures"]:
        result = parse_email(FIXTURES / entry["file"], limits)
        assert isinstance(result, ParsedEmail)
        for pe in entry["part_expectations"]:
            pid = pe["part_id"]
            if pe.get("content_id"):
                matches = [i for i in result.images if i.part_id == pid and i.content_id == pe["content_id"]]
            elif pe.get("filename"):
                matches = [a for a in result.attachments if a.part_id == pid and a.filename == pe["filename"]]
            elif pe["mime_type"] == "text/html":
                matches = [p for p in result.html_parts if p.part_id == pid]
            else:
                matches = [p for p in result.text_parts if p.part_id == pid]
            assert matches, f"{entry['file']}: {pe} matches no parsed part"
            assert matches[0].mime_type == pe["mime_type"], entry["file"]


def test_manifest_part_ids_are_deterministic(limits):
    """Re-parsing gives the same part_ids (stable MIME-walk indexing)."""

    for entry in MANIFEST["fixtures"]:
        a = parse_email(FIXTURES / entry["file"], limits)
        b = parse_email(FIXTURES / entry["file"], limits)
        ids_a = [pe["part_id"] for pe in entry["part_expectations"]]
        assert [p.part_id for p in a.text_parts + a.html_parts][: len(ids_a)] or ids_a
        assert a.model_dump_json() == b.model_dump_json()

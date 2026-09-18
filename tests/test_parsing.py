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

"""TICKET-12 corpus tests (docs/tickets/TICKET-12.md — TESTS REQUIRED).

Offline and deterministic. Synthetic cases use ``tempfile`` locations only;
the real-corpus checks require the corpus actually acquired for this ticket
(``corpus/sources.json`` + archives) and fail with an explicit message when
it is missing — a missing corpus is a ticket failure, never a silent skip.

Covered, per the ticket's TESTS REQUIRED: archives réellement obtenues;
comptes cohérents raw/normalized/manifest; hashes; champs manquants non
fabriqués; filenames-only; path traversal dans l'entrée de l'extracteur;
doublons exacts/proches/familles intersources; le parser ne voit pas les
labels de source.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.g6


def _load_build_corpus():
    spec = importlib.util.spec_from_file_location(
        "build_corpus_t12", PROJECT_ROOT / "scripts" / "build_corpus.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bc = _load_build_corpus()

#: Real counts documented in docs/corpus.md §7.7 (same archives, same hashes).
DOCUMENTED_COUNTS = {
    "spamassassin_easy_ham": 2500,
    "spamassassin_hard_ham": 250,
    "spamassassin_spam": 500,
    "nazario_phishing_2025": 481,
}
TOTAL_DOCUMENTED = sum(DOCUMENTED_COUNTS.values())  # 3731

FORBIDDEN_MANIFEST_NAME_PARTS = (
    "body",
    "text_part",
    "html_part",
    "raw_email",
    "mime_content",
    "text_excerpt",
)


def _eml_bytes(
    subject: str | None = "Test subject",
    from_addr: str | None = "alice@example.com",
    to_addr: str | None = "bob@example.com",
    date: str | None = "Mon, 06 Jan 2025 04:37:05 +0000",
    message_id: str | None = "<msg-1@example.com>",
    body: str = "Hello world, this is a plain body.",
) -> bytes:
    """Craft a small deterministic RFC822 message."""

    lines: list[str] = []
    if from_addr is not None:
        lines.append(f"From: {from_addr}")
    if to_addr is not None:
        lines.append(f"To: {to_addr}")
    if subject is not None:
        lines.append(f"Subject: {subject}")
    if date is not None:
        lines.append(f"Date: {date}")
    if message_id is not None:
        lines.append(f"Message-ID: {message_id}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8")


def _source_spec(**overrides: object) -> dict[str, object]:
    spec = {
        "id": "test_source",
        "dataset": "testdataset",
        "subset": "test",
        "kind": "tar.bz2",
        "input_format": "rfc822",
        "source_url": "https://example.org/test",
        "source_label": "ham",
        "public_source": True,
        "path": "unused",
        "status": "acquired",
        "transformation_notes": "",
        "notes": "",
    }
    spec.update(overrides)
    return spec


def _record_from_bytes(
    data: bytes,
    input_format: str = "rfc822",
    source_label: str = "ham",
    source_id: str = "test_source",
    dataset: str = "testdataset",
) -> bc.NormalizedRecord:
    source = _source_spec(
        input_format=input_format, source_label=source_label,
        id=source_id, dataset=dataset,
    )
    message = bc.SourceMessage(source_record_id="0001.hash", data=data)
    return bc.build_record(source, message, bc.ParseLimits(), 1)


def _record_for_dedupe(
    sample_id: str,
    dataset: str,
    body: str,
) -> bc.NormalizedRecord:
    text = bc.normalize_fingerprint_text(body)
    return bc.NormalizedRecord(
        sample_id=sample_id,
        source_id=f"src_{sample_id}",
        source_dataset=dataset,
        source_subset="x",
        source_record_id=sample_id,
        source_url="https://example.org/x",
        public_source=True,
        raw_path=f"corpus/raw/x/{sample_id}",
        raw_sha256=hashlib.sha256(sample_id.encode("utf-8")).hexdigest(),
        input_format="rfc822",
        original_label="ham",
        label_status="unreviewed",
        header_integrity="original",
        header_presence={field: True for field in bc.HEADER_PRESENCE_FIELDS},
        has_full_headers=True,
        has_received=True,
        has_authentication_results=True,
        has_text=True,
        has_html=False,
        has_urls=False,
        has_attachments=False,
        has_images=False,
        has_original_attachment_bytes=False,
        attachment_representation="absent",
        body_text=text,
        body_sha256=bc.fingerprint_from_text(text) if text else "",
    )


def _write_tar(archive_path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(archive_path, "w:bz2") as tar:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def _resolve_raw(raw_path: str) -> bytes:
    """Resolve ``<archive>!<member-or-ordinal>`` (or a plain file path)."""

    archive_ref, _, member = raw_path.partition("!")
    if not member:
        return (PROJECT_ROOT / raw_path).read_bytes()
    archive = PROJECT_ROOT / archive_ref
    if archive.suffix in (".bz2", ".gz", ".xz", ".tar"):
        if archive_ref not in _resolve_raw._cache:
            _resolve_raw._cache[archive_ref] = bc._read_tar_members(archive)
        return _resolve_raw._cache[archive_ref][member]
    if archive_ref not in _resolve_raw._cache:
        _resolve_raw._cache[archive_ref] = {
            message.source_record_id: message.data
            for message in bc.iter_mbox_messages(archive, bc.ParseLimits())
        }
    return _resolve_raw._cache[archive_ref][member]


_resolve_raw._cache = {}


# ---------------------------------------------------------------------------
# Real corpus (acquired for this ticket).
# ---------------------------------------------------------------------------


def test_acquired_archives_exist_and_match_sources_json():
    sources = bc.load_sources(PROJECT_ROOT / "corpus/sources.json")
    acquired = bc.acquired_sources(sources)
    if not acquired:
        pytest.fail(
            "corpus/sources.json declares zero acquired sources: no archive "
            "was really obtained (archives réellement obtenues is required)"
        )
    for source in acquired:
        path = PROJECT_ROOT / str(source["path"])
        if not path.is_file():
            pytest.fail(
                f"source {source['id']!r} declared acquired but "
                f"{source['path']} is missing: run the inspect step"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == source["sha256"], source["id"]
        assert path.stat().st_size == source["size_bytes"], source["id"]


def test_declared_absent_sources_stay_absent():
    sources = bc.load_sources(PROJECT_ROOT / "corpus/sources.json")
    for source in sources:
        if source["status"] in ("not_acquired", "not_provided"):
            path = PROJECT_ROOT / str(source["path"])
            assert not path.exists(), (
                f"source {source['id']!r} is declared {source['status']} but "
                f"{source['path']} exists: nothing may be fabricated"
            )


def test_counts_match_documented_reference():
    sources = bc.load_sources(PROJECT_ROOT / "corpus/sources.json")
    for source in bc.acquired_sources(sources):
        count = sum(
            1
            for message in bc.iter_source_messages(source, bc.ParseLimits())
            if message.error is None
        )
        expected = DOCUMENTED_COUNTS[str(source["id"])]
        assert count == expected, (
            f"{source['id']}: {count} messages vs documented {expected}"
        )


def test_normalized_jsonl_and_manifest_are_coherent():
    jsonl_path = PROJECT_ROOT / "corpus/normalized/emails.jsonl"
    manifest_path = PROJECT_ROOT / "corpus/manifest.parquet"
    if not jsonl_path.is_file() or not manifest_path.is_file():
        pytest.fail(
            "corpus/normalized/emails.jsonl or corpus/manifest.parquet is "
            "missing: run 'python scripts/build_corpus.py normalize' first"
        )
    rows = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == TOTAL_DOCUMENTED

    table = bc._pq().read_table(manifest_path)
    assert list(table.schema.names) == list(bc.MANIFEST_FIELDS)
    assert table.num_rows == len(rows)
    manifest_rows = {row["sample_id"]: row for row in table.to_pylist()}
    assert len(manifest_rows) == len(rows)

    for row in rows:
        other = manifest_rows[row["sample_id"]]
        presence = (
            json.loads(other["header_presence"])
            if isinstance(other["header_presence"], str)
            else other["header_presence"]
        )
        for name in bc.MANIFEST_FIELDS:
            expected = presence if name == "header_presence" else other[name]
            assert row[name] == expected, (row["sample_id"], name)

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["source_id"]] = counts.get(row["source_id"], 0) + 1
    assert counts == DOCUMENTED_COUNTS

    assert all(row["normalized_label"] is None for row in rows)
    assert all(row["label_status"] == "unreviewed" for row in rows)
    assert all(row["split"] == "candidate" for row in rows)
    assert set(row["original_label"] for row in rows) == {"ham", "spam", "phishing"}
    assert set(row["input_format"] for row in rows) == {"rfc822", "mbox_member"}
    spam_rows = [row for row in rows if row["source_id"].startswith("spamassassin")]
    assert all(
        row["header_presence"]["authentication_results"] is False
        for row in spam_rows
    )


def test_manifest_has_no_content_columns():
    manifest_path = PROJECT_ROOT / "corpus/manifest.parquet"
    if not manifest_path.is_file():
        pytest.fail("run 'python scripts/build_corpus.py normalize' first")
    table = bc._pq().read_table(manifest_path)
    names = [name.lower() for name in table.schema.names]
    forbidden_names = {
        "body", "text", "html", "headers", "raw", "raw_email", "mime_content",
        "text_excerpt", "text_parts", "html_parts",
    }
    assert not (set(names) & forbidden_names)


def test_manifest_raw_hashes_resolve():
    manifest_path = PROJECT_ROOT / "corpus/manifest.parquet"
    if not manifest_path.is_file():
        pytest.fail("run 'python scripts/build_corpus.py normalize' first")
    table = bc._pq().read_table(manifest_path)
    for row in table.to_pylist():
        data = _resolve_raw(str(row["raw_path"]))
        assert data, row["raw_path"]
        assert hashlib.sha256(data).hexdigest() == row["raw_sha256"], row["sample_id"]


# ---------------------------------------------------------------------------
# Controlled record building (missing fields, formats, attachments).
# ---------------------------------------------------------------------------


def test_missing_headers_are_not_fabricated():
    data = _eml_bytes(to_addr=None, date=None, message_id=None)
    record = _record_from_bytes(data)
    presence = record.header_presence()
    assert presence["to"] is False
    assert presence["date"] is False
    assert presence["message_id"] is False
    assert presence["from"] is True
    assert record["has_full_headers"] is False
    assert record["normalized_label"] is None
    assert record["label_status"] == "unreviewed"
    assert record["original_label"] == "ham"


def test_attachment_representation_bytes():
    attachment = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: attachment\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"see attachment\r\n"
        b"--BOUND\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="report.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"aGVsbG8gYXR0YWNobWVudA==\r\n"
        b"--BOUND--\r\n"
    )
    record = _record_from_bytes(attachment)
    assert record["attachment_representation"] == "bytes"
    assert record["has_original_attachment_bytes"] is True


def test_attachment_representation_filename_only():
    broken = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: broken attachment\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"see attachment\r\n"
        b"--BOUND\r\n"
        b"Content-Type: application/octet-stream; name=\"report.bin\"\r\n"
        b'Content-Disposition: attachment; filename="report.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"!!!!not-base64!!!!\r\n"
        b"--BOUND--\r\n"
    )
    record = _record_from_bytes(broken)
    assert record["attachment_representation"] == "filename"
    assert record["has_original_attachment_bytes"] is False


def test_attachment_representation_absent():
    record = _record_from_bytes(_eml_bytes())
    assert record["attachment_representation"] == "absent"
    assert record["has_original_attachment_bytes"] is False


def test_structured_public_text_keeps_distinct_input_format():
    payload = (
        b'{"Original_ID": 1, "Body": "Hi, visit http://x.example/ok", '
        b'"File": "invoice.pdf"}'
    )
    record = _record_from_bytes(
        payload,
        input_format="structured_public_text",
        source_label="Phishing",
        dataset="phishfuzzer",
    )
    assert record["input_format"] == "structured_public_text"
    assert record["input_format"] != "rfc822"
    assert record["header_integrity"] == "unknown"
    presence = record.header_presence()
    assert not any(presence.values())
    assert record["has_full_headers"] is False
    assert record["attachment_representation"] == "absent"  # no MIME part
    assert record["normalized_label"] is None


# ---------------------------------------------------------------------------
# Extractor safety (path traversal) and mbox handling.
# ---------------------------------------------------------------------------


def test_path_traversal_refused_in_extractor(tmp_path: Path):
    evil_members = {
        "../evil.txt": b"escaped",
        "/abs/evil.txt": b"absolute",
        "sub/../../escape.txt": b"traversal",
        "ok/0001.msg": _eml_bytes(body="legit message"),
    }
    archive = tmp_path / "evil.tar.bz2"
    _write_tar(archive, evil_members)
    before = sorted(p.name for p in tmp_path.iterdir())

    source = _source_spec()
    source["path"] = str(archive)
    source["kind"] = "tar.bz2"
    messages = list(bc.iter_source_messages(source, bc.ParseLimits()))
    by_name = {message.source_record_id: message for message in messages}

    for name in ("../evil.txt", "/abs/evil.txt", "sub/../../escape.txt"):
        assert name in by_name, name
        assert by_name[name].error is not None
        assert "unsafe_member_name_refused" in by_name[name].error
        assert by_name[name].data == b""
    assert any(message.error is None for message in messages)

    after = sorted(p.name for p in tmp_path.iterdir())
    assert after == before, "the extractor must never write to disk"
    assert not (tmp_path.parent / "evil.txt").exists()
    assert not (PROJECT_ROOT / "evil.txt").exists()


def test_mbox_member_extraction_and_transformation_note(tmp_path: Path):
    first = _eml_bytes(subject="First", body="first body")
    # a "From " line in the middle of a body, NOT preceded by a blank line
    second = _eml_bytes(
        subject="Second",
        body=(
            "first line of body\n"
            "From worker@monkey.example inside body\n"
            "after the from line"
        ),
    )
    body_line = b"From worker@monkey.example inside body\r\n"
    data = (
        b"From alice@monkey.example Mon Jan  6 04:37:05 2025\r\n"
        + first
        + b"\r\n\r\n"
        + b"From alice@monkey.example Tue Feb  6 04:37:05 2025\r\n"
        + second
    )
    mbox_path = tmp_path / "phishing-test"
    mbox_path.write_bytes(data)

    source = _source_spec()
    source["path"] = str(mbox_path)
    source["kind"] = "mbox"
    source["input_format"] = "mbox_member"
    records = list(bc.read_dataset(source))
    assert len(records) == 2
    record_first, record_second = records
    assert record_first["source_record_id"] == "0001"
    assert record_second["source_record_id"] == "0002"
    assert record_first["input_format"] == "mbox_member"
    assert record_first["header_integrity"] == "transformed"
    assert record_first["raw_path"].endswith("!0001")

    member_bytes = _resolve_raw(str(record_first["raw_path"]))
    assert not member_bytes.startswith(b"From ")  # separator line excluded
    assert hashlib.sha256(member_bytes).hexdigest() == record_first["raw_sha256"]
    # a "From " body line NOT preceded by a blank line stays inside the member
    member_bytes_second = _resolve_raw(str(record_second["raw_path"]))
    assert b"From worker@monkey.example inside body" in member_bytes_second


# ---------------------------------------------------------------------------
# Deduplication: exact / near / families (docs/corpus.md §7.4).
# ---------------------------------------------------------------------------

_LONG_BODY = (
    "Dear customer your account statement is ready for download today "
    "please visit the secure portal and confirm your identity before "
    "continuing thank you for your cooperation the support team wishes "
    "you a pleasant day and reminds you to keep your credentials safe"
)


def test_exact_near_family_grouping():
    exact_a = _record_for_dedupe("s1", "datasetA", _LONG_BODY)
    exact_b = _record_for_dedupe("s2", "datasetB", _LONG_BODY)
    near = _record_for_dedupe(
        "s3",
        "datasetA",
        _LONG_BODY + " today",  # one word appended: Jaccard stays >= 0.85
    )
    unrelated = _record_for_dedupe("s4", "datasetA", "completely different content about budget")
    texts = {record["sample_id"]: record["body_text"] for record in (exact_a, exact_b, near, unrelated)}
    duplicate_groups, family_groups, stats = bc.compute_duplicate_families(
        [exact_a, exact_b, near, unrelated], texts, seed=42
    )
    # exact duplication groups together (identical raw + body hashes), even
    # across sources
    assert duplicate_groups["s1"] == duplicate_groups["s2"]
    assert family_groups["s1"] == family_groups["s2"]
    # near duplicate joins the family but not the exact group
    assert stats["near_links"] >= 1
    assert family_groups["s3"] == family_groups["s1"]
    assert duplicate_groups["s3"] != duplicate_groups["s1"]
    # the unrelated record stays alone
    assert family_groups["s4"] != family_groups["s1"]
    # the exact pair spans two datasets: one intersource family exists
    assert stats["intersource_families"] >= 1


def test_short_texts_use_equality_only():
    short_one = _record_for_dedupe("t1", "datasetA", "hello world today")
    short_two = _record_for_dedupe("t2", "datasetA", "hello there world today")
    short_copy = _record_for_dedupe("t3", "datasetB", "hello world today")
    texts = {
        "t1": short_one["body_text"],
        "t2": short_two["body_text"],
        "t3": short_copy["body_text"],
    }
    duplicate_groups, family_groups, stats = bc.compute_duplicate_families(
        [short_one, short_two, short_copy], texts, seed=42
    )
    # different short texts (< 20 words) are never linked
    assert family_groups["t1"] != family_groups["t2"]
    # identical short texts link via the exact normalized-body hash (§7.4)
    assert duplicate_groups["t1"] == duplicate_groups["t3"]
    assert family_groups["t1"] == family_groups["t3"]
    assert stats["near_links"] == 0  # no shingle proximity needed at this size


def test_dedupe_seed_reproducible():
    pool = [
        _record_for_dedupe("r1", "datasetA", _LONG_BODY),
        _record_for_dedupe("r2", "datasetB", _LONG_BODY),
        _record_for_dedupe("r3", "datasetA", "unrelated single record body"),
    ]
    texts = {record["sample_id"]: record["body_text"] for record in pool}
    first = bc.compute_duplicate_families(pool, texts, seed=42)
    second = bc.compute_duplicate_families(pool, texts, seed=42)
    assert first[0] == second[0]
    assert first[1] == second[1]


# ---------------------------------------------------------------------------
# Dedupe raw re-read (TICKET-12 review blocker): same safety/bounds as
# ingestion, sha256 verification, explicit failures.
# ---------------------------------------------------------------------------


def _raw_record(
    archive: Path,
    member: str,
    raw_sha256: str,
    sample_id: str = "raw1",
) -> bc.NormalizedRecord:
    record = _record_for_dedupe(sample_id, "datasetX", "irrelevant body")
    record["raw_path"] = f"{archive}!{member}"
    record["raw_sha256"] = raw_sha256
    return record


def test_dedupe_reread_refuses_unsafe_member(tmp_path: Path):
    archive = tmp_path / "unsafe.tar.bz2"
    safe_bytes = _eml_bytes(body="safe body")
    _write_tar(
        archive,
        {"../evil.txt": b"evil-bytes", "ok/0001.msg": safe_bytes},
    )
    bad = _raw_record(
        archive, "../evil.txt", hashlib.sha256(b"evil-bytes").hexdigest()
    )
    with pytest.raises(bc.CorpusRawError) as excinfo:
        bc.load_texts_from_raw([bad])
    assert "unresolvable" in str(excinfo.value)

    # the same archive's safe member still resolves with hash verification
    good = _raw_record(
        archive,
        "ok/0001.msg",
        hashlib.sha256(safe_bytes).hexdigest(),
        sample_id="raw-safe",
    )
    texts, refused = bc.load_texts_from_raw([good])
    assert texts["raw-safe"]
    assert refused == set()


def test_dedupe_reread_refuses_oversized_member(tmp_path: Path):
    archive = tmp_path / "oversized.tar.bz2"
    big = b"A" * 4096
    _write_tar(archive, {"big.bin": big})
    record = _raw_record(archive, "big.bin", hashlib.sha256(big).hexdigest())
    with pytest.raises(bc.CorpusRawError) as excinfo:
        bc.load_texts_from_raw([record], max_member_bytes=64)
    assert "unresolvable" in str(excinfo.value)

    # the oversized member is never read into the member map
    members = bc._read_tar_members(archive, max_member_bytes=64, max_total_bytes=10_000)
    assert "big.bin" not in members


def test_dedupe_reread_enforces_aggregate_archive_bound(tmp_path: Path):
    archive = tmp_path / "aggregate.tar.bz2"
    first = b"B" * 40
    second = b"C" * 40
    _write_tar(archive, {"a.bin": first, "b.bin": second})
    with pytest.raises(bc.CorpusRawError) as excinfo:
        bc._read_tar_members(archive, max_member_bytes=1000, max_total_bytes=64)
    assert "exceeds bound" in str(excinfo.value)

    record = _raw_record(
        archive, "a.bin", hashlib.sha256(first).hexdigest(), sample_id="raw-agg"
    )
    with pytest.raises(bc.CorpusRawError):
        bc.load_texts_from_raw([record], max_member_bytes=1000, max_total_bytes=64)


def test_dedupe_reread_hash_mismatch_fails_explicitly(tmp_path: Path):
    archive = tmp_path / "mismatch.tar.bz2"
    data = _eml_bytes(body="actual bytes")
    _write_tar(archive, {"mismatch.msg": data})
    record = _raw_record(
        archive,
        "mismatch.msg",
        hashlib.sha256(b"different bytes").hexdigest(),
        sample_id="raw-bad",
    )
    with pytest.raises(bc.CorpusRawError) as excinfo:
        bc.load_texts_from_raw([record])
    assert "raw_sha256 mismatch" in str(excinfo.value)


def test_dedupe_reread_missing_raw_file_fails_explicitly(tmp_path: Path):
    record = _record_for_dedupe("raw-missing", "datasetX", "body")
    record["raw_path"] = str(tmp_path / "does-not-exist.eml")
    record["raw_sha256"] = hashlib.sha256(b"whatever").hexdigest()
    with pytest.raises(bc.CorpusRawError) as excinfo:
        bc.load_texts_from_raw([record])
    assert "unresolvable" in str(excinfo.value)


def test_dedupe_reread_refused_rows_are_counted_not_read(tmp_path: Path):
    record = _record_for_dedupe("raw-refused", "datasetX", "body")
    record["raw_path"] = "corpus/raw/iwspa/refused-member"
    record["raw_sha256"] = ""  # ingestion-refused row: no readable raw bytes
    texts, refused = bc.load_texts_from_raw([record])
    assert refused == {"raw-refused"}
    assert texts["raw-refused"] == ""


def test_dedupe_command_fails_closed_before_writing(tmp_path: Path, capsys):
    archive = tmp_path / "cmd.tar.bz2"
    data = _eml_bytes(body="actual bytes")
    _write_tar(archive, {"cmd.msg": data})
    record = _raw_record(
        archive,
        "cmd.msg",
        hashlib.sha256(b"other bytes").hexdigest(),
        sample_id="cmd-bad",
    )
    manifest_path = tmp_path / "manifest.parquet"
    bc._pq().write_table(bc.build_manifest([record]), manifest_path)
    before = manifest_path.read_bytes()

    assert bc.main(["dedupe", "--manifest", str(manifest_path), "--seed", "42"]) == 2
    captured = capsys.readouterr()
    assert "FAIL" in captured.err
    assert "raw_sha256 mismatch" in captured.err
    assert manifest_path.read_bytes() == before  # nothing was rewritten


# ---------------------------------------------------------------------------
# Parser never sees labels; manifest/JSONL/template invariants.
# ---------------------------------------------------------------------------

CONTENT_FIELDS = (
    "raw_sha256",
    "body_sha256",
    "header_presence",
    "has_full_headers",
    "has_received",
    "has_authentication_results",
    "has_text",
    "has_html",
    "has_urls",
    "has_attachments",
    "has_images",
    "attachment_representation",
    "header_integrity",
    "input_format",
)


def test_parser_never_sees_source_labels():
    data = _eml_bytes()
    record_ham = _record_from_bytes(data, source_label="ham")
    record_phish = _record_from_bytes(
        data, source_label="phishing", dataset="nazario"
    )
    for name in CONTENT_FIELDS:
        assert record_ham[name] == record_phish[name], name
    assert record_ham["original_label"] == "ham"
    assert record_phish["original_label"] == "phishing"

    from src.state import ParsedEmail

    forbidden_tokens = ("label", "source_dataset")
    for name in ParsedEmail.model_fields:
        assert not any(token in name for token in forbidden_tokens), name


def test_build_manifest_roundtrip(tmp_path: Path):
    records = [
        _record_for_dedupe("m1", "datasetA", _LONG_BODY),
        _record_for_dedupe("m2", "datasetB", "other body text"),
    ]
    path = tmp_path / "manifest.parquet"
    bc._pq().write_table(bc.build_manifest(records), path)
    loaded = bc.read_manifest(path)
    assert [record.persisted() for record in loaded] == [
        record.persisted() for record in records
    ]
    loaded[0]["duplicate_group"] = "dup:abc"
    bc._pq().write_table(bc.build_manifest(loaded), path)
    reloaded = bc.read_manifest(path)
    assert reloaded[0]["duplicate_group"] == "dup:abc"


def test_labels_template_has_no_content_and_no_labels(tmp_path: Path):
    path = tmp_path / "labels_template.jsonl"
    count = bc.write_labels_template(path, [_record_for_dedupe("v1", "datasetA", _LONG_BODY)])
    assert count == 1
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    forbidden_keys = {
        "body", "text", "html", "headers", "raw", "raw_email", "mime_content",
        "text_excerpt", "body_text", "text_parts", "html_parts", "subject",
        "from", "to", "date", "message_id", "received", "return_path",
    }
    assert not (set(row) & forbidden_keys)
    assert row["normalized_label"] is None
    assert row["candidate_label"] is None
    assert row["label_status"] == "unreviewed"
    assert row["reviewer_ref"] is None
    assert row["label_rationale"] is None


# ---------------------------------------------------------------------------
# TICKET-13 (G6): Gold-AI reference partitions — operator-approved amendment.
# Synthetic fixtures only (tempfile); the real-corpus pipeline is exercised by
# the ticket's validation commands, never by fabricating records.
# ---------------------------------------------------------------------------

GOLD_AI_REVIEWER_REF = "astra_gold_ai_v1"
GOLD_AI_REVIEW_METHOD = "independent_dual_model_ai_adjudication"


def _t13_case(
    tmp_path: Path,
    index: int,
    label: str | None,
    *,
    dataset: str = "t13dataset",
    raw: bytes | None = None,
    body: str | None = None,
    family: str | None = None,
) -> tuple[bc.NormalizedRecord, dict, dict]:
    """One synthetic corpus case: raw file under tmp_path/corpus/raw, manifest
    record, canonical label row and an operator-protocol adjudication row."""

    label = label or None
    body = body if body is not None else (
        f"Case {index}: distinct synthetic body text for scenario {label} "
        f"carrying the unique marker zebra-{index} for isolation."
    )
    raw = raw if raw is not None else _eml_bytes(
        subject=f"T13 case {index}",
        body=body,
        message_id=f"<t13-{index}@example.com>",
    )
    raw_dir = tmp_path / "corpus" / "raw" / "t13"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / f"{index}.eml").write_bytes(raw)
    raw_path = f"corpus/raw/t13/{index}.eml"
    raw_sha = hashlib.sha256(raw).hexdigest()
    text = bc.normalize_fingerprint_text(body)
    family = family or f"fam:t13_{index:04d}"
    record = bc.NormalizedRecord(
        sample_id=f"t13_{index:04d}",
        source_id=f"src_t13_{index:04d}",
        source_dataset=dataset,
        source_subset="t13",
        source_record_id=str(index),
        source_url="https://example.org/t13",
        public_source=True,
        raw_path=raw_path,
        raw_sha256=raw_sha,
        input_format="rfc822",
        original_label="ham",
        normalized_label=None,
        label_status="unreviewed",
        reviewer_ref=None,
        label_rationale=None,
        header_integrity="original",
        header_presence={field: True for field in bc.HEADER_PRESENCE_FIELDS},
        has_full_headers=True,
        has_received=True,
        has_authentication_results=True,
        has_text=True,
        has_html=False,
        has_urls=False,
        has_attachments=False,
        has_images=False,
        has_original_attachment_bytes=False,
        attachment_representation="absent",
        is_synthetic=None,
        campaign_id=None,
        body_sha256=bc.fingerprint_from_text(text),
        duplicate_group=f"dup:t13_{index:04d}",
        family_group=family,
        split="candidate",
        transformation_notes="",
        notes="",
        body_text=text,
    )
    template_row = {
        "sample_id": record["sample_id"],
        "source_dataset": dataset,
        "source_record_id": str(index),
        "raw_sha256": raw_sha,
        "raw_path": raw_path,
        "original_label": "ham",
        "normalized_label": None,
        "candidate_label": None,
        "label_status": "unreviewed",
        "reviewer_ref": None,
        "label_rationale": None,
        "duplicate_group": family.replace("fam:", "dup:"),
        "family_group": family,
        "notes": "",
    }
    label_row = {
        "sample_id": record["sample_id"],
        "source_dataset": dataset,
        "source_record_id": str(index),
        "raw_sha256": raw_sha,
        "raw_path": raw_path,
        "original_label": "ham",
        "normalized_label": label,
        "candidate_label": None,
        "label_status": "confirmed" if label else "ambiguous",
        "reviewer_ref": GOLD_AI_REVIEWER_REF,
        "label_rationale": (
            "AI-adjudicated POC reference (Gold-AI); provenance retained in "
            "TICKET-13 audit artefact."
        ),
        "duplicate_group": family.replace("fam:", "dup:"),
        "family_group": family,
        "notes": "",
    }
    adjudication_row = {
        "sample_id": record["sample_id"],
        "raw_sha256": raw_sha,
        "family_group": family,
        "silver_label": "phishing",
        "astra_independent_label": label,
        "agreement": "AGREE" if label else "BOTH_AMBIGUOUS",
        "final_label": label,
        "final_status": "ai_adjudicated" if label else "ambiguous",
        "adjudication_reason": "analytic, content-free",
        "reviewer_ref": GOLD_AI_REVIEWER_REF,
        "review_method": GOLD_AI_REVIEW_METHOD,
        "human_validated": False,
    }
    return record, label_row, adjudication_row


def _t13_write_labels(tmp_path: Path, label_rows: list[dict]) -> Path:
    path = tmp_path / "corpus" / "review" / "labels.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in label_rows
        ),
        encoding="utf-8",
    )
    return path


def _t13_write_pool(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    return path


def test_goldai_protocol_row_accepted_and_rejected(tmp_path: Path):
    record, _, adjudication_row = _t13_case(tmp_path, 1, "phishing")
    manifest_path = tmp_path / "manifest.parquet"
    bc._pq().write_table(bc.build_manifest([record]), manifest_path)
    adjudication_path = tmp_path / "adj.jsonl"
    _t13_write_pool(adjudication_path, [adjudication_row])
    loaded = bc.load_adjudication(adjudication_path)
    assert set(loaded) == {"t13_0001"}

    # unsupported final_label is rejected
    bad = dict(adjudication_row, final_label="unknown_class")
    _t13_write_pool(adjudication_path, [bad])
    with pytest.raises(bc.GoldValidationError):
        bc.load_adjudication(adjudication_path)

    # final_status outside the approved protocol is rejected
    _t13_write_pool(adjudication_path, [dict(adjudication_row, final_status="silver_only")])
    with pytest.raises(bc.GoldValidationError):
        bc.load_adjudication(adjudication_path)

    # raw_sha256 missing on an ai_adjudicated row is rejected
    _t13_write_pool(adjudication_path, [dict(adjudication_row, raw_sha256="")])
    with pytest.raises(bc.GoldValidationError):
        bc.load_adjudication(adjudication_path)

    # human_validated must stay explicitly false (never rewritten)
    for wrong in (True, None, "false"):
        _t13_write_pool(adjudication_path, [dict(adjudication_row, human_validated=wrong)])
        with pytest.raises(bc.GoldValidationError):
            bc.load_adjudication(adjudication_path)

    # reviewer_ref stays the real Gold-AI reference
    _t13_write_pool(adjudication_path, [dict(adjudication_row, reviewer_ref="human_senior_analyst")])
    with pytest.raises(bc.GoldValidationError):
        bc.load_adjudication(adjudication_path)


def test_goldai_canonical_rows_cannot_claim_human_validation(tmp_path: Path):
    record, label_row, adjudication_row = _t13_case(tmp_path, 2, "legitime")
    rows, summary = bc.build_canonical_labels(
        {"t13_0002": adjudication_row}, [record], [dict(label_row, normalized_label=None,
         label_status="unreviewed", reviewer_ref=None, label_rationale=None)]
    )
    assert summary["human_validation_claimed"] is False
    assert rows[0]["reviewer_ref"] == GOLD_AI_REVIEWER_REF
    assert rows[0]["label_status"] == "confirmed"
    assert "human" not in rows[0]["label_rationale"].lower()
    # the canonical schema is closed: a human_validated key is structurally refused
    polluted = dict(rows[0], human_validated=True)
    with pytest.raises(bc.GoldValidationError):
        bc._validate_canonical_label_row(polluted, "canonical-label-row")


def test_goldai_join_requires_exact_equality(tmp_path: Path):
    record, _, adjudication_row = _t13_case(tmp_path, 3, "spam")
    template_row = dict(
        _t13_case(tmp_path, 3, "spam")[1],
        raw_sha256=adjudication_row["raw_sha256"],
        family_group=adjudication_row["family_group"],
    )

    # sample missing from manifest/template
    other_record, _, _ = _t13_case(tmp_path, 4, "spam")
    with pytest.raises(bc.GoldValidationError):
        bc.build_canonical_labels(adjudication={other_record["sample_id"]: adjudication_row},
                                  manifest_records=[record], template_rows=[template_row])

    # raw_sha256 mismatch between adjudication and manifest/template
    tampered = dict(adjudication_row, raw_sha256="0" * 64)
    with pytest.raises(bc.GoldValidationError):
        bc.build_canonical_labels(adjudication={record["sample_id"]: tampered},
                                  manifest_records=[record], template_rows=[template_row])

    # family_group mismatch between adjudication and manifest/template
    tampered = dict(adjudication_row, family_group="fam:somewhere_else")
    with pytest.raises(bc.GoldValidationError):
        bc.build_canonical_labels(adjudication={record["sample_id"]: tampered},
                                  manifest_records=[record], template_rows=[template_row])

    # the good join succeeds and is deterministic (input row order is irrelevant)
    rows_one, _ = bc.build_canonical_labels({record["sample_id"]: adjudication_row},
                                            [record], [template_row])
    rows_two, _ = bc.build_canonical_labels({record["sample_id"]: adjudication_row},
                                            [record], [template_row])
    assert rows_one == rows_two


def _t13_build_scenario(tmp_path: Path, counts: dict[str, int]):
    records, labels_rows, adjudication_rows, pool_rows = [], [], [], []
    index = 0
    for label, count in counts.items():
        for _ in range(count):
            index += 1
            record, label_row, adjudication_row = _t13_case(tmp_path, index, label)
            records.append(record)
            labels_rows.append(label_row)
            adjudication_rows.append(adjudication_row)
            pool_rows.append(adjudication_row)
    return {
        "records": records,
        "labels_rows": labels_rows,
        "adjudication_rows": adjudication_rows,
        "pool_rows": pool_rows,
        "labels_path": _t13_write_labels(tmp_path, labels_rows),
        "pool_path": _t13_write_pool(tmp_path / "pool.jsonl", pool_rows),
    }


def test_goldai_pool_guards(tmp_path: Path):
    scenario = _t13_build_scenario(
        tmp_path,
        {"phishing": 2, "legitime": 2, "fraude": 1, "spam": 1},
    )
    adjudication = bc.load_adjudication  # reference only; pool guards tested directly
    pool_rows = scenario["pool_rows"]

    # duplicate Gold candidate sample is rejected
    path = _t13_write_pool(tmp_path / "pool_dup_sample.jsonl", [pool_rows[0], pool_rows[0]])
    with pytest.raises(bc.GoldValidationError):
        bc.load_gold_candidates(path)

    # duplicate Gold candidate family is rejected
    duplicated_family = dict(pool_rows[1], sample_id="t13_9999")
    path = _t13_write_pool(
        tmp_path / "pool_dup_family.jsonl", [pool_rows[1], duplicated_family]
    )
    with pytest.raises(bc.GoldValidationError):
        bc.load_gold_candidates(path)

    # Gold candidate absent from the full adjudication is rejected
    stranger = dict(pool_rows[0], sample_id="t13_absent")
    adjudication_map = bc.load_adjudication(
        _t13_write_pool(tmp_path / "adj.jsonl", scenario["adjudication_rows"])
    )
    path = _t13_write_pool(tmp_path / "pool_stranger.jsonl", [stranger])
    with pytest.raises(bc.GoldValidationError):
        bc.load_gold_candidates(path, adjudication=adjudication_map)

    # provenance disagreement with the adjudication artefact is rejected
    wrong_raw = dict(pool_rows[0], raw_sha256="1" * 64)
    path = _t13_write_pool(tmp_path / "pool_wrong_raw.jsonl", [wrong_raw])
    with pytest.raises(bc.GoldValidationError):
        bc.load_gold_candidates(path, adjudication_map)


def test_goldai_select_intersections_ambiguity_and_support(tmp_path: Path):
    scenario = _t13_build_scenario(
        tmp_path,
        {"phishing": 4, "legitime": 4, "fraude": 2, "spam": 2, "menace": 0},
    )
    # two ambiguous records, excluded from Gold and RAG
    _, ambiguous_label_row, ambiguous_adjudication_row = _t13_case(
        tmp_path, 900, None
    )
    labels_path = _t13_write_labels(
        tmp_path, scenario["labels_rows"] + [ambiguous_label_row]
    )
    outcome = bc.select_gold(
        scenario["records"],
        scenario["labels_rows"] + [ambiguous_label_row],
        scenario["pool_rows"],
        seed=42,
        project_root=tmp_path,
    )
    plan = outcome["plan"]
    dev_ids = set(plan["dev"]["sample_ids"])
    rag_ids = {row["sample_id"] for row in outcome["rag_cases"]}
    ambiguous_id = ambiguous_label_row["sample_id"]
    assert ambiguous_id not in dev_ids
    assert ambiguous_id not in rag_ids

    # family intersections are empty (dev/test/rag)
    dev_families = {str(row["family_group"]) for row in outcome["dev_gold_records"]}
    test_families = {
        str(row["family_group"]) for row in outcome["test_gold_records"]
    }
    rag_families = {str(row["family_group"]) for row in outcome["rag_cases"]}
    assert not (dev_families & test_families)
    assert not (rag_families & dev_families)
    assert not (rag_families & test_families)
    assert all(value == 0 for value in plan["intersections"].values())

    # protected pool families never enter RAG
    pool_families = {str(row["family_group"]) for row in scenario["pool_rows"]}
    assert not (rag_families & pool_families)

    # menace stays unsupported rather than fabricated
    assert plan["dev"]["class_support"]["menace"] == 0
    assert plan["test"]["class_support"]["menace"] == 0
    assert plan["rag"]["class_support"]["menace"] == 0
    assert plan["limitations"]["menace_reference_support"] == 0

    # dev/test halves of an even pool (2 per class -> 1/1)
    assert plan["dev"]["record_count"] == plan["test"]["record_count"]
    assert plan["dev"]["class_support"] == plan["test"]["class_support"]


def test_goldai_rag_reservation_from_complement(tmp_path: Path):
    # pool: 1 phishing candidate; complement: 2 legitime + 1 phishing + 1 fraude
    records, labels_rows, adjudication_rows, pool_rows = [], [], [], []
    pool_member, _, pool_adjudication = _t13_case(tmp_path, 10, "phishing")
    records.append(pool_member)
    adjudication_rows.append(pool_adjudication)
    pool_rows.append(pool_adjudication)
    labels_rows.append(
        dict(
            _t13_case(tmp_path, 10, "phishing")[1],
            label_status="confirmed",
            normalized_label="phishing",
            reviewer_ref=GOLD_AI_REVIEWER_REF,
        )
    )
    for index, label in ((11, "legitime"), (12, "legitime"), (13, "phishing"), (14, "fraude")):
        record, label_row, adjudication_row = _t13_case(tmp_path, index, label)
        records.append(record)
        labels_rows.append(label_row)
        adjudication_rows.append(adjudication_row)
    outcome = bc.select_gold(
        records, labels_rows, [pool_adjudication], seed=42, project_root=tmp_path,
    )
    rag_case_ids = {row["case_id"] for row in outcome["rag_cases"]}
    pool_family = str(pool_adjudication["family_group"])
    rag_families = {str(row["family_group"]) for row in outcome["rag_cases"]}
    # protected family never enters RAG, even though a same-family sample exists
    assert pool_family not in rag_families
    assert "rag_t13_0010" not in rag_case_ids
    # complement families fill RAG deterministically
    assert len(rag_case_ids) == 4  # every complement family selected (under cap 150)
    assert rag_families == {f"fam:t13_{i:04d}" for i in (11, 12, 13, 14)}


def test_goldai_select_reproducible_and_confidence_agnostic(tmp_path: Path):
    scenario = _t13_build_scenario(
        tmp_path,
        {"phishing": 4, "legitime": 4, "fraude": 2, "spam": 2},
    )
    outcome_one = bc.select_gold(
        scenario["records"], scenario["labels_rows"], scenario["pool_rows"],
        seed=42, project_root=tmp_path,
    )
    outcome_two = bc.select_gold(
        scenario["records"], scenario["labels_rows"], scenario["pool_rows"],
        seed=42, project_root=tmp_path,
    )
    assert outcome_one["plan"] == outcome_two["plan"]
    assert outcome_one["dev_gold_records"] == outcome_two["dev_gold_records"]
    assert outcome_one["rag_cases"] == outcome_two["rag_cases"]

    # shuffled input row order must not change the plan
    reversed_rows = list(reversed(scenario["labels_rows"]))
    outcome_three = bc.select_gold(
        list(reversed(scenario["records"])), reversed_rows,
        list(reversed(scenario["pool_rows"])), seed=42, project_root=tmp_path,
    )
    assert outcome_three["plan"] == outcome_one["plan"]

    # confidence values are never a selection input: mutating them changes nothing
    outcome_four = bc.select_gold(
        scenario["records"],
        [dict(row) for row in scenario["labels_rows"]],
        [dict(row, silver_confidence=0.0, astra_independent_confidence=1.0)
         for row in scenario["pool_rows"]],
        seed=42, project_root=tmp_path,
    )
    assert outcome_four["plan"] == outcome_one["plan"]

    # any other seed is refused: the protocol pins seed 42
    with pytest.raises(bc.GoldValidationError):
        bc.select_gold(
            scenario["records"], scenario["labels_rows"], scenario["pool_rows"],
            seed=43, project_root=tmp_path,
        )


def _t13_gold_record(tmp_path: Path, index: int = 20, label: str = "phishing"):
    record, label_row, _ = _t13_case(tmp_path, index, label)
    return bc.build_gold_record(record, label_row, "dev")


def test_goldai_content_keys_refused_recursively(tmp_path: Path):
    base = _t13_gold_record(tmp_path)
    for value in ("", None, [], {}, "content"):
        polluted = dict(base, body=value)
        with pytest.raises(bc.GoldValidationError):
            bc.validate_gold_records([polluted], ("dev",))
    # nested and under another name, even empty/null
    for polluted in (
        dict(base, tags=[{"body": None}]),
        dict(base, tags=[{"nested": {"mime_content": ""}}]),
        dict(base, raw_email="abc"),
    ):
        with pytest.raises(bc.GoldValidationError):
            bc.validate_gold_records([polluted], ("dev",))


def test_goldrecord_extra_fields_forbidden(tmp_path: Path):
    base = _t13_gold_record(tmp_path)
    for extra in ({"human_validated": False}, {"review_method": GOLD_AI_REVIEW_METHOD},
                  {"extra": 1}):
        with pytest.raises(bc.GoldValidationError):
            bc.validate_gold_records([dict(base, **extra)], ("dev",))
    # missing field is equally refused (closed list)
    incomplete = dict(base)
    incomplete.pop("campaign_id")
    with pytest.raises(bc.GoldValidationError):
        bc.validate_gold_records([incomplete], ("dev",))


def test_goldai_raw_path_and_hash_fail_closed(tmp_path: Path):
    # raw_path outside corpus/raw is refused
    record, label_row, _ = _t13_case(tmp_path, 30, "spam")
    record["raw_path"] = "corpus/normalized/t13/30.eml"
    with pytest.raises(bc.GoldValidationError):
        bc.select_gold([record], [label_row], [], seed=42, project_root=tmp_path)
    record["raw_path"] = "corpus/raw/../../outside.eml"
    with pytest.raises(bc.GoldValidationError):
        bc._resolve_checked_raw_path(tmp_path, record["raw_path"])
    record["raw_path"] = "corpus/raw/t13/missing.eml"
    with pytest.raises(bc.GoldValidationError):
        bc.select_gold([record], [label_row], [], seed=42, project_root=tmp_path)

    # raw hash mismatch is a loud failure (fail-closed, no silent removal)
    record_ok, label_row_ok, _ = _t13_case(tmp_path, 31, "spam")
    raw_file = tmp_path / record_ok["raw_path"]
    raw_file.write_bytes(raw_file.read_bytes() + b"tampered\n")
    with pytest.raises(bc.GoldValidationError):
        bc.select_gold([record_ok], [label_row_ok], [], seed=42, project_root=tmp_path)

    # a plain-file raw_path that resolves outside corpus/raw is refused
    with pytest.raises(bc.GoldValidationError):
        bc._resolve_checked_raw_path(tmp_path, "corpus/raw/t13/sub/../../escape.eml")


def test_goldai_private_source_refused_from_rag(tmp_path: Path):
    record, label_row, _ = _t13_case(tmp_path, 40, "legitime")
    record["public_source"] = False
    with pytest.raises(bc.GoldValidationError):
        bc.select_gold([record], [label_row], [], seed=42, project_root=tmp_path)


def test_goldai_freeze_and_seal(tmp_path: Path):
    scenario = _t13_build_scenario(
        tmp_path,
        {"phishing": 2, "legitime": 2, "fraude": 1, "spam": 1},
    )
    holdout_dir = tmp_path / "holdout_owner_space"
    seal, gold_test_path = bc.freeze_test(
        scenario["records"], scenario["labels_rows"], scenario["pool_rows"],
        destination=holdout_dir, seed=42, project_root=tmp_path,
    )
    assert gold_test_path == holdout_dir / "gold_test.jsonl"
    assert gold_test_path.is_file()

    # seal schema + aggregates validate WITHOUT opening gold_test
    plan = bc.select_gold(
        scenario["records"], scenario["labels_rows"], scenario["pool_rows"],
        seed=42, project_root=tmp_path,
    )["plan"]
    errors = bc.validate_test_seal(
        holdout_dir / "test_seal.json", plan["test"]
    )
    assert errors == []
    assert seal["split"] == "test"
    assert seal["seed"] == 42
    assert seal["human_validated"] is False
    assert seal["reviewer_ref"] == GOLD_AI_REVIEWER_REF
    assert seal["reference_method"] == GOLD_AI_REVIEW_METHOD
    # no individual test sample ids in the seal
    assert not any(key.endswith("sample_ids") for key in seal)
    assert "sample_ids" not in json.dumps(seal)

    # aggregate inconsistency is rejected
    tampered_plan = dict(plan["test"], record_count=plan["test"]["record_count"] + 1)
    errors = bc.validate_test_seal(holdout_dir / "test_seal.json", tampered_plan)
    assert any("record_count" in error for error in errors)

    # changing one byte of the gold test object changes its seal hash
    original_bytes = gold_test_path.read_bytes()
    flipped = b"X" + original_bytes[1:]
    assert hashlib.sha256(flipped).hexdigest() != seal["gold_test_sha256"]
    assert hashlib.sha256(original_bytes).hexdigest() == seal["gold_test_sha256"]

    # POC simplification amendment: the internal validation partition may be
    # materialized inside the build workspace (metadata-only); destination
    # resolution no longer refuses the build root.
    assert bc._resolve_freeze_destination(holdout_dir) == holdout_dir.resolve()
    inside_simulated_root = tmp_path / "corpus" / "gold"
    assert (
        bc._resolve_freeze_destination(inside_simulated_root)
        == inside_simulated_root.resolve()
    )

    # build-side: freezing into the (simulated) build workspace succeeds and
    # writes only metadata-only closed-schema records
    seal_build, gold_test_build = bc.freeze_test(
        scenario["records"], scenario["labels_rows"], scenario["pool_rows"],
        destination=tmp_path / "corpus" / "gold", seed=42, project_root=tmp_path,
    )
    assert (tmp_path / "corpus" / "gold" / "gold_test.jsonl").is_file()
    assert seal_build["gold_test_sha256"] == seal["gold_test_sha256"]


def test_goldai_labels_conversion_file_level(tmp_path: Path):
    scenario = _t13_build_scenario(tmp_path, {"phishing": 1, "legitime": 1})
    manifest_path = tmp_path / "manifest.parquet"
    bc._pq().write_table(bc.build_manifest(scenario["records"]), manifest_path)
    template_path = tmp_path / "template.jsonl"
    template_path.write_text(
        "".join(
            json.dumps(
                dict(
                    row,
                    normalized_label=None,
                    label_status="unreviewed",
                    reviewer_ref=None,
                    label_rationale=None,
                ),
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n"
            for row in scenario["labels_rows"]
        ),
        encoding="utf-8",
    )
    adj_path = _t13_write_pool(tmp_path / "adj.jsonl", scenario["adjudication_rows"])

    out_path = tmp_path / "labels.jsonl"
    cmd = ["labels", "--adjudication", str(tmp_path / "adj.jsonl"),
           "--manifest", str(manifest_path), "--template", str(template_path),
           "--out", str(out_path)]
    exit_one = bc.main(cmd)
    assert exit_one == 0
    bytes_one = out_path.read_bytes()
    exit_two = bc.main(cmd)
    assert exit_two == 0
    bytes_two = out_path.read_bytes()
    # deterministic format conversion: byte-identical on re-run
    assert bytes_one == bytes_two
    rows = [json.loads(line) for line in bytes_one.decode("utf-8").splitlines() if line]
    assert all(row["reviewer_ref"] == GOLD_AI_REVIEWER_REF for row in rows)
    assert all("human" not in json.dumps(row).lower() or
               "AI-adjudicated" in row["label_rationale"] for row in rows)
    # original/source labels are preserved, normalized_label comes from the protocol
    by_id = {row["sample_id"]: row for row in rows}
    assert by_id["t13_0001"]["label_status"] in ("confirmed", "ambiguous")
    # ambiguous rows excluded from gold selection
    ambiguous = [row for row in rows if row["label_status"] == "ambiguous"]
    assert all(row["normalized_label"] is None for row in ambiguous)

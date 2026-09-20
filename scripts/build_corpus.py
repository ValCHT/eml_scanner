#!/usr/bin/env python3
"""Corpus inspection, normalization and deduplication (TICKET-12, G6).

Implements docs/tickets/TICKET-12.md on top of docs/corpus.md §7.3–§7.4:

- ``inspect``   : verifies the acquired raw archives against ``corpus/sources.json``
                  (hash-pinned, immutable), counts real messages and reports the
                  per-source inventory under ``runs/corpus/inspection/``.
- ``normalize`` : streams every raw message through the production parser
                  (``src.parsing.parse_bytes``, bytes only — source labels are
                  never passed to the parser), writes
                  ``corpus/normalized/emails.jsonl`` (metadata only), builds
                  ``corpus/manifest.parquet`` via :func:`build_manifest` and the
                  human-review template ``corpus/review/labels_template.jsonl``.
                  Source labels are kept verbatim in ``original_label``;
                  ``normalized_label`` stays null until human review.
- ``dedupe``    : exact duplicate components (raw SHA-256 and normalized-body
                  hash) plus bounded near-duplicate proximity (5-word shingles,
                  Jaccard >= 0.85; texts under 20 words compare by normalized
                  equality only) and family components, written back into the
                  manifest and the review template. ``--seed`` fixes the
                  deterministic candidate tie-breaking when a per-record
                  candidate pool is capped.

TICKET-13 (G6, operator-approved Gold-AI amendment, 2026-09-20):

- ``labels``       : deterministic format conversion of the externally produced,
                     operator-approved AI adjudication (``final_status =
                     ai_adjudicated``, ``reviewer_ref = astra_gold_ai_v1``,
                     ``human_validated = false``) onto the canonical review
                     interface ``corpus/review/labels.jsonl`` (template schema
                     preserved). This is a format conversion only — never new
                     semantic labeling by the coding agent — and the source
                     artefact stays the audit reference. Reference labels for
                     this exploratory POC are AI-adjudicated (Gold-AI), NOT
                     human analyst ground truth.
- ``select``       : deterministic SplitPlan over the operator-approved
                     protected Gold candidate pool: public RAG reservation
                     first (families never span splits; pool families are
                     excluded from RAG), then a label-stratified dev/test
                     split of the pool by ``family_group`` (seed 42).
                     Materializes ``corpus/gold/gold_dev.jsonl`` (dev only)
                     and ``corpus/rag/public_cases.jsonl`` plus the split
                     plan (test aggregates only).
- ``freeze``       : materializes ``gold_test.jsonl`` (metadata-only
                     GoldRecord data) and ``test_seal.json``. POC
                     simplification (operator amendment 2026-09-20): the
                     test split is an INTERNAL VALIDATION partition and may
                     live in the build workspace; it is not an independently
                     isolated or blinded holdout.
- ``verify-splits``: re-derives the plan from the same inputs and compares
                     it with the materialized artifacts (gold_dev, RAG,
                     gold_test); validates ``test_seal.json`` (schema,
                     aggregates, and gold_test.jsonl bytes match).

Interfaces (TICKET-13): :func:`select_gold`, :func:`freeze_test`,
:func:`validate_test_seal`.

Interfaces (TICKET-12): :func:`read_dataset`, :func:`fingerprint`,
:func:`build_manifest`. No archive is fabricated: sources declared
``not_acquired``/``not_provided`` in ``corpus/sources.json`` must stay absent.

Raw bytes are immutable: tar members are read in place (never extracted to
disk) and mbox members are byte-exact container derivatives (only the ``From ``
separator line is excluded; the transformation is recorded). A ``!`` in
``raw_path`` denotes ``<archive>!<member-or-ordinal>``; ``raw_sha256`` always
covers the exact message bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import sys
import tarfile
import unicodedata
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.parsing import ParseLimits, _strip_tags, parse_bytes  # noqa: E402
from src.state import ParsedEmail  # noqa: E402

SOURCES_PATH = Path("corpus/sources.json")
NORMALIZED_PATH = Path("corpus/normalized/emails.jsonl")
MANIFEST_PATH = Path("corpus/manifest.parquet")
LABELS_TEMPLATE_PATH = Path("corpus/review/labels_template.jsonl")

#: §2.3 has_full_headers coverage: From, To, Subject, Date, Message-ID,
#: Received and Return-Path present and non-empty. Authentication-Results and
#: DKIM-Signature stay independent dimensions (never part of the bool).
FULL_HEADERS_FIELDS = (
    "from",
    "to",
    "subject",
    "date",
    "message_id",
    "received",
    "return_path",
)
HEADER_PRESENCE_FIELDS = FULL_HEADERS_FIELDS + (
    "authentication_results",
    "dkim_signature",
)

#: 5-word shingles with Jaccard >= 0.85 (docs/corpus.md §7.4). Texts with
#: fewer than 20 words compare by normalized equality only.
SHINGLE_WORDS = 5
NEAR_DUP_JACCARD = 0.85
SHORT_TEXT_WORDS = 20
#: Bounded candidate pool (§7.4): a shingle seen in more than MAX_SHINGLE_DF
#: records is uninformative and generates no candidate pair; per-record
#: candidate pairs are capped and cap hits are reported, never hidden.
MAX_SHINGLE_DF = 32
MAX_CANDIDATES_PER_RECORD = 256

#: Hard guard while reading archive members; read failures become explicit
#: noted rows, never silent losses.
MAX_MEMBER_BYTES = 256 * 1024 * 1024

#: Aggregate decompressed-size bound for one archive during any re-read
#: (the dedupe raw re-derivation included). Exceeding it is an explicit
#: error, never a silent truncation.
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


class CorpusRawError(RuntimeError):
    """Explicit failure: a manifest row's raw bytes cannot be trusted
    (unresolvable/refused member, archive bound exceeded, or raw_sha256
    mismatch). Never downgraded to empty fingerprint text."""

#: Row-note markers proving a row is kept with an explicit note.
ROW_NOTE_TAGS = (
    "parse_error:",
    "empty_member",
    "unsafe_member_name_refused:",
    "member_too_large_refused:",
    "member_unreadable",
)

MANIFEST_FIELDS = (
    "sample_id",
    "source_id",
    "source_dataset",
    "source_subset",
    "source_record_id",
    "source_url",
    "public_source",
    "raw_path",
    "raw_sha256",
    "input_format",
    "original_label",
    "normalized_label",
    "label_status",
    "reviewer_ref",
    "label_rationale",
    "header_integrity",
    "header_presence",
    "has_full_headers",
    "has_received",
    "has_authentication_results",
    "has_text",
    "has_html",
    "has_urls",
    "has_attachments",
    "has_images",
    "has_original_attachment_bytes",
    "attachment_representation",
    "is_synthetic",
    "campaign_id",
    "body_sha256",
    "duplicate_group",
    "family_group",
    "split",
    "transformation_notes",
    "notes",
)


# ---------------------------------------------------------------------------
# Raw message readers (immutable raw: read in place, never extracted to disk).
# ---------------------------------------------------------------------------


class SourceMessage(NamedTuple):
    """One raw message yielded by a source reader.

    ``error`` is None for a normal message; otherwise it explains a refused
    entry (unsafe member name, oversized member) that still yields a noted
    manifest row — no line is ever lost silently.
    """

    source_record_id: str
    data: bytes
    error: str | None = None


def _member_is_safe(name: str) -> bool:
    """Reject absolute paths and ``..`` traversal in extractor input."""

    if name.startswith("/") or "\\" in name:
        return False
    candidate = PurePosixPath(name)
    if candidate.is_absolute():
        return False
    return ".." not in candidate.parts


def iter_tar_messages(
    archive: Path, limits: ParseLimits, exclude: Iterable[str] = ()
) -> Iterator[SourceMessage]:
    """Yield archive members in deterministic (name-sorted) order.

    Members are read in place; nothing is ever extracted to disk, so a
    traversal name cannot write anything anywhere — it is refused explicitly.
    Members listed in the source ``exclude_members`` (e.g. the SpamAssassin
    ``cmds`` metadata file) are skipped as declared non-messages.
    """

    excluded = {str(name) for name in exclude}
    with tarfile.open(archive, "r:*") as tar:
        members = sorted(
            (member for member in tar.getmembers() if member.isfile()),
            key=lambda member: member.name,
        )
        for member in members:
            if member.name in excluded or PurePosixPath(member.name).name in excluded:
                continue
            if not _member_is_safe(member.name):
                yield SourceMessage(
                    source_record_id=member.name,
                    data=b"",
                    error=f"unsafe_member_name_refused: {member.name}",
                )
                continue
            if member.size > MAX_MEMBER_BYTES:
                yield SourceMessage(
                    source_record_id=member.name,
                    data=b"",
                    error=f"member_too_large_refused: {member.size} bytes",
                )
                continue
            handle = tar.extractfile(member)
            if handle is None:  # pragma: no cover - isfile() guarantees a body
                yield SourceMessage(
                    source_record_id=member.name, data=b"", error="member_unreadable"
                )
                continue
            yield SourceMessage(source_record_id=member.name, data=handle.read())


def iter_mbox_messages(mailbox: Path, limits: ParseLimits) -> Iterator[SourceMessage]:
    """Yield byte-exact RFC822 members from an mbox container.

    A message starts at a ``From `` separator line at the beginning of the
    file or right after a blank line; the separator line itself is excluded
    from the member bytes (documented transformation). A ``From `` body line
    not preceded by a blank line stays inside the body.
    """

    data = mailbox.read_bytes()
    lines = data.splitlines(keepends=True)
    current: list[bytes] = []
    at_boundary = True  # start of file acts as a separator boundary
    ordinal = 0

    def flush() -> SourceMessage:
        nonlocal current, ordinal
        ordinal += 1
        message = b"".join(current)
        current = []
        return SourceMessage(source_record_id=f"{ordinal:04d}", data=message)

    for line in lines:
        stripped = line.rstrip(b"\r\n")
        if stripped.startswith(b"From ") and at_boundary:
            if current:
                yield flush()
            at_boundary = False
            continue
        current.append(line)
        at_boundary = stripped == b""
    if current:
        yield flush()
    if ordinal == 0 and lines:
        raise ValueError(f"mbox has no 'From ' separator line: {mailbox}")


def iter_source_messages(
    source: Mapping[str, Any], limits: ParseLimits
) -> Iterator[SourceMessage]:
    """Dispatch on ``source['kind']``; kinds without acquired data raise."""

    path = PROJECT_ROOT / str(source["path"])
    kind = str(source["kind"])
    if kind == "tar.bz2":
        return iter_tar_messages(path, limits, exclude=source.get("exclude_members") or ())
    if kind == "mbox":
        return iter_mbox_messages(path, limits)
    if kind == "json":
        raise NotImplementedError(
            "json sources are declared not_acquired; no reader is fabricated "
            "for data that is not present (TICKET-12)"
        )
    raise ValueError(f"source kind {kind!r} has no reader")


# ---------------------------------------------------------------------------
# Fingerprint normalization (comparison only, docs/corpus.md §7.4).
# ---------------------------------------------------------------------------


def normalize_fingerprint_text(text: str) -> str:
    """NFKC + casefold + whitespace collapse; comparison-only normal form.

    URLs are deliberately NOT substituted in this baseline (conservative:
    distinct phishing URLs must not merge families); no tracking-token
    substitution is applied.
    """

    normalized = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"\s+", " ", normalized).strip()


def fingerprint_text_of_parsed(parsed: ParsedEmail | None) -> str:
    """Normalized body text: text/plain parts, else tag-stripped HTML parts."""

    if parsed is None:
        return ""
    texts = [part.text for part in parsed.text_parts if part.text]
    if not texts and parsed.html_parts:
        texts = [_strip_tags(part.text) for part in parsed.html_parts]
    return normalize_fingerprint_text("\n".join(texts))


def fingerprint_from_text(text: str) -> str:
    """SHA-256 hex of the fingerprint-normalized text (empty text → '')."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def fingerprint(record: Mapping[str, Any]) -> str:
    """TICKET-12 interface: fingerprint of a normalized record.

    Returns the recorded ``body_sha256`` (digest of the fingerprint-
    normalized body text) or computes it from the in-memory ``body_text``.
    """

    if record.get("body_sha256"):
        return str(record["body_sha256"])
    return fingerprint_from_text(str(record.get("body_text", "")))


def word_count(text: str) -> int:
    return len(text.split())


# ---------------------------------------------------------------------------
# Normalized record.
# ---------------------------------------------------------------------------


class NormalizedRecord:
    """One normalized record: manifest fields plus in-memory-only text.

    A plain fixed-field container (no dynamic attributes): ``body_text`` is
    never persisted (metadata only in JSONL/Parquet; bodies stay in raw).
    """

    def __init__(self, **fields: Any) -> None:
        unknown = set(fields) - set(MANIFEST_FIELDS) - {"body_text"}
        if unknown:
            raise ValueError(f"unknown record fields: {sorted(unknown)}")
        defaulted = {
            "normalized_label": None,
            "reviewer_ref": None,
            "label_rationale": None,
            "is_synthetic": None,
            "campaign_id": None,
            "duplicate_group": "",
            "family_group": "",
            "split": "candidate",
            "transformation_notes": "",
            "notes": "",
            "body_text": "",
        }
        missing = (set(MANIFEST_FIELDS) | {"body_text"}) - set(fields) - set(defaulted)
        if missing:
            raise ValueError(f"missing record fields: {sorted(missing)}")
        object.__setattr__(self, "_fields", {**defaulted, **fields})

    @property
    def fields(self) -> dict[str, Any]:
        return dict(self._fields)

    def __getitem__(self, key: str) -> Any:
        return self._fields[key]

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._fields:
            raise KeyError(key)
        self._fields[key] = value

    def __contains__(self, key: object) -> bool:
        return key in self._fields

    def get(self, key: str, default: Any = None) -> Any:
        return self._fields.get(key, default)

    def persisted(self) -> dict[str, Any]:
        """Fields for JSONL/Parquet; ``body_text`` is never persisted."""

        return {key: self._fields[key] for key in MANIFEST_FIELDS}

    def header_presence(self) -> dict[str, bool]:
        return dict(self._fields["header_presence"])


# ---------------------------------------------------------------------------
# Record building (parser sees bytes only — never labels).
# ---------------------------------------------------------------------------

_HEADER_FIELD_CANONICAL = {
    "from": "From",
    "to": "To",
    "subject": "Subject",
    "date": "Date",
    "message_id": "Message-ID",
    "received": "Received",
    "return_path": "Return-Path",
    "authentication_results": "Authentication-Results",
    "dkim_signature": "DKIM-Signature",
}


def _header_presence(parsed: ParsedEmail | None) -> dict[str, bool]:
    if parsed is None:
        return {field: False for field in HEADER_PRESENCE_FIELDS}
    present: set[str] = set()
    for header in parsed.headers:
        name = header.name.lower().strip()
        if not header.decoded_value.strip():
            continue
        for field, canonical in _HEADER_FIELD_CANONICAL.items():
            if name == canonical.lower():
                present.add(field)
    return {field: field in present for field in HEADER_PRESENCE_FIELDS}


def attachment_representation(parsed: ParsedEmail | None) -> str:
    """``bytes`` when decoded attachment bytes exist; ``filename`` when the
    corpus only carries names; ``absent`` when there is no attachment part."""

    if parsed is None or not parsed.attachments:
        return "absent"
    if any(att.decode_status == "ok" and att.sha256 for att in parsed.attachments):
        return "bytes"
    return "filename"


def header_integrity_for(input_format: str) -> str:
    """Local handling-chain integrity of the header block (docs/corpus.md §7.7):

    - ``rfc822``: bytes preserved verbatim from the archive member → original;
    - ``mbox_member``: byte stream derived from the container (separator line
      excluded) → transformed (the header block itself is untouched);
    - ``structured_public_text``: no SMTP headers to preserve → unknown.
    """

    if input_format == "rfc822":
        return "original"
    if input_format == "mbox_member":
        return "transformed"
    return "unknown"


def _merge_notes(*parts: str) -> str:
    return "; ".join(part for part in parts if part)


def build_record(
    source: Mapping[str, Any],
    source_message: SourceMessage,
    limits: ParseLimits,
    ordinal: int,
) -> NormalizedRecord:
    """Build one normalized record from raw bytes.

    The parser receives the message bytes only. Source labels never enter the
    parser and never alter the bytes (raw stays immutable). A parse failure
    keeps the row with an explicit note (no line lost without note).
    """

    data = source_message.data
    raw_sha256 = hashlib.sha256(data).hexdigest() if data else ""
    input_format = str(source["input_format"])

    parsed: ParsedEmail | None = None
    parse_note = source_message.error or ""
    if not parse_note:
        if not data:
            parse_note = "empty_member"
        else:
            outcome = parse_bytes(data, input_format, limits)
            if isinstance(outcome, ParsedEmail):
                parsed = outcome
            else:
                parse_note = f"parse_error: {outcome.error} ({outcome.detail})"

    body_text = fingerprint_text_of_parsed(parsed)
    presence = _header_presence(parsed)
    representation = attachment_representation(parsed)

    return NormalizedRecord(
        sample_id=f"{source['id']}_{ordinal:05d}",
        source_id=str(source["id"]),
        source_dataset=str(source["dataset"]),
        source_subset=str(source.get("subset", "")),
        source_record_id=source_message.source_record_id,
        source_url=source.get("source_url"),
        public_source=bool(source.get("public_source", True)),
        raw_path=f"{source['path']}!{source_message.source_record_id}",
        raw_sha256=raw_sha256,
        input_format=input_format,
        original_label=source.get("source_label"),
        label_status="unreviewed",
        header_integrity="unknown" if parse_note else header_integrity_for(input_format),
        header_presence=presence,
        has_full_headers=all(presence[field] for field in FULL_HEADERS_FIELDS),
        has_received=presence["received"],
        has_authentication_results=presence["authentication_results"],
        has_text=bool(parsed and any(part.text.strip() for part in parsed.text_parts)),
        has_html=bool(parsed and any(_strip_tags(p.text).strip() for p in parsed.html_parts)),
        has_urls=bool(parsed and parsed.links),
        has_attachments=bool(parsed and parsed.attachments),
        has_images=bool(parsed and parsed.images),
        has_original_attachment_bytes=representation == "bytes",
        attachment_representation=representation,
        body_text=body_text,
        body_sha256=fingerprint_from_text(body_text),
        transformation_notes=str(source.get("transformation_notes", "")),
        notes=_merge_notes(
            parse_note,
            (
                "content_limits: " + ",".join(parsed.content_limits)
                if parsed is not None and parsed.content_limits
                else ""
            ),
        ),
    )


def read_dataset(source: Mapping[str, Any]) -> Iterator[NormalizedRecord]:
    """TICKET-12 interface: iterate normalized records of one source spec.

    Statuses other than ``acquired`` yield nothing (declared absence). The
    parser receives message bytes only — never labels, paths or notes.
    """

    if source.get("status") != "acquired":
        return
    limits = ParseLimits()
    ordinal = 0
    for source_message in iter_source_messages(source, limits):
        ordinal += 1
        yield build_record(source, source_message, limits, ordinal)


# ---------------------------------------------------------------------------
# Manifest (Parquet) and JSONL writers.
# ---------------------------------------------------------------------------


def _pa() -> Any:
    import pyarrow as pa

    return pa


def _pq() -> Any:
    import pyarrow.parquet as pq

    return pq


def manifest_schema() -> Any:
    pa = _pa()
    string = pa.string()
    return pa.schema(
        [
            ("sample_id", string),
            ("source_id", string),
            ("source_dataset", string),
            ("source_subset", string),
            ("source_record_id", string),
            ("source_url", string),
            ("public_source", pa.bool_()),
            ("raw_path", string),
            ("raw_sha256", string),
            ("input_format", string),
            ("original_label", string),
            ("normalized_label", string),
            ("label_status", string),
            ("reviewer_ref", string),
            ("label_rationale", string),
            ("header_integrity", string),
            ("header_presence", string),  # JSON object of the 9 header fields
            ("has_full_headers", pa.bool_()),
            ("has_received", pa.bool_()),
            ("has_authentication_results", pa.bool_()),
            ("has_text", pa.bool_()),
            ("has_html", pa.bool_()),
            ("has_urls", pa.bool_()),
            ("has_attachments", pa.bool_()),
            ("has_images", pa.bool_()),
            ("has_original_attachment_bytes", pa.bool_()),
            ("attachment_representation", string),
            ("is_synthetic", pa.bool_()),
            ("campaign_id", string),
            ("body_sha256", string),
            ("duplicate_group", string),
            ("family_group", string),
            ("split", string),
            ("transformation_notes", string),
            ("notes", string),
        ]
    )


def build_manifest(records: Iterable[NormalizedRecord]) -> Any:
    """TICKET-12 interface: build the Parquet manifest table (metadata only)."""

    pa = _pa()
    columns: dict[str, list[Any]] = {name: [] for name in MANIFEST_FIELDS}
    for record in records:
        row = record.persisted()
        for name in MANIFEST_FIELDS:
            value = row[name]
            columns[name].append(
                json.dumps(value, ensure_ascii=False, sort_keys=True)
                if name == "header_presence"
                else value
            )
    return pa.Table.from_pydict(columns, schema=manifest_schema())


def write_jsonl_records(path: Path, records: Iterable[NormalizedRecord]) -> int:
    """Write ``corpus/normalized/emails.jsonl`` (metadata only, one per line)."""

    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(
                json.dumps(record.persisted(), ensure_ascii=False, sort_keys=True) + "\n"
            )
            count += 1
    return count


def write_labels_template(path: Path, records: Iterable[NormalizedRecord]) -> int:
    """Write the human-review template (separate file, no pre-filled label).

    No message content; ``normalized_label`` stays null and ``label_status``
    stays ``unreviewed`` until a human analyst decides.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            row = record.persisted()
            handle.write(
                json.dumps(
                    {
                        "sample_id": row["sample_id"],
                        "source_dataset": row["source_dataset"],
                        "source_record_id": row["source_record_id"],
                        "raw_sha256": row["raw_sha256"],
                        "raw_path": row["raw_path"],
                        "original_label": row["original_label"],
                        "normalized_label": None,
                        "candidate_label": None,
                        "label_status": "unreviewed",
                        "reviewer_ref": None,
                        "label_rationale": None,
                        "duplicate_group": row["duplicate_group"],
                        "family_group": row["family_group"],
                        "notes": "",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )
            count += 1
    return count


def read_manifest(path: Path) -> list[NormalizedRecord]:
    """Read a manifest.parquet back into normalized records."""

    table = _pq().read_table(path)
    if list(table.schema.names) != list(MANIFEST_FIELDS):
        raise ValueError(f"unexpected manifest schema in {path}")
    records: list[NormalizedRecord] = []
    for row in table.to_pylist():
        presence = row["header_presence"]
        row["header_presence"] = json.loads(presence) if presence else {}
        records.append(NormalizedRecord(**row))
    return records


# ---------------------------------------------------------------------------
# Deduplication (docs/corpus.md §7.4): exact, proximity, families.
# ---------------------------------------------------------------------------


class _UnionFind:
    def __init__(self, keys: Iterable[str]) -> None:
        self.parent: dict[str, str] = {key: key for key in keys}

    def find(self, key: str) -> str:
        root = key
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[key] != root:
            self.parent[key], key = root, self.parent[key]
        return root

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            # Deterministic: the lexicographically smaller root wins.
            if root_b < root_a:
                root_a, root_b = root_b, root_a
            self.parent[root_b] = root_a

    def components(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = defaultdict(list)
        for key in sorted(self.parent):
            groups[self.find(key)].append(key)
        return dict(groups)


def _jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _shingle_hashes(text: str) -> list[str]:
    """5-word shingles, hashed; empty for texts under the shingle floor."""

    words = text.split()
    if len(words) < SHINGLE_WORDS:
        return []
    return [
        hashlib.blake2b(
            " ".join(words[index : index + SHINGLE_WORDS]).encode("utf-8"),
            digest_size=8,
        ).hexdigest()
        for index in range(len(words) - SHINGLE_WORDS + 1)
    ]


def _component_id(prefix: str, members: Iterable[str]) -> str:
    digest = hashlib.sha256(",".join(sorted(members)).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:16]}"


def compute_duplicate_families(
    records: Iterable[NormalizedRecord],
    text_by_sample: Mapping[str, str],
    seed: int = 42,
) -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    """Assign exact ``duplicate_group`` and ``family_group`` components.

    Exact duplication links records sharing ``raw_sha256`` or a non-empty
    ``body_sha256``. Proximity links (5-word shingles, Jaccard >= 0.85, on a
    bounded candidate pool) extend family components across sources. Group
    ids are content-derived; ``seed`` only fixes the deterministic
    tie-break when a candidate pool is capped.
    """

    by_sample = {record["sample_id"]: record for record in records}
    sample_ids = sorted(by_sample)

    exact = _UnionFind(sample_ids)
    for attribute in ("raw_sha256", "body_sha256"):
        buckets: dict[str, list[str]] = defaultdict(list)
        for sample_id in sample_ids:
            value = by_sample[sample_id][attribute]
            if value:
                buckets[value].append(sample_id)
        for members in buckets.values():
            for other in members[1:]:
                exact.union(members[0], other)

    family = _UnionFind(sample_ids)
    for members in exact.components().values():
        for other in members[1:]:
            family.union(members[0], other)

    # --- bounded near-duplicate candidate pool -----------------------------
    shingles_by_sample = {
        sample_id: set(_shingle_hashes(text_by_sample.get(sample_id, "")))
        for sample_id in sample_ids
    }
    document_frequency: dict[str, int] = defaultdict(int)
    for hashes in shingles_by_sample.values():
        for shingle in hashes:
            document_frequency[shingle] += 1
    inverted: dict[str, list[str]] = defaultdict(list)
    for sample_id in sample_ids:
        for shingle in sorted(shingles_by_sample[sample_id]):
            if document_frequency[shingle] <= MAX_SHINGLE_DF:
                inverted[shingle].append(sample_id)

    candidate_pairs: set[frozenset[str]] = set()
    candidate_cap_hits = 0
    for sample_id in sample_ids:
        candidates: set[str] = set()
        for shingle in sorted(shingles_by_sample[sample_id]):
            if document_frequency[shingle] > MAX_SHINGLE_DF:
                continue
            candidates.update(inverted[shingle])
        candidates.discard(sample_id)
        if len(candidates) > MAX_CANDIDATES_PER_RECORD:
            candidate_cap_hits += 1
            rng = random.Random(seed)
            candidates = set(rng.sample(sorted(candidates), MAX_CANDIDATES_PER_RECORD))
        for other in candidates:
            candidate_pairs.add(frozenset((sample_id, other)))

    near_links = 0
    for pair in sorted(candidate_pairs, key=sorted):
        first, second = sorted(pair)
        text_first = text_by_sample.get(first, "")
        text_second = text_by_sample.get(second, "")
        if word_count(text_first) < SHORT_TEXT_WORDS or word_count(text_second) < SHORT_TEXT_WORDS:
            # §7.4: short texts compare by normalized equality only.
            if text_first and text_first == text_second:
                family.union(first, second)
                near_links += 1
            continue
        score = _jaccard(shingles_by_sample[first], shingles_by_sample[second])
        if score >= NEAR_DUP_JACCARD:
            family.union(first, second)
            near_links += 1

    duplicate_groups = {
        sample_id: _component_id("dup", members)
        for members in exact.components().values()
        for sample_id in members
    }
    family_groups = {
        sample_id: _component_id("fam", members)
        for members in family.components().values()
        for sample_id in members
    }

    datasets = {sample_id: by_sample[sample_id]["source_dataset"] for sample_id in sample_ids}
    stats = {
        "records": len(sample_ids),
        "exact_multi_groups": sum(
            1 for members in exact.components().values() if len(members) > 1
        ),
        "near_links": near_links,
        "candidate_pairs_compared": len(candidate_pairs),
        "candidate_cap_hits": candidate_cap_hits,
        "families_multi_members": sum(
            1 for members in family.components().values() if len(members) > 1
        ),
        "intersource_families": sum(
            1
            for members in family.components().values()
            if len({datasets[member] for member in members}) > 1
        ),
        "largest_family": max(
            (len(members) for members in family.components().values()), default=1
        ),
    }
    return duplicate_groups, family_groups, stats


def _read_tar_members(
    archive: Path,
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_total_bytes: int = MAX_ARCHIVE_UNCOMPRESSED_BYTES,
) -> dict[str, bytes]:
    """Read regular members of a tar archive once, raw stays read-only.

    Applies the same rules as ingestion: unsafe member names and members
    over the per-member bound are **refused without being read** (a manifest
    row referencing them fails explicitly downstream), and the aggregate
    uncompressed size of one archive is bounded — exceeding the bound
    raises :class:`CorpusRawError` instead of reading on.
    """

    members: dict[str, bytes] = {}
    total_bytes = 0
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if not _member_is_safe(member.name):
                continue  # refused, never read
            if member.size > max_member_bytes:
                continue  # refused, never read
            if total_bytes + member.size > max_total_bytes:
                raise CorpusRawError(
                    f"archive uncompressed size exceeds bound "
                    f"({max_total_bytes} bytes): {archive}"
                )
            handle = tar.extractfile(member)
            if handle is None:  # pragma: no cover - isfile() guarantees a body
                continue
            data = handle.read()
            total_bytes += len(data)
            members[member.name] = data
    return members


def _read_mbox_members(mailbox: Path) -> dict[str, bytes]:
    return {
        message.source_record_id: message.data
        for message in iter_mbox_messages(mailbox, ParseLimits())
    }


def load_texts_from_raw(
    records: Iterable[NormalizedRecord],
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_total_bytes: int = MAX_ARCHIVE_UNCOMPRESSED_BYTES,
) -> tuple[dict[str, str], set[str]]:
    """Re-derive fingerprint text from the immutable raw bytes.

    Comparison-only (docs/corpus.md §7.4): the manifest stays content-free;
    proximity needs the normalized text, recomputed here from raw.

    Fail-closed rules (TICKET-12 review):
    - a record with an empty ``raw_sha256`` is an ingestion-refused row
      (unsafe/oversized/empty member): no text is derived and it is counted,
      never treated as readable;
    - otherwise the resolved bytes must be non-empty **and**
      ``sha256(data) == record.raw_sha256`` before any fingerprint is
      derived; anything else raises :class:`CorpusRawError` explicitly.

    Returns ``(texts, refused_ids)``; an empty fingerprint text for a
    readable, hash-verified row is legitimate (empty body), not an error.
    """

    limits = ParseLimits()
    tar_cache: dict[str, dict[str, bytes]] = {}
    mbox_cache: dict[str, dict[str, bytes]] = {}
    texts: dict[str, str] = {}
    refused: set[str] = set()
    for record in records:
        sample_id = str(record["sample_id"])
        expected_sha = str(record["raw_sha256"])
        if not expected_sha:
            refused.add(sample_id)
            texts[sample_id] = ""
            continue
        data = _read_mbox_or_tar(
            str(record["raw_path"]),
            str(record["input_format"]),
            tar_cache,
            mbox_cache,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
        )
        if not data:
            raise CorpusRawError(
                f"raw bytes unresolvable for {sample_id}: {record['raw_path']} "
                "(refused/unsafe/oversized member or missing raw file)"
            )
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha:
            raise CorpusRawError(
                f"raw_sha256 mismatch for {sample_id}: manifest={expected_sha} "
                f"actual={actual_sha} ({record['raw_path']})"
            )
        parsed = parse_bytes(data, str(record["input_format"]), limits)
        texts[sample_id] = fingerprint_text_of_parsed(
            parsed if isinstance(parsed, ParsedEmail) else None
        )
    return texts, refused


def _read_mbox_or_tar(
    raw_path: str,
    input_format: str,
    tar_cache: dict[str, dict[str, bytes]],
    mbox_cache: dict[str, dict[str, bytes]],
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_total_bytes: int = MAX_ARCHIVE_UNCOMPRESSED_BYTES,
) -> bytes:
    """Resolve ``<archive>!<member-or-ordinal>`` (or a plain file path)."""

    archive_ref, _, member = raw_path.partition("!")
    if not member:
        try:
            return (PROJECT_ROOT / raw_path).read_bytes()
        except OSError:
            return b""
    archive = PROJECT_ROOT / archive_ref
    if input_format == "mbox_member":
        if archive_ref not in mbox_cache:
            mbox_cache[archive_ref] = _read_mbox_members(archive)
        return mbox_cache[archive_ref].get(member, b"")
    if archive.suffix.lower() in (".bz2", ".gz", ".xz", ".tar"):
        if archive_ref not in tar_cache:
            tar_cache[archive_ref] = _read_tar_members(
                archive,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes,
            )
        return tar_cache[archive_ref].get(member, b"")
    try:
        return archive.read_bytes()  # pragma: no cover - unknown raw layout
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------


def load_sources(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("corpus/sources.json must contain a non-empty 'sources' list")
    required = {"id", "dataset", "kind", "status", "path", "input_format"}
    for source in sources:
        missing = required - set(source)
        if missing:
            raise ValueError(
                f"source {source.get('id')!r} missing fields: {sorted(missing)}"
            )
    ids = [source["id"] for source in sources]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate source ids in corpus/sources.json")
    return sources


def acquired_sources(sources: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [source for source in sources if source.get("status") == "acquired"]


def cmd_inspect(args: argparse.Namespace) -> int:
    sources_path = Path(args.sources)
    sources = load_sources(sources_path)
    limits = ParseLimits()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "command": "inspect",
        "sources_json_sha256": hashlib.sha256(sources_path.read_bytes()).hexdigest(),
        "sources": [],
        "totals": {},
    }
    problems: list[str] = []
    total_messages = 0
    for source in sources:
        entry: dict[str, Any] = {
            "id": source["id"],
            "dataset": source["dataset"],
            "status": source["status"],
            "source_url": source.get("source_url"),
            "path": source["path"],
        }
        status = str(source["status"])
        path = PROJECT_ROOT / str(source["path"])
        if status == "acquired":
            if not path.is_file():
                entry["verified"] = False
                entry["problem"] = "declared acquired but file missing"
                problems.append(f"{source['id']}: declared acquired but file missing")
                report["sources"].append(entry)
                continue
            size = path.stat().st_size
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entry.update(
                size_bytes=size,
                sha256=digest,
                acquired_utc=source.get("acquired_utc"),
                verified=True,
            )
            expected_sha = source.get("sha256")
            expected_size = source.get("size_bytes")
            if expected_sha and expected_sha != digest:
                entry["verified"] = False
                entry["problem"] = "sha256 mismatch against corpus/sources.json"
                problems.append(f"{source['id']}: sha256 mismatch")
                report["sources"].append(entry)
                continue
            if expected_size is not None and int(expected_size) != size:
                entry["verified"] = False
                entry["problem"] = "size mismatch against corpus/sources.json"
                problems.append(f"{source['id']}: size mismatch")
                report["sources"].append(entry)
                continue
            counts: dict[str, Any] = {
                "messages": 0,
                "parse_failures": 0,
                "refused_members": 0,
                "lexical_url_messages": 0,
                "parsed_url_messages": 0,
                "html_messages": 0,
                "text_messages": 0,
                "messages_with_attachments": 0,
                "messages_with_images": 0,
                "attachments_with_bytes": 0,
                "header_coverage": {field: 0 for field in HEADER_PRESENCE_FIELDS},
            }
            for message in iter_source_messages(source, limits):
                if message.error is not None:
                    counts["refused_members"] += 1
                    continue
                counts["messages"] += 1
                counts["lexical_url_messages"] += int(
                    b"http://" in message.data or b"https://" in message.data
                )
                parsed = parse_bytes(message.data, str(source["input_format"]), limits)
                if not isinstance(parsed, ParsedEmail):
                    counts["parse_failures"] += 1
                    continue
                counts["parsed_url_messages"] += int(bool(parsed.links))
                counts["html_messages"] += int(bool(parsed.html_parts))
                counts["text_messages"] += int(
                    any(part.text.strip() for part in parsed.text_parts)
                )
                counts["messages_with_attachments"] += int(bool(parsed.attachments))
                counts["messages_with_images"] += int(bool(parsed.images))
                counts["attachments_with_bytes"] += int(
                    any(
                        attachment.decode_status == "ok" and attachment.sha256
                        for attachment in parsed.attachments
                    )
                )
                for field, present in _header_presence(parsed).items():
                    counts["header_coverage"][field] += int(present)
            entry["counts"] = counts
            total_messages += counts["messages"]
        elif status in ("not_acquired", "not_provided"):
            has_content = path.exists() and (
                any(path.iterdir()) if path.is_dir() else True
            )
            if has_content:
                entry["verified"] = False
                entry["problem"] = (
                    f"declared {status} but path has content (fabrication guard)"
                )
                problems.append(f"{source['id']}: declared {status} but path has content")
            else:
                entry["verified"] = True
                entry["declaration"] = str(source.get("transformation_notes", ""))
        else:
            entry["verified"] = False
            entry["problem"] = f"unknown status {status!r}"
            problems.append(f"{source['id']}: unknown status {status!r}")
        report["sources"].append(entry)

    report["totals"] = {
        "declared_sources": len(sources),
        "acquired_sources": len(acquired_sources(sources)),
        "raw_messages_total": total_messages,
        "problems": problems,
    }
    (out_dir / "inspection.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )

    lines = [
        "# Corpus inspection — TICKET-12",
        "",
        "| source | status | messages | sha256 (12) | acquired (UTC) |",
        "|---|---|---:|---|---|",
    ]
    for entry in report["sources"]:
        digest = entry.get("sha256")
        lines.append(
            "| {id} | {status} | {messages} | {sha} | {utc} |".format(
                id=entry["id"],
                status=entry["status"],
                messages=entry.get("counts", {}).get("messages", "—"),
                sha=digest[:12] + "…" if digest else "—",
                utc=entry.get("acquired_utc") or "—",
            )
        )
    lines += ["", f"raw messages total: {total_messages}", f"problems: {len(problems)}"]
    lines += [f"- {problem}" for problem in problems]
    (out_dir / "inspection.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        f"inspect: {len(sources)} declared sources, "
        f"{len(acquired_sources(sources))} acquired, {total_messages} raw messages, "
        f"{len(problems)} problems"
    )
    if problems:
        for problem in problems:
            print(f"  problem: {problem}")
        return 1
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    sources = load_sources(Path(args.sources))
    targets = acquired_sources(sources)
    if not targets:
        print("FAIL: no acquired source in corpus/sources.json", file=sys.stderr)
        return 2
    limits = ParseLimits()

    records: list[NormalizedRecord] = []
    per_source: dict[str, int] = defaultdict(int)
    for source in targets:
        for record in read_dataset(source):
            records.append(record)
            per_source[source["id"]] += 1
        if per_source[source["id"]] == 0:
            print(
                f"FAIL: source {source['id']!r} declared acquired but produced 0 messages",
                file=sys.stderr,
            )
            return 2

    normalized_path = PROJECT_ROOT / NORMALIZED_PATH
    manifest_path = PROJECT_ROOT / MANIFEST_PATH
    labels_path = PROJECT_ROOT / LABELS_TEMPLATE_PATH
    if manifest_path.is_file():
        manifest_path.unlink()  # normalize owns the manifest; dedupe extends it

    jsonl_count = write_jsonl_records(normalized_path, records)
    manifest = build_manifest(records)
    _pq().write_table(manifest, manifest_path)
    template_count = write_labels_template(labels_path, records)

    if not (jsonl_count == template_count == manifest.num_rows == len(records)):
        print(
            f"FAIL: count mismatch jsonl={jsonl_count} template={template_count} "
            f"manifest={manifest.num_rows} records={len(records)}",
            file=sys.stderr,
        )
        return 1

    parse_failures = 0
    for record in records:
        if any(tag in record["notes"] for tag in ROW_NOTE_TAGS):
            parse_failures += 1
    summary = {
        "command": "normalize",
        "acquired_source_ids": sorted(str(source["id"]) for source in targets),
        "records_total": len(records),
        "records_per_source": dict(sorted(per_source.items())),
        "rows_with_parse_note": parse_failures,
        "normalized_label_all_null": all(
            record["normalized_label"] is None for record in records
        ),
        "label_status_values": sorted({record["label_status"] for record in records}),
        "input_format_values": sorted({record["input_format"] for record in records}),
        "jsonl_path": str(normalized_path),
        "manifest_path": str(manifest_path),
        "labels_template_path": str(labels_path),
    }
    out_dir = PROJECT_ROOT / "runs" / "corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "normalize.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(
        f"normalize: {len(records)} records "
        f"({', '.join(f'{key}={value}' for key, value in sorted(per_source.items()))}); "
        f"{parse_failures} rows kept with explicit parse notes"
    )
    return 0


def cmd_dedupe(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = PROJECT_ROOT / manifest_path
    records = read_manifest(manifest_path)
    if not records:
        print(f"FAIL: empty manifest {manifest_path}", file=sys.stderr)
        return 2

    try:
        texts, refused = load_texts_from_raw(records)
    except CorpusRawError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        print(
            "FAIL: dedupe stopped before writing anything (fail-closed, "
            "no silent fingerprint)",
            file=sys.stderr,
        )
        return 2
    empty_text_rows = sorted(
        sample for sample, text in texts.items() if not text and sample not in refused
    )
    duplicate_groups, family_groups, stats = compute_duplicate_families(
        records, texts, seed=int(args.seed)
    )
    for record in records:
        record["duplicate_group"] = duplicate_groups[record["sample_id"]]
        record["family_group"] = family_groups[record["sample_id"]]

    tmp_path = manifest_path.with_name(manifest_path.name + ".tmp")
    _pq().write_table(build_manifest(records), tmp_path)
    shutil.move(tmp_path, manifest_path)
    write_jsonl_records(PROJECT_ROOT / NORMALIZED_PATH, records)
    write_labels_template(PROJECT_ROOT / LABELS_TEMPLATE_PATH, records)

    stats["seed"] = int(args.seed)
    stats["refused_rows_no_raw_sha256"] = len(refused)
    stats["empty_fingerprint_text_rows"] = len(empty_text_rows)
    stats["note"] = (
        "every readable row was sha256-verified against manifest raw_sha256 "
        "before fingerprinting; refused rows (empty raw_sha256) keep their "
        "note and are counted, never silently fingerprinted "
        "(docs/corpus.md §7.4)"
    )
    out_dir = PROJECT_ROOT / "runs" / "corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dedupe.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(
        f"dedupe: {stats['records']} records, {stats['exact_multi_groups']} exact groups >1, "
        f"{stats['near_links']} proximity links, {stats['intersource_families']} intersource "
        f"families (seed={args.seed})"
    )
    return 0


# ---------------------------------------------------------------------------
# TICKET-13 (G6): Gold-AI reference partitions — operator-approved amendment
# (2026-09-20). Reference labels for this exploratory POC are AI-adjudicated
# (Gold-AI: ChatGPT Silver annotation + GPT-6 Astra independent
# annotation/adjudication); they are NOT human analyst ground truth and are
# never described as such. The external adjudication artefact is the audit
# source; the mapping to the canonical review schema is a deterministic format
# conversion, not new semantic labeling by the coding agent.
# ---------------------------------------------------------------------------

LABELS_PATH = Path("corpus/review/labels.jsonl")
GOLD_DEV_PATH = Path("corpus/gold/gold_dev.jsonl")
TEST_SEAL_PATH = Path("corpus/gold/test_seal.json")
PUBLIC_CASES_PATH = Path("corpus/rag/public_cases.jsonl")
SPLIT_PLAN_PATH = Path("runs/tickets/TICKET-13/split_plan.json")

#: Fixed six-class taxonomy (docs/contracts.md §2.1 Label).
TAXONOMY_LABELS = (
    "spear_phishing",
    "phishing",
    "fraude",
    "menace",
    "spam",
    "legitime",
)

#: Real reviewer provenance of the operator-approved Gold-AI protocol. Never
#: rewritten, never claimed to be a human reviewer.
GOLD_AI_REVIEWER_REF = "astra_gold_ai_v1"
GOLD_AI_REVIEW_METHOD = "independent_dual_model_ai_adjudication"

#: Canonical review row (exactly the TICKET-12 review-template schema; closed).
CANONICAL_LABEL_FIELDS = (
    "sample_id",
    "source_dataset",
    "source_record_id",
    "raw_sha256",
    "raw_path",
    "original_label",
    "normalized_label",
    "candidate_label",
    "label_status",
    "reviewer_ref",
    "label_rationale",
    "duplicate_group",
    "family_group",
    "notes",
)

#: GoldRecord closed field list (docs/contracts.md §2.8). extra='forbid'.
GOLD_FIELDS = (
    "sample_id",
    "raw_sha256",
    "email_sha256",
    "raw_path",
    "source_dataset",
    "input_format",
    "normalized_label",
    "label_status",
    "reviewer_ref",
    "label_rationale",
    "public_source",
    "is_synthetic",
    "campaign_id",
    "duplicate_group",
    "family_group",
    "tags",
    "split",
)

#: RAG public-case source fields (docs/contracts.md §2.8). ``analyst_*`` names
#: are legacy V1 names for this Gold-AI POC run and do NOT imply a human
#: reviewer; provenance is carried by ``analyst_validation_ref`` = reviewer_ref.
RAG_FIELDS = (
    "case_id",
    "public_source_url",
    "dataset",
    "record_sha256",
    "validated_label",
    "analyst_validation_ref",
    "campaign_id",
    "duplicate_group",
    "family_group",
    "text_excerpt",
    "analyst_rationale",
    "is_public",
    "split",
)

#: Content keys refused anywhere inside a GoldRecord/RAG case (recursive,
#: case-insensitive) — even with an empty or null value.
GOLD_CONTENT_KEYS = (
    "body",
    "html",
    "headers",
    "raw",
    "raw_email",
    "mime_content",
    "text_parts",
    "html_parts",
    "attachments",
    "images",
    "text_excerpt",
)

#: Indicative six-class targets (docs/corpus.md §7.5); deficits stay visible
#: and are never filled with fabricated labels.
GOLD_TARGETS = {
    "spear_phishing": 30,
    "phishing": 50,
    "fraude": 30,
    "menace": 20,
    "spam": 30,
    "legitime": 40,
}

#: RAG reservation (operator amendment §10): seed 42, family granularity,
#: class caps first, deterministic fill without any confidence filter.
RAG_TARGET_TOTAL = 150
RAG_CLASS_CAPS = (("phishing", 50), ("legitime", 50), ("spam", 50))
RAG_FILL_CLASS = "fraude"
RAG_TEXT_EXCERPT_CHARS = 1200

SELECTION_PROTOCOL = (
    "gold_ai_operator_amendment_2026_09_20: "
    "RAG families reserved first from the eligible confirmed complement "
    "(protected operator Gold candidate pool families excluded), then "
    "label-stratified dev/test split of the protected pool by family_group, "
    "seed 42; family-granular, one record per family in RAG; no confidence "
    "value is ever used as a selection or easy-case filter; deficits stay "
    "visible, never filled."
)

SEAL_VERSION = "t13-gold-seal-1"
SEAL_REQUIRED_KEYS = (
    "version",
    "split",
    "record_count",
    "family_count",
    "label_support",
    "seed",
    "gold_test_sha256",
    "selection_protocol",
    "created_at",
    "reference_method",
    "reviewer_ref",
    "human_validated",
)


class GoldValidationError(RuntimeError):
    """GoldRecord/canonical-label/seal contract violation (fails the gate)."""


def _iter_forbidden_hits(
    obj: object, keys: tuple[str, ...], path: str = "$"
) -> list[str]:
    """Recursively find forbidden content keys (case-insensitive), even when
    the value is empty or null."""

    hits: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in keys:
                hits.append(f"{path}.{key}")
            hits.extend(_iter_forbidden_hits(value, keys, f"{path}.{key}"))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            hits.extend(_iter_forbidden_hits(value, keys, f"{path}[{index}]"))
    return hits


def _sha256_of_jsonl_rows(rows: Iterable[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(
            (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        )
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_canonical_label_row(row: Mapping[str, Any], where: str) -> None:
    """Canonical review row schema + Gold-AI provenance guard (fail-closed).

    - exact closed field set (template schema preserved, no extra keys — the
      canonical interface structurally cannot carry ``human_validated`` or
      other non-template keys);
    - ``label_status`` is ``confirmed`` (with a taxonomy label) or ``ambiguous``
      (with ``normalized_label`` null);
    - ``reviewer_ref`` is the real protocol provenance, never rewritten;
    - ``label_rationale`` must stay content-free (no forbidden content keys).
    """

    if set(row.keys()) != set(CANONICAL_LABEL_FIELDS):
        raise GoldValidationError(
            f"{where}: canonical label row field mismatch "
            f"(extra={sorted(set(row) - set(CANONICAL_LABEL_FIELDS))}, "
            f"missing={sorted(set(CANONICAL_LABEL_FIELDS) - set(row))})"
        )
    status = str(row["label_status"])
    if status not in ("confirmed", "ambiguous"):
        raise GoldValidationError(f"{where}: label_status {status!r} not accepted")
    label = row["normalized_label"]
    if status == "confirmed":
        if label not in TAXONOMY_LABELS:
            raise GoldValidationError(
                f"{where}: confirmed row without a taxonomy normalized_label "
                f"({label!r})"
            )
    else:
        if label is not None:
            raise GoldValidationError(
                f"{where}: ambiguous row must keep normalized_label null"
            )
    reviewer = str(row["reviewer_ref"] or "")
    if reviewer != GOLD_AI_REVIEWER_REF:
        raise GoldValidationError(
            f"{where}: reviewer_ref must remain {GOLD_AI_REVIEWER_REF!r} "
            f"(got {reviewer!r}); never claim a human reviewer"
        )
    content_hits = _iter_forbidden_hits(row, GOLD_CONTENT_KEYS)
    if content_hits:
        raise GoldValidationError(
            f"{where}: forbidden content key(s) {content_hits[:4]}"
        )


def load_canonical_labels(path: Path) -> dict[str, dict[str, Any]]:
    """Load the canonical ``corpus/review/labels.jsonl`` (closed schema)."""

    if not path.is_file():
        raise GoldValidationError(
            f"canonical labels missing: {path} — run the 'labels' subcommand "
            "(deterministic conversion of the operator-approved adjudication)"
        )
    labels: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            sample_id = str(row.get("sample_id") or "")
            if not sample_id:
                raise GoldValidationError(f"{path}:{number}: empty sample_id")
            if sample_id in labels:
                raise GoldValidationError(
                    f"{path}:{number}: duplicate sample_id {sample_id!r}"
                )
            _validate_canonical_label_row(row, f"{path}:{number}")
            labels[sample_id] = row
    if not labels:
        raise GoldValidationError(f"{path}: no canonical label rows")
    return labels


def load_adjudication(path: Path) -> dict[str, dict[str, Any]]:
    """Load the operator-approved AI adjudication artefact (audit source).

    Only rows exactly matching the approved Gold-AI protocol are eligible:
    ``final_status`` in {ai_adjudicated, ambiguous}, a taxonomy final label
    for ai_adjudicated rows, ``human_validated`` explicitly false (never
    rewritten), ``reviewer_ref`` == the real AI reference and
    ``review_method`` == the recorded dual-model adjudication method.
    """

    if not path.is_file():
        raise GoldValidationError(
            f"operator adjudication artefact missing: {path} "
            "(never fabricated here)"
        )
    adjudication: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            where = f"{path}:{number}"
            sample_id = str(row.get("sample_id") or "")
            status = str(row.get("final_status") or "")
            if not sample_id:
                raise GoldValidationError(f"{where}: empty sample_id")
            if sample_id in adjudication:
                raise GoldValidationError(f"{where}: duplicate sample_id")
            if status not in ("ai_adjudicated", "ambiguous"):
                raise GoldValidationError(
                    f"{where}: final_status {status!r} is outside the "
                    "operator-approved protocol"
                )
            if status == "ai_adjudicated":
                if str(row.get("final_label")) not in TAXONOMY_LABELS:
                    raise GoldValidationError(
                        f"{where}: unsupported final_label "
                        f"{row.get('final_label')!r}"
                    )
                if not str(row.get("raw_sha256") or ""):
                    raise GoldValidationError(f"{where}: raw_sha256 missing")
                if not str(row.get("family_group") or ""):
                    raise GoldValidationError(f"{where}: family_group missing")
            if row.get("human_validated") is not False:
                raise GoldValidationError(
                    f"{where}: human_validated must stay explicitly false "
                    "(Gold-AI protocol; human validation is never fabricated "
                    "or simulated)"
                )
            if str(row.get("reviewer_ref") or "") != GOLD_AI_REVIEWER_REF:
                raise GoldValidationError(
                    f"{where}: reviewer_ref must remain {GOLD_AI_REVIEWER_REF!r}"
                )
            if (
                str(row.get("review_method") or "") != GOLD_AI_REVIEW_METHOD
            ):
                raise GoldValidationError(
                    f"{where}: review_method must remain "
                    f"{GOLD_AI_REVIEW_METHOD!r}"
                )
            adjudication[sample_id] = row
    if not adjudication:
        raise GoldValidationError(f"{path}: no adjudication rows")
    return adjudication


def load_gold_candidates(
    path: Path, adjudication: Mapping[str, Mapping[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Load the operator-selected protected Gold candidate pool.

    The pool is taken exactly as provided (no re-ranking, no easy-case
    substitution, no class filling): every row must itself match the approved
    Gold-AI protocol, and — when the full adjudication map is supplied — must
    exist in it with identical provenance. Sample ids and family_groups must
    be unique (one record per family).
    """

    if not path.is_file():
        raise GoldValidationError(
            f"operator Gold candidate pool missing: {path} (never fabricated)"
        )
    pool: list[dict[str, Any]] = []
    seen_samples: set[str] = set()
    seen_families: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            where = f"{path}:{number}"
            sample_id = str(row.get("sample_id") or "")
            family = str(row.get("family_group") or "")
            if not sample_id or not family:
                raise GoldValidationError(f"{where}: empty sample_id/family_group")
            if sample_id in seen_samples:
                raise GoldValidationError(
                    f"{where}: duplicate Gold candidate sample {sample_id!r}"
                )
            if family in seen_families:
                raise GoldValidationError(
                    f"{where}: duplicate Gold candidate family {family!r}"
                )
            if str(row.get("final_status") or "") != "ai_adjudicated":
                raise GoldValidationError(
                    f"{where}: Gold candidate must be ai_adjudicated"
                )
            if str(row.get("final_label") or "") not in TAXONOMY_LABELS:
                raise GoldValidationError(
                    f"{where}: unsupported Gold candidate final_label "
                    f"{row.get('final_label')!r}"
                )
            if row.get("human_validated") is not False:
                raise GoldValidationError(
                    f"{where}: human_validated must remain explicitly false"
                )
            if str(row.get("reviewer_ref") or "") != GOLD_AI_REVIEWER_REF:
                raise GoldValidationError(
                    f"{where}: reviewer_ref must remain {GOLD_AI_REVIEWER_REF!r}"
                )
            if str(row.get("review_method") or "") != GOLD_AI_REVIEW_METHOD:
                raise GoldValidationError(
                    f"{where}: review_method must remain {GOLD_AI_REVIEW_METHOD!r}"
                )
            if adjudication is not None:
                source = adjudication.get(sample_id)
                if source is None:
                    raise GoldValidationError(
                        f"{where}: Gold candidate {sample_id!r} absent from "
                        "the full adjudication artefact"
                    )
                for key in ("raw_sha256", "family_group", "final_label"):
                    if str(row.get(key)) != str(source.get(key)):
                        raise GoldValidationError(
                            f"{where}: {key} disagrees with the adjudication "
                            f"artefact ({row.get(key)!r} vs {source.get(key)!r})"
                        )
            if not str(row.get("raw_sha256") or ""):
                raise GoldValidationError(f"{where}: raw_sha256 missing")
            seen_samples.add(sample_id)
            seen_families.add(family)
            pool.append(row)
    if not pool:
        raise GoldValidationError(f"{path}: empty Gold candidate pool")
    return pool


def _adjudication_rationale(row: Mapping[str, Any], status: str) -> str:
    """Content-free rationale: protocol provenance only, never message
    content, never a human-validation claim."""

    origin = (
        "dual independent AI agreement"
        if str(row.get("agreement")) == "AGREE"
        else "Astra adjudication after AI disagreement/ambiguity"
    )
    if status == "ai_adjudicated":
        return (
            "AI-adjudicated POC reference (Gold-AI); "
            f"{origin}; provenance retained in TICKET-13 audit artefact."
        )
    return (
        "AI-adjudicated POC reference marked ambiguous; excluded from Gold "
        "and RAG; provenance retained in TICKET-13 audit artefact."
    )


def build_canonical_labels(
    adjudication: Mapping[str, Mapping[str, Any]],
    manifest_records: Iterable[NormalizedRecord],
    template_rows: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Deterministic format conversion onto the canonical review interface.

    Joins each operator-approved adjudication row onto the TICKET-12 review
    template/manifest by ``sample_id``, requiring exact equality of
    ``sample_id``/``raw_sha256``/``family_group`` against BOTH. Template
    metadata is preserved verbatim; ``normalized_label``/``label_status``/
    ``reviewer_ref``/``label_rationale`` come from the protocol rules. This is
    a format conversion only — never new semantic labeling.
    """

    manifest_rows = list(manifest_records)
    if not manifest_rows:
        raise GoldValidationError("empty manifest for canonical conversion")
    manifest_by_id = {
        str(record["sample_id"]): record for record in manifest_rows
    }
    if len(manifest_by_id) != len(manifest_rows):
        raise GoldValidationError(
            "duplicate sample_id in manifest for canonical conversion"
        )
    template_by_id = {str(row["sample_id"]): dict(row) for row in template_rows}
    rows: list[dict[str, Any]] = []
    mismatches: list[str] = []
    for sample_id in sorted(adjudication):
        adjudication_row = adjudication[sample_id]
        manifest_row = manifest_by_id.get(sample_id)
        template_row = template_by_id.get(sample_id)
        if manifest_row is None or template_row is None:
            mismatches.append(f"{sample_id}: missing from manifest/template")
            continue
        for key in ("raw_sha256", "family_group"):
            for source_name, source in (
                ("manifest", manifest_row),
                ("template", template_row),
            ):
                actual = str(source[key])
                if actual != str(adjudication_row[key]):
                    mismatches.append(
                        f"{sample_id}: {key} mismatch between adjudication "
                        f"({adjudication_row[key]!r}) and {source_name} "
                        f"({actual!r})"
                    )
        if mismatches and mismatches[-1].startswith(f"{sample_id}:"):
            continue
        status = str(adjudication_row["final_status"])
        label = (
            str(adjudication_row["final_label"])
            if status == "ai_adjudicated"
            else None
        )
        canonical = {
            "sample_id": str(template_row["sample_id"]),
            "source_dataset": template_row["source_dataset"],
            "source_record_id": template_row["source_record_id"],
            "raw_sha256": template_row["raw_sha256"],
            "raw_path": template_row["raw_path"],
            "original_label": template_row["original_label"],
            "normalized_label": label,
            "candidate_label": template_row.get("candidate_label"),
            "label_status": "confirmed" if status == "ai_adjudicated" else "ambiguous",
            "reviewer_ref": GOLD_AI_REVIEWER_REF,
            "label_rationale": _adjudication_rationale(adjudication_row, status),
            "duplicate_group": template_row["duplicate_group"],
            "family_group": template_row["family_group"],
            "notes": template_row.get("notes", ""),
        }
        rows.append(canonical)
    if mismatches:
        raise GoldValidationError(
            "adjudication/manifest/template join failed (fail-closed, no "
            f"canonical labels written): {'; '.join(mismatches[:5])}"
        )
    rows.sort(key=lambda row: row["sample_id"])
    confirmed = [row for row in rows if row["label_status"] == "confirmed"]
    ambiguous = [row for row in rows if row["label_status"] == "ambiguous"]
    summary = {
        "total": len(rows),
        "confirmed": len(confirmed),
        "ambiguous": len(ambiguous),
        "confirmed_distribution": {
            label: sum(1 for row in confirmed if row["normalized_label"] == label)
            for label in sorted(TAXONOMY_LABELS)
        },
        "reviewer_ref": GOLD_AI_REVIEWER_REF,
        "human_validation_claimed": False,
        "terminology": (
            "AI-adjudicated reference labels (Gold-AI), reference-confirmed; "
            "NOT human ground truth, NOT analyst-validated"
        ),
    }
    return rows, summary


def write_labels_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> int:
    """Write the canonical ``labels.jsonl`` (deterministic, closed schema)."""

    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            )
            count += 1
    return count


def build_gold_record(
    manifest_row: NormalizedRecord, label_row: Mapping[str, Any], split: str
) -> dict[str, Any]:
    """Closed GoldRecord (docs/contracts.md §2.8): metadata/labels only.

    ``email_sha256`` is the V1 field, obligatorily equal to ``raw_sha256``.
    Provenance stays truthful: ``reviewer_ref`` carries the real Gold-AI
    reference; no human validation is claimed anywhere.
    """

    if label_row["label_status"] != "confirmed":
        raise GoldValidationError(
            f"{label_row['sample_id']}: only confirmed rows become GoldRecords"
        )
    return {
        "sample_id": str(manifest_row["sample_id"]),
        "raw_sha256": str(manifest_row["raw_sha256"]),
        "email_sha256": str(manifest_row["raw_sha256"]),
        "raw_path": str(manifest_row["raw_path"]),
        "source_dataset": str(manifest_row["source_dataset"]),
        "input_format": str(manifest_row["input_format"]),
        "normalized_label": label_row["normalized_label"],
        "label_status": "confirmed",
        "reviewer_ref": label_row["reviewer_ref"],
        "label_rationale": label_row["label_rationale"],
        "public_source": bool(manifest_row["public_source"]),
        "is_synthetic": manifest_row["is_synthetic"],
        "campaign_id": manifest_row["campaign_id"],
        "duplicate_group": str(manifest_row["duplicate_group"]),
        "family_group": str(manifest_row["family_group"]),
        "tags": ["gold_ai", "ai_adjudicated", "reference_confirmed"],
        "split": split,
    }


def build_rag_case(
    manifest_row: NormalizedRecord,
    label_row: Mapping[str, Any],
    text_excerpt: str,
) -> dict[str, Any]:
    """Public RAG case source row (docs/contracts.md §2.8). Public only."""

    excerpt = (text_excerpt or "").strip()[:RAG_TEXT_EXCERPT_CHARS]
    return {
        "case_id": f"rag_{manifest_row['sample_id']}",
        "public_source_url": str(manifest_row["source_url"]),
        "dataset": str(manifest_row["source_dataset"]),
        "record_sha256": str(manifest_row["raw_sha256"]),
        "validated_label": label_row["normalized_label"],
        "analyst_validation_ref": label_row["reviewer_ref"],
        "campaign_id": manifest_row["campaign_id"],
        "duplicate_group": str(manifest_row["duplicate_group"]),
        "family_group": str(manifest_row["family_group"]),
        "text_excerpt": excerpt,
        "analyst_rationale": label_row["label_rationale"],
        "is_public": True,
        "split": "rag_reference",
    }


def _resolve_checked_raw_path(project_root: Path, raw_path: str) -> Path:
    """Resolve a manifest ``raw_path`` and refuse anything outside
    ``corpus/raw/`` (relative to the given project root; symlink resolution
    included; contracts §2.8)."""

    if not raw_path:
        raise GoldValidationError("empty raw_path")
    pure = PurePosixPath(raw_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise GoldValidationError(
            f"raw_path escapes the corpus/raw perimeter: {raw_path!r}"
        )
    parts = pure.parts
    if len(parts) < 3 or parts[0] != "corpus" or parts[1] != "raw":
        raise GoldValidationError(
            f"raw_path must live under corpus/raw/**: {raw_path!r}"
        )
    root = Path(project_root)
    archive_ref = raw_path.partition("!")[0]
    resolved = (root / archive_ref).resolve()
    raw_root = (root / "corpus" / "raw").resolve()
    if resolved != raw_root and raw_root not in resolved.parents:
        raise GoldValidationError(
            f"raw_path escapes corpus/raw after link resolution: {raw_path!r}"
        )
    if not resolved.is_file():
        raise GoldValidationError(
            f"raw_path does not resolve to an existing file: {raw_path!r}"
        )
    return resolved


class _RawLoader:
    """Root-parameterized raw reader with per-root caches (tar/mbox members
    are read in place; raw stays immutable)."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = Path(project_root)
        self.tar_cache: dict[str, dict[str, bytes]] = {}
        self.mbox_cache: dict[str, dict[str, bytes]] = {}

    def load(self, raw_path: str, input_format: str) -> bytes:
        archive_ref, _, member = raw_path.partition("!")
        archive = _resolve_checked_raw_path(self.project_root, archive_ref)
        cache_key = str(archive)
        if not member:
            return archive.read_bytes()
        if input_format == "mbox_member":
            if cache_key not in self.mbox_cache:
                self.mbox_cache[cache_key] = _read_mbox_members(archive)
            data = self.mbox_cache[cache_key].get(member, b"")
        else:
            if cache_key not in self.tar_cache:
                self.tar_cache[cache_key] = _read_tar_members(archive)
            data = self.tar_cache[cache_key].get(member, b"")
        if not data:
            raise GoldValidationError(
                f"raw bytes unresolvable for {raw_path!r} "
                "(refused/unsafe/oversized member or missing raw file)"
            )
        return data

    def verified_bytes(
        self, sample_id: str, raw_path: str, raw_sha256: str, input_format: str
    ) -> bytes:
        data = self.load(raw_path, input_format)
        actual = hashlib.sha256(data).hexdigest()
        if actual != raw_sha256:
            raise GoldValidationError(
                f"raw_sha256 mismatch for {sample_id}: expected={raw_sha256} "
                f"actual={actual} ({raw_path}) — fail-closed, no silent sample "
                "removal"
            )
        return data


def _body_text_for_excerpt(data: bytes, input_format: str) -> str:
    """Body text for the public RAG excerpt (headers never included)."""

    parsed = parse_bytes(data, input_format, ParseLimits())
    if not isinstance(parsed, ParsedEmail):
        return ""
    text = "\n".join(part.text for part in parsed.text_parts if part.text)
    if not text and parsed.html_parts:
        text = "\n".join(_strip_tags(part.text) for part in parsed.html_parts)
    return text.strip()


def validate_gold_records(
    rows: Iterable[Mapping[str, Any]], expected_splits: tuple[str, ...]
) -> None:
    """Closed-schema + content-key validation of GoldRecords (fail-closed)."""

    for row in rows:
        where = f"gold[{row.get('sample_id')}]"
        if set(row.keys()) != set(GOLD_FIELDS):
            raise GoldValidationError(
                f"{where}: GoldRecord field mismatch "
                f"(extra={sorted(set(row) - set(GOLD_FIELDS))}, "
                f"missing={sorted(set(GOLD_FIELDS) - set(row))})"
            )
        content_hits = _iter_forbidden_hits(row, GOLD_CONTENT_KEYS)
        if content_hits:
            raise GoldValidationError(
                f"{where}: forbidden content key(s) {content_hits[:4]}"
            )
        if row["label_status"] != "confirmed":
            raise GoldValidationError(
                f"{where}: GoldRecord label_status must be confirmed"
            )
        if row["normalized_label"] not in TAXONOMY_LABELS:
            raise GoldValidationError(
                f"{where}: unsupported normalized_label {row['normalized_label']!r}"
            )
        if row["split"] not in expected_splits:
            raise GoldValidationError(
                f"{where}: split {row['split']!r} outside {expected_splits}"
            )
        if row["email_sha256"] != row["raw_sha256"]:
            raise GoldValidationError(
                f"{where}: email_sha256 must equal raw_sha256 (V1 invariant)"
            )
        for key in ("raw_sha256", "email_sha256"):
            value = str(row[key])
            if len(value) != 64 or value != value.lower():
                raise GoldValidationError(f"{where}: malformed {key}")
        if str(row["reviewer_ref"]) != GOLD_AI_REVIEWER_REF:
            raise GoldValidationError(
                f"{where}: reviewer_ref must remain {GOLD_AI_REVIEWER_REF!r}"
            )


def validate_rag_cases(rows: Iterable[Mapping[str, Any]]) -> None:
    """Closed-schema validation of public RAG cases (public only)."""

    for row in rows:
        case_id = str(row.get("case_id"))
        where = f"rag[{case_id}]"
        if set(row.keys()) != set(RAG_FIELDS):
            raise GoldValidationError(
                f"{where}: RAG case field mismatch "
                f"(extra={sorted(set(row) - set(RAG_FIELDS))}, "
                f"missing={sorted(set(RAG_FIELDS) - set(row))})"
            )
        if row["is_public"] is not True:
            raise GoldValidationError(f"{where}: private_source refused from RAG")
        if row["split"] != "rag_reference":
            raise GoldValidationError(f"{where}: split must be rag_reference")
        if row["validated_label"] not in TAXONOMY_LABELS:
            raise GoldValidationError(
                f"{where}: unsupported validated_label {row['validated_label']!r}"
            )
        content_hits = [
            hit
            for hit in _iter_forbidden_hits(row, GOLD_CONTENT_KEYS)
            if hit != "$.text_excerpt"
        ]
        if content_hits:
            raise GoldValidationError(
                f"{where}: forbidden content key(s) {content_hits[:4]}"
            )
        if len(str(row["text_excerpt"])) > RAG_TEXT_EXCERPT_CHARS:
            raise GoldValidationError(f"{where}: text_excerpt exceeds bound")


def _class_support(rows: Iterable[Mapping[str, Any]], label_key: str) -> dict[str, int]:
    counter: dict[str, int] = {label: 0 for label in TAXONOMY_LABELS}
    for row in rows:
        label = str(row[label_key])
        if label in counter:
            counter[label] += 1
    return counter


def select_gold(
    manifest_records: Iterable[NormalizedRecord],
    label_rows: Iterable[Mapping[str, Any]],
    gold_candidates: Iterable[Mapping[str, Any]],
    seed: int = 42,
    project_root: Path | None = None,
    rag_total: int = RAG_TARGET_TOTAL,
) -> dict[str, Any]:
    """Deterministic TICKET-13 SplitPlan over the operator-approved Gold pool.

    Preconditions enforced (fail-closed, before anything is written):
    - every Gold candidate exists in the canonical labels with
      ``label_status=confirmed`` and the same ``family_group``/label;
    - candidate families and sample ids are unique;
    - raw_path resolves under ``corpus/raw/**`` and ``raw_sha256`` matches the
      local bytes for every materialized dev and RAG record (mismatch = loud
      failure, no silent sample removal).

    Order of operations (protocol): reserve RAG first from the eligible
    confirmed complement (protected pool families excluded, public sources
    only), then label-stratified dev/test split of the protected pool by
    ``family_group`` (seed 42). The select command materializes dev records
    and RAG cases; test records are returned deterministically for the
    ``freeze`` step, which materializes the internal POC validation
    partition as metadata-only GoldRecords.
    """

    if seed != 42:
        raise GoldValidationError("selection protocol requires seed 42")
    project_root = Path(project_root) if project_root is not None else PROJECT_ROOT
    manifest_by_id = {str(record["sample_id"]): record for record in manifest_records}
    labels = {
        str(row["sample_id"]): dict(row)
        for row in label_rows
    }
    candidates = [dict(row) for row in gold_candidates]

    # --- protected pool guards ------------------------------------------------
    pool_samples: set[str] = set()
    pool_families: set[str] = set()
    for row in candidates:
        sample_id = str(row["sample_id"])
        family = str(row["family_group"])
        if sample_id in pool_samples or family in pool_families:
            raise GoldValidationError(
                f"duplicate Gold candidate sample/family: {sample_id!r}/{family!r}"
            )
        label_row = labels.get(sample_id)
        if label_row is None:
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} absent from canonical labels"
            )
        if label_row["label_status"] != "confirmed":
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} is not confirmed in canonical labels"
            )
        if str(label_row["normalized_label"]) != str(row["final_label"]):
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} label disagrees with canonical "
                f"labels ({row['final_label']!r} vs {label_row['normalized_label']!r})"
            )
        if str(row["raw_sha256"]) != str(label_row["raw_sha256"]):
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} raw_sha256 disagrees with "
                f"canonical labels ({row['raw_sha256']!r} vs "
                f"{label_row['raw_sha256']!r}) — fail-closed"
            )
        if str(label_row["family_group"]) != family:
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} family_group disagrees with "
                "canonical labels"
            )
        if sample_id not in manifest_by_id:
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} absent from the manifest"
            )
        if str(row["raw_sha256"]) != str(manifest_by_id[sample_id]["raw_sha256"]):
            raise GoldValidationError(
                f"Gold candidate {sample_id!r} raw_sha256 disagrees with the "
                f"manifest ({row['raw_sha256']!r} vs "
                f"{manifest_by_id[sample_id]['raw_sha256']!r}) — fail-closed"
            )
        pool_samples.add(sample_id)
        pool_families.add(family)

    # --- eligible confirmed complement for RAG --------------------------------
    complement: dict[str, dict[str, Any]] = {}
    refused_private: list[str] = []
    for sample_id, label_row in labels.items():
        if sample_id in pool_samples:
            continue
        if str(label_row["family_group"]) in pool_families:
            continue  # protected Gold family — never enters RAG
        if label_row["label_status"] != "confirmed":
            continue  # ambiguous rows are excluded from Gold and RAG
        manifest_row = manifest_by_id.get(sample_id)
        if manifest_row is None:
            raise GoldValidationError(
                f"confirmed sample {sample_id!r} missing from the manifest"
            )
        if not manifest_row["public_source"]:
            refused_private.append(sample_id)
            continue
        complement[sample_id] = label_row
    if refused_private:
        raise GoldValidationError(
            "private/non-public confirmed samples refused from the public "
            f"RAG pool: {sorted(refused_private)[:5]}"
        )

    # --- RAG reservation: family granularity, one record per family -----------
    mixed_label_families: set[str] = set()
    family_to_label: dict[str, str] = {}
    family_members: dict[str, list[str]] = {}
    for sample_id, label_row in complement.items():
        family = str(label_row["family_group"])
        label = str(label_row["normalized_label"])
        if family in family_to_label and family_to_label[family] != label:
            mixed_label_families.add(family)
            continue
        family_to_label[family] = label
        family_members.setdefault(family, []).append(sample_id)
    for family in mixed_label_families:
        family_to_label.pop(family, None)
        family_members.pop(family, None)

    rng = random.Random(seed)
    rag_families: list[str] = []
    rag_caps: dict[str, int] = {}
    for label, cap in RAG_CLASS_CAPS:
        class_families = sorted(
            family for family, fam_label in family_to_label.items()
            if fam_label == label
        )
        rng.shuffle(class_families)
        taken = class_families[:cap]
        rag_caps[label] = len(taken)
        rag_families.extend(taken)
    remaining = rag_total - len(rag_families)
    if remaining > 0:
        fill_families = sorted(
            family for family, fam_label in family_to_label.items()
            if fam_label == RAG_FILL_CLASS
        )
        rng.shuffle(fill_families)
        taken = fill_families[:remaining]
        rag_families.extend(taken)
        rag_caps[RAG_FILL_CLASS] = len(taken)
    rag_pool_overlap = sorted(set(rag_families) & pool_families)
    if rag_pool_overlap:
        raise GoldValidationError(
            f"protected Gold family entered RAG: {rag_pool_overlap[:5]}"
        )
    rag_sample_ids: list[str] = []
    for family in rag_families:
        rag_sample = sorted(family_members[family])[0]
        rag_sample_ids.append(rag_sample)
    rag_class_support = _class_support(
        [labels[sample] for sample in rag_sample_ids], "normalized_label"
    )

    # --- dev/test: label-stratified family split of the protected pool --------
    dev_samples: list[str] = []
    test_samples: list[str] = []
    for label in TAXONOMY_LABELS:
        class_families = sorted(
            str(row["family_group"]) for row in candidates
            if str(row["final_label"]) == label
        )
        rng.shuffle(class_families)
        half = len(class_families) // 2
        for index, family in enumerate(class_families):
            member = min(
                str(row["sample_id"]) for row in candidates
                if str(row["family_group"]) == family
            )
            (dev_samples if index < half else test_samples).append(member)
    test_class_support = _class_support(
        [labels[sample] for sample in test_samples], "normalized_label"
    )
    dev_class_support = _class_support(
        [labels[sample] for sample in dev_samples], "normalized_label"
    )

    # --- raw integrity for everything the build materializes (fail-closed) ----
    loader = _RawLoader(project_root)
    for sample_id in sorted(dev_samples + rag_sample_ids):
        manifest_row = manifest_by_id[sample_id]
        loader.verified_bytes(
            sample_id,
            str(manifest_row["raw_path"]),
            str(manifest_row["raw_sha256"]),
            str(manifest_row["input_format"]),
        )
    excerpts = {
        sample_id: _body_text_for_excerpt(
            loader.verified_bytes(
                sample_id,
                str(manifest_by_id[sample_id]["raw_path"]),
                str(manifest_by_id[sample_id]["raw_sha256"]),
                str(manifest_by_id[sample_id]["input_format"]),
            ),
            str(manifest_by_id[sample_id]["input_format"]),
        )
        for sample_id in sorted(rag_sample_ids)
    }

    rag_cases = [
        build_rag_case(
            manifest_by_id[sample], labels[sample], excerpts[sample]
        )
        for sample in sorted(rag_sample_ids)
    ]
    dev_records = [
        build_gold_record(manifest_by_id[sample], labels[sample], "dev")
        for sample in sorted(dev_samples)
    ]
    test_records = [
        build_gold_record(manifest_by_id[sample], labels[sample], "test")
        for sample in sorted(test_samples)
    ]
    validate_gold_records(dev_records, ("dev",))
    validate_gold_records(test_records, ("test",))
    validate_rag_cases(rag_cases)

    plan = {
        "selection_protocol": SELECTION_PROTOCOL,
        "seed": seed,
        "reference": {
            "kind": "gold_ai",
            "reviewer_ref": GOLD_AI_REVIEWER_REF,
            "review_method": GOLD_AI_REVIEW_METHOD,
            "human_validated": False,
        },
        "labels": {
            "confirmed": sum(
                1 for row in labels.values() if row["label_status"] == "confirmed"
            ),
            "ambiguous": sum(
                1 for row in labels.values() if row["label_status"] == "ambiguous"
            ),
        },
        "pool": {
            "count": len(candidates),
            "family_count": len(pool_families),
            "class_support": _class_support(candidates, "final_label"),
            "protected": True,
        },
        "dev": {
            "sample_ids": sorted(dev_samples),
            "record_count": len(dev_samples),
            "family_count": len({str(labels[s]["family_group"]) for s in dev_samples}),
            "class_support": dev_class_support,
        },
        "test": {
            # Aggregates ONLY in the plan — the individual test records are
            # materialized by `freeze` into gold_test.jsonl (internal POC
            # validation partition; metadata-only).
            "record_count": len(test_samples),
            "family_count": len(
                {str(labels[s]["family_group"]) for s in test_samples}
            ),
            "class_support": test_class_support,
        },
        "rag": {
            "count": len(rag_cases),
            "family_count": len(rag_families),
            "class_support": rag_class_support,
            "class_caps": dict(rag_caps),
            "deficits": {
                label: max(0, cap - rag_caps[label])
                for label, cap in RAG_CLASS_CAPS
            },
        },
        "intersections": {
            "dev_test_families": len(
                {str(labels[s]["family_group"]) for s in dev_samples}
                & {str(labels[s]["family_group"]) for s in test_samples}
            ),
            "rag_dev_families": len(
                {str(labels[s]["family_group"]) for s in rag_sample_ids}
                & {str(labels[s]["family_group"]) for s in dev_samples}
            ),
            "rag_test_families": len(
                {str(labels[s]["family_group"]) for s in rag_sample_ids}
                & {str(labels[s]["family_group"]) for s in test_samples}
            ),
        },
        "targets_vs_dev": {
            label: {
                "target": GOLD_TARGETS[label],
                "actual": dev_class_support[label],
                "deficit": max(0, GOLD_TARGETS[label] - dev_class_support[label]),
            }
            for label in sorted(TAXONOMY_LABELS)
        },
        "limitations": {
            "menace_reference_support": test_class_support["menace"] + dev_class_support["menace"],
            "spear_phishing_gold_support": dev_class_support["spear_phishing"] + test_class_support["spear_phishing"],
            "macro_f1_non_conclusive_if_class_unsupported": True,
        },
    }
    return {
        "plan": plan,
        "dev_gold_records": dev_records,
        "rag_cases": rag_cases,
        "test_gold_records": test_records,
    }


def _resolve_freeze_destination(destination: str | Path) -> Path:
    """Resolve the freeze destination (POC simplification, operator
    amendment 2026-09-20): the internal validation partition
    ``gold_test.jsonl`` may be materialized inside the build workspace as
    metadata-only GoldRecord data; only metadata-only closed-schema writes
    are permitted here, raw bytes stay in ``corpus/raw/**``."""

    return Path(destination).expanduser().resolve()


def freeze_test(
    manifest_records: Iterable[NormalizedRecord],
    label_rows: Iterable[Mapping[str, Any]],
    gold_candidates: Iterable[Mapping[str, Any]],
    destination: str | Path,
    seed: int = 42,
    project_root: Path | None = None,
    created_at: str | None = None,
) -> tuple[dict[str, Any], Path]:
    """Materialize the sealed test split and return the aggregate seal.

    POC simplification (operator amendment 2026-09-20): the test split is an
    INTERNAL VALIDATION partition — metadata-only GoldRecord data — and is
    materialized in the build workspace (e.g. ``corpus/gold``). Reproduces
    the exact same deterministic split as :func:`select_gold` (same inputs,
    seed 42), verifies every test record's raw hash, writes
    ``gold_test.jsonl`` (GoldRecords, split=test) and ``test_seal.json`` into
    the destination directory, and returns ``(seal, gold_test_path)``. The
    seal carries aggregates only — never individual test sample ids.
    """

    if seed != 42:
        raise GoldValidationError("selection protocol requires seed 42")
    project_root = Path(project_root) if project_root is not None else PROJECT_ROOT
    resolved_destination = _resolve_freeze_destination(destination)
    outcome = select_gold(
        manifest_records, label_rows, gold_candidates, seed=seed, project_root=project_root
    )
    test_records = outcome["test_gold_records"]
    validate_gold_records(test_records, ("test",))

    # Owner-side integrity: every test record's raw bytes are resolved under
    # the owner's local raw tree and hash-verified before sealing.
    loader = _RawLoader(project_root)
    for record in test_records:
        loader.verified_bytes(
            str(record["sample_id"]),
            str(record["raw_path"]),
            str(record["raw_sha256"]),
            str(record["input_format"]),
        )

    resolved_destination.mkdir(parents=True, exist_ok=True)
    gold_bytes = (
        "\n".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True)
            for row in test_records
        )
        + ("\n" if test_records else "")
    ).encode("utf-8")
    gold_test_path = resolved_destination / "gold_test.jsonl"
    gold_test_path.write_bytes(gold_bytes)
    digest = hashlib.sha256(gold_bytes).hexdigest()
    seal = {
        "version": SEAL_VERSION,
        "split": "test",
        "record_count": len(test_records),
        "family_count": len({str(row["family_group"]) for row in test_records}),
        "label_support": _class_support(test_records, "normalized_label"),
        "seed": seed,
        "gold_test_sha256": digest,
        "selection_protocol": SELECTION_PROTOCOL,
        "created_at": created_at
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reference_method": GOLD_AI_REVIEW_METHOD,
        "reviewer_ref": GOLD_AI_REVIEWER_REF,
        "human_validated": False,
    }
    seal_out_path = resolved_destination / "test_seal.json"
    seal_out_path.write_text(
        json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return seal, gold_test_path


def validate_test_seal(
    seal_path: Path, expected: Mapping[str, Any]
) -> list[str]:
    """Validate the external test seal schema and aggregates WITHOUT opening
    ``gold_test``. Returns a list of violations (empty = valid)."""

    if not seal_path.is_file():
        return [f"test seal missing: {seal_path}"]
    try:
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"test seal is not valid JSON: {exc}"]
    errors: list[str] = []
    for key in SEAL_REQUIRED_KEYS:
        if key not in seal:
            errors.append(f"missing key {key!r}")
    if errors:
        return errors
    if seal["version"] != SEAL_VERSION:
        errors.append(f"unexpected version {seal['version']!r}")
    if seal["split"] != "test":
        errors.append(f"split must be 'test', got {seal['split']!r}")
    if seal["seed"] != 42:
        errors.append("seed must be 42")
    if seal["human_validated"] is not False:
        errors.append("human_validated must remain false (Gold-AI reference)")
    if seal["reviewer_ref"] != GOLD_AI_REVIEWER_REF:
        errors.append(
            f"reviewer_ref must remain {GOLD_AI_REVIEWER_REF!r}"
        )
    if seal["reference_method"] != GOLD_AI_REVIEW_METHOD:
        errors.append(
            f"reference_method must remain {GOLD_AI_REVIEW_METHOD!r}"
        )
    if seal["selection_protocol"] != SELECTION_PROTOCOL:
        errors.append("selection_protocol mismatch")
    digest = str(seal["gold_test_sha256"])
    if len(digest) != 64 or digest != digest.lower():
        errors.append("gold_test_sha256 must be a lowercase SHA-256 hex digest")
    if not isinstance(seal["record_count"], int) or isinstance(seal["record_count"], bool):
        errors.append("record_count must be an integer")
    if not isinstance(seal["label_support"], dict):
        errors.append("label_support must be an object")
    if errors:
        return errors
    support = seal["label_support"]
    for label, value in support.items():
        if label not in TAXONOMY_LABELS:
            errors.append(f"unknown label {label!r} in label_support")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"label_support[{label!r}] must be a non-negative integer")
    if sum(int(v) for v in support.values()) != seal["record_count"]:
        errors.append("label_support does not sum to record_count")
    if not (
        isinstance(seal["family_count"], int)
        and not isinstance(seal["family_count"], bool)
    ) or seal["family_count"] < 0:
        errors.append("family_count must be a non-negative integer")
    elif seal["family_count"] > seal["record_count"]:
        errors.append("family_count exceeds record_count")
    # Aggregate consistency against the build-side recomputation.
    expected_support = (
        expected.get("label_support")
        or expected.get("class_support")
        or {}
    )
    if seal["record_count"] != expected.get("record_count"):
        errors.append(
            f"record_count disagrees with the build-side plan "
            f"({seal['record_count']} vs {expected.get('record_count')})"
        )
    if seal["family_count"] != expected.get("family_count"):
        errors.append(
            f"family_count disagrees with the build-side plan "
            f"({seal['family_count']} vs {expected.get('family_count')})"
        )
    if dict(support) != dict(expected_support):
        errors.append(
            "label_support disagrees with the build-side plan "
            f"({support} vs {expected_support})"
        )
    return errors


def _t13_input_path(raw: str | Path) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else PROJECT_ROOT / path


def cmd_labels(args: argparse.Namespace) -> int:
    """Deterministic conversion: operator-approved AI adjudication ->
    canonical ``corpus/review/labels.jsonl`` (format conversion only)."""

    adjudication_path = _t13_input_path(args.adjudication)
    adjudication = load_adjudication(adjudication_path)
    manifest = read_manifest(_t13_input_path(args.manifest))
    template_path = _t13_input_path(args.template)
    template_rows = [
        json.loads(line)
        for line in template_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not template_rows:
        print(f"FAIL: empty review template {template_path}", file=sys.stderr)
        return 2
    try:
        rows, summary = build_canonical_labels(adjudication, manifest, template_rows)
    except GoldValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    out_path = _t13_input_path(args.out)
    count = write_labels_jsonl(out_path, rows)

    audit_dir = PROJECT_ROOT / "runs" / "tickets" / "TICKET-13"
    audit_dir.mkdir(parents=True, exist_ok=True)
    summary.update(
        {
            "command": "labels",
            "adjudication_path": str(adjudication_path),
            "adjudication_sha256": _file_sha256(adjudication_path),
            "out_path": str(out_path),
            "out_sha256": _file_sha256(out_path),
            "row_count": count,
            "format_conversion_only": True,
            "new_semantic_labeling_by_agent": False,
        }
    )
    (audit_dir / "labels_import.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(
        f"labels: {summary['total']} canonical rows "
        f"({summary['confirmed']} confirmed, {summary['ambiguous']} ambiguous; "
        f"reviewer_ref={GOLD_AI_REVIEWER_REF}; human validation claimed: none)"
    )
    return 0


def cmd_select(args: argparse.Namespace) -> int:
    """Deterministic SplitPlan: RAG reservation + dev materialization +
    test aggregates. Never writes a test split or a seal."""

    try:
        outcome = select_gold(
            read_manifest(_t13_input_path(args.manifest)),
            list(load_canonical_labels(_t13_input_path(args.labels)).values()),
            load_gold_candidates(
                _t13_input_path(args.gold_candidates),
                adjudication=load_adjudication(_t13_input_path(args.adjudication)),
            ),
            seed=int(args.seed),
        )
    except GoldValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    plan = outcome["plan"]
    plan_path = _t13_input_path(args.plan_out)
    gold_dev_path = _t13_input_path(args.gold_dev)
    rag_path = _t13_input_path(args.rag_out)
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    gold_dev_path.parent.mkdir(parents=True, exist_ok=True)
    rag_path.parent.mkdir(parents=True, exist_ok=True)
    write_labels_jsonl(gold_dev_path, outcome["dev_gold_records"])
    write_labels_jsonl(rag_path, outcome["rag_cases"])
    plan_path.write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    audit_dir = PROJECT_ROOT / "runs" / "tickets" / "TICKET-13"
    audit_dir.mkdir(parents=True, exist_ok=True)
    pool_path = _t13_input_path(args.gold_candidates)
    receipt = {
        "command": "select",
        "seed": int(args.seed),
        "selection_protocol": SELECTION_PROTOCOL,
        "inputs": {
            "manifest": str(args.manifest),
            "labels": str(_t13_input_path(args.labels)),
            "labels_sha256": _file_sha256(_t13_input_path(args.labels)),
            "gold_candidates": str(pool_path),
            "gold_candidates_sha256": _file_sha256(pool_path),
        },
        "gold_dev_path": str(gold_dev_path),
        "public_cases_path": str(rag_path),
        "split_plan_path": str(plan_path),
        "dev": plan["dev"],
        "test_aggregates": plan["test"],
        "rag": plan["rag"],
        "intersections": plan["intersections"],
        "limitations": plan["limitations"],
        "test_split": "materialized by freeze as an internal POC validation "
        "partition (metadata-only; not an independent holdout — POC "
        "simplification amendment 2026-09-20)",
    }
    (audit_dir / "select.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    rag = plan["rag"]
    print(
        f"select: dev={plan['dev']['record_count']} "
        f"(families={plan['dev']['family_count']}), "
        f"test aggregate={plan['test']['record_count']} (families="
        f"{plan['test']['family_count']}, aggregates only), "
        f"RAG={rag['count']} (families={rag['family_count']}, "
        f"support={rag['class_support']}); intersections empty: "
        f"{all(value == 0 for value in plan['intersections'].values())}"
    )
    return 0


def cmd_freeze(args: argparse.Namespace) -> int:
    """Materialize the internal validation partition and its seal."""

    try:
        seal, gold_test_path = freeze_test(
            read_manifest(_t13_input_path(args.manifest)),
            list(load_canonical_labels(_t13_input_path(args.labels)).values()),
            load_gold_candidates(
                _t13_input_path(args.gold_candidates),
                adjudication=load_adjudication(_t13_input_path(args.adjudication)),
            ),
            destination=args.destination,
            seed=int(args.seed),
        )
    except GoldValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(
        f"freeze: gold_test.jsonl written to {gold_test_path} "
        f"(record_count={seal['record_count']}, family_count="
        f"{seal['family_count']}, gold_test_sha256="
        f"{seal['gold_test_sha256'][:12]}…); seal at {gold_test_path.parent / 'test_seal.json'}"
    )
    return 0


def cmd_verify_splits(args: argparse.Namespace) -> int:
    """Re-derive the plan and compare it with the materialized artifacts
    (gold_dev, public_cases, gold_test, split plan); validate the test seal
    (schema, aggregates, gold_test.jsonl bytes match)."""

    try:
        outcome = select_gold(
            read_manifest(_t13_input_path(args.manifest)),
            list(load_canonical_labels(_t13_input_path(args.labels)).values()),
            load_gold_candidates(
                _t13_input_path(args.gold_candidates),
                adjudication=load_adjudication(_t13_input_path(args.adjudication)),
            ),
            seed=int(args.seed),
        )
    except GoldValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    plan = outcome["plan"]
    problems: list[str] = []

    plan_path = _t13_input_path(args.plan_out)
    if not plan_path.is_file():
        problems.append(f"split plan missing: {plan_path}")
    else:
        on_disk = json.loads(plan_path.read_text(encoding="utf-8"))
        if on_disk != plan:
            problems.append("split_plan.json does not match the recomputation")

    gold_dev_path = _t13_input_path(args.gold_dev)
    if not gold_dev_path.is_file():
        problems.append(f"gold_dev.jsonl missing: {gold_dev_path}")
    else:
        dev_rows = [
            json.loads(line)
            for line in gold_dev_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if dev_rows != outcome["dev_gold_records"]:
            problems.append("gold_dev.jsonl does not match the recomputation")

    rag_path = _t13_input_path(args.rag_in)
    if not rag_path.is_file():
        problems.append(f"public_cases.jsonl missing: {rag_path}")
    else:
        rag_rows = [
            json.loads(line)
            for line in rag_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if rag_rows != outcome["rag_cases"]:
            problems.append("public_cases.jsonl does not match the recomputation")

    intersection_errors = [
        f"family intersection {name}={value} is not empty"
        for name, value in plan["intersections"].items()
        if value != 0
    ]
    problems.extend(intersection_errors)

    gold_test_path = PROJECT_ROOT / "corpus" / "gold" / "gold_test.jsonl"
    seal_path = _t13_input_path(args.seal)
    if not gold_test_path.is_file():
        problems.append(
            f"internal validation partition missing: {gold_test_path} — run "
            "the freeze step (POC simplification amendment)"
        )
    else:
        test_rows = [
            json.loads(line)
            for line in gold_test_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        try:
            validate_gold_records(test_rows, ("test",))
        except GoldValidationError as exc:
            problems.append(f"gold_test.jsonl invalid: {exc}")
        if test_rows != outcome["test_gold_records"]:
            problems.append(
                "gold_test.jsonl does not match the recomputed deterministic split"
            )
        digest = hashlib.sha256(gold_test_path.read_bytes()).hexdigest()
        if seal_path.is_file():
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            if str(seal.get("gold_test_sha256")) != digest:
                problems.append(
                    "test seal gold_test_sha256 does not match the "
                    "gold_test.jsonl bytes on disk"
                )

    seal_path = _t13_input_path(args.seal)
    if not seal_path.is_file():
        problems.append(
            f"test seal missing: {seal_path} — run the freeze step"
        )
    else:
        seal_errors = validate_test_seal(seal_path, plan["test"])
        problems.extend(f"test seal: {error}" for error in seal_errors)
        seal_note = (
            "test seal validated (schema + aggregates + gold_test.jsonl "
            "bytes match); internal validation partition materialized per "
            "the POC simplification amendment"
        )

    audit_dir = PROJECT_ROOT / "runs" / "tickets" / "TICKET-13"
    audit_dir.mkdir(parents=True, exist_ok=True)
    receipt = {
        "command": "verify-splits",
        "seed": int(args.seed),
        "problems": problems,
        "intersections": plan["intersections"],
        "dev": {"record_count": plan["dev"]["record_count"], "class_support": plan["dev"]["class_support"]},
        "rag": {"record_count": plan["rag"]["count"], "class_support": plan["rag"]["class_support"]},
        "test_aggregates": plan["test"],
        "seal_validated": seal_path.is_file() and not any(
            error.startswith("test seal") for error in problems
        ),
        "status_note": seal_note,
        "gold_test_partition": "internal POC validation partition (metadata-only; "
        "not an independent holdout — POC simplification amendment 2026-09-20)",
    }
    (audit_dir / "verify_splits.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(
        f"verify-splits: plan reproduced exactly; dev={plan['dev']['record_count']}, "
        f"RAG={plan['rag']['count']}, test aggregate={plan['test']['record_count']}; "
        f"{seal_note}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Corpus build/inspect/dedupe CLI (TICKET-12)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect", help="verify acquired archives and report counts"
    )
    inspect_parser.add_argument("--sources", default=str(SOURCES_PATH))
    inspect_parser.add_argument("--out", default="runs/corpus/inspection")
    inspect_parser.set_defaults(func=cmd_inspect)

    normalize_parser = subparsers.add_parser(
        "normalize", help="normalized JSONL + Parquet manifest + review template"
    )
    normalize_parser.add_argument("--sources", default=str(SOURCES_PATH))
    normalize_parser.set_defaults(func=cmd_normalize)

    dedupe_parser = subparsers.add_parser(
        "dedupe", help="duplicate/family groups written into the manifest"
    )
    dedupe_parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    dedupe_parser.add_argument("--seed", type=int, default=42)
    dedupe_parser.set_defaults(func=cmd_dedupe)

    # --- TICKET-13 (G6): Gold-AI reference partitions -------------------------

    labels_parser = subparsers.add_parser(
        "labels",
        help="deterministic conversion: operator AI adjudication -> canonical labels.jsonl",
    )
    labels_parser.add_argument("--adjudication", required=True)
    labels_parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    labels_parser.add_argument("--template", default=str(LABELS_TEMPLATE_PATH))
    labels_parser.add_argument("--out", default=str(LABELS_PATH))
    labels_parser.set_defaults(func=cmd_labels)

    select_parser = subparsers.add_parser(
        "select",
        help="TICKET-13 SplitPlan: RAG reservation + dev gold + test aggregates",
    )
    select_parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    select_parser.add_argument("--labels", default=str(LABELS_PATH))
    select_parser.add_argument("--adjudication", required=True)
    select_parser.add_argument("--gold-candidates", required=True)
    select_parser.add_argument("--seed", type=int, default=42)
    select_parser.add_argument("--gold-dev", default=str(GOLD_DEV_PATH))
    select_parser.add_argument("--rag-out", default=str(PUBLIC_CASES_PATH))
    select_parser.add_argument("--plan-out", default=str(SPLIT_PLAN_PATH))
    select_parser.set_defaults(func=cmd_select)

    freeze_parser = subparsers.add_parser(
        "freeze",
        help="materialize gold_test.jsonl (metadata-only) + test_seal.json "
        "(internal validation partition per the POC simplification amendment)",
    )
    freeze_parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    freeze_parser.add_argument("--labels", default=str(LABELS_PATH))
    freeze_parser.add_argument("--adjudication", required=True)
    freeze_parser.add_argument("--gold-candidates", required=True)
    freeze_parser.add_argument("--destination", default="corpus/gold")
    freeze_parser.add_argument("--seed", type=int, default=42)
    freeze_parser.set_defaults(func=cmd_freeze)

    verify_parser = subparsers.add_parser(
        "verify-splits",
        help="reproduce the plan, compare artifacts, validate the external seal",
    )
    verify_parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    verify_parser.add_argument("--labels", default=str(LABELS_PATH))
    verify_parser.add_argument("--adjudication", required=True)
    verify_parser.add_argument("--gold-candidates", required=True)
    verify_parser.add_argument("--seed", type=int, default=42)
    verify_parser.add_argument("--gold-dev", default=str(GOLD_DEV_PATH))
    verify_parser.add_argument("--rag-in", default=str(PUBLIC_CASES_PATH))
    verify_parser.add_argument("--plan-out", default=str(SPLIT_PLAN_PATH))
    verify_parser.add_argument("--seal", default=str(TEST_SEAL_PATH))
    verify_parser.set_defaults(func=cmd_verify_splits)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

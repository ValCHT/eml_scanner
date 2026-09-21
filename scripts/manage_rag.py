#!/usr/bin/env python3
"""TICKET-15 — local public-only RAG index management (gate G7-A).

A thin CLI over ``src.tools.rag.RagAdapter`` covering the frozen
``add`` / ``search`` / ``clear`` surface plus read-only ``stats``:

    python scripts/manage_rag.py add --input corpus/rag/public_cases.jsonl
    python scripts/manage_rag.py search --query "..." --k 3 --exclude fam:x,dup:y
    python scripts/manage_rag.py stats
    python scripts/manage_rag.py clear --yes

Public-only enforcement (fail-closed):

- the input file must pass the TICKET-13 closed-schema RAG validation
  (``scripts/build_corpus.validate_rag_cases``: exact field set, no content
  key anywhere, is_public=True, split=rag_reference, taxonomy label,
  text_excerpt ≤ 1200 chars);
- the Gold guard loads ``gold_dev.jsonl`` as metadata-only GoldRecords
  (same loader/validator as the evaluation) and refuses to index any case
  whose ``family_group`` is a dev Gold family or whose ``record_sha256``
  is a dev Gold record hash. ``gold_test.jsonl`` is NEVER opened by this
  ticket (build agents have no access to the sealed partition before
  T19E): the RAG/test disjointness is inherited from the TICKET-13
  deterministic split construction (RAG families are reserved first from
  the eligible confirmed complement, then dev/test are split by family
  from the protected Gold pool) and is re-verified when T19E is
  authorized. Only the AGGREGATE ``corpus/gold/test_seal.json`` (counts,
  hashes, provenance) is read and archived in the receipt — never used to
  reconstruct or open test membership;
- the embedding is the frozen chromadb ONNX ``all-MiniLM-L6-v2`` (version +
  SHA-256 fingerprint recorded in the collection metadata); no alternative
  model, no download outside chromadb's pinned archive.

Provenance (kept explicit, never overstated): the 150 public cases carry
operator-approved, AI-adjudicated labels (``astra_gold_ai_v1``,
``human_validated=false``) — they are NOT human analyst ground truth.

Artifacts: ``runs/tickets/TICKET-15/rag_receipt.json`` (per-command receipt:
command, file fingerprints, added counts, model info, isolation checks).
Exit 0 on success, 1 on refusal/validation failure, 2 when a required
optional dependency is missing (BLOCKED).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for _path in (str(SCRIPTS_DIR), str(PROJECT_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import build_corpus  # scripts/build_corpus.py: GoldRecord/RAG contract validation

from pydantic import ValidationError

from src.config import ToolsConfig, load_settings, load_yaml_config
from src.tools.rag import (
    RagAdapter,
    RagError,
    RagSourceCase,
    RagSourceError,
    RagUnavailableError,
)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2

RECEIPT_RELATIVE = Path("runs/tickets/TICKET-15/rag_receipt.json")
DEFAULT_INPUT = Path("corpus/rag/public_cases.jsonl")
DEFAULT_GOLD_DEV = Path("corpus/gold/gold_dev.jsonl")
DEFAULT_TEST_SEAL = Path("corpus/gold/test_seal.json")


@dataclass(frozen=True)
class GoldGuard:
    """Dev Gold metadata + the sealed test aggregate (gold_test never opened)."""

    families: frozenset[str]
    record_sha256: frozenset[str]
    dev_partition: dict[str, Any]
    test_seal: dict[str, Any]

    @property
    def summary(self) -> dict[str, Any]:
        """Receipt projection WITHOUT the full family listing of gold_dev."""

        return {
            "gold_dev": {
                key: value
                for key, value in self.dev_partition.items()
                if key != "families"
            },
            "gold_test_seal": self.test_seal,
            "gold_test_opened": False,
            "protected_family_count": len(self.families),
            "protected_record_hash_count": len(self.record_sha256),
        }


def load_test_seal(path: Path) -> dict[str, Any]:
    """Aggregate-only check of the sealed test partition (never opened).

    ``corpus/gold/test_seal.json`` is the TICKET-13 seal: aggregate counts,
    the partition hash and the selection protocol. It is read and archived
    as a seal — it is NEVER used to reconstruct or open test membership,
    and ``gold_test.jsonl`` stays unread before T19E.
    """

    if not path.is_file():
        raise build_corpus.GoldValidationError(f"test seal missing: {path}")
    try:
        seal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise build_corpus.GoldValidationError(f"test seal unreadable: {path} ({error})") from error
    if not isinstance(seal, dict):
        raise build_corpus.GoldValidationError(f"test seal is not a JSON object: {path}")
    problems: list[str] = []
    if seal.get("split") != "test":
        problems.append(f"split must be 'test' (got {seal.get('split')!r})")
    record_count = seal.get("record_count")
    family_count = seal.get("family_count")
    if not isinstance(record_count, int) or isinstance(record_count, bool) or record_count <= 0:
        problems.append("record_count must be a positive integer")
    if not isinstance(family_count, int) or isinstance(family_count, bool) or family_count <= 0:
        problems.append("family_count must be a positive integer")
    if record_count != family_count:
        problems.append("record_count and family_count must be equal (one record per family)")
    support = seal.get("label_support")
    if (
        not isinstance(support, dict)
        or not support
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in support.values()
        )
    ):
        problems.append("label_support must be a non-empty mapping of non-negative integers")
    elif isinstance(record_count, int) and sum(support.values()) != record_count:
        problems.append("label_support must sum to record_count")
    partition_hash = seal.get("gold_test_sha256")
    if (
        not isinstance(partition_hash, str)
        or len(partition_hash) != 64
        or any(character not in "0123456789abcdef" for character in partition_hash)
    ):
        problems.append("gold_test_sha256 must be 64 lowercase hex characters")
    if not isinstance(seal.get("human_validated"), bool):
        problems.append("human_validated must be an explicit boolean")
    if not str(seal.get("reviewer_ref") or "").strip():
        problems.append("reviewer_ref must state the reference method")
    if not str(seal.get("selection_protocol") or "").strip():
        problems.append("selection_protocol must document the deterministic split construction")
    if problems:
        raise build_corpus.GoldValidationError(
            "test seal invalid: " + "; ".join(problems)
        )
    protocol = str(seal["selection_protocol"])
    return {
        "path": str(path),
        "version": seal.get("version"),
        "split": seal["split"],
        "seal_sha256": _file_sha256(path),
        "gold_test_sha256": partition_hash,
        "record_count": record_count,
        "family_count": family_count,
        "label_support": dict(sorted(support.items())),
        "reviewer_ref": seal["reviewer_ref"],
        "human_validated": seal["human_validated"],
        "rag_families_reserved_before_dev_test_split": (
            "RAG families reserved first" in protocol
        ),
        "selection_protocol": protocol,
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path, where: str) -> list[dict[str, Any]]:
    if not path.is_file():
        raise build_corpus.GoldValidationError(f"{where}: file missing: {path}")
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise build_corpus.GoldValidationError(
                    f"{where}:{number}: invalid JSON ({error})"
                ) from error
            if not isinstance(row, dict):
                raise build_corpus.GoldValidationError(f"{where}:{number}: not a JSON object")
            rows.append(row)
    if not rows:
        raise build_corpus.GoldValidationError(f"{where}: file holds no record: {path}")
    return rows


def load_public_cases(path: Path) -> list[RagSourceCase]:
    """Closed-schema validation of the public RAG source, then typing."""

    rows = _read_jsonl(path, "public_cases")
    build_corpus.validate_rag_cases(rows)
    cases: list[RagSourceCase] = []
    for row in rows:
        try:
            cases.append(RagSourceCase.model_validate(row))
        except ValidationError as error:
            where = str(row.get("case_id", "<unknown>"))
            raise build_corpus.GoldValidationError(
                f"rag[{where}]: invalid public case ({error.error_count()} error(s))"
            ) from error
    return cases


def gold_isolation_guard(gold_dev_path: Path, test_seal_path: Path) -> GoldGuard:
    """Dev-only Gold guard + sealed-test aggregate.

    ``gold_dev.jsonl`` is opened as METADATA/label file with the full
    GoldRecord closed-schema validation (same loader as the evaluation) and
    used EXCLUSIVELY to enforce the family/record isolation invariant of the
    RAG index — never for labels, thresholds, tuning or any development
    decision. ``gold_test.jsonl`` is NOT opened: the RAG/test disjointness
    is inherited from the TICKET-13 deterministic split construction and is
    re-verified when T19E is authorized; only ``test_seal.json`` aggregates
    are read and archived.
    """

    rows = _read_jsonl(gold_dev_path, "gold[dev]")
    build_corpus.validate_gold_records(rows, expected_splits=("dev",))
    dev_families = {str(row["family_group"]) for row in rows}
    dev_hashes = {str(row["raw_sha256"]) for row in rows}
    seal = load_test_seal(test_seal_path)
    if seal["human_validated"] is False and str(seal["reviewer_ref"]) != "astra_gold_ai_v1":
        raise build_corpus.GoldValidationError(
            "test seal provenance is inconsistent: human_validated=false "
            "requires reviewer_ref=astra_gold_ai_v1"
        )
    return GoldGuard(
        families=frozenset(dev_families),
        record_sha256=frozenset(dev_hashes),
        dev_partition={
            "path": str(gold_dev_path),
            "record_count": len(rows),
            "family_count": len(dev_families),
            "families": sorted(dev_families),
        },
        test_seal=seal,
    )


def write_receipt(command: str, payload: Mapping[str, Any], receipt_path: Path) -> Path:
    """Merge one command receipt into the T15 artifact (runs/ is restricted)."""

    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, Any] = {}
    if receipt_path.is_file():
        try:
            loaded = json.loads(receipt_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                receipt = loaded
        except (OSError, json.JSONDecodeError):
            receipt = {}
    receipt["ticket"] = "TICKET-15"
    receipt["gate"] = "G7-A"
    receipt[command] = {
        **payload,
        "recorded_at_utc": datetime.now(UTC).isoformat(),
    }
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return receipt_path


def _tools_config() -> ToolsConfig:
    """Real configs/tools.yaml for the CLI (same values the runtime uses)."""

    return load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)


def _resolve_index_dir(args: argparse.Namespace) -> Path:
    """``--index-dir`` override or the canonical ``RAG_DIR`` setting."""

    if args.index_dir:
        return Path(args.index_dir)
    return Path(load_settings(None).RAG_DIR)


def cmd_add(args: argparse.Namespace) -> int:
    """Validate, isolate-check and index the public cases; write the receipt."""

    input_path = Path(args.input)
    cases = load_public_cases(input_path)
    guard = gold_isolation_guard(Path(args.gold_dev), Path(args.test_seal))

    rag_families = {case.family_group for case in cases}
    rag_hashes = {case.record_sha256 for case in cases}
    dev_intersection = sorted(set(guard.dev_partition["families"]) & rag_families)
    if dev_intersection:
        raise build_corpus.GoldValidationError(
            f"RAG families intersect the gold_dev partition: {dev_intersection}"
        )
    colliding_hashes = sorted(rag_hashes & guard.record_sha256)
    if colliding_hashes:
        raise build_corpus.GoldValidationError(
            f"RAG records collide with gold_dev record hashes: {colliding_hashes[:5]}"
        )

    adapter = RagAdapter(_tools_config().rag, _resolve_index_dir(args))
    added = adapter.add(cases)
    description = adapter.describe()
    validation_refs = sorted({case.analyst_validation_ref for case in cases})
    payload = {
        "status": "ok",
        "input_path": str(input_path),
        "input_sha256": _file_sha256(input_path),
        "source_case_count": len(cases),
        "added_cases": added,
        "index": description,
        "label_provenance": {
            "validation_refs": validation_refs,
            "reference_method": guard.test_seal["reviewer_ref"],
            "human_validated": bool(guard.test_seal["human_validated"]),
            "note": (
                "operator-approved AI-adjudicated POC reference labels "
                "(astra_gold_ai_v1); NOT human analyst ground truth"
            ),
        },
        "isolation": {
            **guard.summary,
            "rag_family_count": len(rag_families),
            "rag_record_hash_count": len(rag_hashes),
            "rag_families_intersecting_gold_dev": dev_intersection,
            "rag_record_hashes_in_gold_dev": colliding_hashes,
            "test_disjointness": {
                "status": "inherited_from_t13_split_construction",
                "reverified_at": "TICKET-19E",
                "note": (
                    "gold_test.jsonl is sealed before T19E and was never "
                    "opened by T15; the T13 deterministic split reserved the "
                    "RAG families before the dev/test family split of the "
                    "protected Gold pool, so RAG/test disjointness is "
                    "inherited by construction and re-verified at T19E"
                ),
            },
        },
    }
    receipt_file = write_receipt("add", payload, Path(args.receipt))
    print(
        f"rag add: added={added} total={description['count']} "
        f"index={description['index_dir']} model={description['embedding_model_id']}"
    )
    print(f"receipt: {receipt_file}")
    return EXIT_OK


def cmd_clear(args: argparse.Namespace) -> int:
    """Refuse without --yes; otherwise wipe the index and write the receipt."""

    if not args.yes:
        print("clear refused: pass --yes to delete the public index content", file=sys.stderr)
        return EXIT_FAIL
    adapter = RagAdapter(_tools_config().rag, _resolve_index_dir(args))
    adapter.clear()
    description = adapter.describe()
    payload = {"status": "cleared", "index": description}
    receipt_file = write_receipt("clear", payload, Path(args.receipt))
    print(f"rag clear: count={description['count']} index={description['index_dir']}")
    print(f"receipt: {receipt_file}")
    return EXIT_OK


def cmd_search(args: argparse.Namespace) -> int:
    """Read-only neighbour listing (bounded output, no side effect)."""

    adapter = RagAdapter(_tools_config().rag, _resolve_index_dir(args))
    exclusions = [item.strip() for item in args.exclude.split(",") if item.strip()]
    neighbours = adapter.search(args.query, exclusions=exclusions, k=int(args.k))
    print(
        json.dumps(
            [case.model_dump(mode="json") for case in neighbours],
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    )
    return EXIT_OK


def cmd_stats(args: argparse.Namespace) -> int:
    """Read-only index description (counts and model info only)."""

    adapter = RagAdapter(_tools_config().rag, _resolve_index_dir(args))
    print(json.dumps(adapter.describe(), ensure_ascii=False, sort_keys=True, indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="index public validated cases")
    add_parser.add_argument("--input", default=str(DEFAULT_INPUT))
    add_parser.add_argument("--index-dir", default=None)
    add_parser.add_argument("--gold-dev", default=str(DEFAULT_GOLD_DEV))
    add_parser.add_argument("--test-seal", default=str(DEFAULT_TEST_SEAL))
    add_parser.add_argument("--receipt", default=str(PROJECT_ROOT / RECEIPT_RELATIVE))

    clear_parser = subparsers.add_parser("clear", help="delete the index content")
    clear_parser.add_argument("--index-dir", default=None)
    clear_parser.add_argument("--yes", action="store_true")
    clear_parser.add_argument("--receipt", default=str(PROJECT_ROOT / RECEIPT_RELATIVE))

    search_parser = subparsers.add_parser("search", help="list neighbours for a query")
    search_parser.add_argument("--query", required=True)
    search_parser.add_argument("--k", type=int, default=3)
    search_parser.add_argument("--exclude", default="")
    search_parser.add_argument("--index-dir", default=None)

    stats_parser = subparsers.add_parser("stats", help="index description")
    stats_parser.add_argument("--index-dir", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "add":
            return cmd_add(args)
        if args.command == "clear":
            return cmd_clear(args)
        if args.command == "search":
            return cmd_search(args)
        if args.command == "stats":
            return cmd_stats(args)
        return EXIT_FAIL
    except RagUnavailableError as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return EXIT_BLOCKED
    except (build_corpus.GoldValidationError, RagSourceError, RagError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return EXIT_FAIL
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())

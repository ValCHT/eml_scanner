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
- the Gold guard loads ``gold_dev.jsonl`` AND ``gold_test.jsonl`` as
  metadata-only GoldRecords (same loader/validator as the evaluation) and
  refuses to index any case whose ``family_group`` is a Gold family or
  whose ``record_sha256`` is a Gold record hash. The Gold files are read
  ONLY for this isolation assertion — never for labels, tuning or
  selection decisions (operator amendment, internal POC partition);
- the embedding is the frozen chromadb ONNX ``all-MiniLM-L6-v2`` (version +
  SHA-256 fingerprint recorded in the collection metadata); no alternative
  model, no download outside chromadb's pinned archive.

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
DEFAULT_GOLD_TEST = Path("corpus/gold/gold_test.jsonl")


@dataclass(frozen=True)
class GoldGuard:
    """Metadata-only Gold isolation guard (families + record hashes)."""

    families: frozenset[str]
    record_sha256: frozenset[str]
    partitions: dict[str, Any]

    @property
    def summary(self) -> dict[str, Any]:
        """Receipt projection WITHOUT the full family listing per partition."""

        return {
            "gold_partitions": {
                split: {key: value for key, value in data.items() if key != "families"}
                for split, data in self.partitions.items()
            },
            "protected_family_count": len(self.families),
            "protected_record_hash_count": len(self.record_sha256),
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


def gold_isolation_guard(gold_dev_path: Path, gold_test_path: Path) -> GoldGuard:
    """Metadata-only Gold guard: protected family groups + record hashes.

    ``gold_dev.jsonl`` and ``gold_test.jsonl`` are opened as METADATA/label
    files with the full GoldRecord closed-schema validation (same loader as
    the evaluation harness). They are used EXCLUSIVELY to enforce the
    family/record isolation invariant of the RAG index — never for labels,
    thresholds, tuning or any development decision (operator amendment,
    internal POC validation partition).
    """

    families: set[str] = set()
    hashes: set[str] = set()
    partitions: dict[str, Any] = {}
    for split, path in (("dev", gold_dev_path), ("test", gold_test_path)):
        rows = _read_jsonl(path, f"gold[{split}]")
        build_corpus.validate_gold_records(rows, expected_splits=(split,))
        split_families = {str(row["family_group"]) for row in rows}
        split_hashes = {str(row["raw_sha256"]) for row in rows}
        families |= split_families
        hashes |= split_hashes
        partitions[split] = {
            "path": str(path),
            "record_count": len(rows),
            "family_count": len(split_families),
            "families": sorted(split_families),
        }
    return GoldGuard(
        families=frozenset(families),
        record_sha256=frozenset(hashes),
        partitions=partitions,
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
    guard = gold_isolation_guard(Path(args.gold_dev), Path(args.gold_test))

    rag_families = {case.family_group for case in cases}
    intersections = {
        f"gold_{split}": sorted(set(guard.partitions[split]["families"]) & rag_families)
        for split in ("dev", "test")
    }
    colliding = {split: ids for split, ids in intersections.items() if ids}
    if colliding:
        raise build_corpus.GoldValidationError(
            f"RAG families intersect the gold partitions: {colliding}"
        )
    colliding_hashes = sorted({case.record_sha256 for case in cases} & guard.record_sha256)
    if colliding_hashes:
        raise build_corpus.GoldValidationError(
            f"RAG records collide with gold record hashes: {colliding_hashes[:5]}"
        )

    adapter = RagAdapter(_tools_config().rag, _resolve_index_dir(args))
    added = adapter.add(cases)
    description = adapter.describe()
    payload = {
        "status": "ok",
        "input_path": str(input_path),
        "input_sha256": _file_sha256(input_path),
        "source_case_count": len(cases),
        "added_cases": added,
        "index": description,
        "isolation": {
            **guard.summary,
            "rag_families_intersecting_gold": intersections,
            "rag_record_hashes_in_gold": colliding_hashes,
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
    add_parser.add_argument("--gold-test", default=str(DEFAULT_GOLD_TEST))
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

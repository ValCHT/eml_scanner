#!/usr/bin/env python3
"""Report validator (TICKET-02 scope: reject invalid JSON and schema violations).

At G0 the validator only needs to prove the rejection path: a malformed or
schema-invalid file must be refused with a readable error and a non-zero
exit, and a valid minimal document must be accepted. Assessment/report
validation against the frozen schemas grows with the gates that produce
them (G2/G5); the validator deliberately never "repairs" a document.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.llm import validate_against_schema  # noqa: E402


def validate_file(path: Path, schema: dict[str, object] | None) -> list[str]:
    """Return the list of validation problems for one JSON file."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"{path}: unreadable file: {error}"]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        return [f"{path}: invalid JSON: {error}"]
    if schema is None:
        return []
    return [f"{path}: {problem}" for problem in validate_against_schema(data, schema)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate JSON documents (never repairs them)")
    parser.add_argument("files", nargs="*", type=Path, help="JSON files to validate")
    parser.add_argument("--schema", type=Path, default=None, help="optional JSON Schema to enforce")
    parser.add_argument(
        "--assessments",
        type=Path,
        default=None,
        help="JSONL file of archived assessments (G2); each line must be valid JSON",
    )
    args = parser.parse_args()

    schema: dict[str, object] | None = None
    if args.schema is not None:
        try:
            schema = json.loads(args.schema.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"error: schema file unusable: {error}", file=sys.stderr)
            return 2
        if not isinstance(schema, dict):
            print("error: schema file must contain a JSON object", file=sys.stderr)
            return 2

    problems: list[str] = []
    checked = 0
    for path in args.files:
        checked += 1
        problems.extend(validate_file(path, schema))

    if args.assessments is not None:
        if not args.assessments.is_file():
            print(f"error: assessments file missing: {args.assessments}", file=sys.stderr)
            return 2
        for line_number, line in enumerate(args.assessments.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            checked += 1
            try:
                json.loads(line)
            except json.JSONDecodeError as error:
                problems.append(f"{args.assessments}:{line_number}: invalid JSON: {error}")

    if checked == 0:
        print("error: nothing to validate (pass files or --assessments)", file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"validate: FAIL ({len(problems)} problem(s))", file=sys.stderr)
        return 1
    print(f"validate: OK ({checked} document(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

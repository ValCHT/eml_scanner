#!/usr/bin/env python3
"""Report validator (TICKET-02: JSON rejection; TICKET-04: real Assessment validation).

``--assessments <file.jsonl>`` validates each line as a real INTERNAL
Assessment (TICKET-04 / G2):

- strict schema conformance (schemas/assessment.schema.json, local checks);
- exactly six probabilities, finite, in [0, 1], sum 1 ± 0.000001;
- local cardinalities (<= 6 inferences, <= 3 decisive evidence IDs,
  summary length) and reference shape against the registries embedded in
  the archived record (``evidence_registry`` / ``observable_registry``
  keys when present).

Invalid documents are rejected and never repaired or normalized: a bad
probability vector, an unknown reference or an invalid shape fails with a
non-zero exit.

At G0 the ``files``/``--schema`` path only proves the rejection path: a
malformed or schema-invalid file must be refused with a readable error and
a non-zero exit. The validator deliberately never "repairs" a document.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.llm import validate_against_schema  # noqa: E402
from src.verify import validate_assessment_shape_and_refs  # noqa: E402

ASSESSMENT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "assessment.schema.json"


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


def _validate_assessment_line(
    path: Path, line_number: int, data: object
) -> list[str]:
    """Full G2 Assessment validation of one archived JSONL record.

    The ONLY accepted layout is the wrapped record actually archived by the
    G2 harness: ``{"assessment": {...}, "evidence_registry": {...},
    "observable_registry": {...}, ...}``. The registries are MANDATORY:
    without them the validator could not prove that the referenced IDs
    exist, so a bare Assessment object (or a wrapped record missing a
    registry) is rejected — never accepted on probabilities alone.

    The Assessment is validated strictly against the frozen schema AND its
    references against the sibling registries (unknown IDs, any
    non-INTERNE provenance, non-empty ``rag_case_ids`` reject the record).
    Invalid documents are rejected and never repaired or normalized.
    """

    where = f"{path}:{line_number}"
    if not isinstance(data, dict):
        return [f"{where}: expected a JSON object (Assessment record)"]

    problems: list[str] = []

    try:
        schema = json.loads(ASSESSMENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{where}: assessment schema unreadable: {error}"]

    if not isinstance(data.get("assessment"), dict):
        return [
            f"{where}: missing 'assessment' object — the G2 archive format "
            "requires {assessment, evidence_registry, observable_registry}"
        ]
    target = data["assessment"]
    evidence_registry = data.get("evidence_registry")
    observable_registry = data.get("observable_registry")
    for name, registry_value in (
        ("evidence_registry", evidence_registry),
        ("observable_registry", observable_registry),
    ):
        if not isinstance(registry_value, dict):
            problems.append(
                f"{where}: missing or invalid '{name}' — references cannot be "
                "proven without it (record rejected, not repaired)"
            )
    if problems:
        return problems

    # 1. Strict schema conformance against the frozen schema.
    schema_problems = validate_against_schema(target, schema)
    for problem in schema_problems:
        problems.append(f"{where}: schema: {problem}")

    # 2. Semantic/shape/reference validation (TICKET-04 scope).
    registry: dict[str, dict[str, object]] = {
        "evidence": evidence_registry,
        "observables": observable_registry,
    }
    problems.extend(
        f"{where}: {issue}"
        for issue in validate_assessment_shape_and_refs(target, registry, "internal")
    )
    return problems


def validate_assessments_file(path: Path) -> tuple[int, list[str]]:
    """Validate every non-empty line of a JSONL assessments archive."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return 0, [f"{path}: unreadable file: {error}"]
    checked = 0
    problems: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        checked += 1
        try:
            data = json.loads(line)
        except json.JSONDecodeError as error:
            problems.append(f"{path}:{line_number}: invalid JSON: {error}")
            continue
        problems.extend(_validate_assessment_line(path, line_number, data))
    return checked, problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate JSON documents (never repairs them)")
    parser.add_argument("files", nargs="*", type=Path, help="JSON files to validate")
    parser.add_argument("--schema", type=Path, default=None, help="optional JSON Schema to enforce")
    parser.add_argument(
        "--assessments",
        type=Path,
        default=None,
        help=(
            "JSONL file of archived assessments (G2); each line must be a "
            "valid Assessment (schema, probabilities, shape, references)"
        ),
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
        line_checked, line_problems = validate_assessments_file(args.assessments)
        checked += line_checked
        problems.extend(line_problems)

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

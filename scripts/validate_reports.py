#!/usr/bin/env python3
"""Report validator (TICKET-02: JSON rejection; TICKET-04: real Assessment validation;
TICKET-11: batch run directories).

``--assessments <file.jsonl>`` validates each line as a real INTERNAL
Assessment (TICKET-04 / G2):

- strict schema conformance (schemas/assessment.schema.json, local checks);
- exactly six probabilities, finite, in [0, 1], sum 1 ± 0.000001;
- local cardinalities (<= 6 inferences, <= 3 decisive evidence IDs,
  summary length) and reference shape against the registries embedded in
  the archived record (``evidence_registry`` / ``observable_registry``
  keys when present).

``--run-dir <dir>`` validates a TICKET-11 batch output directory:

- ``results.jsonl``: one explicit line per input, ``ok`` rows reference an
  existing ``<dir>/reports/<run_id>/report.json``; ``error`` rows carry a
  non-empty cause and no report path;
- every referenced report satisfies the frozen triage report schema plus the
  deterministic invariants (summary ≤ 100 words and inert, non-negative
  timings, nullable verdict consistency, no secret-like content);
- row/report agreement (run_id, gate, final_source, action) and manifest
  SHA-256 agreement catch a report paired with the wrong input row;
- ``metrics.json`` and ``run_manifest.json`` must exist.

Invalid documents are rejected and never repaired or normalized: a bad
probability vector, an unknown reference, an invalid shape, a missing report
or a mismatched row fails with a non-zero exit. The validator deliberately
never "repairs" a document.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.llm import validate_against_schema  # noqa: E402
from src.reporting import validate_report  # noqa: E402
from src.verify import validate_assessment_shape_and_refs  # noqa: E402

ASSESSMENT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "assessment.schema.json"

#: Row fields that must agree with the referenced report when present.
_ROW_REPORT_FIELDS = (
    "run_id",
    "run_status",
    "gate_decision",
    "final_source",
    "internal_verdict",
    "final_verdict",
    "recommended_action",
)


def _load_json(path: Path) -> tuple[object | None, list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return None, [f"{path}: unreadable file: {error}"]
    try:
        return json.loads(text), []
    except json.JSONDecodeError as error:
        return None, [f"{path}: invalid JSON: {error}"]


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


# ---------------------------------------------------------------------------
# TICKET-11: batch run directory
# ---------------------------------------------------------------------------


def _validate_result_row(
    run_dir: Path,
    line_number: int,
    row: object,
    manifest_inputs: dict[str, dict[str, object]],
) -> list[str]:
    where = f"{run_dir / 'results.jsonl'}:{line_number}"
    if not isinstance(row, dict):
        return [f"{where}: expected a JSON object"]
    problems: list[str] = []
    status = row.get("status")
    if status not in ("ok", "error"):
        problems.append(f"{where}: status must be 'ok' or 'error', got {status!r}")
        return problems
    if status == "error":
        error = row.get("error")
        if not isinstance(error, str) or not error.strip():
            problems.append(f"{where}: error row without an explicit cause")
        if row.get("report_path") is not None:
            problems.append(f"{where}: error row must not reference a report")
        return problems

    report_path = row.get("report_path")
    if not isinstance(report_path, str) or not report_path:
        problems.append(f"{where}: ok row without a report_path")
        return problems
    target = (run_dir / report_path).resolve()
    reports_root = (run_dir / "reports").resolve()
    if reports_root not in target.parents:
        problems.append(f"{where}: report_path escapes reports/ : {report_path}")
        return problems
    if not target.is_file():
        problems.append(f"{where}: referenced report missing: {report_path}")
        return problems
    report, load_problems = _load_json(target)
    problems.extend(load_problems)
    if report is None:
        return problems
    for problem in validate_report(report):
        problems.append(f"{where}: {problem}")

    if isinstance(report, dict):
        for field in _ROW_REPORT_FIELDS:
            if field in row and row[field] != report.get(field):
                problems.append(
                    f"{where}: row/report mismatch on {field!r}: "
                    f"{row[field]!r} != {report.get(field)!r}"
                )
    input_name = row.get("input")
    manifest_entry = manifest_inputs.get(str(input_name))
    if manifest_entry is None:
        problems.append(f"{where}: input {input_name!r} absent from run_manifest.json")
    elif row.get("input_sha256") != manifest_entry.get("sha256"):
        problems.append(f"{where}: input_sha256 does not match run_manifest.json")
    return problems


def validate_run_dir(run_dir: Path) -> tuple[int, list[str]]:
    """Validate one TICKET-11 batch directory (rows + referenced reports)."""

    problems: list[str] = []
    results_path = run_dir / "results.jsonl"
    if not results_path.is_file():
        return 0, [f"{run_dir}: results.jsonl missing"]
    for required in ("metrics.json", "run_manifest.json"):
        if not (run_dir / required).is_file():
            problems.append(f"{run_dir}: {required} missing")
    manifest, manifest_problems = _load_json(run_dir / "run_manifest.json")
    problems.extend(manifest_problems)
    manifest_inputs: dict[str, dict[str, object]] = {}
    if isinstance(manifest, dict) and isinstance(manifest.get("inputs"), list):
        for entry in manifest["inputs"]:
            if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                manifest_inputs[entry["path"]] = entry
    metrics, metrics_problems = _load_json(run_dir / "metrics.json")
    problems.extend(metrics_problems)

    checked = 0
    ok_rows = 0
    error_rows = 0
    seen_run_ids: set[str] = set()
    seen_reports: set[str] = set()
    try:
        text = results_path.read_text(encoding="utf-8")
    except OSError as error:
        return 0, [f"{results_path}: unreadable file: {error}"]
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        checked += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            problems.append(f"{results_path}:{line_number}: invalid JSON: {error}")
            continue
        row_problems = _validate_result_row(run_dir, line_number, row, manifest_inputs)
        problems.extend(row_problems)
        if isinstance(row, dict):
            if row.get("status") == "ok":
                ok_rows += 1
                run_id = row.get("run_id")
                if isinstance(run_id, str):
                    if run_id in seen_run_ids:
                        problems.append(f"{results_path}:{line_number}: duplicate run_id {run_id}")
                    seen_run_ids.add(run_id)
                if isinstance(row.get("report_path"), str):
                    if row["report_path"] in seen_reports:
                        problems.append(
                            f"{results_path}:{line_number}: duplicate report_path "
                            f"{row['report_path']}"
                        )
                    seen_reports.add(row["report_path"])
            elif row.get("status") == "error":
                error_rows += 1

    if checked == 0:
        problems.append(f"{results_path}: no result rows")
    if isinstance(metrics, dict):
        if metrics.get("reports_archived") != ok_rows:
            problems.append(
                f"{run_dir}: metrics.reports_archived ({metrics.get('reports_archived')}) "
                f"does not match the {ok_rows} ok row(s)"
            )
        if metrics.get("errors") != error_rows:
            problems.append(
                f"{run_dir}: metrics.errors ({metrics.get('errors')}) "
                f"does not match the {error_rows} error row(s)"
            )
    return checked + ok_rows, problems


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
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "TICKET-11 batch output directory: results.jsonl + every referenced "
            "report.json (schema + invariants) + metrics.json + run_manifest.json"
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

    if args.run_dir is not None:
        if not args.run_dir.is_dir():
            print(f"error: run directory missing: {args.run_dir}", file=sys.stderr)
            return 2
        run_checked, run_problems = validate_run_dir(args.run_dir)
        checked += run_checked
        problems.extend(run_problems)

    if checked == 0:
        print(
            "error: nothing to validate (pass files, --assessments or --run-dir)",
            file=sys.stderr,
        )
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

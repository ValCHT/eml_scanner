#!/usr/bin/env python3
"""Sequential batch CLI (TICKET-11, docs/architecture.md §1.7).

Usage:
    python run_batch.py --input tests/fixtures --mode live --output runs/gates/G5/batch

Inputs are sorted by path and processed strictly sequentially (no
parallelism). A failing email never stops the batch: its explicit error line is
written to ``results.jsonl`` and the next email runs. Files written under
``--output``:

- ``results.jsonl`` — one line per input (``status=ok`` with the archived
  report path, or ``status=error`` with the explicit cause);
- ``metrics.json`` — gates, verdicts, actions, timings, provenance and tool
  statuses aggregated over the real runs;
- ``run_manifest.json`` — inputs with their SHA-256, runtime identity, config
  fingerprint and limitations;
- ``reports/<run_id>/`` — the real per-email report artifacts.

``--mode recorded`` does not exist in this POC: there is no recorded runtime
and nothing is simulated, so the batch refuses that mode explicitly. Exit 0
only when every input produced an archived report; any processing error still
writes its row and exits non-zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import SourceProfile, load_settings  # noqa: E402
from src.graph import config_sha256, run_email  # noqa: E402
from src.reporting import ReportWriteError  # noqa: E402
from src.tools import expurgate  # noqa: E402

_SOURCE_PROFILES: tuple[SourceProfile, ...] = (
    "fixture",
    "public_corpus",
    "private_authorized",
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code_commit() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def collect_inputs(input_path: Path) -> list[Path]:
    """Deterministic input list: ``.eml`` files sorted by relative POSIX path."""

    root = input_path if input_path.is_dir() else input_path.parent
    if input_path.is_file():
        candidates = [input_path]
    else:
        candidates = [path for path in input_path.rglob("*.eml") if path.is_file()]
    return sorted(candidates, key=lambda path: path.relative_to(root).as_posix())


def _provenance_counts(report: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for entry in report.get("evidence", []):
        provenance = entry.get("provenance")
        if isinstance(provenance, str):
            counts[provenance] += 1
    return counts


def _tool_status_counts(report: dict[str, Any]) -> dict[str, Counter[str]]:
    counts: dict[str, Counter[str]] = {}
    enrichment = report.get("enrichment", {})
    for tool in ("virustotal", "opencti", "urlscan"):
        counter: Counter[str] = Counter()
        for result in enrichment.get(tool, []):
            counter[str(result.get("status"))] += 1
        counts[tool] = counter
    return counts


def run_batch(
    input_path: Path,
    mode: str,
    output: Path,
    source_profile: SourceProfile,
) -> int:
    if mode != "live":
        print(
            "error: --mode recorded is not implemented in this POC: there is no "
            "recorded runtime and nothing is simulated; refusing explicitly",
            file=sys.stderr,
        )
        return 2

    inputs = collect_inputs(input_path)
    if not inputs:
        print(f"error: no .eml input found under {input_path}", file=sys.stderr)
        return 2

    settings = load_settings(None)
    batch_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    reports_root = output / "reports"
    reports_root.mkdir(parents=True, exist_ok=True)
    batch_settings = settings.model_copy(update={"RUNS_DIR": reports_root})

    started_at = datetime.now(UTC)
    rows: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    for email_path in inputs:
        relative = email_path.relative_to(input_path if input_path.is_dir() else input_path.parent)
        row: dict[str, Any] = {
            "input": relative.as_posix(),
            "input_sha256": _sha256_file(email_path),
            "status": "error",
            "run_id": None,
            "report_path": None,
            "error": None,
        }
        try:
            report = run_email(email_path, batch_settings, source_profile=source_profile)
        except (ReportWriteError, OSError, RuntimeError, ValueError) as error:
            row["error"] = expurgate(f"{type(error).__name__}: {error}")
            rows.append(row)
            print(f"[error] {relative.as_posix()}: {row['error']}", file=sys.stderr)
            continue
        except Exception as error:  # unexpected: still a per-input error line
            row["error"] = expurgate(f"{type(error).__name__}: {error}")
            rows.append(row)
            print(f"[error] {relative.as_posix()}: {row['error']}", file=sys.stderr)
            continue

        run_id = str(report.get("run_id"))
        report_path = reports_root / run_id / "report.json"
        row.update(
            {
                "status": "ok",
                "run_id": run_id,
                "report_path": report_path.relative_to(output).as_posix(),
                "run_status": report.get("run_status"),
                "gate_decision": report.get("gate_decision"),
                "gate_reasons": report.get("gate_reasons", []),
                "internal_verdict": report.get("internal_verdict"),
                "final_verdict": report.get("final_verdict"),
                "final_source": report.get("final_source"),
                "recommended_action": report.get("recommended_action"),
                "total_ms": report.get("timings", {}).get("total_ms"),
            }
        )
        rows.append(row)
        reports.append(report)
        print(
            f"[ok] {relative.as_posix()}: gate={row['gate_decision']} "
            f"final={row['final_verdict']} action={row['recommended_action']}",
            file=sys.stderr,
        )

    results_path = output / "results.jsonl"
    with results_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    finished_at = datetime.now(UTC)
    errors = [row for row in rows if row["status"] != "ok"]
    metrics = _build_metrics(batch_id, source_profile, rows, reports, errors)
    (output / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    manifest = _build_manifest(
        batch_id=batch_id,
        mode=mode,
        source_profile=source_profile,
        settings=settings,
        inputs=inputs,
        input_root=input_path if input_path.is_dir() else input_path.parent,
        started_at=started_at,
        finished_at=finished_at,
        errors=errors,
    )
    (output / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )

    print(
        f"batch {batch_id}: {len(rows) - len(errors)}/{len(rows)} reports archived, "
        f"{len(errors)} error(s); output={output}"
    )
    return 0 if not errors else 1


def _build_metrics(
    batch_id: str,
    source_profile: SourceProfile,
    rows: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    gate_decisions = Counter(str(row.get("gate_decision")) for row in reports)
    final_sources = Counter(str(report.get("final_source")) for report in reports)
    run_statuses = Counter(str(report.get("run_status")) for report in reports)
    actions = Counter(str(report.get("recommended_action")) for report in reports)
    internal_verdicts = Counter(str(report.get("internal_verdict")) for report in reports)
    final_verdicts = Counter(str(report.get("final_verdict")) for report in reports)
    provenance: Counter[str] = Counter()
    tool_statuses: dict[str, Counter[str]] = {
        "virustotal": Counter(),
        "opencti": Counter(),
        "urlscan": Counter(),
    }
    phase_names = (
        "parse_ms",
        "internal_llm_ms",
        "gate_ms",
        "vt_ms",
        "opencti_ms",
        "urlscan_ms",
        "rag_ms",
        "merge_ms",
        "final_llm_ms",
        "verify_ms",
        "policy_ms",
        "report_ms",
    )
    phase_totals = {name: 0.0 for name in phase_names}
    total_values: list[float] = []
    internal_attempts = 0
    final_attempts = 0
    for report in reports:
        provenance.update(_provenance_counts(report))
        for tool, counter in _tool_status_counts(report).items():
            tool_statuses[tool].update(counter)
        timings = report.get("timings", {})
        for name in phase_names:
            value = timings.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                phase_totals[name] += float(value)
        total = timings.get("total_ms")
        if isinstance(total, (int, float)) and not isinstance(total, bool):
            total_values.append(float(total))
        for call in report.get("llm_calls", []):
            if call.get("phase") == "internal":
                internal_attempts += int(call.get("attempts") or 0)
            elif call.get("phase") == "final":
                final_attempts += int(call.get("attempts") or 0)

    def _counter_dict(counter: Counter[str]) -> dict[str, int]:
        return {key: counter[key] for key in sorted(counter)}

    return {
        "batch_id": batch_id,
        "source_profile": source_profile,
        "inputs": len(rows),
        "reports_archived": len(reports),
        "errors": len(errors),
        "simple_path_live_observed": gate_decisions.get("simple", 0) > 0,
        "gate_decisions": dict(gate_decisions),
        "final_sources": _counter_dict(final_sources),
        "run_status": _counter_dict(run_statuses),
        "actions": _counter_dict(actions),
        "verdicts": {
            "internal": _counter_dict(internal_verdicts),
            "final": _counter_dict(final_verdicts),
        },
        "timings_ms": {
            "total_sum": round(sum(total_values), 3),
            "total_mean": round(sum(total_values) / len(total_values), 3) if total_values else 0.0,
            "total_max": round(max(total_values), 3) if total_values else 0.0,
            "per_phase": {name: round(value, 3) for name, value in phase_totals.items()},
        },
        "provenance_counts": _counter_dict(provenance),
        "tool_statuses": {
            tool: _counter_dict(counter) for tool, counter in tool_statuses.items()
        },
        "llm_attempts": {
            "internal": internal_attempts,
            "final": final_attempts,
        },
        "cost_usd": None,
        "cost_status": "unknown",
        "errors_detail": [
            {"input": row.get("input"), "error": row.get("error")} for row in errors
        ],
        "limitations": [
            "RAG disabled (RAG_ENABLED=false): rag_lookup is a documented no-op before G7-A",
            "vision disabled (MODEL_SUPPORTS_VISION=false): no pixel analysis",
            "configs/tools.yaml egress stays safe-by-default; the official batch "
            "approves no third-party service, so lookups may be skipped/privacy_policy",
            "cost_usd unknown: no provider invoice is invented",
        ],
    }


def _build_manifest(
    *,
    batch_id: str,
    mode: str,
    source_profile: SourceProfile,
    settings: Any,
    inputs: list[Path],
    input_root: Path,
    started_at: datetime,
    finished_at: datetime,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    tools, gate, policy = _load_configs_for_hash(settings)
    return {
        "batch_id": batch_id,
        "mode": mode,
        "source_profile": source_profile,
        "model": settings.LITELLM_MODEL,
        "chat_url": settings.LITELLM_CHAT_URL,
        "python_version": platform.python_version(),
        "code_commit": _code_commit(),
        "config_sha256": config_sha256(settings, tools, gate, policy),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "inputs": [
            {
                "path": path.relative_to(input_root).as_posix(),
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in inputs
        ],
        "spaced_collections": [],
        "offline_recomputations": [],
        "errors": len(errors),
        "limitations": [
            "sequential execution only; no parallelism",
            "RAG and vision disabled in the frozen baseline",
            "provider timings/quotas are those of this run only",
        ],
    }


def _load_configs_for_hash(settings: Any) -> tuple[Any, Any, Any]:
    from src.graph import _load_configs

    return _load_configs(settings)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sequential live batch over .eml inputs")
    parser.add_argument("--input", type=Path, required=True, help="file or directory of .eml inputs")
    parser.add_argument(
        "--mode",
        choices=("live", "recorded"),
        default="live",
        help="live runs real adapters/model; recorded is refused (never simulated)",
    )
    parser.add_argument("--output", type=Path, required=True, help="batch output directory")
    parser.add_argument(
        "--source-profile",
        choices=_SOURCE_PROFILES,
        default="fixture",
        help="source profile of every input (never guessed from the content)",
    )
    args = parser.parse_args()
    return run_batch(args.input, args.mode, args.output, args.source_profile)


if __name__ == "__main__":
    raise SystemExit(main())

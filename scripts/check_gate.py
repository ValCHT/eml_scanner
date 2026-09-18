#!/usr/bin/env python3
"""Gate controller (docs/gates.md §5.2).

A fixed-list checker: validates prerequisites, runs the gate's commands,
expurgates stdout/stderr, archives receipts under ``runs/gates/G<n>/`` and
writes ``gate.json``. No scheduling, no agents, no orchestration engine.

Usage:
    python scripts/check_gate.py G0 --record   # run commands and record receipt
    python scripts/check_gate.py G0            # verify the recorded receipt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

SECRET_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"(?i)(api[_-]?key|token|secret|password|authorization)\s*[=:]\s*\S+",
        r"sk-[A-Za-z0-9]{8,}",
    )
]

#: Fixed command list per gate (docs/gates.md §5.2). Python 3.11 venv active.
GATE_COMMANDS: dict[str, list[str]] = {
    "G0": [
        [sys.executable, "-m", "pip", "check"],
        [sys.executable, "-m", "pytest", "tests/test_bootstrap.py", "tests/test_contracts.py", "-q"],
    ],
    "G1": [[sys.executable, "-m", "pytest", "tests/test_parsing.py", "-q"]],
    "G2": [
        [sys.executable, "-m", "pytest", "tests/test_internal.py", "--live", "-q"],
        [sys.executable, "scripts/validate_reports.py", "--assessments", "runs/gates/G2/assessments.jsonl"],
    ],
    "G3": [[sys.executable, "-m", "pytest", "tests/test_gate.py", "-q"]],
    "G4": [
        [sys.executable, "-m", "pytest", "tests/test_virustotal.py", "tests/test_opencti.py",
         "tests/test_urlscan.py", "--live", "-q"],
        [sys.executable, "scripts/smoke.py", "tools", "--require-all"],
    ],
    "G5": [
        [sys.executable, "-m", "pytest", "tests/test_evidence.py", "tests/test_verify.py",
         "tests/test_policy.py", "tests/test_graph.py", "tests/test_reporting.py", "--live", "-q"],
        [sys.executable, "run_batch.py", "--input", "tests/fixtures", "--mode", "live",
         "--output", "runs/gates/G5/batch"],
        [sys.executable, "scripts/validate_reports.py", "--run-dir", "runs/gates/G5/batch"],
    ],
    "G6": [
        [sys.executable, "-m", "pytest", "tests/test_corpus.py", "tests/test_metrics.py",
         "tests/test_evaluation.py", "-q"],
        [sys.executable, "scripts/evaluate.py", "--split", "dev", "--mode", "live",
         "--variant", "baseline", "--out", "runs/eval/dev_baseline"],
        [sys.executable, "scripts/evaluate.py", "--mode", "recompute",
         "--from-run", "runs/eval/dev_baseline", "--out", "runs/eval/dev_recomputed"],
    ],
    # Optional gates (docs/gates.md §5.1): G7-A RAG (TICKET-15), G7-B vision
    # (TICKET-16), G7-C fine-tuning decision (TICKET-17).
    "G7-A": [[sys.executable, "-m", "pytest", "tests/test_rag.py", "-q"]],
    "G7-B": [[sys.executable, "-m", "pytest", "tests/test_vision.py", "--live", "-q"]],
    "G7-C": [
        [sys.executable, "scripts/evaluate.py", "--mode", "recompute",
         "--from-run", "runs/eval/dev_baseline", "--out", "runs/eval/dev_for_ft_decision"],
    ],
}

#: Tickets that must be recorded as DONE before the gate receipt may reach
#: PASS (docs/gates.md §5.1). G0 requires TICKET-01 AND TICKET-02: command
#: success alone never yields a premature G0 PASS.
REQUIRED_TICKETS: dict[str, list[str]] = {
    "G0": ["TICKET-01", "TICKET-02"],
}

#: Files that must exist for the gate (docs/gates.md §5.2).
REQUIRED_FILES: dict[str, list[str]] = {
    "G7-C": ["docs/fine_tuning_decision.md"],
}

REQUIRED_TESTS: dict[str, dict[str, int]] = {
    "G0": {"min_collected": 1, "failures": 0, "skipped": 0, "xfailed": 0},
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Operator-maintained record of tickets whose own validation reached DONE.
#: The gate controller never infers ticket completion from command success.
COMPLETED_TICKETS_FILE = PROJECT_ROOT / "runs" / "gates" / "completed_tickets.json"


def load_completed_tickets() -> list[str]:
    if not COMPLETED_TICKETS_FILE.is_file():
        return []
    data = json.loads(COMPLETED_TICKETS_FILE.read_text(encoding="utf-8"))
    return list(data.get("completed_tickets", [])) if isinstance(data, dict) else []


def record_completed_ticket(ticket: str) -> int:
    """Record a ticket as DONE (explicit operator/ticket-flow action)."""

    tickets = load_completed_tickets()
    if ticket not in tickets:
        tickets.append(ticket)
    COMPLETED_TICKETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    COMPLETED_TICKETS_FILE.write_text(
        json.dumps({"completed_tickets": sorted(tickets)}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"recorded completed ticket: {ticket}")
    return 0


def expurgate(text: str) -> str:
    """Mask anything resembling a secret before archiving."""

    out = text
    for pattern in SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def worktree_fingerprint() -> str:
    """Fingerprint of the tracked worktree (git commit or tree hash)."""

    import subprocess as sp

    try:
        commit = sp.run(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, shell=False,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return f"commit:{commit}"
    except Exception:
        return "commit:unavailable"


def parse_pytest_summary(output: str) -> dict[str, int]:
    """Parse a pytest -q summary line into counts."""

    counts = {"collected": 0, "passed": 0, "failures": 0, "skipped": 0, "xfailed": 0}
    m = re.search(r"(\d+) passed", output)
    if m:
        counts["passed"] = int(m.group(1))
        counts["collected"] += counts["passed"]
    m = re.search(r"(\d+) failed", output)
    if m:
        counts["failures"] = int(m.group(1))
        counts["collected"] += counts["failures"]
    m = re.search(r"(\d+) skipped", output)
    if m:
        counts["skipped"] = int(m.group(1))
        counts["collected"] += counts["skipped"]
    m = re.search(r"(\d+) xfailed", output)
    if m:
        counts["xfailed"] = int(m.group(1))
        counts["collected"] += counts["xfailed"]
    m = re.search(r"collected (\d+) items?", output)
    if m:
        counts["collected"] = max(counts["collected"], int(m.group(1)))
    return counts


def check_prerequisites(gate: str) -> list[str]:
    """Fixed prerequisite checks; returns a list of missing items."""

    missing: list[str] = []
    if gate not in GATE_COMMANDS:
        missing.append(f"unknown gate {gate}")
        return missing
    if not (PROJECT_ROOT / "pyproject.toml").is_file():
        missing.append("pyproject.toml")
    for required in REQUIRED_FILES.get(gate, []):
        if not (PROJECT_ROOT / required).is_file():
            missing.append(required)
    if gate == "G0":
        for required in (
            "src/config.py", "src/state.py", "tests/test_bootstrap.py",
            "tests/test_contracts.py", "configs/gate.yaml", "configs/policy.yaml",
            "configs/tools.yaml", "schemas/assessment.schema.json",
            "schemas/triage_report.schema.json",
        ):
            if not (PROJECT_ROOT / required).is_file():
                missing.append(required)
    return missing


def record(gate: str) -> int:
    missing = check_prerequisites(gate)
    if missing:
        receipt = {
            "status": "FAIL", "gate": gate, "missing_prerequisites": missing,
            "tested_commit": worktree_fingerprint(), "commands": [], "tests": {},
        }
        out_dir = PROJECT_ROOT / "runs" / "gates" / gate
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "gate.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(f"BLOCKED/FAIL: missing prerequisites: {', '.join(missing)}")
        return 2

    commands: list[dict[str, object]] = []
    all_ok = True
    for cmd in GATE_COMMANDS[gate]:
        start = time.monotonic()
        proc = subprocess.run(cmd, cwd=PROJECT_ROOT, shell=False, capture_output=True, text=True)
        elapsed = time.monotonic() - start
        log_name = f"cmd_{len(commands):02d}_{'_'.join(Path(cmd[0]).parts[-1:])}_{abs(hash(' '.join(cmd))) % 10000}.log"
        log_path = PROJECT_ROOT / "runs" / "gates" / gate / log_name
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            expurgate(proc.stdout) + "\n--- STDERR ---\n" + expurgate(proc.stderr),
            encoding="utf-8",
        )
        commands.append({
            "command": " ".join(cmd),
            "exit_code": proc.returncode,
            "log": str(log_path.relative_to(PROJECT_ROOT)),
            "duration_s": round(elapsed, 3),
        })
        if proc.returncode != 0:
            all_ok = False

    tests: dict[str, int] = {}
    for entry in commands:
        log_file = PROJECT_ROOT / str(entry["log"])
        if log_file.is_file() and "pytest" in str(entry["command"]):
            summary = parse_pytest_summary(log_file.read_text(encoding="utf-8"))
            tests = summary
            break

    required = REQUIRED_TESTS.get(gate)
    if required and tests:
        if tests.get("collected", 0) < required["min_collected"]:
            all_ok = False
        for key in ("failures", "skipped", "xfailed"):
            if tests.get(key, 0) > required[key]:
                all_ok = False

    # Ticket completion is NEVER inferred from command success (docs/gates.md
    # §5.2). The gate may only reach PASS once its required tickets have been
    # recorded DONE in the operator registry.
    completed = load_completed_tickets()
    missing_tickets = [
        t for t in REQUIRED_TICKETS.get(gate, []) if t not in completed
    ]
    if missing_tickets:
        all_ok = False

    receipt = {
        "status": "PASS" if all_ok else "FAIL",
        "gate": gate,
        "completed_tickets": completed,
        "missing_tickets": missing_tickets,
        "tested_commit": worktree_fingerprint(),
        "validated_scope_hashes": {},
        "commands": commands,
        "tests": tests,
        "live_evidence_refs": [],
        "dependency_receipts": [],
        "limitations": [],
        "python_version": platform.python_version(),
    }
    out_dir = PROJECT_ROOT / "runs" / "gates" / gate
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "gate.json").write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

    print(f"gate={gate} status={receipt['status']}")
    if missing_tickets:
        print(f"  missing tickets for PASS: {', '.join(missing_tickets)}")
    for entry in commands:
        print(f"  exit={entry['exit_code']} {entry['command']}")
    return 0 if all_ok else 1


def verify(gate: str) -> int:
    receipt_path = PROJECT_ROOT / "runs" / "gates" / gate / "gate.json"
    if not receipt_path.is_file():
        print(f"NO RECEIPT: {receipt_path} is missing; run with --record first")
        return 2
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("status") != "PASS":
        print(f"gate={gate} status={receipt.get('status')} (not PASS)")
        return 1
    if receipt.get("tested_commit") != worktree_fingerprint():
        print(f"gate={gate} receipt stale: worktree changed since recording")
        return 1
    print(f"gate={gate} status=PASS receipt verified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Fixed-list gate controller")
    parser.add_argument("gate", help="gate id, e.g. G0 or G7-A")
    parser.add_argument("--record", action="store_true", help="run commands and write the receipt")
    parser.add_argument(
        "--complete-ticket", metavar="TICKET",
        help="record a ticket as DONE in the operator registry, then exit",
    )
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    if args.complete_ticket:
        return record_completed_ticket(args.complete_ticket)
    if args.record:
        return record(args.gate)
    return verify(args.gate)


if __name__ == "__main__":
    raise SystemExit(main())

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
        # HTTP auth header: Authorization: Bearer <token>
        r"(?i)authorization\s*:\s*Bearer\s+\S+",
        # JSON fields: "api_key": "<secret>", "token": "...", etc.
        r'(?i)"(?:api[_-]?key|access[_-]?token|secret|token|password|authorization)"\s*:\s*"[^"]*"',
        # Common key=value / key: value forms (query strings, dotenv, logs)
        r"(?i)\b(api[_-]?key|access[_-]?token|token|secret|password)\s*[=:]\s*\S+",
        # Well-known key prefixes
        r"sk-[A-Za-z0-9]{8,}",
        r"akml-[A-Za-z0-9_-]{4,}",
    )
]

#: Fixed command list per gate (docs/gates.md §5.2). Python 3.11 venv active.
#: TICKET-02 extends G0 with the client tests and the real Luna smoke:
#: the three VALIDATION COMMANDS of docs/tickets/TICKET-02.md.
GATE_COMMANDS: dict[str, list[str]] = {
    "G0": [
        [sys.executable, "-m", "pip", "check"],
        [
            sys.executable, "-m", "pytest",
            "tests/test_llm_client.py", "tests/test_bootstrap.py", "tests/test_contracts.py",
            "-q",
        ],
        [sys.executable, "scripts/smoke.py", "luna", "--if-configured"],
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
#: success alone never yields a premature G0 PASS. The table is complete for
#: every gate so no later gate can PASS without its tickets recorded DONE.
REQUIRED_TICKETS: dict[str, list[str]] = {
    "G0": ["TICKET-01", "TICKET-02"],
    "G1": ["TICKET-03"],
    "G2": ["TICKET-04"],
    "G3": ["TICKET-05"],
    "G4": ["TICKET-06", "TICKET-07", "TICKET-08"],
    "G5": ["TICKET-09", "TICKET-10", "TICKET-11"],
    "G6": ["TICKET-12", "TICKET-13", "TICKET-14"],
    "G7-A": ["TICKET-15"],
    "G7-B": ["TICKET-16"],
    "G7-C": ["TICKET-17"],
}

#: Files that must exist for the gate (docs/gates.md §5.2).
REQUIRED_FILES: dict[str, list[str]] = {
    "G7-C": ["docs/fine_tuning_decision.md"],
}

#: The eleven mandatory fields of docs/evaluation.md §8.5 when the G7-C
#: decision is YES. A decision file missing any of them forbids PASS.
G7C_YES_FIELDS = (
    "target_failure_modes",
    "why_prompting_is_insufficient",
    "why_retrieval_is_insufficient",
    "why_enrichment_is_insufficient",
    "training_data_needed",
    "estimated_number_of_examples",
    "candidate_models",
    "evaluation_protocol",
    "non_regression_requirements",
    "estimated_training_cost",
    "phase_2_go_no_go_conditions",
)


def _count_dev_records(dir_path: Path) -> int | None:
    """Deterministic dev record count from an archived evaluation artifact.

    Counts non-empty lines of ``*.jsonl`` files, or reads a sample count
    from ``metrics.json``. Returns ``None`` when nothing parseable exists.
    """

    if not dir_path.is_dir():
        return None
    jsonl_lines = 0
    has_jsonl = False
    for jsonl in sorted(dir_path.glob("*.jsonl")):
        has_jsonl = True
        jsonl_lines += sum(1 for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip())
    if has_jsonl:
        return jsonl_lines
    metrics = dir_path / "metrics.json"
    if metrics.is_file():
        try:
            data = json.loads(metrics.read_text(encoding="utf-8"))
            for key in ("sample_count", "n", "count", "records"):
                if isinstance(data.get(key), int):
                    return data[key]
        except (json.JSONDecodeError, AttributeError):
            return None
    return None


def _check_g7c_artifact_concordance(
    baseline_dir: Path | None = None, ft_dir: Path | None = None
) -> list[str]:
    """Concordance of dev counts with archived evaluation artifacts (§5.2).

    The G7-C recompute output must exist; when both the baseline run and the
    recompute expose a parseable dev record count, they must be equal.
    """

    problems: list[str] = []
    ft_dir = ft_dir or PROJECT_ROOT / "runs" / "eval" / "dev_for_ft_decision"
    baseline_dir = baseline_dir or PROJECT_ROOT / "runs" / "eval" / "dev_baseline"

    if not ft_dir.is_dir() or not any(ft_dir.iterdir()):
        return [
            "missing archived recompute artifact runs/eval/dev_for_ft_decision "
            "(output of the G7-C evaluate.py --mode recompute command)"
        ]

    base_count = _count_dev_records(baseline_dir)
    ft_count = _count_dev_records(ft_dir)
    if base_count is not None and ft_count is not None and base_count != ft_count:
        problems.append(
            f"dev record count mismatch between archived artifacts: "
            f"dev_baseline={base_count} vs dev_for_ft_decision={ft_count}"
        )
    return problems


def validate_g7c_decision_file(
    path: Path | None = None,
    baseline_dir: Path | None = None,
    ft_dir: Path | None = None,
) -> list[str]:
    """G7-C (docs/gates.md §5.2): the decision file must carry an explicit
    YES/NO/INCONCLUSIVE status; when YES, all eleven §8.5 fields must be
    present with a NON-EMPTY value (UNKNOWN is acceptable where the spec
    allows it), and the dev counts/references must be concordant with the
    archived evaluation artifacts. An empty or status-less file, or a YES
    with placeholder-only fields, can never yield a PASS."""

    problems: list[str] = []
    path = path or PROJECT_ROOT / "docs" / "fine_tuning_decision.md"
    if not path.is_file():
        return ["docs/fine_tuning_decision.md missing"]
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return ["docs/fine_tuning_decision.md is empty"]

    m = re.search(r"(?i)\bfine[-_ ]?tun\w*[^\n]*?\b(YES|NO|INCONCLUSIVE)\b", text)
    decision = m.group(1).upper() if m else None
    if decision is None:
        problems.append("no explicit decision status YES|NO|INCONCLUSIVE found")
        return problems

    if decision == "YES":
        # Locate every field and take its value as the text up to the next
        # field (or EOF), so heading/list/code-fence layouts are all accepted.
        positions: list[tuple[int, str]] = []
        for field in G7C_YES_FIELDS:
            fm = re.search(rf"(?im)^[#*\-\s]*{re.escape(field)}\b", text)
            if fm:
                positions.append((fm.start(), field))
        positions.sort()
        for i, (start, field) in enumerate(positions):
            end = positions[i + 1][0] if i + 1 < len(positions) else len(text)
            segment = text[start:end]
            # Value = same-line remainder after the field name, plus any
            # following lines, excluding the field-name line itself.
            lines = segment.splitlines()
            rest: list[str] | None = None
            for j, line in enumerate(lines):
                if re.search(rf"(?i)\b{re.escape(field)}\b", line):
                    rest = [line.split(field, 1)[1], *lines[j + 1:]]
                    break
            value = "\n".join(rest) if rest is not None else segment
            value = value.strip().strip("#*:-` \n\t")
            if not value:
                problems.append(
                    f"YES decision but §8.5 field has no value: {field} "
                    "(UNKNOWN is acceptable where the spec allows it)"
                )
        for field in G7C_YES_FIELDS:
            if not re.search(rf"(?im)^[#*\-\s]*{re.escape(field)}\b", text):
                problems.append(f"YES decision but §8.5 field missing: {field}")
        problems.extend(_check_g7c_artifact_concordance(baseline_dir, ft_dir))
    return problems

REQUIRED_TESTS: dict[str, dict[str, int]] = {
    "G0": {"min_collected": 1, "failures": 0, "skipped": 0, "xfailed": 0},
}

#: docs/gates.md §5.2 rule applied GENERICALLY to every gate that runs pytest:
#: at least one test collected, zero failed/skipped/xfailed. A pytest exit 0
#: made only of skipped tests must never allow a PASS.
PYTEST_PASS_RULE = {"min_collected": 1, "failures": 0, "skipped": 0, "xfailed": 0}

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Operator-maintained record of tickets whose own validation reached DONE.
#: The gate controller never infers ticket completion from command success.
COMPLETED_TICKETS_FILE = PROJECT_ROOT / "runs" / "gates" / "completed_tickets.json"

#: G3 (docs/tickets/TICKET-05.md): the deterministic replay artifact is the
#: source of the no-live-SIMPLE limitation recorded in the receipt. The
#: controller never re-infers SIMPLE/COMPLEX itself.
G3_REPLAY_RELPATH = Path("runs") / "gates" / "G3" / "complexity_replay.json"
G3_NO_SIMPLE_LIMITATION = "No live G2 sample satisfied BASELINE V0 SIMPLE criteria"


def g3_replay_limitations(path: Path | None = None) -> tuple[list[str], list[str]]:
    """Receipt limitations/problems derived from the G3 replay artifact.

    The deterministic artifact records ``simple_path_live_observed`` (top
    level or inside ``distribution``). ``false`` yields exactly the documented
    limitation; ``true`` yields none. Every failure mode fails CLOSED — a
    missing, unreadable or malformed artifact, a missing key or a non-boolean
    value returns a problem so G3 can never silently PASS. SIMPLE/COMPLEX is
    never re-inferred here.
    """

    artifact = path or (PROJECT_ROOT / G3_REPLAY_RELPATH)
    try:
        data = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [], [f"G3 replay artifact unreadable ({artifact}): {exc}"]
    if not isinstance(data, dict):
        return [], [f"G3 replay artifact is not a JSON object: {artifact}"]
    distribution = data.get("distribution")
    if "simple_path_live_observed" in data:
        container = data
    elif isinstance(distribution, dict) and "simple_path_live_observed" in distribution:
        container = distribution
    else:
        return [], [f"G3 replay artifact missing simple_path_live_observed: {artifact}"]
    observed = container["simple_path_live_observed"]
    if not isinstance(observed, bool):
        return [], [
            f"G3 replay artifact simple_path_live_observed is not a boolean: {observed!r}"
        ]
    if observed:
        return [], []
    return [G3_NO_SIMPLE_LIMITATION], []


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
    """Deterministic fingerprint of HEAD **and** the tracked worktree/index.

    Any tracked modification (staged or unstaged) changes the hash, so a
    recorded receipt can never stay valid after the code it validated moved.
    Untracked files do not participate.
    """

    import hashlib
    import subprocess as sp

    try:
        head = sp.run(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, shell=False,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        # Covers tracked staged + unstaged changes relative to HEAD.
        diff = sp.run(
            ["git", "diff", "HEAD", "--", "."], cwd=PROJECT_ROOT, shell=False,
            capture_output=True, text=True, check=True,
        ).stdout
        digest = hashlib.sha256((head + "\x00" + diff).encode("utf-8")).hexdigest()
        state = "clean" if not diff else "dirty"
        return f"commit:{head};tree:{state}:{digest[:16]}"
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
            "src/config.py", "src/llm.py", "src/state.py", "tests/test_llm_client.py",
            "tests/test_bootstrap.py", "tests/test_contracts.py", "scripts/smoke.py",
            "scripts/validate_reports.py", "configs/gate.yaml", "configs/policy.yaml",
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
    pytest_ran = False
    for entry in commands:
        log_file = PROJECT_ROOT / str(entry["log"])
        if log_file.is_file() and "pytest" in str(entry["command"]):
            summary = parse_pytest_summary(log_file.read_text(encoding="utf-8"))
            if summary.get("collected", 0) > 0 or summary.get("passed", 0) > 0:
                tests = summary
                pytest_ran = True
            break

    # Generic pytest rule (docs/gates.md §5.2): applied to every gate with
    # pytest commands, not only G0. Skipped/xfailed tests never allow PASS.
    if pytest_ran:
        if tests.get("collected", 0) < PYTEST_PASS_RULE["min_collected"]:
            all_ok = False
        for key in ("failures", "skipped", "xfailed"):
            if tests.get(key, 0) > PYTEST_PASS_RULE[key]:
                all_ok = False

    # G0 live status (docs/tickets/TICKET-02.md): the smoke receipt must be
    # live_ok (real answer) or live_pending (no credentials, G0-only
    # allowance). A live_failed with credentials present always blocks PASS.
    limitations: list[str] = []
    if gate == "G0":
        smoke_receipt = PROJECT_ROOT / "runs" / "gates" / "G0" / "smoke_luna" / "smoke_result.json"
        if smoke_receipt.is_file():
            try:
                smoke_data = json.loads(smoke_receipt.read_text(encoding="utf-8"))
                smoke_status = smoke_data.get("status")
                if smoke_status == "live_pending":
                    limitations.append(
                        "live_pending: no Luna credentials in this environment; "
                        "G2 must lift this pending before PASS (docs/gates.md §5.1)"
                    )
                elif smoke_status != "live_ok":
                    all_ok = False
                    limitations.append(f"smoke status {smoke_status!r} forbids G0 PASS")
            except (json.JSONDecodeError, OSError):
                all_ok = False
                limitations.append("smoke receipt unreadable")
        else:
            all_ok = False
            limitations.append("missing smoke receipt runs/gates/G0/smoke_luna/smoke_result.json")

    # G3 (docs/tickets/TICKET-05.md): the receipt carries the limitation
    # exactly when the deterministic replay artifact reports no live SIMPLE.
    # A missing/malformed indicator fails closed (never a silent PASS).
    g3_replay_problems: list[str] = []
    if gate == "G3":
        g3_limitations, g3_replay_problems = g3_replay_limitations()
        limitations.extend(g3_limitations)
        if g3_replay_problems:
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

    # G7-C deep validation (docs/gates.md §5.2, evaluation.md §8.5): an
    # existing-but-empty or incomplete decision file can never yield PASS.
    g7c_problems: list[str] = []
    if gate == "G7-C":
        g7c_problems = validate_g7c_decision_file()
        if g7c_problems:
            all_ok = False

    receipt = {
        "status": "PASS" if all_ok else "FAIL",
        "gate": gate,
        "completed_tickets": completed,
        "missing_tickets": missing_tickets,
        "g7c_validation_problems": g7c_problems,
        "g3_replay_problems": g3_replay_problems,
        "tested_commit": worktree_fingerprint(),
        "validated_scope_hashes": {},
        "commands": commands,
        "tests": tests,
        "live_evidence_refs": [],
        "dependency_receipts": [],
        "limitations": limitations,
        "python_version": platform.python_version(),
    }
    out_dir = PROJECT_ROOT / "runs" / "gates" / gate
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "gate.json").write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

    print(f"gate={gate} status={receipt['status']}")
    if missing_tickets:
        print(f"  missing tickets for PASS: {', '.join(missing_tickets)}")
    if g7c_problems:
        for problem in g7c_problems:
            print(f"  G7-C validation problem: {problem}")
    if g3_replay_problems:
        for problem in g3_replay_problems:
            print(f"  G3 replay problem: {problem}")
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

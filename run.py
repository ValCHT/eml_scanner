#!/usr/bin/env python3
"""Single-email CLI (TICKET-11, docs/architecture.md §1.7).

Usage:
    python run.py tests/fixtures/malicious_url_redirect.eml --source-profile fixture

``--source-profile`` is required and is never guessed from the email content:
only ``fixture`` permits persisting the complete LLM request body, so an
arbitrary real email must not silently default to it.

Executes the frozen StateGraph pipeline once, writes ``report.json`` /
``summary.txt`` / ``events.jsonl`` under ``RUNS_DIR/<run_id>/`` and exits 0
only when the report was really archived. A refused write, an unhandled
pipeline failure or a missing report exits non-zero: a saved report is never
announced without the file. The action in the report is a recommendation; the
CLI never touches the mailbox.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import SourceProfile, load_settings  # noqa: E402
from src.graph import run_email  # noqa: E402
from src.reporting import ReportWriteError  # noqa: E402

_SOURCE_PROFILES: tuple[SourceProfile, ...] = (
    "fixture",
    "public_corpus",
    "private_authorized",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SOC email triage pipeline once")
    parser.add_argument("email", type=Path, help="path to the .eml file to analyse")
    parser.add_argument(
        "--source-profile",
        choices=_SOURCE_PROFILES,
        required=True,
        help="source profile of the input (required; never guessed from the content)",
    )
    args = parser.parse_args()

    if not args.email.is_file():
        print(f"error: input file not found: {args.email}", file=sys.stderr)
        return 2

    settings = load_settings(None)
    try:
        report = run_email(args.email, settings, source_profile=args.source_profile)
    except ReportWriteError as error:
        print(f"error: report not saved: {error}", file=sys.stderr)
        return 1
    except Exception as error:  # explicit, never a silent success
        print(f"error: pipeline failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1

    report_path = Path(settings.RUNS_DIR) / report["run_id"] / "report.json"
    print(f"report: {report_path}")
    print(f"run_status: {report['run_status']}")
    print(f"gate: {report['gate_decision']} ({', '.join(report['gate_reasons']) or 'no reason'})")
    print(f"action: {report['recommended_action']}")
    print(report["analyst_summary"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

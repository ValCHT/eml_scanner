#!/usr/bin/env python3
"""TICKET-19A/B real smokes: native tool calling and the bounded agentic core.

Two explicit subcommands, both requiring the real configured runtime
(``LITELLM_*``); credentials are never printed and no observation is ever
simulated.

``capability`` (T19A)
    ONE controlled fixture with a parser-produced URL observable. The probe
    prompt explicitly requires ``lookup_virustotal`` exactly once for the
    known ``observable_id``, then stop. The provider lookup is intentionally
    NOT executed: the probe only proves that the real configured
    provider/model returns the NATIVE ``message.tool_calls`` structure.
    A provider answer without native tool calls is reported as
    ``BLOCKED_PROVIDER_NATIVE_TOOL_CALLING``, never replaced by a JSON
    planner fallback.

``smoke`` (T19B)
    Runs the bounded agentic core on EXACTLY the five T14 dev-smoke samples
    (deterministic selection re-verified, all 83 gold_dev records and raw
    bytes validated first). Each sample runs exactly once; a driver/provider
    outcome stays honest (no selective rerun, no budget change). Every run
    writes ``runs/agentic/<run_id>/{manifest,trace,final,summary}`` with
    ``measurement_scope=smoke`` and ``performance_claims_allowed=false``.

No full benchmark exists here: the 83-email dev run, gold_test, Visual-79
and any architecture/model comparison belong to TICKET-19E.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for _path in (str(SCRIPTS_DIR), str(PROJECT_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import evaluate as evaluation_harness  # noqa: E402  (read-only harness reuse)

from src.agent.client import AgentChatClient  # noqa: E402
from src.agent.models import (  # noqa: E402
    AGENT_REASONING_EFFORT,
    ARCHITECTURE_NAME,
    DEFAULT_AGENT_LIMITS,
    MAX_AGENT_SECONDS,
    MAX_SINGLE_LLM_SECONDS,
    MEASUREMENT_SCOPE,
    PERFORMANCE_CLAIMS_ALLOWED,
)
from src.agent.prompt import (  # noqa: E402
    agent_system_prompt_sha256,
    build_capability_probe_messages,
)
from src.agent.runner import run_agentic_email  # noqa: E402
from src.agent.tools import AGENT_TOOLS  # noqa: E402
from src.config import Settings, load_settings  # noqa: E402
from src.parsing import ParseFailure, ParseLimits, ParsedEmail, parse_email  # noqa: E402

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2

#: Default controlled fixture of the T19A capability probe.
DEFAULT_FIXTURE = Path("tests") / "fixtures" / "malicious_url_redirect.eml"

#: The EXACT five bounded T14 dev-smoke samples (frozen order).
T14_SMOKE_SAMPLE_IDS: tuple[str, ...] = (
    "nazario_phishing_2025_00116",
    "nazario_phishing_2025_00020",
    "nazario_phishing_2025_00112",
    "spamassassin_hard_ham_00192",
    "nazario_phishing_2025_00404",
)

#: Explicit status vocabulary of the two smokes (docs/tickets/TICKET-19A/B).
STATUS_T19A_READY = "IMPLEMENTED_WAITING_FOR_LIVE_TOOLCALL_SMOKE"
STATUS_T19A_BLOCKED = "BLOCKED_PROVIDER_NATIVE_TOOL_CALLING"
STATUS_T19A_DONE = "DONE"
STATUS_T19B_READY = "IMPLEMENTED_NOT_LIVE_VALIDATED"
STATUS_T19B_DONE = "IMPLEMENTED_SMOKE_VALIDATED"


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False),
        encoding="utf-8",
    )


def _settings() -> Settings:
    return load_settings(None)


def _resolve_run_root(args: argparse.Namespace) -> Path:
    run_root = Path(args.run_root)
    if not run_root.is_absolute():
        run_root = PROJECT_ROOT / run_root
    return run_root


def _write_blocked_receipt(args: argparse.Namespace, ticket: str, status: str) -> Path:
    """Archive the honest blocked attempt (no request was made)."""

    run_root = _resolve_run_root(args)
    blocked_dir = run_root / ("blocked_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    blocked_dir.mkdir(parents=True, exist_ok=True)
    path = blocked_dir / f"{ticket.lower()}_status.json"
    _write_json(
        path,
        {
            "ticket": ticket,
            "status": status,
            "reason": "LITELLM_API_KEY absent: no request was made and no response simulated",
            "attempted_at": datetime.now(UTC).isoformat(),
            "architecture": ARCHITECTURE_NAME,
            "measurement_scope": MEASUREMENT_SCOPE,
            "performance_claims_allowed": PERFORMANCE_CLAIMS_ALLOWED,
        },
    )
    return path


def _require_llm_key(settings: Settings, ticket: str, args: argparse.Namespace) -> int | None:
    if settings.LITELLM_API_KEY is not None:
        return None
    status = STATUS_T19A_READY if ticket == "T19A" else STATUS_T19B_READY
    print(
        f"BLOCKED: LITELLM_API_KEY absent: no real {ticket} smoke is possible; "
        "no response is simulated",
        file=sys.stderr,
    )
    print(f"{ticket} status: {status}")
    receipt = _write_blocked_receipt(args, ticket, status)
    print(f"{ticket} blocked receipt: {receipt}")
    return EXIT_BLOCKED


# ---------------------------------------------------------------------------
# T19A — native tool-calling capability probe
# ---------------------------------------------------------------------------


def _capability_observable(parsed: ParsedEmail) -> Any:
    urls = [observable for observable in parsed.observables if observable.type == "url"]
    if not urls:
        return None
    preferred = [o for o in urls if "link_target" in o.roles]
    return (preferred or urls)[0]


def run_capability(args: argparse.Namespace) -> int:
    settings = _settings()
    blocked = _require_llm_key(settings, "T19A", args)
    if blocked is not None:
        return blocked

    fixture = Path(args.fixture)
    if not fixture.is_absolute():
        fixture = PROJECT_ROOT / fixture
    parsed = parse_email(fixture, ParseLimits())
    if isinstance(parsed, ParseFailure):
        print(f"FAIL: fixture is not parsable: {parsed.error}: {parsed.detail}", file=sys.stderr)
        return EXIT_FAIL
    observable = _capability_observable(parsed)
    if observable is None:
        print("FAIL: fixture has no parser-produced URL observable", file=sys.stderr)
        return EXIT_FAIL

    run_root = _resolve_run_root(args)
    run_id = str(uuid.uuid4())
    run_dir = run_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    capture_dir = run_dir / "responses"
    capture_dir.mkdir(parents=True, exist_ok=True)

    objective = (
        "Call lookup_virustotal exactly once with the argument "
        '{"observable_id": "' + observable.id + '"} and then stop. '
        "This observable_id exists in OBSERVABLE_REGISTRY below. "
        "Do not call any other tool."
    )
    messages = build_capability_probe_messages(
        observable.id, objective, parsed, agent_limits=DEFAULT_AGENT_LIMITS
    )
    client = AgentChatClient(
        settings,
        capture_dir=capture_dir,
        persist_request_body=(args.source_profile == "fixture"),
    )
    started_at = datetime.now(UTC).isoformat()
    response = client.complete_with_tools(
        messages,
        AGENT_TOOLS,
        deadline=time.monotonic() + MAX_SINGLE_LLM_SECONDS,
        max_output_tokens=int(settings.FINAL_MAX_OUTPUT_TOKENS),
        turn_index=1,
        effort=AGENT_REASONING_EFFORT,
    )

    matching = [
        call
        for call in response.tool_calls
        if call.name == "lookup_virustotal"
        and call.call_id
        and call.arguments_error is None
        and call.arguments == {"observable_id": observable.id}
    ]
    observed = response.status == "ok" and bool(matching)
    call = matching[0] if matching else None
    transport_failure = bool(
        response.error
        and (
            response.error.startswith("LLMTransportError")
            or response.error.startswith("LLMTimeout")
            or response.error == "llm_not_configured"
        )
    )
    if observed:
        status = STATUS_T19A_DONE
        exit_code = EXIT_OK
    elif transport_failure:
        status = STATUS_T19A_READY
        exit_code = EXIT_BLOCKED
    else:
        status = STATUS_T19A_BLOCKED
        exit_code = EXIT_FAIL

    manifest = {
        "schema_version": "1.0",
        "architecture": ARCHITECTURE_NAME,
        "run_kind": "t19a_native_tool_call_capability",
        "measurement_scope": MEASUREMENT_SCOPE,
        "performance_claims_allowed": PERFORMANCE_CLAIMS_ALLOWED,
        "run_id": run_id,
        "fixture": str(fixture.relative_to(PROJECT_ROOT)),
        "observable_id": observable.id,
        "observable_type": observable.type,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "requested_model": response.requested_model,
        "returned_model": response.returned_model,
        "effective_prompt_sha256": agent_system_prompt_sha256(DEFAULT_AGENT_LIMITS),
        "tool_choice": "auto",
        "provider_lookup_executed": False,
        "native_tool_call_observed": observed,
        "status": status,
        "request_sha256": response.request_sha256,
        "response_sha256": response.response_sha256,
        "finish_reason": response.finish_reason,
        "error": response.error,
    }
    trace_events = [
        {
            "ts": started_at,
            "event": "llm_turn",
            "turn": 1,
            "status": response.status,
            "requested_model": response.requested_model,
            "returned_model": response.returned_model,
            "finish_reason": response.finish_reason,
            "native_tool_calls": [
                {
                    "id": call_item.call_id,
                    "name": call_item.name,
                    "arguments": call_item.arguments,
                    "arguments_error": call_item.arguments_error,
                }
                for call_item in response.tool_calls
            ],
            "request_sha256": response.request_sha256,
            "response_sha256": response.response_sha256,
            "error": response.error,
        },
        {
            "ts": datetime.now(UTC).isoformat(),
            "event": "run_end",
            "status": status,
            "native_tool_call_observed": observed,
            "provider_lookup_executed": False,
            "note": (
                "T19A capability probe only: the requested provider lookup was "
                "intentionally not executed"
            ),
        },
    ]
    final_document = {
        "run_id": run_id,
        "status": status,
        "native_tool_call_observed": observed,
        "tool_call": (
            {
                "tool_call_id": call.call_id,
                "name": call.name,
                "arguments_json": call.arguments_raw
                if call.arguments_raw is not None
                else json.dumps(call.arguments, sort_keys=True),
                "arguments": call.arguments,
            }
            if call is not None
            else None
        ),
        "requested_model": response.requested_model,
        "returned_model": response.returned_model,
        "error": response.error,
    }
    summary = "\n".join(
        [
            f"T19A native tool-calling capability probe — run {run_id}",
            f"fixture: {manifest['fixture']}; observable: {observable.id}",
            f"requested_model: {response.requested_model}",
            f"returned_model: {response.returned_model}",
            f"native_tool_call_observed: {observed}",
            f"status: {status}",
            "portée: capability probe uniquement; aucun lookup fournisseur exécuté;",
            "measurement_scope=smoke; performance_claims_allowed=false",
        ]
    ) + "\n"

    _write_json(run_dir / "manifest.json", manifest)
    (run_dir / "trace.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n" for event in trace_events),
        encoding="utf-8",
    )
    _write_json(run_dir / "final.json", final_document)
    (run_dir / "summary.txt").write_text(summary, encoding="utf-8")

    print(f"[T19A] native_tool_call_observed={observed} status={status}")
    print(f"[T19A] artifacts: {run_dir}")
    if call is not None:
        print(f"[T19A] tool_call name={call.name} id={call.call_id} arguments={call.arguments}")
    if response.error:
        print(f"[T19A] provider error: {response.error}", file=sys.stderr)
    return exit_code


# ---------------------------------------------------------------------------
# T19B — bounded agentic core on the frozen five T14 smoke samples
# ---------------------------------------------------------------------------


def run_smoke(args: argparse.Namespace) -> int:
    settings = _settings()
    blocked = _require_llm_key(settings, "T19B", args)
    if blocked is not None:
        return blocked

    run_root = _resolve_run_root(args)

    evaluation_config = evaluation_harness.load_evaluation_config(
        PROJECT_ROOT / "configs" / "evaluation.yaml"
    )
    gold_rows, _gold_path = evaluation_harness.load_gold_records(evaluation_config, "dev")
    verified_bytes, raw_failures = evaluation_harness.validate_gold_raw_files(gold_rows)
    if raw_failures:
        for failure in raw_failures:
            print(f"FAIL (gold validation): {failure}", file=sys.stderr)
        return EXIT_FAIL
    selected = evaluation_harness.select_smoke_sample(gold_rows)
    selected_ids = [str(row["sample_id"]) for row in selected]
    if selected_ids != list(T14_SMOKE_SAMPLE_IDS):
        print(
            "FAIL: the deterministic T14 smoke selection no longer matches the "
            f"frozen five sample ids: {selected_ids!r}",
            file=sys.stderr,
        )
        return EXIT_FAIL
    rows_by_id = {str(row["sample_id"]): row for row in selected}

    batch_id = "smoke_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    batch_dir = run_root / batch_id
    batch_dir.mkdir(parents=True, exist_ok=False)
    started_at = datetime.now(UTC).isoformat()
    results: list[dict[str, Any]] = []

    try:
        temp_dir = tempfile.TemporaryDirectory(prefix="eml_agentic_smoke_")
    except OSError as error:  # pragma: no cover - environment failure
        print(f"FAIL: cannot create a temporary directory: {error}", file=sys.stderr)
        return EXIT_FAIL
    try:
        for index, sample_id in enumerate(T14_SMOKE_SAMPLE_IDS):
            gold_row = rows_by_id[sample_id]
            source_profile = evaluation_harness.derive_source_profile(
                gold_row, evaluation_config
            )
            email_file = Path(temp_dir.name) / f"{index:04d}_{sample_id}.eml"
            email_file.write_bytes(verified_bytes[sample_id])
            try:
                result = run_agentic_email(
                    email_file,
                    settings,
                    source_profile=source_profile,  # type: ignore[arg-type]
                    run_root=run_root,
                    sample_id=sample_id,
                )
            except Exception as error:
                print(
                    f"FAIL: sample {sample_id}: agentic pipeline exception: "
                    f"{type(error).__name__}: {error}",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            if result.email_sha256 != str(gold_row["raw_sha256"]):
                print(
                    f"FAIL (gold/raw mismatch): sample {sample_id}: analyzed "
                    f"email_sha256 {result.email_sha256} != raw_sha256 "
                    f"{gold_row['raw_sha256']}",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            row = result.to_index_row()
            row["gold_label"] = gold_row["normalized_label"]
            results.append(row)
            print(
                f"[{index + 1}/{len(T14_SMOKE_SAMPLE_IDS)}] {sample_id} "
                f"status={result.status} action={result.action} "
                f"verdict={result.verdict} turns={result.llm_turn_count} "
                f"provider_calls={result.provider_tool_call_count}"
            )
    finally:
        temp_dir.cleanup()

    index = {
        "schema_version": "1.0",
        "architecture": ARCHITECTURE_NAME,
        "run_kind": "t19b_agentic_core_smoke",
        "measurement_scope": MEASUREMENT_SCOPE,
        "performance_claims_allowed": PERFORMANCE_CLAIMS_ALLOWED,
        "batch_id": batch_id,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "selected_sample_ids": selected_ids,
        "model_requested": settings.LITELLM_MODEL,
        "effective_prompt_sha256": agent_system_prompt_sha256(DEFAULT_AGENT_LIMITS),
        "limits": {
            "max_llm_turns": 5,
            "max_tool_calls": 4,
            "max_urlscan_calls": 1,
            "max_agent_seconds": MAX_AGENT_SECONDS,
            "max_single_llm_seconds": MAX_SINGLE_LLM_SECONDS,
        },
        "secret_presence": settings.secret_presence(),
        "rows": results,
        "notes": [
            "bounded smoke only: every provider outcome (including "
            "unavailable/not_found) is an honest archived result",
            "each sample ran exactly once; no selective rerun and no budget change",
            "no performance, Macro-F1 or architecture/model winner claim is allowed "
            "before TICKET-19E",
        ],
    }
    _write_json(batch_dir / "index.json", index)
    print(f"[T19B] batch index: {batch_dir / 'index.json'}")
    print(f"T19B status: {STATUS_T19B_DONE}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capability = subparsers.add_parser(
        "capability", help="T19A native tool-calling capability probe"
    )
    capability.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    capability.add_argument("--run-root", default="runs/agentic")
    capability.add_argument(
        "--source-profile",
        default="fixture",
        choices=["fixture", "public_corpus", "private_authorized"],
    )
    capability.set_defaults(func=run_capability)

    smoke = subparsers.add_parser(
        "smoke", help="T19B bounded agentic core on the frozen T14 five samples"
    )
    smoke.add_argument("--run-root", default="runs/agentic")
    smoke.set_defaults(func=run_smoke)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

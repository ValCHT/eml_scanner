#!/usr/bin/env python3
"""Real smoke tests (docs/gates.md §5.2, TICKET-02).

``smoke.py luna --if-configured`` performs a REAL structured-output POST to
the endpoint configured by ``Settings``:

- credentials absent            -> exit 0, status ``live_pending`` (G0-only
  allowance; G2 must lift it);
- credentials present, success  -> exit 0, ``live_ok``, real metadata
  archived under ``runs/gates/G0/smoke_luna/``: SHA-256 of the EXACT
  provider response bytes (computed before parsing), returned model, usage;
  never request headers, never the raw response body;
- credentials present, failure  -> non-zero exit, ``live_failed``; G0 then
  FAIL/BLOCKED.

``smoke.py luna --require-configured`` (TICKET-04, G2): credentials are
MANDATORY —

- credentials absent            -> explicit failure, non-zero exit (never
  ``live_pending``; G2 lifts the G0 allowance);
- credentials + real successful structured call -> exit 0;
- credentials + failed real call -> non-zero exit.

Success is never simulated.

``smoke.py luna-efforts`` runs REAL structured probes for ``medium`` and
``xhigh`` reasoning efforts (same tiny ``{ok: boolean}`` schema, no SOC
content) and archives factual observations per effort: HTTP-level success,
requested/returned model, usage, schema validity, ``reasoning_tokens``.
A 200 response never counts as "effort supported": only facts are recorded,
and an unverifiable/unsupported effort is recorded as an explicit
limitation, never simulated.

There is no mock/recorded/replay mode: a fabricated answer is a FAIL
condition of the ticket.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import Settings, load_settings  # noqa: E402
from src.llm import LunaClient, expurgate  # noqa: E402

#: Minimal smoke schema required by TICKET-02 (small {ok:boolean} contract).
SMOKE_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}

SMOKE_MESSAGES = [
    {"role": "system", "content": "You are a connectivity smoke test. Answer with the JSON object required by the schema."},
    {"role": "user", "content": 'Return exactly {"ok": true}.'},
]

SMOKE_EFFORT = "low"
SMOKE_MAX_OUTPUT_TOKENS = 128
SMOKE_DEADLINE_SECONDS = 60.0

#: The exact model the runtime is allowed to observe in this environment.
EXPECTED_SANDBOX_MODEL = "claude-haiku-4-5"

#: Reasoning efforts probed by ``luna-efforts`` (blocker 4). ``low`` is the
#: smoke default; the POC protocol (MEDIUM/XHIGH in G2/G6) needs these two.
PROBED_EFFORTS: tuple[str, ...] = ("medium", "xhigh")


def _latest_response_meta(capture_dir: Path) -> dict[str, object] | None:
    """Read the newest ``attempt_*_response_meta.json`` written by the client.

    The client persists metadata only (raw-bytes SHA-256, size, returned
    model, usage, fence flag); the raw response body is never on disk.
    """

    if not capture_dir.is_dir():
        return None
    metas = sorted(capture_dir.glob("attempt_*_response_meta.json"))
    if not metas:
        return None
    try:
        data = json.loads(metas[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _public_payload(result: object, record: object, capture_dir: Path) -> dict[str, object]:
    """Secret-free evidence: metadata only. Never headers, keys or raw body.

    ``response_sha256`` is the hash of the EXACT provider response bytes
    (computed by the client before parsing), read from the attempt metadata
    — never a hash of the normalized result.
    """

    meta = _latest_response_meta(capture_dir)
    data: dict[str, object] = {
        "status": "live_ok",
        "requested_model": getattr(record, "requested_model", None),
        "returned_model": getattr(record, "returned_model", None),
        "reasoning_effort": getattr(record, "reasoning_effort", None),
        "attempts": getattr(record, "attempts", 0),
        "usage": {
            "input_tokens": getattr(record, "input_tokens", None),
            "cached_input_tokens": getattr(record, "cached_input_tokens", None),
            "output_tokens": getattr(record, "output_tokens", None),
            "reasoning_tokens": getattr(record, "reasoning_tokens", None),
        },
        "response_sha256": (meta or {}).get("response_sha256"),
        "response_bytes": (meta or {}).get("response_bytes"),
        "fence_extracted": (meta or {}).get("fence_extracted"),
        "note_model_identity": (
            "sandbox derogation: requested model is claude-haiku-4-5 "
            "(Genspark environment); it is never presented as Luna."
            if getattr(record, "requested_model", "") == EXPECTED_SANDBOX_MODEL
            else "requested model comes from Settings (canonical: openai/gpt-5.6-luna)."
        ),
    }
    if isinstance(result, dict):
        data["result"] = result
    return data


def _write_receipt(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def smoke_luna(if_configured: bool = False, require_configured: bool = False) -> int:
    """Real Luna smoke; distinguishes pending (no key) from failure (key present).

    ``complete_json`` never raises (frozen public contract): every failure
    comes back as ``(None, record)`` with ``record.status="error"``.

    Modes (mutually exclusive at the CLI level):

    - ``--if-configured``: no credentials => explicit ``live_pending`` and
      exit 0 (permissive G0 behavior, unchanged);
    - ``--require-configured``: no credentials => explicit failure and
      non-zero exit; credentials + real successful structured call => exit
      0; credentials + failed real call => non-zero. Success is never
      simulated.
    """

    settings: Settings = load_settings(None)
    capture_dir = PROJECT_ROOT / "runs" / "gates" / "G0" / "smoke_luna"
    key_present = settings.LITELLM_API_KEY is not None

    if not key_present:
        if require_configured:
            payload = {
                "status": "live_failed",
                "reason": (
                    "LITELLM_API_KEY absent: --require-configured demands real "
                    "credentials; nothing simulated, no live_pending allowance."
                ),
                "requested_model": settings.LITELLM_MODEL,
                "endpoint_configured": settings.LITELLM_CHAT_URL,
            }
            _write_receipt(capture_dir / "smoke_result.json", payload)
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            print(
                "smoke luna: FAILED - credentials absent and --require-configured passed",
                file=sys.stderr,
            )
            return 1
        payload = {
            "status": "live_pending",
            "reason": "LITELLM_API_KEY absent: no real call possible; nothing simulated.",
            "requested_model": settings.LITELLM_MODEL,
            "endpoint_configured": settings.LITELLM_CHAT_URL,
            "g0_note": "live_pending is a G0-only allowance; G2 requires a real endpoint.",
        }
        _write_receipt(capture_dir / "smoke_result.json", payload)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if if_configured:
            print("smoke luna: live_pending (no credentials; --if-configured => exit 0)")
            return 0
        print("smoke luna: FAILED - credentials absent and --if-configured not passed", file=sys.stderr)
        return 1

    # Credentials exist: a failure here is REAL and must be non-zero.
    client = LunaClient(settings, phase="internal", capture_dir=capture_dir)
    deadline = time.monotonic() + SMOKE_DEADLINE_SECONDS
    result, record = client.complete_json(
        messages=SMOKE_MESSAGES,
        schema=SMOKE_SCHEMA,
        effort=SMOKE_EFFORT,
        max_output_tokens=SMOKE_MAX_OUTPUT_TOKENS,
        deadline=deadline,
    )

    payload = _public_payload(result, record, capture_dir)
    if result is None or record.status != "ok" or not isinstance(result, dict) or result.get("ok") is not True:
        payload["status"] = "live_failed"
        _write_receipt(capture_dir / "smoke_result.json", payload)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print(
            "smoke luna: FAILED with credentials present -> G0 FAIL/BLOCKED until fixed "
            f"(attempts={record.attempts}, error artifacts: {record.response_refs})",
            file=sys.stderr,
        )
        return 1

    _write_receipt(capture_dir / "smoke_result.json", payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print("smoke luna: live_ok (real structured answer; metadata archived, raw body never persisted)")
    return 0


def probe_luna_efforts() -> int:
    """Real MEDIUM/XHIGH probes (blocker 4): facts only, never claims.

    For each effort a real structured POST is sent with the same tiny
    ``{ok: boolean}`` schema (no SOC content). Archived per effort:

    - ``http_success``: the call completed with a validated structured
      answer at HTTP level (200 + ``finish_reason=stop`` + schema-valid);
    - requested model / returned model (identity enforced by the client);
    - usage, including ``reasoning_tokens``;
    - ``response_sha256`` of the exact provider bytes;
    - fence deviation flag when observed;
    - ``effort_verified``: what the observable behavior does — and does not
      — prove. A 200 alone never proves the effort was applied: the only
      externally observable signal is ``reasoning_tokens``; it is recorded
      as indicative, never as proof.

    Exit code: 0 when the probes ran and facts were archived (an xhigh
    rejection/ignore is a recorded LIMITATION, not a simulated success);
    non-zero when nothing could be executed (no credentials) or no probe
    produced facts.
    """

    settings: Settings = load_settings(None)
    out_path = PROJECT_ROOT / "runs" / "gates" / "G0" / "effort_probes.json"
    if settings.LITELLM_API_KEY is None:
        payload = {
            "status": "live_pending",
            "reason": "LITELLM_API_KEY absent: probes impossible; nothing simulated.",
            "requested_model": settings.LITELLM_MODEL,
            "probed_efforts": list(PROBED_EFFORTS),
            "limitations": ["effort probes not executable without credentials"],
        }
        _write_receipt(out_path, payload)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("luna-efforts: live_pending (no credentials) -> exit 1", file=sys.stderr)
        return 1

    limitations: list[str] = []
    probes: dict[str, object] = {}
    for effort in PROBED_EFFORTS:
        capture_dir = PROJECT_ROOT / "runs" / "gates" / "G0" / f"smoke_effort_{effort}"
        client = LunaClient(settings, phase="internal", capture_dir=capture_dir)
        started = time.monotonic()
        result, record = client.complete_json(
            messages=SMOKE_MESSAGES,
            schema=SMOKE_SCHEMA,
            effort=effort,
            max_output_tokens=SMOKE_MAX_OUTPUT_TOKENS,
            deadline=time.monotonic() + SMOKE_DEADLINE_SECONDS,
        )
        elapsed = round(time.monotonic() - started, 3)
        meta = _latest_response_meta(capture_dir)
        http_success = record.status == "ok" and result is not None
        entry: dict[str, object] = {
            "effort_requested": effort,
            "http_success": http_success,
            "requested_model": record.requested_model,
            "returned_model": record.returned_model,
            "attempts": record.attempts,
            "usage": {
                "input_tokens": record.input_tokens,
                "cached_input_tokens": record.cached_input_tokens,
                "output_tokens": record.output_tokens,
                "reasoning_tokens": record.reasoning_tokens,
            },
            "response_sha256": (meta or {}).get("response_sha256"),
            "response_bytes": (meta or {}).get("response_bytes"),
            "fence_extracted": (meta or {}).get("fence_extracted"),
            "schema_valid": result is not None,
            "result": result if isinstance(result, dict) else None,
            "error_artifacts": record.response_refs,
            "duration_s": elapsed,
            "effort_verified": (
                # FACTUAL scope: HTTP acceptance + schema-valid answer is
                # observed; the internal reasoning budget itself is NOT
                # externally verifiable. reasoning_tokens is indicative only.
                "not_provable_from_outside: 200 + schema-valid observed; "
                "reasoning_tokens recorded as indicative signal"
            ),
        }
        if http_success:
            entry["status"] = "probe_ok"
        else:
            entry["status"] = "probe_failed"
            limitations.append(
                f"effort {effort!r} probe failed after {record.attempts} attempt(s); "
                f"artifacts: {record.response_refs}"
            )
        probes[effort] = entry

    medium_entry = probes.get("medium")
    xhigh_entry = probes.get("xhigh")
    assert isinstance(medium_entry, dict) and isinstance(xhigh_entry, dict)
    medium_reasoning = (medium_entry.get("usage") or {}).get("reasoning_tokens")  # type: ignore[union-attr]
    xhigh_reasoning = (xhigh_entry.get("usage") or {}).get("reasoning_tokens")  # type: ignore[union-attr]
    if isinstance(medium_reasoning, int) and isinstance(xhigh_reasoning, int):
        limitations.append(
            f"reasoning_tokens medium={medium_reasoning} vs xhigh={xhigh_reasoning}: "
            "observational only, no causal claim about effort application"
        )
    else:
        limitations.append("reasoning_tokens not comparable (probe failure on at least one effort)")

    payload = {
        "status": "probes_executed",
        "requested_model": settings.LITELLM_MODEL,
        "probed_efforts": list(PROBED_EFFORTS),
        "probes": probes,
        "limitations": limitations,
        "decision_note": (
            "These facts feed the A/B/C protocol decision: if xhigh was "
            "rejected or is not verifiable with this runtime, MEDIUM/XHIGH "
            "cannot be claimed supported and the protocol must adapt."
        ),
    }
    _write_receipt(out_path, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"luna-efforts: probes executed; limitations={len(limitations)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Real smoke tests (no mock mode)")
    parser.add_argument("target", choices=["luna", "luna-efforts"], help="smoke target")
    parser.add_argument(
        "--if-configured",
        action="store_true",
        help="credentials absent => exit 0 with explicit live_pending (never a fake success)",
    )
    parser.add_argument(
        "--require-configured",
        action="store_true",
        help=(
            "TICKET-04/G2: credentials mandatory - absent => explicit failure "
            "(non-zero); real structured call must succeed => exit 0"
        ),
    )
    args = parser.parse_args()
    if args.if_configured and args.require_configured:
        parser.error("--if-configured and --require-configured are mutually exclusive")
    os.chdir(PROJECT_ROOT)
    if args.target == "luna":
        return smoke_luna(
            if_configured=args.if_configured,
            require_configured=args.require_configured,
        )
    return probe_luna_efforts()


if __name__ == "__main__":
    raise SystemExit(main())

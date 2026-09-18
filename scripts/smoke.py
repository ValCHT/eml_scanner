#!/usr/bin/env python3
"""Real smoke tests (docs/gates.md §5.2, TICKET-02).

``smoke.py luna --if-configured`` performs a REAL structured-output POST to
the endpoint configured by ``Settings``:

- credentials absent            -> exit 0, status ``live_pending`` (G0-only
  allowance; G2 must lift it);
- credentials present, success  -> exit 0, ``live_ok``, real evidence
  archived under ``runs/gates/G0/smoke_luna/`` (usage, returned model,
  response hash; never request headers);
- credentials present, failure  -> non-zero exit, ``live_failed``; G0 then
  FAIL/BLOCKED.

There is no mock/recorded/replay mode: a fabricated answer is a FAIL
condition of the ticket.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import Settings, load_settings  # noqa: E402
from src.llm import (  # noqa: E402
    LLMError,
    LunaClient,
    expurgate,
)

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


def _public_payload(result: object, record: object) -> dict[str, object]:
    """Secret-free evidence: usage, models, hashes. Never headers/keys."""

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
        "response_sha256": None,
        "note_model_identity": (
            "sandbox derogation: requested model is claude-haiku-4-5 "
            "(Genspark environment); it is never presented as Luna."
            if getattr(record, "requested_model", "") == EXPECTED_SANDBOX_MODEL
            else "requested model comes from Settings (canonical: openai/gpt-5.6-luna)."
        ),
    }
    if isinstance(result, dict):
        data["result"] = result
        data["response_sha256"] = hashlib.sha256(
            json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
    return data


def smoke_luna(if_configured: bool) -> int:
    """Real Luna smoke; distinguishes pending (no key) from failure (key present)."""

    settings: Settings = load_settings(None)
    capture_dir = PROJECT_ROOT / "runs" / "gates" / "G0" / "smoke_luna"
    key_present = settings.LITELLM_API_KEY is not None

    if not key_present:
        payload = {
            "status": "live_pending",
            "reason": "LITELLM_API_KEY absent: no real call possible; nothing simulated.",
            "requested_model": settings.LITELLM_MODEL,
            "endpoint_configured": settings.LITELLM_CHAT_URL,
            "g0_note": "live_pending is a G0-only allowance; G2 requires a real endpoint.",
        }
        capture_dir.mkdir(parents=True, exist_ok=True)
        (capture_dir / "smoke_result.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if if_configured:
            print("smoke luna: live_pending (no credentials; --if-configured => exit 0)")
            return 0
        print("smoke luna: FAILED - credentials absent and --if-configured not passed", file=sys.stderr)
        return 1

    # Credentials exist: a failure here is REAL and must be non-zero.
    client = LunaClient(settings, phase="internal", capture_dir=capture_dir)
    deadline = time.monotonic() + SMOKE_DEADLINE_SECONDS
    try:
        result, record = client.complete_json(
            messages=SMOKE_MESSAGES,
            schema=SMOKE_SCHEMA,
            effort=SMOKE_EFFORT,
            max_output_tokens=SMOKE_MAX_OUTPUT_TOKENS,
            deadline=deadline,
        )
    except LLMError as error:
        payload = {
            "status": "live_failed",
            "requested_model": settings.LITELLM_MODEL,
            "endpoint_configured": settings.LITELLM_CHAT_URL,
            "error": expurgate(str(error)),
            "response_sha256": None,
        }
        capture_dir.mkdir(parents=True, exist_ok=True)
        (capture_dir / "smoke_result.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print(
            "smoke luna: FAILED with credentials present -> G0 FAIL/BLOCKED until fixed",
            file=sys.stderr,
        )
        return 1

    payload = _public_payload(result, record)
    if result is None or record.status != "ok" or not isinstance(result, dict) or result.get("ok") is not True:
        payload["status"] = "live_failed"
        (capture_dir / "smoke_result.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("smoke luna: FAILED - no valid structured answer obtained", file=sys.stderr)
        return 1

    (capture_dir / "smoke_result.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print("smoke luna: live_ok (real structured answer archived)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Real smoke tests (no mock mode)")
    parser.add_argument("target", choices=["luna"], help="smoke target")
    parser.add_argument(
        "--if-configured",
        action="store_true",
        help="credentials absent => exit 0 with explicit live_pending (never a fake success)",
    )
    args = parser.parse_args()
    os.chdir(PROJECT_ROOT)
    if args.target == "luna":
        return smoke_luna(if_configured=args.if_configured)
    return 2  # pragma: no cover - argparse already restricts choices


if __name__ == "__main__":
    raise SystemExit(main())

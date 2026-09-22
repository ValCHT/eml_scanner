#!/usr/bin/env python3
"""Bounded OSINT backend smoke (TICKET-19D-OSINT §41, no LLM).

Two fixed targets, one execution each, no application retry:

1. ``example.com`` (domain)   -> ThreatFox + RDAP + DNS + CT
2. ``1.1.1.1``      (ipv4)    -> ThreatFox + RDAP

The script reads ONLY ``ABUSECH_API_KEY`` from the environment (the
operator injects it from the macOS Keychain in the calling shell)::

    ABUSECH_API_KEY="$(security find-generic-password -a "$USER" \\
        -s "abusech-api-key" -w)" python scripts/smoke_osint.py --require-threatfox

The key value is never printed, never archived (the adapter never stores
request headers), and a post-run scan asserts no capture contains it.

Exit codes: 0 = result.json written (assessment of the exchanges is left
to the operator/status); 2 = ``--require-threatfox`` demanded but a real
ThreatFox exchange could not be demonstrated for both targets (missing key
or genuine provider/network failure — never a retry loop).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import ToolsConfig, load_settings, load_yaml_config  # noqa: E402
from src.state import Observable  # noqa: E402
from src.tools import ToolContext, expurgate  # noqa: E402
from src.tools.osint import OsintAdapter  # noqa: E402
from src.config import EgressConfig  # noqa: E402

TICKET_DIR = PROJECT_ROOT / "runs" / "tickets" / "TICKET-19D-OSINT" / "smoke"

TARGETS: list[tuple[str, str]] = [
    ("example.com", "domain"),
    ("1.1.1.1", "ipv4"),
]


def _observable(target: str, kind: str, index: int) -> Observable:
    return Observable(
        id=f"obs_smoke_{index:02d}",
        value=target,
        normalized_value=target,
        type=kind,  # type: ignore[arg-type]
        provenance="INTERNE",
        source_ref="smoke:fixed-target",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded OSINT backend smoke (no LLM).")
    parser.add_argument(
        "--require-threatfox",
        action="store_true",
        help="Fail unless both targets show a real ThreatFox HTTP exchange.",
    )
    args = parser.parse_args()

    settings = load_settings(None)
    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    assert isinstance(tools_config, ToolsConfig)

    capture_dir = TICKET_DIR / "captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    clock = time.monotonic
    adapter = OsintAdapter(settings, tools_config.osint, clock=clock)

    key_present = settings.ABUSECH_API_KEY is not None
    print(f"threatfox key present: {key_present}")

    entries = []
    for index, (target, kind) in enumerate(TARGETS):
        query = _observable(target, kind, index)
        context = ToolContext(
            run_id="smoke-osint",
            source_profile="public_corpus",
            deadline=clock() + 120.0,
            egress=EgressConfig(
                allow_real_urls=False,
                approved_services=[],
                approved_exact_url_hosts=[],
                trusted_authserv_ids=[],
                shared_hosts=[],
                trusted_cti_sources=[],
            ),
            capture_dir=capture_dir,
            mode="live",
        )
        started = clock()
        result = adapter.lookup(query, context)
        elapsed = round((clock() - started) * 1000.0, 3)
        bundle = json.loads((capture_dir / str(result.response_ref)).read_bytes()) if result.response_ref else None
        sources = bundle["sources"] if bundle else {}
        entry = {
            "target": target,
            "type": kind,
            "registrable_domain": bundle.get("registrable_domain") if bundle else None,
            "tool_status": result.status,
            "tool_reason": result.reason,
            "source_statuses": {name: info["status"] for name, info in sources.items()},
            "source_reasons": {name: info["reason"] for name, info in sources.items()},
            "requests_sent": result.requests_sent,
            "response_ref": result.response_ref,
            "response_sha256": result.response_sha256,
            "evidence_count": len(result.evidence),
            "elapsed_ms": elapsed,
        }
        entries.append(entry)
        print(
            f"{target} ({kind}): tool={result.status} "
            + " ".join(f"{name}={info['status']}" for name, info in sources.items())
            + f" requests={result.requests_sent} evidence={len(result.evidence)}"
        )

    # Secret-absence scan over every capture written by this smoke.
    secret_fragment = settings.ABUSECH_API_KEY.get_secret_value() if key_present else None
    secret_persisted = False
    for path in sorted(capture_dir.iterdir()):
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        if secret_fragment and secret_fragment in text:
            secret_persisted = True
        if "Auth-Key" in text:
            secret_persisted = True
    print(f"secret_persisted: {secret_persisted}")

    document = {
        "targets": [
            {
                "target": entry["target"],
                "type": entry["type"],
                "registrable_domain": entry["registrable_domain"],
                "source_statuses": entry["source_statuses"],
                "source_reasons": entry["source_reasons"],
                "requests_sent": entry["requests_sent"],
                "response_sha256": entry["response_sha256"],
            }
            for entry in entries
        ],
        "tool": "osint",
        "psl_version": "1.0.2.20260921",
        "secret_persisted": secret_persisted,
        "key_present": key_present,
    }
    result_path = TICKET_DIR / "result.json"
    result_path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
    )
    print(f"wrote {expurgate(str(result_path))}")

    if secret_persisted:
        print("FAIL: secret material found in captures")
        return 2
    if args.require_threatfox:
        # A real exchange means the backend sent the request: statuses ok /
        # not_found (a genuine provider failure is archived honestly as
        # unavailable and does NOT count). not_configured means no exchange.
        exchanged = all(_threatfox_exchanged(entry) for entry in entries)
        if not exchanged:
            print("ThreatFox live exchange NOT demonstrated for both targets")
            return 2
        print("ThreatFox live exchange demonstrated for both targets")
    return 0


def _threatfox_exchanged(entry: dict[str, object]) -> bool:
    statuses = entry["source_statuses"]
    assert isinstance(statuses, dict)
    return statuses.get("threatfox") in ("ok", "not_found")


if __name__ == "__main__":
    raise SystemExit(main())

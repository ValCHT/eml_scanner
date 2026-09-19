#!/usr/bin/env python3
"""Real OpenAI-compatible runtime smoke tests.

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

``smoke.py luna-efforts`` is retained as a backward-compatible command name
for the two required Qwen3.8 probes. It refuses to run on any other model, so
the cheap GPT-OSS role can never be used to draw a conclusion about xhigh.
It archives factual observations under ``runs/runtime-migration``. A 200
response alone never proves semantic effort enforcement.

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
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import (  # noqa: E402
    EgressConfig,
    Settings,
    ToolsConfig,
    load_settings,
    load_yaml_config,
)
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

#: Runtime roles fixed by the migration decision.
CHEAP_TECHNICAL_MODEL = "openai/gpt-oss-20b"
OFFICIAL_POC_MODEL = "Qwen/Qwen3.8-27B"

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
        "runtime_role": (
            "cheap_technical_test"
            if getattr(record, "requested_model", "") == CHEAP_TECHNICAL_MODEL
            else (
                "official_poc"
                if getattr(record, "requested_model", "") == OFFICIAL_POC_MODEL
                else "explicit_custom_configuration"
            )
        ),
    }
    if isinstance(result, dict):
        data["result"] = result
    return data


def _write_receipt(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# TICKET-06 — VirusTotal real GET-lookup smoke (no upload, no POST)
# ---------------------------------------------------------------------------

#: Deterministic "unknown artifact" probe seed; the probed SHA-256 is derived
#: from the run identity so one run always probes one value, which is
#: practically guaranteed absent from VirusTotal. Pure GET lookup of a hash
#: string: never a file upload.
_UNKNOWN_HASH_SEED = "soc-email-triage/virustotal-smoke/unknown-artifact/"

#: Closed unavailable-cause vocabulary (architecture §1.6); a result may exit
#: 0 only with a real result or one of these causes.
_VT_CAUSES = (
    "not_configured",
    "access_not_authorized",
    "timeout",
    "rate_limited",
    "auth_error",
    "api_error",
    "malformed_response",
    "deadline",
)


def smoke_virustotal(if_configured: bool = False) -> int:
    """Real VirusTotal adapter smoke; GET lookups only, no upload.

    Behavior (docs/tickets/TICKET-06.md, docs/gates.md §5.2):

    - Without key or authorization: the REAL adapter is exercised and MUST
      return an explicit ``unavailable`` with its cause and ZERO requests.
      Exit 0 (a contractual unavailable is not a skipped test); the receipt
      records ``vt_nominal_validated=false`` with the exact limitation.
    - With key + authorization: real GET lookups — the configured public
      known hash (``LIVE_VT_KNOWN_SHA256``) when set, plus one deterministic
      unknown-hash probe expected ``not_found`` (real endpoint reach).
      ``vt_nominal_validated`` is true ONLY when a real known-hash ``ok``
      response was observed.
    - Any unexpected exception, or a result without its cause, exits
      non-zero. A fabricated answer is impossible by construction (the
      adapter has no mock mode) and would be a FAIL condition.
    """

    from src.state import Observable
    from src.tools import ToolContext
    from src.tools.virustotal import VirusTotalAdapter

    settings: Settings = load_settings(None)
    capture_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "virustotal"
    capture_dir.mkdir(parents=True, exist_ok=True)
    tools_config: ToolsConfig = load_yaml_config(
        PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig
    )
    adapter = VirusTotalAdapter(settings, tools_config.virustotal)

    run_id = str(uuid.uuid4())
    context = ToolContext(
        run_id=run_id,
        source_profile="fixture",
        deadline=time.monotonic() + tools_config.virustotal.phase_timeout_s,
        egress=tools_config.egress,
        capture_dir=capture_dir,
        mode="live",
    )

    results: list[dict[str, object]] = []
    limitations: list[str] = []
    vt_nominal_validated = False
    error: str | None = None

    try:
        # 1) Real unknown-hash probe (deterministic per run): a REAL exchange
        #    proving the endpoint is reachable, expected not_found.
        unknown = hashlib.sha256((_UNKNOWN_HASH_SEED + run_id).encode("utf-8")).hexdigest()
        result = adapter.lookup(
            Observable(
                id="smoke_unknown_sha256",
                value=unknown,
                normalized_value=unknown,
                type="sha256",
                roles=["attachment"],
                provenance="INTERNE",
                source_ref="smoke:unknown_probe",
            ),
            context,
        )
        results.append(result.model_dump(mode="json"))

        # 2) Real known-hash probe when the operator configured one.
        known = settings.LIVE_VT_KNOWN_SHA256
        if known:
            result = adapter.lookup(
                Observable(
                    id="smoke_known_sha256",
                    value=known,
                    normalized_value=known,
                    type="sha256",
                    roles=["attachment"],
                    provenance="INTERNE",
                    source_ref="smoke:configured_known_hash",
                ),
                context,
            )
            results.append(result.model_dump(mode="json"))
            vt_nominal_validated = result.status == "ok"
            if not vt_nominal_validated:
                limitations.append(
                    f"known-hash lookup returned {result.status} ({result.reason!r}); "
                    "vt_nominal_validated stays false"
                )
        else:
            limitations.append(
                "LIVE_VT_KNOWN_SHA256 not configured: no nominal (known-hash) real "
                "response could be observed; vt_nominal_validated=false"
            )
    except Exception as exc:  # noqa: BLE001 — any unexpected failure is REAL
        error = expurgate(f"{type(exc).__name__}: {exc}")

    if error is not None:
        payload = {
            "smoke": "virustotal",
            "status": "live_failed",
            "error": error,
            "vt_nominal_validated": False,
            "results": results,
            "limitations": limitations,
            "requests_sent_total": sum(
                int(entry.get("requests_sent") or 0) for entry in results
            ),
            "post_requests_sent": 0,
        }
        _write_receipt(capture_dir / "smoke_result.json", payload)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("smoke virustotal: FAILED (unexpected exception)", file=sys.stderr)
        return 1

    # Every result must be a real outcome or an explicit unavailable/skip
    # carrying its closed-vocabulary cause. A causeless status is a FAIL.
    for entry in results:
        status = entry.get("status")
        reason = entry.get("reason")
        if status in ("ok", "not_found"):
            continue
        if status == "unavailable":
            cause = str(reason or "").split(":", 1)[0].strip()
            if cause not in _VT_CAUSES:
                return _fail_smoke(
                    capture_dir,
                    f"unavailable result without a valid cause: {reason!r}",
                    payload_results=results,
                    limitations=limitations,
                )
        elif status == "skipped":
            if not str(reason or "").strip():
                return _fail_smoke(
                    capture_dir,
                    "skipped result without its reason",
                    payload_results=results,
                    limitations=limitations,
                )
        else:  # pragma: no cover - ToolResult status is closed vocabulary
            return _fail_smoke(
                capture_dir,
                f"unexpected result status {status!r}",
                payload_results=results,
                limitations=limitations,
            )

    configured = settings.VT_API_KEY is not None and settings.VT_ACCESS_AUTHORIZED
    if not configured:
        status = (
            "unavailable_access_not_authorized"
            if settings.VT_API_KEY is not None
            else "unavailable_not_configured"
        )
        limitations.append(
            "VT key/rights absent: the real adapter was exercised and returned an "
            "explicit unavailable with zero requests; vt_nominal_validated=false "
            "(nominal availability is not claimed)"
        )
    else:
        status = "live_ok"

    payload = {
        "smoke": "virustotal",
        "status": status,
        "vt_nominal_validated": vt_nominal_validated,
        "results": results,
        "limitations": limitations,
        "requests_sent_total": sum(
            int(entry.get("requests_sent") or 0) for entry in results
        ),
        "post_requests_sent": 0,
        "transport_invariant": (
            "GET only (vt-py get_async); no scan/upload/download path exists in the adapter"
        ),
    }
    _write_receipt(capture_dir / "smoke_result.json", payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(
        f"smoke virustotal: {status} (vt_nominal_validated={vt_nominal_validated}, "
        f"requests_sent={payload['requests_sent_total']}, post=0)"
    )
    return 0


def _fail_smoke(
    capture_dir: Path,
    message: str,
    *,
    payload_results: list[dict[str, object]],
    limitations: list[str],
) -> int:
    """Explicit smoke failure: non-zero exit, no fake success possible."""

    payload = {
        "smoke": "virustotal",
        "status": "live_failed",
        "error": message,
        "vt_nominal_validated": False,
        "results": payload_results,
        "limitations": limitations,
        "post_requests_sent": 0,
    }
    _write_receipt(capture_dir / "smoke_result.json", payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"smoke virustotal: FAILED ({message})", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# TICKET-07 — OpenCTI real read-only CTI smoke (no mutation, no upload)
# ---------------------------------------------------------------------------

#: Closed unavailable-cause vocabulary (architecture §1.6); a result may
#: exit 0 only with a real result or one of these causes.
_CTI_CAUSES = (
    "not_configured",
    "timeout",
    "rate_limited",
    "auth_error",
    "api_error",
    "malformed_response",
    "deadline",
)


def _near_miss_value(value: str) -> str:
    """A value one character away from the configured known observable."""

    return value[:-1] + ("m" if value.endswith("n") else "x")


def _smoke_approved_egress(tools_config: ToolsConfig) -> EgressConfig:
    """Egress with the OpenCTI service explicitly operator-approved.

    Used ONLY for this smoke's own context against the operator-selected
    public OpenCTI demo. ``configs/tools.yaml`` is deliberately not changed:
    the default ``approved_services=[]`` remains safe-by-default.
    """

    approved = sorted(
        {service.lower() for service in tools_config.egress.approved_services} | {"opencti"}
    )
    return tools_config.egress.model_copy(update={"approved_services": approved})


def _fail_smoke_opencti(
    capture_dir: Path,
    message: str,
    *,
    payload_results: list[dict[str, object]],
    limitations: list[str],
) -> int:
    """Explicit OpenCTI smoke failure: non-zero exit, nothing simulated."""

    payload = {
        "smoke": "opencti",
        "status": "live_failed",
        "error": message,
        "cti_exact_match_validated": False,
        "no_match_validated": False,
        "results": payload_results,
        "limitations": limitations,
        "mutations_sent": 0,
    }
    _write_receipt(capture_dir / "smoke_result.json", payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"smoke opencti: FAILED ({message})", file=sys.stderr)
    return 1


def smoke_opencti(if_configured: bool = False, require_configured: bool = False) -> int:
    """Real OpenCTI read-only smoke; GraphQL query only, no mutation.

    The smoke context explicitly approves the OpenCTI service for the
    operator-selected public demo instance; ``configs/tools.yaml`` is NOT
    changed (the default ``approved_services=[]`` stays safe-by-default).

    Behavior (docs/tickets/TICKET-07.md, docs/gates.md §5.2):

    - Without a token: the REAL adapter is exercised and returns an explicit
      ``unavailable/not_configured`` with ZERO requests. ``--require-configured``
      fails non-zero; ``--if-configured`` records the limitation and exits 0.
    - With a token: captures the observed platform version/schema, then runs
      REAL read-only lookups — the operator-verified known observable
      (``LIVE_CTI_KNOWN_VALUE``/``LIVE_CTI_KNOWN_TYPE``) must yield a
      locally-verified EXACT match, one deterministic unknown SHA-256 probe
      must be ``not_found``, and a near-miss value must never become an exact
      match. Nothing is fabricated: a missing known observable, a failed
      exact match or a bad status is an explicit non-zero failure.
    """

    from src.state import Observable
    from src.tools import ToolContext
    from src.tools.opencti import OpenCTIAdapter

    settings: Settings = load_settings(None)
    capture_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "opencti"
    capture_dir.mkdir(parents=True, exist_ok=True)
    tools_config: ToolsConfig = load_yaml_config(
        PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig
    )
    adapter = OpenCTIAdapter(settings, tools_config.opencti)

    def _context() -> ToolContext:
        return ToolContext(
            run_id=str(uuid.uuid4()),
            source_profile="fixture",
            deadline=time.monotonic() + tools_config.opencti.phase_timeout_s,
            egress=_smoke_approved_egress(tools_config),
            capture_dir=capture_dir,
            mode="live",
        )

    if settings.OPENCTI_API_KEY is None:
        result = adapter.lookup(
            Observable(
                id="smoke_unconfigured_probe",
                value="ticket07-smoke-unconfigured-probe.org",
                normalized_value="ticket07-smoke-unconfigured-probe.org",
                type="domain",
                roles=["link_target"],
                provenance="INTERNE",
                source_ref="smoke:unconfigured",
            ),
            _context(),
        )
        results = [result.model_dump(mode="json")]
        if result.status != "unavailable" or result.requests_sent != 0:
            return _fail_smoke_opencti(
                capture_dir,
                f"unconfigured adapter returned {result.status!r} with "
                f"{result.requests_sent} request(s)",
                payload_results=results,
                limitations=[],
            )
        if require_configured:
            return _fail_smoke_opencti(
                capture_dir,
                "OPENCTI_API_KEY absent: --require-configured demands real "
                "credentials; nothing simulated",
                payload_results=results,
                limitations=[],
            )
        payload = {
            "smoke": "opencti",
            "status": "unavailable_not_configured",
            "cti_exact_match_validated": False,
            "no_match_validated": False,
            "results": results,
            "limitations": [
                "OPENCTI_API_KEY absent: the real adapter was exercised and returned "
                "an explicit unavailable with zero requests; no nominal CTI validation"
            ],
            "requests_sent_total": 0,
            "mutations_sent": 0,
        }
        _write_receipt(capture_dir / "smoke_result.json", payload)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("smoke opencti: unavailable_not_configured")
        return 0

    results: list[dict[str, object]] = []
    limitations: list[str] = []
    try:
        context = _context()
        observation = adapter.observe_version_and_schema(context)
        if observation.get("status") != "ok":
            return _fail_smoke_opencti(
                capture_dir,
                f"version/schema observation failed: {observation}",
                payload_results=results,
                limitations=limitations,
            )
        if observation.get("revoked_on_stix_cyber_observable") is False:
            limitations.append(
                "observed StixCyberObservable schema has no 'revoked' field: "
                "cti_revoked cannot be produced for cyber observables"
            )
        known = settings.LIVE_CTI_KNOWN_VALUE
        known_type = settings.LIVE_CTI_KNOWN_TYPE
        if not known or not known_type:
            return _fail_smoke_opencti(
                capture_dir,
                "LIVE_CTI_KNOWN_VALUE/LIVE_CTI_KNOWN_TYPE not configured: no real "
                "exact-match validation is possible; nothing fabricated",
                payload_results=results,
                limitations=limitations,
            )

        known_query = Observable(
            id="smoke_known_observable",
            value=known,
            normalized_value=known,
            type=known_type,
            roles=["link_target"],
            provenance="INTERNE",
            source_ref="smoke:known_observable",
        )
        known_result = adapter.lookup(known_query, context)
        results.append(known_result.model_dump(mode="json"))
        exact_evidence = [
            evidence
            for evidence in known_result.evidence
            if evidence.predicate == "cti_exact_match"
            and evidence.match_level == "EXACT"
            and evidence.value is True
        ]
        if known_result.status != "ok" or len(exact_evidence) != 1:
            return _fail_smoke_opencti(
                capture_dir,
                f"known observable lookup: status={known_result.status!r} "
                f"reason={known_result.reason!r} exact_evidence={len(exact_evidence)}; "
                "no local exact verification",
                payload_results=results,
                limitations=limitations,
            )

        near = _near_miss_value(known)
        near_result = adapter.lookup(
            Observable(
                id="smoke_near_miss",
                value=near,
                normalized_value=near,
                type=known_type,
                roles=["link_target"],
                provenance="INTERNE",
                source_ref="smoke:near_miss",
            ),
            context,
        )
        results.append(near_result.model_dump(mode="json"))
        if near_result.status not in ("ok", "not_found"):
            return _fail_smoke_opencti(
                capture_dir,
                f"near-miss lookup returned unexpected status {near_result.status!r}",
                payload_results=results,
                limitations=limitations,
            )
        if near_result.status == "not_found" and near_result.evidence:
            return _fail_smoke_opencti(
                capture_dir,
                "near-miss lookup is not_found yet carries evidence",
                payload_results=results,
                limitations=limitations,
            )

        unknown = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        unknown_result = adapter.lookup(
            Observable(
                id="smoke_unknown_sha256",
                value=unknown,
                normalized_value=unknown,
                type="sha256",
                roles=["attachment"],
                provenance="INTERNE",
                source_ref="smoke:unknown_probe",
            ),
            context,
        )
        results.append(unknown_result.model_dump(mode="json"))
        if unknown_result.status != "not_found" or unknown_result.evidence:
            return _fail_smoke_opencti(
                capture_dir,
                f"no-match probe returned status={unknown_result.status!r} with "
                f"{len(unknown_result.evidence)} evidence item(s)",
                payload_results=results,
                limitations=limitations,
            )
    except Exception as exc:  # noqa: BLE001 — any unexpected failure is REAL
        return _fail_smoke_opencti(
            capture_dir,
            f"unexpected exception: {expurgate(f'{type(exc).__name__}: {exc}')}",
            payload_results=results,
            limitations=limitations,
        )

    # Every result must be a real outcome or an explicit unavailable/skip
    # carrying its closed-vocabulary cause. A causeless status is a FAIL.
    for entry in results:
        status = entry.get("status")
        reason = entry.get("reason")
        if status in ("ok", "not_found"):
            continue
        if status == "unavailable":
            cause = str(reason or "").split(":", 1)[0].strip()
            if cause not in _CTI_CAUSES:
                return _fail_smoke_opencti(
                    capture_dir,
                    f"unavailable result without a valid cause: {reason!r}",
                    payload_results=results,
                    limitations=limitations,
                )
        elif status == "skipped":
            if not str(reason or "").strip():
                return _fail_smoke_opencti(
                    capture_dir,
                    "skipped result without its reason",
                    payload_results=results,
                    limitations=limitations,
                )
        else:  # pragma: no cover - ToolResult status is closed vocabulary
            return _fail_smoke_opencti(
                capture_dir,
                f"unexpected result status {status!r}",
                payload_results=results,
                limitations=limitations,
            )

    payload = {
        "smoke": "opencti",
        "status": "live_ok",
        "cti_exact_match_validated": True,
        "no_match_validated": True,
        "platform_version": observation.get("version"),
        "schema_observation": {
            "revoked_on_stix_cyber_observable": observation.get(
                "revoked_on_stix_cyber_observable"
            ),
            "hashes_on_stix_file": observation.get("hashes_on_stix_file"),
            "requests_sent": observation.get("requests_sent"),
            "archived": observation.get("archived"),
        },
        "results": results,
        "limitations": limitations,
        "requests_sent_total": sum(
            int(entry.get("requests_sent") or 0) for entry in results
        ),
        "mutations_sent": 0,
        "egress_note": (
            "OpenCTI service explicitly approved for this smoke context only "
            "(configs/tools.yaml unchanged; default approved_services=[] stays "
            "safe-by-default)"
        ),
        "transport_invariant": (
            "read-only GraphQL query only via pycti "
            "stix_cyber_observable.list(search, first=10, getAll=False); "
            "no mutation/create/update path exists in the adapter"
        ),
    }
    _write_receipt(capture_dir / "smoke_result.json", payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(
        "smoke opencti: live_ok (cti_exact_match_validated=True, "
        f"no_match_validated=True, platform={payload['platform_version']})"
    )
    return 0


def smoke_luna(if_configured: bool = False, require_configured: bool = False) -> int:
    """Real runtime smoke; distinguishes pending from failure.

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
    """Real Qwen3.8 MEDIUM/XHIGH probes: facts only, never claims.

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
    out_path = (
        PROJECT_ROOT
        / "runs"
        / "runtime-migration"
        / "compatibility"
        / "qwen38_effort_probes.json"
    )
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

    if settings.LITELLM_MODEL != OFFICIAL_POC_MODEL:
        payload = {
            "status": "configuration_error",
            "reason": (
                "medium/xhigh probes require the official Qwen3.8 model; "
                "GPT-OSS must not be used to validate xhigh"
            ),
            "requested_model": settings.LITELLM_MODEL,
            "required_model": OFFICIAL_POC_MODEL,
            "probed_efforts": [],
        }
        _write_receipt(out_path, payload)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 1

    limitations: list[str] = []
    probes: dict[str, object] = {}
    for effort in PROBED_EFFORTS:
        capture_dir = out_path.parent / f"qwen38_effort_{effort}"
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

    compatible = all(
        isinstance(probes.get(effort), dict)
        and probes[effort].get("http_success") is True  # type: ignore[union-attr]
        for effort in PROBED_EFFORTS
    )
    payload = {
        "status": "compatible" if compatible else "incompatible",
        "requested_model": settings.LITELLM_MODEL,
        "probed_efforts": list(PROBED_EFFORTS),
        "probes": probes,
        "limitations": limitations,
        "decision_note": (
            "HTTP acceptance, returned-model identity and reasoning-token "
            "observations are recorded. Semantic effort distinction is not "
            "claimed from a successful HTTP response alone."
        ),
    }
    _write_receipt(out_path, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(
        f"luna-efforts: probes executed; compatible={compatible}; "
        f"limitations={len(limitations)}"
    )
    return 0 if compatible else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Real smoke tests (no mock mode)")
    parser.add_argument(
        "target", choices=["luna", "luna-efforts", "virustotal", "opencti"], help="smoke target"
    )
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
    if args.target == "virustotal":
        return smoke_virustotal(if_configured=args.if_configured)
    if args.target == "opencti":
        return smoke_opencti(
            if_configured=args.if_configured,
            require_configured=args.require_configured,
        )
    return probe_luna_efforts()


if __name__ == "__main__":
    raise SystemExit(main())

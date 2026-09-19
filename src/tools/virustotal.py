"""VirusTotal real lookup adapter — GET only, no upload (TICKET-06, gate G4).

Contract (docs/architecture.md §1.6, docs/contracts.md §2.7, TICKET-06):

- Four GET endpoints ONLY: ``/files/{sha256}``, ``/urls/{vt.url_id(url)}``,
  ``/domains/{domain}``, ``/ip_addresses/{ip}``. sha1/md5 are deliberately
  never looked up (one SHA-256 per file; no sha1/md5 endpoint in the frozen
  list). No POST, no scan, no upload, no file download: vt-py's ``scan_*``,
  ``post*``, ``download_*``, ``patch*`` and ``delete`` methods are never
  called — the transport only awaits ``get_async``.
- Statuses: ``ok`` / ``not_found`` / ``unavailable`` / ``skipped``. Every
  ``unavailable`` carries its closed-vocabulary cause (not_configured,
  access_not_authorized, timeout, rate_limited, auth_error, api_error,
  malformed_response, deadline); ``skipped`` carries disabled /
  not_applicable / privacy_policy / budget.
- Without key or authorization: explicit ``unavailable`` with ZERO
  requests. An unavailable VT never blocks the pipeline and never becomes
  a benign observation.
- Local conservative rate limiter (requests_per_minute / requests_per_day
  UTC from configs/tools.yaml), persisted as a small quota-journal JSON so
  process restarts do not forget the budget; NEVER waits on a 429 — the
  response maps to unavailable/rate_limited and the pipeline continues.
- Phase budget: every request timeout is the EXACT remaining float budget —
  min(actual remaining deadline, phase_timeout_s from the configuration) —
  never rounded upward and never extended by a grace margin; below a
  minimal safe send budget the lookup returns unavailable/deadline instead
  of exceeding the frozen deadline. The VT phase stays ≤ 20 s.
- The API key exists only inside the transport (headers built by vt-py);
  it never enters the context, the logs, the captures or the results.
- URL lookups obey the egress rules (architecture §1.6 "Sorties vers
  tiers"): userinfo / credential-like parameters / action-effect URLs /
  personal identifiers / internal hosts / non-global IP literals /
  .test-.invalid-localhost / non-HTTP(S) are refused, and a real URL is
  sent only when the operator's egress policy explicitly allows real URLs,
  this tool and the exact URL host. Otherwise the lookup is
  ``skipped``/``privacy_policy`` with zero requests. Domains keep the same
  internal/reserved-host refusal; IPs must be global.
- Nominal VT availability is never claimed by the adapter: callers and the
  smoke report ``vt_nominal_validated`` only from REAL ``ok`` responses.

There is no mock/test/real mode: a fabricated VT answer is a FAIL condition
of the ticket. Controlled error objects (timeout / connection failure) may
be fed to ``normalize_response`` for deterministic error mapping — they are
local facts, never provider observations.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from ..config import Settings, VirustotalToolConfig
from ..state import Link, Observable, ParsedEmail, ToolResult
from . import ResponseMetadata, ToolContext, det_id, expurgate, now_utc_iso

_VT_HOST = "https://www.virustotal.com/api/v3"

_USER_AGENT = "soc-email-triage-poc/0.1 (GET lookups only)"

#: Observable types with a frozen VT GET endpoint (architecture §1.6).
LOOKUPABLE_TYPES: tuple[str, ...] = ("sha256", "url", "domain", "ipv4", "ipv6")

#: Below this remaining budget a request cannot be sent safely: returning
#: ``unavailable/deadline`` is more honest than starting an exchange that is
#: already doomed to overrun the frozen deadline (TICKET-06 PR #9 blocker 2).
_MIN_REQUEST_BUDGET_S = 0.5

#: Credential-like / action-effect markers (architecture §1.6: "jeton
#: évident/password/reset/unsubscribe/action à effet").
_CREDENTIAL_LIKE_RE = re.compile(
    r"(?i)(?:[?&])(?:token|api[_-]?key|access[_-]?token|key|password|passwd|"
    r"secret|session|otp|authorization)="
)
_ACTION_EFFECT_RE = re.compile(
    r"(?i)(?:reset[-_]?password|password[-_]?reset|forgot[-_]?password|"
    r"unsubscribe|sign[-_]?out|log[-_]?out|confirm[-_]?action|verify[-_]?account|"
    r"delete[-_]?account|cancel[-_]?subscription)"
)
_PERSONAL_IDENTIFIER_RE = re.compile(
    r"(?i)(?:^|[/?&=])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

#: Hosts/TLDs that must never leave the machine (architecture §1.6:
#: ".test/.invalid/localhost ou hôte interne").
_RESERVED_HOST_SUFFIXES = (
    ".localhost",
    ".test",
    ".invalid",
    ".local",
    ".example",
    ".internal",
    ".corp",
    ".home.arpa",
)


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested; no I/O)
# ---------------------------------------------------------------------------


def endpoint_for(query: Observable) -> tuple[str, str] | None:
    """Frozen endpoint for one observable: ``(method, path)`` or ``None``.

    Only the four GET endpoints exist; any other observable type has no
    authorized lookup (sha1/md5/email/message_id/campaign_id are never
    substituted by another endpoint).
    """

    value = (query.normalized_value or query.value).strip()
    if query.type == "sha256":
        if not re.fullmatch(r"[0-9a-f]{64}", value, re.IGNORECASE):
            return None
        return "GET", f"/files/{value.lower()}"
    if query.type == "url":
        if not value:
            return None
        import vt

        return "GET", f"/urls/{vt.url_id(value)}"
    if query.type == "domain":
        host = value.lower().rstrip(".")
        if not host or "." not in host or host.endswith(_RESERVED_HOST_SUFFIXES):
            return None
        return "GET", f"/domains/{host}"
    if query.type in ("ipv4", "ipv6"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if not address.is_global:
            return None
        return "GET", f"/ip_addresses/{address.compressed}"
    return None


def url_send_refusal(url: str, egress: Any) -> str | None:
    """Refusal code when this URL must NOT be disclosed to a third party.

    Returns ``None`` only when every local refusal rule passes AND the
    operator's egress policy explicitly allows real URLs for this tool and
    this exact host. Passing these checks is an operator decision, never a
    proof that the URL is harmless.
    """

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "scheme_not_http_s"
    if parsed.username or parsed.password:
        return "userinfo_present"
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return "missing_host"
    if hostname == "localhost" or hostname.endswith(_RESERVED_HOST_SUFFIXES):
        return "internal_or_reserved_host"
    try:
        address = ipaddress.ip_address(hostname)
        if not address.is_global:
            return "non_global_ip"
    except ValueError:
        pass  # a name, not an IP literal
    if _CREDENTIAL_LIKE_RE.search(url):
        return "credential_like_parameter"
    if _PERSONAL_IDENTIFIER_RE.search(url):
        return "personal_identifier"
    if _ACTION_EFFECT_RE.search(url):
        return "action_effect_url"
    if not egress.allow_real_urls:
        return "egress_allow_real_urls_false"
    if "virustotal" not in {service.lower() for service in egress.approved_services}:
        return "tool_not_approved_in_egress"
    if hostname not in {host.lower() for host in egress.approved_exact_url_hosts}:
        return "exact_url_host_not_approved"
    return None


# ---------------------------------------------------------------------------
# Quota journal (small JSON; restart-safe budget; never a security control)
# ---------------------------------------------------------------------------


class _RateLimiter:
    """Conservative LOCAL rate limiter; records requests, never waits."""

    def __init__(
        self,
        requests_per_minute: int,
        requests_per_day: int,
        journal_path: Path,
        clock: Callable[[], float],
    ) -> None:
        self._rpm = requests_per_minute
        self._rpd = requests_per_day
        self._path = Path(journal_path)
        self._clock = clock
        self._window: list[float] = []
        self._day = datetime.now(UTC).date().isoformat()
        self._day_count = 0
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        # A journal from a previous UTC day keeps its counts but they no
        # longer apply; a new UTC day starts at zero by construction.
        if data.get("day_utc") == self._day:
            self._day_count = int(data.get("day_count") or 0)
            window = data.get("window_requests_monotonic")
            if isinstance(window, list):
                self._window = [
                    float(item) for item in window if isinstance(item, (int, float))
                ]

    def _prune(self) -> None:
        now = self._clock()
        self._window = [stamp for stamp in self._window if now - stamp < 60.0]
        today = datetime.now(UTC).date().isoformat()
        if today != self._day:
            self._day = today
            self._day_count = 0

    def allow(self) -> bool:
        self._prune()
        return len(self._window) < self._rpm and self._day_count < self._rpd

    def record(self, http_status: int | None, headers: Mapping[str, str] | None) -> None:
        """Record one sent request (it consumed quota even on error)."""

        self._window.append(self._clock())
        self._prune()
        self._day_count += 1
        entry: dict[str, Any] = {
            "day_utc": self._day,
            "day_count": self._day_count,
            "window_requests_monotonic": self._window,
            "requests_per_minute": self._rpm,
            "requests_per_day": self._rpd,
            "updated_at": now_utc_iso(),
            "last_http_status": http_status,
        }
        # Service rate-limit headers are factual observations of THIS key's
        # usage; they never replace the local conservative counters.
        if headers:
            quota_headers = {
                name.lower(): headers[name]
                for name in headers
                if name.lower().startswith("x-ratelimit-")
            }
            if quota_headers:
                entry["provider_rate_headers"] = quota_headers
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError:
            # The journal is a budget-survival optimization, not a control:
            # an unwritable path degrades to in-memory counting only.
            pass


# ---------------------------------------------------------------------------
# Transport (vt-py, GET only) — isolated so a later ticket that owns the
# dependency manifests can evolve it without touching the adapter logic
# (same precedent as src/llm.py's isolated transport)
# ---------------------------------------------------------------------------


class VTTransportError(Exception):
    """Local transport failure; ``kind`` is a controlled error-object kind."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = expurgate(detail)


def _vt_get_raw(
    apikey: str,
    endpoint: str,
    timeout_s: float,
) -> tuple[int, bytes, dict[str, str]]:
    """One real GET against the VirusTotal API v3 (exact raw bytes).

    Uses vt-py's ``get_async`` exclusively — never ``post*``, ``scan*``,
    ``download*``, ``patch*`` or ``delete``. Returns
    ``(http_status, raw_body_bytes, response_headers)``.

    ``timeout_s`` is the EXACT remaining budget as a float (never rounded
    upward): it is passed both to the aiohttp client total timeout and to
    the outer ``asyncio.wait_for`` — the wall-clock bound never extends
    beyond this value.
    """

    try:
        import vt
    except ImportError as error:
        raise VTTransportError(
            "connection_error", f"vt-py transport dependency missing: {error}"
        ) from error

    async def _run() -> tuple[int, bytes, dict[str, str]]:
        client = vt.Client(apikey, agent=_USER_AGENT, timeout=timeout_s)
        try:
            response = await client.get_async(endpoint)
            raw = await response.read_async()
            return int(response.status), raw, dict(response.headers)
        finally:
            await client.close_async()

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        # Hard bound: EXACTLY the remaining budget — no grace extension.
        return loop.run_until_complete(asyncio.wait_for(_run(), timeout=timeout_s))
    except (TimeoutError, asyncio.TimeoutError) as error:
        raise VTTransportError("timeout", f"VT GET timed out after {timeout_s}s") from error
    except asyncio.CancelledError:  # pragma: no cover - cancellation plumbing
        raise
    except Exception as error:  # aiohttp/OS layer failures are local facts
        raise VTTransportError("connection_error", f"VT transport error: {error}") from error
    finally:
        asyncio.set_event_loop(None)
        loop.close()


# ---------------------------------------------------------------------------
# Response capture (restricted data under runs/, git-ignored)
# ---------------------------------------------------------------------------


def _capture_name(query: Observable) -> str:
    kind = {
        "sha256": "files",
        "url": "urls",
        "domain": "domains",
        "ipv4": "ip",
        "ipv6": "ip",
    }[query.type]
    value_digest = hashlib.sha256(
        (query.normalized_value or query.value).encode("utf-8")
    ).hexdigest()
    return f"virustotal_{kind}_{value_digest[:16]}"


def _archive_response(
    context: ToolContext,
    query: Observable,
    raw: bytes,
    metadata: ResponseMetadata,
) -> str:
    """Archive the EXACT provider response bytes + provenance metadata.

    Returns the local reference (file name inside the capture directory).
    Only factual fields are stored: origin, HTTP status, service date,
    exact-bytes SHA-256, the queried observable — never any header with key
    material and never the outgoing request.
    """

    name = _capture_name(query)
    body_path = Path(context.capture_dir) / f"{name}.json"
    meta_path = Path(context.capture_dir) / f"{name}.meta.json"
    body_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.write_bytes(raw)
    meta = {
        "tool": "virustotal",
        "origin": metadata.origin,
        "http_status": metadata.http_status,
        "response_date": metadata.response_date,
        "response_sha256": metadata.response_sha256,
        "collected_at": now_utc_iso(),
        "run_id": context.run_id,
        "mode": context.mode,
        "query": {
            "observable_id": query.id,
            "type": query.type,
            "normalized_value": query.normalized_value,
        },
    }
    meta_path.write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return body_path.name


# ---------------------------------------------------------------------------
# Normalizer (pure; controlled error objects in, ToolResult out)
# ---------------------------------------------------------------------------


def normalize_response(
    query: Observable,
    body: Mapping[str, object] | None,
    metadata: ResponseMetadata,
) -> ToolResult:
    """Map one provider exchange to the normalized ToolResult (§2.7).

    ``body`` is the parsed provider JSON (or ``None`` for controlled error
    objects). A missing/absent field stays absent: values are never
    fabricated, counters never rebuilt from a wrong denominator, and no
    ``not_found``/``unavailable``/``malformed`` case can ever produce a
    benign-looking observation.
    """

    collected_at = now_utc_iso()
    observed_at = metadata.response_date or collected_at
    base: dict[str, Any] = {
        "tool": "virustotal",
        "query_observable_id": query.id,
        "observables": [],
        "response_sha256": metadata.response_sha256,
        "response_ref": metadata.response_ref,
        "collected_at": collected_at,
        "visibility": None,
        "scan_id": None,
    }

    def _result(
        status: str,
        reason: str | None,
        evidence: list[dict[str, Any]] | None = None,
        mode: str = "none",
    ) -> ToolResult:
        return ToolResult(
            **base,
            status=status,  # type: ignore[arg-type]
            reason=reason,
            evidence=evidence or [],
            mode=mode,  # type: ignore[arg-type]
        )

    def _evidence(
        predicate: str,
        value: float,
        pointer: str,
        match_level: str,
    ) -> dict[str, Any]:
        return {
            "id": det_id("ev", predicate, str(value), metadata.response_ref, pointer),
            "provenance": "OSINT",
            "source_kind": "virustotal",
            "observable_id": query.id,
            "predicate": predicate,  # type: ignore[typeddict-item]
            "value": value,
            "source_ref": f"{metadata.response_ref}#/{pointer}",
            "observed_at": observed_at,
            "match_level": match_level,  # type: ignore[typeddict-item]
            "source_group": "virustotal",
        }

    # --- controlled error objects (local transport facts) --------------------
    if metadata.error_kind == "timeout":
        return _result("unavailable", "timeout")
    if metadata.error_kind == "connection_error":
        return _result("unavailable", "api_error")
    if metadata.error_kind == "malformed":
        return _result("unavailable", "malformed_response")

    # --- HTTP status mapping ---------------------------------------------------
    status = metadata.http_status
    if status is None:
        return _result("unavailable", "api_error", mode="live")
    if status == 404:
        return _result("not_found", None, mode="live")
    if status in (401, 403):
        return _result("unavailable", "auth_error", mode="live")
    if status == 429:
        return _result("unavailable", "rate_limited", mode="live")
    if not 200 <= status < 300:
        return _result("unavailable", "api_error", mode="live")

    # --- 200: parse and project -----------------------------------------------
    if not isinstance(body, Mapping):
        return _result("unavailable", "malformed_response", mode="live")
    data = body.get("data")
    if not isinstance(data, Mapping):
        return _result("unavailable", "malformed_response", mode="live")
    attributes = data.get("attributes")
    if attributes is not None and not isinstance(attributes, Mapping):
        return _result("unavailable", "malformed_response", mode="live")
    assert isinstance(attributes, Mapping) or attributes is None

    match_level = "EXACT"
    reason: str | None = None
    if query.type == "url":
        returned_url = attributes.get("url") if attributes else None
        if isinstance(returned_url, str) and returned_url != query.value:
            # The response is not demonstrably for the exact queried URL: the
            # counts keep their values but may never corroborate THIS exact
            # observable (verify rule V06). Downgraded from EXACT, never
            # presented as an exact corroboration.
            match_level = "GENERIC"
            reason = "url_response_mismatch"

    evidence: list[dict[str, Any]] = []
    raw_stats = attributes.get("last_analysis_stats") if attributes else None
    if raw_stats is not None:
        if not isinstance(raw_stats, Mapping):
            return _result("unavailable", "malformed_response", mode="live")
        numeric: dict[str, int] = {}
        for key, raw_value in raw_stats.items():
            if isinstance(raw_value, bool) or not isinstance(raw_value, int):
                return _result("unavailable", "malformed_response", mode="live")
            if raw_value < 0:
                return _result("unavailable", "malformed_response", mode="live")
            numeric[str(key)] = raw_value
        predicate_by_key = {
            "malicious": "vt_malicious_count",
            "suspicious": "vt_suspicious_count",
            "harmless": "vt_harmless_count",
            "undetected": "vt_undetected_count",
        }
        for key, value in numeric.items():
            predicate = predicate_by_key.get(key)
            if predicate is None:
                continue  # unknown category: kept in the denominator only
            evidence.append(
                _evidence(
                    predicate,
                    value,
                    f"data/attributes/last_analysis_stats/{key}",
                    match_level,
                )
            )
        if numeric:
            # Real denominator: the sum of EVERY returned analysis category
            # (including categories without a dedicated predicate, e.g.
            # timeout / type-unsupported). Never "12/90 built from a bad
            # total"; the scope is the response itself.
            engine_total = sum(numeric.values())
            evidence.append(
                _evidence(
                    "vt_engine_total",
                    engine_total,
                    "data/attributes/last_analysis_stats",
                    match_level,
                )
            )
    analysis_date = attributes.get("last_analysis_date") if attributes else None
    if isinstance(analysis_date, (int, float)) and not isinstance(analysis_date, bool):
        evidence.append(
            _evidence(
                "vt_analysis_time",
                float(analysis_date),
                "data/attributes/last_analysis_date",
                match_level,
            )
        )
    return _result("ok", reason, evidence, mode="live")


# ---------------------------------------------------------------------------
# ToolResult construction helpers
# ---------------------------------------------------------------------------


def _base_result(query: Observable) -> dict[str, Any]:
    return {
        "tool": "virustotal",
        "query_observable_id": query.id,
        "observables": [],
        "response_sha256": None,
        "response_ref": None,
        "collected_at": now_utc_iso(),
        "visibility": None,
        "scan_id": None,
    }


def _skip(
    query: Observable,
    reason: str,
    elapsed_ms: float,
    mode: str = "none",
    reason_detail: str | None = None,
) -> ToolResult:
    detail = reason if reason_detail is None else f"{reason}: {reason_detail}"
    return ToolResult(
        **_base_result(query),
        status="skipped",
        reason=detail,
        mode=mode,  # type: ignore[arg-type]
        elapsed_ms=elapsed_ms,
        requests_sent=0,
    )


def _unavailable(
    query: Observable,
    cause: str,
    elapsed_ms: float,
    mode: str = "none",
    reason_detail: str | None = None,
) -> ToolResult:
    detail = cause if reason_detail is None else f"{cause}: {reason_detail}"
    return ToolResult(
        **_base_result(query),
        status="unavailable",
        reason=detail,
        mode=mode,  # type: ignore[arg-type]
        elapsed_ms=elapsed_ms,
        requests_sent=0,
    )


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class VirusTotalAdapter:
    """Real VirusTotal GET-lookup adapter; one observable per ``lookup``.

    The API key never leaves the transport call. ``lookup`` performs ONE
    authorized lookup; the deterministic (internal-data-only) target plan
    helper is :func:`plan_vt_targets` (§1.6 priority order, max_targets).
    """

    def __init__(
        self,
        settings: Settings,
        config: VirustotalToolConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        quota_journal_path: Path | None = None,
    ) -> None:
        self._settings = settings
        self._config = config
        self._clock = clock
        self._limiter = _RateLimiter(
            requests_per_minute=config.requests_per_minute,
            requests_per_day=config.requests_per_day,
            journal_path=quota_journal_path
            or (Path(settings.RUNS_DIR) / "quota" / "virustotal.json"),
            clock=clock,
        )

    def lookup(self, query: Observable, context: ToolContext) -> ToolResult:
        started = self._clock()

        def _elapsed() -> float:
            return round((self._clock() - started) * 1000.0, 3)

        # --- configuration gate: ZERO requests -----------------------------------
        if not self._config.enabled:
            return _skip(query, "disabled", _elapsed())

        # --- endpoint availability for this observable type ----------------------
        # (request-dependent gates precede credentials/budget gates: a request
        # that can never be sent is refused for the most specific reason)
        try:
            endpoint = endpoint_for(query)
        except ImportError:  # vt-py missing for /urls/{id}
            return _unavailable(
                query,
                "api_error",
                _elapsed(),
                mode="none",
                reason_detail="vt-py transport dependency not installed",
            )
        if endpoint is None or query.type not in LOOKUPABLE_TYPES:
            return _skip(query, "not_applicable", _elapsed())

        # --- egress / privacy gates (zero requests on refusal) --------------------
        if query.type == "url":
            refusal = url_send_refusal(query.value, context.egress)
            if refusal is not None:
                return _skip(
                    query, "privacy_policy", _elapsed(), reason_detail=refusal
                )
        elif query.type == "domain":
            host = (query.normalized_value or query.value).lower().rstrip(".")
            if host == "localhost" or host.endswith(_RESERVED_HOST_SUFFIXES):
                return _skip(
                    query, "privacy_policy", _elapsed(), reason_detail="reserved_host"
                )
        # ipv4/ipv6 non-global cases were already refused by endpoint_for().

        # --- credentials / authorization gates: ZERO requests ---------------------
        if self._settings.VT_API_KEY is None:
            return _unavailable(query, "not_configured", _elapsed())
        if not self._settings.VT_ACCESS_AUTHORIZED:
            return _unavailable(query, "access_not_authorized", _elapsed())

        # --- deadline / budget gates ---------------------------------------------
        remaining = context.deadline - self._clock()
        if remaining <= 0:
            return _unavailable(query, "deadline", _elapsed())
        if not self._limiter.allow():
            return _unavailable(query, "rate_limited", _elapsed())

        # Frozen contract (TICKET-06 PR #9 blocker 2): the request timeout is
        # the EXACT remaining budget as a float — min(actual remaining
        # deadline, phase_timeout_s) — never rounded upward beyond the
        # deadline, never forced to a 1-second minimum. When too little time
        # remains to safely send, the lookup returns unavailable/deadline
        # instead of starting an exchange that would overrun the deadline.
        budget_s = min(remaining, float(self._config.phase_timeout_s))
        if budget_s < _MIN_REQUEST_BUDGET_S:
            return _unavailable(query, "deadline", _elapsed())
        method, path = endpoint
        if method != "GET":  # pragma: no cover - defensive; endpoint_for is pure
            return _unavailable(
                query, "api_error", _elapsed(), mode="none", reason_detail="non_get_endpoint"
            )
        assert self._settings.VT_API_KEY is not None  # narrowed above
        apikey = self._settings.VT_API_KEY.get_secret_value()

        try:
            http_status, raw, headers = _vt_get_raw(apikey, path, budget_s)
        except VTTransportError as error:
            # The request attempt consumed quota (conservative accounting).
            self._limiter.record(None, None)
            metadata = ResponseMetadata(
                origin=_VT_HOST,
                http_status=None,
                error_kind=error.kind,
                error_detail=error.detail,
            )
            result = normalize_response(query, None, metadata)
            return result.model_copy(
                update={
                    "elapsed_ms": _elapsed(),
                    "requests_sent": 1,
                    "mode": context.mode,
                }
            )

        self._limiter.record(http_status, headers)
        metadata = ResponseMetadata(
            origin=_VT_HOST,
            http_status=http_status,
            response_date=headers.get("Date"),
            response_sha256=hashlib.sha256(raw).hexdigest(),
        )
        response_ref = _archive_response(context, query, raw, metadata)
        metadata = metadata.model_copy(update={"response_ref": response_ref})
        body: Mapping[str, object] | None = None
        parsed_body: object = None
        try:
            parsed_body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed_body = None
        if http_status == 200:
            if isinstance(parsed_body, dict):
                body = parsed_body
            else:
                metadata = metadata.model_copy(update={"error_kind": "malformed"})
        # 4xx/5xx: the STATUS drives the cause; an error body, when present,
        # is archived for traceability only and never becomes evidence.
        result = normalize_response(query, body, metadata)
        return result.model_copy(
            update={
                "elapsed_ms": _elapsed(),
                "requests_sent": 1,
                "mode": context.mode,
            }
        )


# ---------------------------------------------------------------------------
# Deterministic target plan (derived from internal data ONLY, §1.6)
# ---------------------------------------------------------------------------

#: Link roles whose URL may become a VT lookup target. Decorative remote
#: resources (``Link.role == "remote_resource"``, e.g. ``<img src=...>``)
#: are NEVER looked up.
_ELIGIBLE_URL_ROLES: tuple[str, ...] = ("href", "visible_url", "form_action", "qr_url")


def _link_target_ref(link: Link) -> str:
    """Deterministic source_ref of the link-target URL observable.

    Mirrors the parser's convention (src/parsing.py:
    ``f"{part_id}:link:{id[:16]}"`` for href URL observables). Kept in one
    place here so the eligibility check stays in sync with the parser; the
    parser contract itself is unchanged.
    """

    return f"{link.part_id}:link:{link.id[:16]}"


def plan_vt_targets(
    parsed: ParsedEmail | None,
    observables: list[Observable],
    max_targets: int,
) -> list[Observable]:
    """Up to ``max_targets`` lookup targets, normative priority order.

    Priority: attachment SHA-256 first, then href/form URLs whose link has a
    display mismatch, then other relevant href/visible/form/QR URLs in their
    deterministic (MIME) order, then exact sender/reply-to domains, then
    eligible public IPs.

    Remote-resource exclusion: the ``Observable`` projection loses the
    ``Link.role`` distinction, so URL eligibility is derived from the
    ``ParsedEmail`` links by deterministic ``source_ref``
    (``{part_id}:link:{id[:16]}``). A URL observable whose ``source_ref``
    does not belong to an eligible link (e.g. a decorative
    ``remote_resource`` ``<img src=...>``) is never selected. When
    ``parsed`` is ``None``, no URL eligibility can be proven and every URL
    observable is conservatively excluded. sha1/md5 are never planned (one
    SHA-256 per file, no extra endpoint); recipients never are (email type
    has no endpoint). Pure function: no network, no LLM, no state mutation.

    Note (deterministic and conservative): the parser deduplicates
    observables by (type, normalized_value) keeping the FIRST source_ref;
    if one identical URL appears both as a remote resource and later as an
    eligible href, the kept ref may be the remote-resource one and the URL
    is then excluded — under-inclusion only, never a decorative resource
    being sent.
    """

    mismatch_refs: set[str] = set()
    eligible_refs: set[str] = set()
    if parsed is not None:
        for link in parsed.links:
            if link.role in _ELIGIBLE_URL_ROLES:
                ref = _link_target_ref(link)
                eligible_refs.add(ref)
                if link.href_display_mismatch:
                    mismatch_refs.add(ref)

    def _rank(index: int, observable: Observable) -> tuple[int, int]:
        if observable.type == "sha256" and "attachment" in observable.roles:
            bucket = 0
        elif observable.type == "url":
            if observable.source_ref in mismatch_refs:
                bucket = 1  # relevant href/form with display mismatch
            elif observable.source_ref in eligible_refs:
                bucket = 2  # other relevant href/visible/form/QR, MIME order
            else:
                bucket = 99  # remote_resource or unknown provenance: never a VT target
        elif observable.type == "domain" and (
            {"sender", "reply_to"} & set(observable.roles)
        ):
            bucket = 3
        elif observable.type in ("ipv4", "ipv6"):
            bucket = 4
        else:
            bucket = 99
        return bucket, index

    scored = sorted(
        ((_rank(index, observable), observable) for index, observable in enumerate(observables)),
        key=lambda pair: (pair[0][0], pair[0][1]),
    )
    targets: list[Observable] = []
    for (bucket, _index), observable in scored:
        if len(targets) >= max_targets:
            break
        if bucket == 99:
            continue  # not a lookupable target (remote_resource, sha1/md5, email, ...)
        if endpoint_for(observable) is None:
            continue  # defensive: bucket filtering already refused these types
        targets.append(observable)
    return targets


__all__ = [
    "VTTransportError",
    "VirusTotalAdapter",
    "endpoint_for",
    "normalize_response",
    "plan_vt_targets",
    "url_send_refusal",
]

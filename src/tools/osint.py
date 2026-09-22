"""Bounded public OSINT adapter — ThreatFox / RDAP / DNS / crt.sh (TICKET-19D-OSINT).

Contract (TICKET-19D-OSINT v2.1, §§4–6, 9, 13–21):

- ONE public entry point: ``OsintAdapter.lookup(query, context)`` returns
  exactly ONE ``ToolResult(tool="osint")``. No ``lookup_rdap`` /
  ``lookup_dns`` / ``lookup_ct`` / ``lookup_threatfox`` tool exists; the
  model only ever chooses ``observable_id`` and the backend selects the
  applicable sources.
- Routing: domain -> ThreatFox (exact hostname) + RDAP (registrable) + DNS
  (exact hostname) + CT (registrable); ipv4/ipv6 -> ThreatFox + RDAP;
  md5/sha256 -> ThreatFox; url/sha1/email/message_id/campaign_id ->
  skipped/not_applicable with ZERO requests. A URL is never converted to a
  domain and never sent to any new source.
- Normalization: lowercase, trailing-dot strip, IDNA/punycode; reserved
  hosts refused locally; only global IPs; lowercase hex hashes of exact
  length. The registrable domain comes from the BUNDLED list only
  (``PublicSuffixList().privatesuffix(...)``); no download, no update, no
  fetch — ever.
- ThreatFox is READ ONLY (search_ioc/search_hash, exact_match=true, one
  request, no retry). At most 5 results projected; reporter/comment/
  references/tags/aliases are never projected and never reach the model.
- RDAP: https://rdap.org bootstrap, at most 1 SAFE (https, non-local,
  non-reserved) redirect, i.e. at most 2 HTTP requests. No WHOIS.
- DNS: ``dns.resolver.Resolver(configure=True)``, A/AAAA/MX/NS/TXT in
  order, 5 s TOTAL budget, max 10 values/type, TXT >512 chars never
  partially projected. No AXFR/ANY/PTR-enumeration/brute-force/DoH.
- CT: single crt.sh query (``q=%.<registrable> output=json
  deduplicate=Y``), bounded read (limit+1, ``response_over_limit`` without
  parsing), best-effort. No pivot: CT/RDAP/DNS names never become
  observables.
- Captures: exact HTTP bytes archived per source plus the composite
  ``osint_bundle_<digest>.json`` (``response_ref``/``response_sha256`` of
  the ToolResult). Request headers (Auth-Key) are never archived. Every
  positive evidence carries ``source_ref`` (capture + logical pointer) and
  ``observed_at``. ``ToolResult.observables`` is ALWAYS empty.
- Statuses: ok (>=1 positive evidence), unavailable (>=1 unavailable, none
  positive), not_found (all applicable non-skipped not_found), skipped
  (nothing applicable). ``requests_sent`` is the exact count of network
  requests really sent. Absence never proves benignity or maliciousness.

There is no mock/test/real mode: a fabricated provider answer is a FAIL
condition of the ticket. Transports are injectable constructor arguments so
deterministic offline tests can feed CONTROLLED responses to the
normalizers; injected objects are local facts, never provider observations.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from ..config import OsintToolConfig, Settings
from ..state import Evidence, Observable, ToolResult
from . import ToolContext, det_id, now_utc_iso

#: Frozen ThreatFox endpoint (TICKET-19D-OSINT §13).
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

#: Frozen RDAP bootstrap origin (§15).
RDAP_ORIGIN = "https://rdap.org"

#: Frozen crt.sh origin (§18).
CT_ORIGIN = "https://crt.sh"

#: Exact PSL version archived when OSINT is active (§1.3, §27.1).
PSL_VERSION = "1.0.2.20260921"

#: Strict hostname shape applied after IDNA conversion (§5.1): labels of
#: letters/digits/hyphens. Python's idna codec alone lets some garbage
#: (e.g. spaces) through; such a value can never be a lookup target.
_HOSTNAME_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")

#: Reserved/local suffixes refused before any request (§5.1).
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

#: DNS types in exact query order (§17.2).
_DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

#: Evidence predicate per DNS type (§17.2).
_DNS_PREDICATE = {
    "A": "osint_dns_a",
    "AAAA": "osint_dns_aaaa",
    "MX": "osint_dns_mx",
    "NS": "osint_dns_ns",
    "TXT": "osint_dns_txt",
}

#: Source groups carried by Evidence.source_group (§6).
_SOURCE_GROUPS = ("threatfox", "rdap", "dns", "certificate_transparency")

_HEX_MD5 = re.compile(r"[0-9a-f]{32}")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")

#: Below this remaining budget a source cannot start safely (§23).
_MIN_REQUEST_BUDGET_S = 0.5


def _psl() -> Any:
    """The bundled PublicSuffixList (embedded data only, never downloaded)."""

    from publicsuffixlist import PublicSuffixList

    return PublicSuffixList()


_PSL = _psl()


def _registrable_domain(normalized_domain: str) -> str | None:
    """Registrable domain via the bundled PSL (§5.2). No network, ever."""

    try:
        result = _PSL.privatesuffix(normalized_domain)
    except Exception:
        return None
    return result if isinstance(result, str) and result else None


def _normalize_target(query: Observable) -> dict[str, Any]:
    """Normalize one observable into a backend target (§§4–5).

    Returns ``{"ok": True, "kind": ..., "normalized": ...,
    "registrable": ...}`` or ``{"ok": False, "reason": ...}`` with
    ``reason`` in (``not_applicable``, ``invalid_observable``,
    ``non_global_ip``). No network.
    """

    kind = query.type
    raw = (query.normalized_value or query.value or "")
    if kind == "domain":
        host = raw.strip().lower().rstrip(".")
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            return {"ok": False, "reason": "invalid_observable"}
        if not host or host == "localhost" or host.endswith(_RESERVED_HOST_SUFFIXES):
            return {"ok": False, "reason": "invalid_observable"}
        if _HOSTNAME_RE.fullmatch(host) is None:
            return {"ok": False, "reason": "invalid_observable"}
        return {
            "ok": True,
            "kind": "domain",
            "normalized": host,
            "registrable": _registrable_domain(host),
        }
    if kind in ("ipv4", "ipv6"):
        try:
            address = ipaddress.ip_address(raw.strip())
        except ValueError:
            return {"ok": False, "reason": "invalid_observable"}
        if not address.is_global:
            return {"ok": False, "reason": "non_global_ip"}
        return {"ok": True, "kind": kind, "normalized": address.compressed}
    if kind == "md5":
        value = raw.strip().lower()
        if not _HEX_MD5.fullmatch(value):
            return {"ok": False, "reason": "invalid_observable"}
        return {"ok": True, "kind": "md5", "normalized": value}
    if kind == "sha256":
        value = raw.strip().lower()
        if not _HEX_SHA256.fullmatch(value):
            return {"ok": False, "reason": "invalid_observable"}
        return {"ok": True, "kind": "sha256", "normalized": value}
    return {"ok": False, "reason": "not_applicable"}


def _applicable_sources(kind: str) -> tuple[str, ...]:
    """Source names applicable to a normalized kind, in order (§4)."""

    if kind == "domain":
        return ("threatfox", "rdap", "dns", "certificate_transparency")
    if kind in ("ipv4", "ipv6"):
        return ("threatfox", "rdap")
    if kind in ("md5", "sha256"):
        return ("threatfox",)
    return ()


# ---------------------------------------------------------------------------
# Real transports (urllib / dnspython). Injectable for offline tests.
# ---------------------------------------------------------------------------


class _HttpRedirectBlock(urllib.request.HTTPRedirectHandler):
    """Block automatic redirects so RDAP redirect policy stays explicit."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:  # noqa: ANN401
        return None


def _real_post(url: str, body: bytes, headers: dict[str, str], timeout_s: float) -> tuple[int, dict[str, str], bytes]:
    """One real HTTP POST, redirects disabled (ThreatFox never redirects)."""

    opener = urllib.request.build_opener(_HttpRedirectBlock)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(request, timeout=timeout_s) as response:
            return int(response.status), dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        try:
            payload = error.read()
        except Exception:
            payload = b""
        return int(error.code), dict(error.headers or {}), payload


def _real_get(url: str, timeout_s: float) -> tuple[int, dict[str, str], bytes]:
    """One real HTTP GET, redirects NOT followed (caller applies policy)."""

    opener = urllib.request.build_opener(_HttpRedirectBlock)
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=timeout_s) as response:
            return int(response.status), dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        try:
            payload = error.read()
        except Exception:
            payload = b""
        return int(error.code), dict(error.headers or {}), payload


def _real_get_bounded(url: str, timeout_s: float, limit: int) -> tuple[int, dict[str, str], bytes]:
    """One real HTTP GET with a hard transport-level read bound.

    At most ``limit`` bytes are ever pulled from the socket (review PR #21
    blocker 1): a provider sending more cannot force an unbounded read and
    the caller refuses to parse the truncated body.
    """

    opener = urllib.request.build_opener(_HttpRedirectBlock)
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=timeout_s) as response:
            return int(response.status), dict(response.headers), response.read(limit)
    except urllib.error.HTTPError as error:
        try:
            payload = error.read(limit)
        except Exception:
            payload = b""
        return int(error.code), dict(error.headers or {}), payload


def _classify_transport(error: Exception) -> str:
    """Map a local transport failure to an unavailable cause (§§14–18)."""

    message = f"{type(error).__name__}: {error}".lower()
    if "timed out" in message or "timeout" in message or isinstance(error, TimeoutError):
        return "timeout"
    return "api_error"


def _real_dns_query(name: str, rdtype: str, lifetime: float) -> list[str]:
    """Real DNS answers via the configured resolver (values only)."""

    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=True)
    try:
        answers = resolver.resolve(name, rdtype, lifetime=lifetime)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raise _DnsEmpty from None
    result: list[str] = []
    for rdata in answers:
        if rdtype in ("A", "AAAA"):
            result.append(str(rdata.address))
        elif rdtype in ("MX", "NS"):
            result.append(str(rdata.target).rstrip(".").lower())
        elif rdtype == "TXT":
            try:
                text = b"".join(rdata.strings).decode("utf-8", errors="replace")
            except Exception:
                continue
            result.append(text)
    return result


class _DnsEmpty(Exception):
    """Local signal: NXDOMAIN/NoAnswer (maps to not_found, never proof)."""


def _headers_ci(headers: dict[str, str]) -> dict[str, str]:
    """HTTP headers with case-insensitive names (wire case varies)."""

    return {str(name).lower(): value for name, value in headers.items()}


# ---------------------------------------------------------------------------
# Capture helpers
# ---------------------------------------------------------------------------


def _target_digest(query: Observable, normalized: str) -> str:
    return hashlib.sha256(f"{query.id}|{normalized}".encode("utf-8")).hexdigest()[:16]


def _archive_bytes(context: ToolContext, filename: str, raw: bytes) -> str:
    path = Path(context.capture_dir) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path.name


def _evidence(
    query: Observable,
    predicate: str,
    value: str | float | bool,
    source_group: str,
    capture_ref: str,
    pointer: str,
    observed_at: str,
    match_level: str = "EXACT",
) -> Evidence:
    return Evidence(
        id=det_id("ev", "osint", predicate, str(value), query.id, pointer),
        provenance="OSINT",
        source_kind="osint",
        observable_id=query.id,
        predicate=predicate,  # type: ignore[arg-type]
        value=value,
        source_ref=f"{capture_ref}#/{pointer}",
        observed_at=observed_at,
        match_level=match_level,  # type: ignore[arg-type]
        source_group=source_group,
    )


# ---------------------------------------------------------------------------
# Source backends (pure normalizers over injected or real transports)
# ---------------------------------------------------------------------------


def _lookup_threatfox(
    query: Observable,
    normalized: str,
    kind: str,
    settings: Settings,
    timeout_s: float,
    context: ToolContext,
    digest: str,
    post: Callable[..., tuple[int, dict[str, str], bytes]] | None,
) -> dict[str, Any]:
    """READ ONLY ThreatFox search (§§13–14). At most one HTTP request."""

    collected_at = now_utc_iso()
    base: dict[str, Any] = {
        "status": "unavailable",
        "reason": "not_configured",
        "requests_sent": 0,
        "query_target": normalized,
        "response_ref": None,
        "response_sha256": None,
        "collected_at": collected_at,
        "evidence": [],
    }
    if settings.ABUSECH_API_KEY is None:
        return base
    if kind in ("domain", "ipv4", "ipv6"):
        body = {"query": "search_ioc", "search_term": normalized, "exact_match": True}
    else:
        body = {"query": "search_hash", "hash": normalized}
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    sender = post if post is not None else _real_post
    try:
        http_status, headers, raw = sender(
            THREATFOX_URL,
            raw_body,
            {"Content-Type": "application/json",
             "Auth-Key": settings.ABUSECH_API_KEY.get_secret_value()},
            timeout_s,
        )
    except Exception as error:  # local transport fact, never a forged IOC
        return {**base, "reason": _classify_transport(error), "requests_sent": 1}
    base["requests_sent"] = 1
    fields = _headers_ci(headers)
    observed_at = fields.get("date", collected_at)
    capture = _archive_bytes(context, f"osint_threatfox_{digest}.json", raw)
    base["response_ref"] = capture
    base["response_sha256"] = hashlib.sha256(raw).hexdigest()
    if http_status in (401, 403):
        return {**base, "reason": "auth_error"}
    if http_status == 429:
        return {**base, "reason": "rate_limited"}
    if not 200 <= http_status < 300:
        return {**base, "reason": "api_error"}
    try:
        document = json.loads(raw.decode("utf-8"))
    except Exception:
        return {**base, "reason": "malformed_response"}
    if not isinstance(document, dict):
        return {**base, "reason": "malformed_response"}
    query_status = document.get("query_status")
    data = document.get("data")
    if query_status == "no_result" or data in (None, [], {}):
        return {**base, "status": "not_found", "reason": None}
    if query_status != "ok" or not isinstance(data, list):
        return {**base, "reason": "api_error"}
    evidence: list[Evidence] = []
    for index, entry in enumerate(data[:5]):
        if not isinstance(entry, dict):
            continue
        pointer = f"data/{index}"
        evidence.append(
            _evidence(query, "osint_threatfox_match", True, "threatfox", capture, f"{pointer}/match", observed_at)
        )
        for field, predicate in (
            ("threat_type", "osint_threatfox_threat_type"),
            ("threat_type_desc", None),
            ("malware_printable", "osint_threatfox_malware"),
            ("confidence_level", "osint_threatfox_confidence"),
            ("first_seen", "osint_threatfox_first_seen"),
            ("last_seen", "osint_threatfox_last_seen"),
        ):
            if predicate is None:
                continue
            value = entry.get(field)
            if value is None or isinstance(value, (dict, list)):
                continue
            evidence.append(
                _evidence(query, predicate, value, "threatfox", capture, f"{pointer}/{field}", observed_at)
            )
    if not evidence:
        return {**base, "status": "not_found", "reason": None}
    return {**base, "status": "ok", "reason": None, "evidence": evidence}


def _rdap_redirect_allowed(location: str) -> str | None:
    """Validated redirect target URL, or None when unsafe (§15)."""

    try:
        parsed = urllib.parse.urlparse(location)
    except Exception:
        return None
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(_RESERVED_HOST_SUFFIXES):
        return None
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            return None
    except ValueError:
        pass
    return location


def _lookup_rdap(
    query: Observable,
    normalized: str,
    kind: str,
    registrable: str | None,
    timeout_s: float,
    context: ToolContext,
    digest: str,
    get: Callable[[str, float], tuple[int, dict[str, str], bytes]] | None,
    clock: Callable[[], float],
    match_level: str = "EXACT",
) -> dict[str, Any]:
    """Bounded RDAP bootstrap + at most one safe redirect (§§15–16)."""

    collected_at = now_utc_iso()
    base: dict[str, Any] = {
        "status": "skipped",
        "reason": "no_registrable_domain",
        "requests_sent": 0,
        "query_target": "",
        "response_ref": None,
        "response_sha256": None,
        "collected_at": collected_at,
        "evidence": [],
    }
    if kind == "domain":
        if not registrable:
            return base
        target = registrable
        first_url = f"{RDAP_ORIGIN}/domain/{urllib.parse.quote(target, safe='')}"
    elif kind in ("ipv4", "ipv6"):
        target = normalized
        first_url = f"{RDAP_ORIGIN}/ip/{urllib.parse.quote(target, safe='')}"
    else:
        return base
    base["query_target"] = target
    fetch = get if get is not None else _real_get
    hop_started = clock()
    requests_sent = 0
    url: str | None = first_url
    authority_host: str | None = None
    status: int | None = None
    headers: dict[str, str] = {}
    raw = b""
    for hop in range(2):
        remaining = timeout_s - (clock() - hop_started)
        if remaining < _MIN_REQUEST_BUDGET_S:
            return {**base, "status": "unavailable", "reason": "deadline", "requests_sent": requests_sent}
        assert url is not None
        try:
            status, headers, raw = fetch(url, remaining)
        except Exception as error:
            return {**base, "status": "unavailable", "reason": _classify_transport(error), "requests_sent": requests_sent + 1}
        requests_sent += 1
        if status in (301, 302, 303, 307, 308):
            if hop == 1:
                return {**base, "status": "unavailable", "reason": "redirect_limit", "requests_sent": requests_sent}
            location = _headers_ci(headers).get("location", "")
            allowed = _rdap_redirect_allowed(location)
            if allowed is None:
                return {**base, "status": "unavailable", "reason": "unsafe_redirect", "requests_sent": requests_sent}
            authority_host = urllib.parse.urlparse(allowed).hostname
            url = allowed
            continue
        break
    else:
        return {**base, "status": "unavailable", "reason": "redirect_limit", "requests_sent": requests_sent}
    if status is None:
        return {**base, "status": "unavailable", "reason": "api_error", "requests_sent": requests_sent}
    base["requests_sent"] = requests_sent
    observed_at = _headers_ci(headers).get("date", collected_at)
    capture = _archive_bytes(context, f"osint_rdap_{digest}.json", raw)
    base["response_ref"] = capture
    base["response_sha256"] = hashlib.sha256(raw).hexdigest()
    if authority_host:
        base["authority_host"] = authority_host
        base["bootstrap_host"] = urllib.parse.urlparse(first_url).hostname
    if status == 404:
        return {**base, "status": "not_found", "reason": None}
    if status in (401, 403):
        return {**base, "status": "unavailable", "reason": "auth_error"}
    if status == 429:
        return {**base, "status": "unavailable", "reason": "rate_limited"}
    if not 200 <= status < 300:
        return {**base, "status": "unavailable", "reason": "api_error"}
    try:
        document = json.loads(raw.decode("utf-8"))
    except Exception:
        return {**base, "status": "unavailable", "reason": "malformed_response"}
    if not isinstance(document, dict):
        return {**base, "status": "unavailable", "reason": "malformed_response"}
    evidence: list[Evidence] = []
    events = document.get("events") if isinstance(document.get("events"), list) else []
    for action, predicate in (
        ("registration", "osint_rdap_registration_date"),
        ("expiration", "osint_rdap_expiration_date"),
        ("last changed", "osint_rdap_last_changed"),
    ):
        for index, event in enumerate(events):
            if isinstance(event, dict) and event.get("eventAction") == action and isinstance(event.get("eventDate"), str):
                evidence.append(
                    _evidence(query, predicate, event["eventDate"], "rdap", capture, f"events/{index}/eventDate", observed_at, match_level)
                )
                break
    entities = document.get("entities") if isinstance(document.get("entities"), list) else []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if "registrar" in [str(role).lower() for role in entity.get("roles", []) if isinstance(role, str)] or "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray")
            name: str | None = None
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) == 4 and item[0] == "fn":
                        name = item[3] if isinstance(item[3], str) else None
                        break
            if name:
                evidence.append(
                    _evidence(query, "osint_rdap_registrar", name, "rdap", capture, "entities/registrar/vcardArray/fn", observed_at, match_level)
                )
            break
    statuses = document.get("status") if isinstance(document.get("status"), list) else []
    for index, value in enumerate(statuses[:10]):
        if isinstance(value, str) and value:
            evidence.append(
                _evidence(query, "osint_rdap_status", value, "rdap", capture, f"status/{index}", observed_at, match_level)
            )
    nameservers = document.get("nameservers") if isinstance(document.get("nameservers"), list) else []
    count = 0
    for index, entry in enumerate(nameservers):
        if count >= 10:
            break
        if isinstance(entry, dict) and isinstance(entry.get("ldhName"), str) and entry["ldhName"]:
            evidence.append(
                _evidence(query, "osint_rdap_nameserver", entry["ldhName"], "rdap", capture, f"nameservers/{index}/ldhName", observed_at, match_level)
            )
            count += 1
    if not evidence:
        return {**base, "status": "not_found", "reason": None}
    return {**base, "status": "ok", "reason": None, "evidence": evidence}


def _lookup_dns(
    query: Observable,
    normalized: str,
    budget_s: float,
    max_values: int,
    context: ToolContext,
    digest: str,
    resolve: Callable[[str, float, float], list[str]] | None,
    clock: Callable[[], float],
) -> dict[str, Any]:
    """Bounded DNS answers, TOTAL budget shared by all types (§17.2)."""

    collected_at = now_utc_iso()
    base: dict[str, Any] = {
        "status": "not_found",
        "reason": None,
        "requests_sent": 0,
        "query_target": normalized,
        "response_ref": None,
        "response_sha256": None,
        "collected_at": collected_at,
        "evidence": [],
    }
    started = clock()
    answers: dict[str, Any] = {"target": normalized, "types": {}}
    evidence: list[Evidence] = []
    timed_out = False
    sent = 0
    for rdtype in _DNS_TYPES:
        remaining = budget_s - (clock() - started)
        if remaining < _MIN_REQUEST_BUDGET_S:
            timed_out = True
            break
        # Every initiated query counts as a sent request — successes,
        # NXDOMAIN/NoAnswer empties, timeouts and transport errors alike
        # (review PR #21 blocker 2). Only a query never started (budget
        # exhausted above) counts zero.
        try:
            if resolve is not None:
                values = resolve(normalized, rdtype, remaining)
            else:
                values = _real_dns_query(normalized, rdtype, remaining)
            sent += 1
        except _DnsEmpty:
            sent += 1
            answers["types"][rdtype] = {"status": "empty"}
            continue
        except Exception as error:
            sent += 1
            message = f"{type(error).__name__}: {error}".lower()
            if "timeout" in message or "timed out" in message or "lifetime" in message:
                timed_out = True
                break
            answers["types"][rdtype] = {"status": "error", "error": type(error).__name__}
            continue
        kept: list[str] = []
        omitted = 0
        for value in values:
            if rdtype == "TXT" and len(value) > 512:
                omitted += 1  # never a partially cut evidence (§17.2)
                continue
            if len(kept) < max_values:
                kept.append(value)
        answers["types"][rdtype] = {"status": "ok", "values": kept, "omitted_over_512": omitted} if rdtype == "TXT" else {"status": "ok", "values": kept}
        for index, value in enumerate(kept):
            evidence.append(
                _evidence(query, _DNS_PREDICATE[rdtype], value, "dns", f"osint_dns_{digest}.json", f"types/{rdtype}/values/{index}", collected_at)
            )
    capture_bytes = json.dumps(answers, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    capture = _archive_bytes(context, f"osint_dns_{digest}.json", capture_bytes)
    base["response_ref"] = capture
    base["response_sha256"] = hashlib.sha256(capture_bytes).hexdigest()
    base["requests_sent"] = sent
    if timed_out and not evidence:
        return {**base, "status": "unavailable", "reason": "timeout", "evidence": []}
    if timed_out:
        base["reason"] = "partial_timeout"
    if not evidence:
        return {**base, "status": "not_found", "reason": None, "evidence": []}
    return {**base, "status": "ok", "evidence": evidence}


def _lookup_ct(
    query: Observable,
    registrable: str | None,
    timeout_s: float,
    max_bytes: int,
    max_names: int,
    context: ToolContext,
    digest: str,
    get: Callable[[str, float], tuple[int, dict[str, str], bytes]] | None,
    match_level: str = "EXACT",
) -> dict[str, Any]:
    """Best-effort crt.sh lookup, bounded read (limit+1) (§§18–19)."""

    collected_at = now_utc_iso()
    base: dict[str, Any] = {
        "status": "skipped",
        "reason": "no_registrable_domain",
        "requests_sent": 0,
        "query_target": "",
        "response_ref": None,
        "response_sha256": None,
        "collected_at": collected_at,
        "evidence": [],
    }
    if not registrable:
        return base
    base["query_target"] = registrable
    params = urllib.parse.urlencode({"q": f"%.{registrable}", "output": "json", "deduplicate": "Y"})
    url = f"{CT_ORIGIN}/?{params}"
    try:
        if get is not None:
            http_status, headers, raw = get(url, timeout_s)
        else:
            # Transport-level bound: at most max_bytes+1 ever cross the
            # socket; over-limit bodies are never parsed (§18).
            http_status, headers, raw = _real_get_bounded(url, timeout_s, max_bytes + 1)
    except Exception as error:
        return {**base, "status": "unavailable", "reason": _classify_transport(error), "requests_sent": 1}
    base["requests_sent"] = 1
    observed_at = _headers_ci(headers).get("date", collected_at)
    if len(raw) > max_bytes:
        # Over-limit bodies are archived for traceability but never parsed.
        capture = _archive_bytes(context, f"osint_ct_{digest}.json", raw[: max_bytes + 1])
        return {
            **base,
            "status": "unavailable",
            "reason": "response_over_limit",
            "response_ref": capture,
            "response_sha256": hashlib.sha256(raw[: max_bytes + 1]).hexdigest(),
        }
    capture = _archive_bytes(context, f"osint_ct_{digest}.json", raw)
    base["response_ref"] = capture
    base["response_sha256"] = hashlib.sha256(raw).hexdigest()
    if http_status == 429:
        return {**base, "status": "unavailable", "reason": "rate_limited"}
    if not 200 <= http_status < 300:
        return {**base, "status": "unavailable", "reason": "api_error"}
    try:
        document = json.loads(raw.decode("utf-8"))
    except Exception:
        return {**base, "status": "unavailable", "reason": "malformed_response"}
    entries = document if isinstance(document, list) else []
    if not entries:
        return {**base, "status": "not_found", "reason": None}
    evidence = [_evidence(query, "osint_ct_certificate_count", float(len(entries)), "certificate_transparency", capture, "count", observed_at, match_level)]
    not_before = sorted(
        str(entry["not_before"]) for entry in entries if isinstance(entry, dict) and entry.get("not_before")
    )
    if not_before:
        evidence.append(
            _evidence(query, "osint_ct_first_not_before", not_before[0], "certificate_transparency", capture, "not_before/min", observed_at, match_level)
        )
        evidence.append(
            _evidence(query, "osint_ct_last_not_before", not_before[-1], "certificate_transparency", capture, "not_before/max", observed_at, match_level)
        )
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for line in str(entry.get("name_value", "")).splitlines():
            cleaned = line.strip()
            if cleaned:
                names.add(cleaned)
    for index, name in enumerate(sorted(names)[:max_names]):
        evidence.append(
            _evidence(query, "osint_ct_dns_name", name, "certificate_transparency", capture, f"names/{index}", observed_at, match_level)
        )
    return {**base, "status": "ok", "reason": None, "evidence": evidence}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class OsintAdapter:
    """Single bounded public-OSINT adapter (§9).

    Transports are injectable for deterministic offline tests; ``None``
    selects the real ``urllib``/``dnspython`` transports. Injected callables
    receive no secret material beyond what the backend itself passes (the
    ThreatFox ``Auth-Key`` header is built inside ``_lookup_threatfox`` and
    is never archived).
    """

    def __init__(
        self,
        settings: Settings,
        config: OsintToolConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        threatfox_post: Callable[..., tuple[int, dict[str, str], bytes]] | None = None,
        http_get: Callable[[str, float], tuple[int, dict[str, str], bytes]] | None = None,
        dns_resolve: Callable[[str, str, float], list[str]] | None = None,
    ) -> None:
        self._settings = settings
        self._config = config
        self._clock = clock
        self._threatfox_post = threatfox_post
        self._http_get = http_get
        self._dns_resolve = dns_resolve

    def lookup(self, query: Observable, context: ToolContext) -> ToolResult:
        started = self._clock()
        elapsed = lambda: round((self._clock() - started) * 1000.0, 3)

        def _skipped(reason: str) -> ToolResult:
            return ToolResult(
                tool="osint",
                query_observable_id=query.id,
                status="skipped",
                reason=reason,
                observables=[],
                mode="none",
                elapsed_ms=elapsed(),
                requests_sent=0,
            )

        if not self._config.enabled:
            return _skipped("disabled")
        target = _normalize_target(query)
        if not target["ok"]:
            return _skipped(target["reason"])
        kind = target["kind"]
        normalized = target["normalized"]
        registrable = target.get("registrable")
        sources = _applicable_sources(kind)
        if not sources:
            return _skipped("not_applicable")

        osint_deadline = min(context.deadline, started + float(self._config.phase_timeout_s))
        if osint_deadline - self._clock() <= 0:
            return ToolResult(
                tool="osint",
                query_observable_id=query.id,
                status="unavailable",
                reason="deadline",
                observables=[],
                mode="none",
                elapsed_ms=elapsed(),
                requests_sent=0,
            )

        digest = _target_digest(query, normalized)
        per_source: dict[str, dict[str, Any]] = {}
        # RDAP/CT query the registrable parent: their evidence is EXACT
        # only when the observable IS the registrable domain, GENERIC
        # otherwise (review PR #21 blocker 3). ThreatFox/DNS always query
        # the exact normalized observable and stay EXACT.
        parent_level = "EXACT" if normalized == (registrable or normalized) else "GENERIC"

        def _budget(source_timeout: float) -> float:
            return max(0.0, min(source_timeout, osint_deadline - self._clock()))

        if "threatfox" in sources:
            budget = _budget(float(self._config.threatfox_timeout_s))
            if budget < _MIN_REQUEST_BUDGET_S:
                per_source["threatfox"] = {
                    "status": "unavailable", "reason": "deadline", "requests_sent": 0,
                    "query_target": normalized, "response_ref": None, "response_sha256": None,
                    "collected_at": now_utc_iso(), "evidence": [],
                }
            else:
                per_source["threatfox"] = _lookup_threatfox(
                    query, normalized, kind, self._settings, budget, context,
                    digest, self._threatfox_post,
                )
        if "rdap" in sources:
            if kind == "domain" and not registrable:
                per_source["rdap"] = {
                    "status": "skipped", "reason": "no_registrable_domain", "requests_sent": 0,
                    "query_target": "", "response_ref": None, "response_sha256": None,
                    "collected_at": now_utc_iso(), "evidence": [],
                }
            else:
                budget = _budget(float(self._config.rdap_timeout_s))
                if budget < _MIN_REQUEST_BUDGET_S:
                    per_source["rdap"] = {
                        "status": "unavailable", "reason": "deadline", "requests_sent": 0,
                        "query_target": registrable or normalized, "response_ref": None,
                        "response_sha256": None, "collected_at": now_utc_iso(), "evidence": [],
                    }
                else:
                    per_source["rdap"] = _lookup_rdap(
                        query, normalized, kind, registrable, budget, context,
                        digest, self._http_get, self._clock, parent_level,
                    )
        if "dns" in sources:
            budget = _budget(float(self._config.dns_timeout_s))
            if budget < _MIN_REQUEST_BUDGET_S:
                per_source["dns"] = {
                    "status": "unavailable", "reason": "deadline", "requests_sent": 0,
                    "query_target": normalized, "response_ref": None, "response_sha256": None,
                    "collected_at": now_utc_iso(), "evidence": [],
                }
            else:
                per_source["dns"] = _lookup_dns(
                    query, normalized, budget, int(self._config.max_dns_values_per_type),
                    context, digest, self._dns_resolve, self._clock,
                )
        if "certificate_transparency" in sources:
            if not registrable:
                per_source["certificate_transparency"] = {
                    "status": "skipped", "reason": "no_registrable_domain", "requests_sent": 0,
                    "query_target": "", "response_ref": None, "response_sha256": None,
                    "collected_at": now_utc_iso(), "evidence": [],
                }
            else:
                budget = _budget(float(self._config.ct_timeout_s))
                if budget < _MIN_REQUEST_BUDGET_S:
                    per_source["certificate_transparency"] = {
                        "status": "unavailable", "reason": "deadline", "requests_sent": 0,
                        "query_target": registrable, "response_ref": None,
                        "response_sha256": None, "collected_at": now_utc_iso(), "evidence": [],
                    }
                else:
                    per_source["certificate_transparency"] = _lookup_ct(
                        query, registrable, budget, int(self._config.max_ct_response_bytes),
                        int(self._config.max_ct_names), context, digest, self._http_get,
                        parent_level,
                    )

        # --- aggregate (§21) -------------------------------------------------
        ordered = [name for name in ("threatfox", "rdap", "dns", "certificate_transparency") if name in per_source]
        evidences: list[Evidence] = []
        for name in ordered:
            evidences.extend(per_source[name]["evidence"])
        requests_sent = sum(int(per_source[name]["requests_sent"]) for name in ordered)
        statuses = {name: per_source[name]["status"] for name in ordered}
        if any(statuses[name] == "ok" for name in ordered):
            status = "ok"
        elif any(statuses[name] == "unavailable" for name in ordered):
            status = "unavailable"
        elif all(statuses[name] in ("not_found",) for name in ordered):
            status = "not_found"
        else:
            status = "skipped"
        reason = ";".join(f"{name}={statuses[name]}" for name in ordered)
        reason = f"sources:{reason}"

        bundle = {
            "observable_id": query.id,
            "normalized_target": normalized,
            "registrable_domain": registrable,
            "psl_version": PSL_VERSION,
            "sources": {
                name: {
                    "status": per_source[name]["status"],
                    "reason": per_source[name]["reason"],
                    "requests_sent": per_source[name]["requests_sent"],
                    "query_target": per_source[name]["query_target"],
                    "response_ref": per_source[name]["response_ref"],
                    "response_sha256": per_source[name]["response_sha256"],
                    "collected_at": per_source[name]["collected_at"],
                    **({"authority_host": per_source[name]["authority_host"]} if "authority_host" in per_source[name] else {}),
                    **({"bootstrap_host": per_source[name]["bootstrap_host"]} if "bootstrap_host" in per_source[name] else {}),
                }
                for name in ordered
            },
        }
        bundle_bytes = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        bundle_ref = _archive_bytes(context, f"osint_bundle_{digest}.json", bundle_bytes)
        return ToolResult(
            tool="osint",
            query_observable_id=query.id,
            status=status,
            reason=reason,
            evidence=evidences,
            observables=[],
            response_sha256=hashlib.sha256(bundle_bytes).hexdigest(),
            response_ref=bundle_ref,
            collected_at=now_utc_iso(),
            mode=context.mode if requests_sent else "none",
            elapsed_ms=elapsed(),
            requests_sent=requests_sent,
        )


__all__ = [
    "CT_ORIGIN",
    "PSL_VERSION",
    "RDAP_ORIGIN",
    "THREATFOX_URL",
    "OsintAdapter",
]

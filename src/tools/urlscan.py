"""urlscan real scan adapter — private/unlisted submissions, bounded poll,
inert DOM (TICKET-08, gate G4).

Contract (docs/architecture.md §1.6, docs/contracts.md §2.7/§2.7.2, TICKET-08):

- Transport: the urlscan public API at the single approved origin
  ``https://urlscan.io`` — ``POST /api/v1/scan/`` (one submission),
  ``GET /api/v1/result/<uuid>/`` (bounded poll), ``GET /dom/<uuid>/`` (inert
  DOM retrieval after a successful result) and ``GET /screenshots/<uuid>.png``
  (binary capture ONLY when the vision gate is active). The API key travels
  only in the ``API-Key`` request header of these same-origin calls; it never
  enters the context, logs, captures or results. Redirects are never followed
  towards another origin: a cross-origin ``Location`` is refused locally
  before any request is sent to it.
- One URL at most per call (``UrlscanAdapter.scan(query, context)``); any
  other observable type (email, domain, hash, IP, message_id, campaign_id)
  is ``skipped/not_applicable`` — urlscan only scans web pages. A second
  submission for the same run is refused locally (``skipped/budget``) with
  ZERO requests: the local submission budget comes from ``max_urls`` and is
  persisted in a small quota journal (restart-safe), never from a provider
  error.
- Visibility (operator amendment, TICKET-08): the ``source_profile`` is
  authoritative. ``fixture`` and ``public_corpus`` submit ``unlisted``;
  ``private_authorized`` submits ``private``. ``public`` is never sent and
  never used as a fallback. The requested visibility is sent explicitly and
  verified in the POST response; a response that does not confirm it yields
  ``unavailable`` (never a silent downgrade).
- Statuses: ``ok`` / ``not_found`` (an explicit urlscan "not found" for the
  final page) / ``unavailable`` (closed causes) / ``skipped`` (disabled,
  not_applicable, privacy_policy, budget). No mock/recorded provider answer
  exists in this module.
- Privacy prefilter (architecture §1.6 "Sorties vers tiers"): the URL is
  refused BEFORE any network call when it carries userinfo, credential-like
  or action-effect parameters, a personal identifier, an internal/reserved
  host (``.test``, ``.invalid``, localhost, …), a non-global IP literal or a
  non-HTTP(S) scheme — and unless the operator's egress policy explicitly
  allows real URLs for ``urlscan`` and the exact host. Passing the filter is
  an operator decision, never a proof that the URL is harmless.
- After an accepted POST: an ambiguous POST failure is NEVER retried (no
  second visit, no double quota). Wait ``first_poll_s`` (10 s), then poll
  every ``poll_interval_s`` (5 s) within the phase budget (≤ 45 s). Before
  a result, a 404 means PENDING (it is never ``not_found``); 410 means the
  result is gone; 429 means rate limited; 401/403 mean an authentication
  error. The budget expiring while the scan is still pending yields
  ``unavailable`` with an explicit cause.
- Result normalization: only factual fields are exposed as SANDBOX evidence
  (final URL, page title, provider verdict flag, main-document navigation
  steps, bounded inert-DOM text and form fields, screenshot hash when one
  was really downloaded). Sub-resource requests are never presented as a
  redirect chain; when no step is demonstrable the chain stays
  partial/unknown and nothing is invented. ``page.url`` is the observation
  of this run, not a guarantee about the past. Form fields, titles and text
  are bounded; the DOM is parsed as inert text without executing scripts,
  and no remote resource is ever fetched. A missing screenshot (or a 404 on
  it) never breaks the result JSON.
- Budget: every request runs under the EXACT remaining float budget
  ``min(remaining deadline, phase_timeout_s)`` — never rounded upward. Below
  a minimal safe send budget the call returns ``unavailable/deadline`` with
  ZERO requests (before the POST) or stops polling without further requests.

Controlled error objects (timeout / connection failure / malformed body and
numeric 404/410/429/401/403/5xx statuses) may be fed to the pure helpers for
deterministic error mapping — they are local facts, never provider
observations, and never become enrichment.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import threading
import time
import uuid as uuid_module
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Literal, Mapping
from urllib.parse import urljoin, urlparse

import requests

from ..config import Settings, SourceProfile, UrlscanToolConfig
from ..state import Observable, ToolResult
from . import ResponseMetadata, ToolContext, det_id, expurgate, now_utc_iso

#: The single operator-approved urlscan origin. Every request URL is built
#: from this constant; an API redirect outside it is refused locally.
URLSCAN_ORIGIN = "https://urlscan.io"
SUBMIT_PATH = "/api/v1/scan/"
RESULT_PATH = "/api/v1/result/{scan_id}/"
DOM_PATH = "/dom/{scan_id}/"
SCREENSHOT_PATH = "/screenshots/{scan_id}.png"

#: Below this remaining budget a request cannot be sent safely.
_MIN_REQUEST_BUDGET_S = 0.5

#: A same-origin redirect chain longer than this is refused as api_error.
_MAX_REDIRECT_HOPS = 3

#: Bound of the main-document navigation walk (cycles guarded separately).
_MAX_NAVIGATION_STEPS = 10

#: Bounds of the inert DOM extraction (docs/contracts.md §2.7.2).
_DOM_MAX_HTML_CHARS = 2_097_152
_DOM_TEXT_STORE_CHARS = 20_000
_DOM_EVIDENCE_EXCERPT_CHARS = 1_000
_DOM_MAX_FORM_FIELDS_STORED = 50
_DOM_MAX_FORM_FIELDS_EVIDENCE = 20

#: Hosts/TLDs that must never leave the machine (mirror of the frozen
#: TICKET-06/TICKET-07 refusal list).
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

#: Credential-like / action-effect / personal-identifier markers (same
#: architecture §1.6 egress rules as TICKET-06/TICKET-07).
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


class UrlscanTransportError(Exception):
    """Local transport failure; ``kind`` is a controlled error-object kind."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = expurgate(detail)


@dataclass(frozen=True)
class _Exchange:
    """One real HTTP exchange observed by the transport (exact bytes)."""

    http_status: int
    content: bytes
    headers: Mapping[str, str]
    url: str
    request_count: int


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested; no I/O)
# ---------------------------------------------------------------------------


def visibility_for(source_profile: SourceProfile, config: UrlscanToolConfig) -> Literal["private", "unlisted"]:
    """Authoritative source_profile -> visibility mapping (TICKET-08).

    ``fixture`` and ``public_corpus`` submit ``unlisted`` (the configured
    ``visibility_fixture``); ``private_authorized`` submits ``private`` (the
    configured ``visibility_real``). ``public`` is never produced: the YAML
    Literals only allow private/unlisted and no fallback exists.
    """

    if source_profile == "private_authorized":
        return config.visibility_real
    return config.visibility_fixture


def submittable_url(query: Observable) -> str | None:
    """The exact URL value to submit, or ``None`` when no scan applies.

    Only ``url`` observables are submittable; every other type has no page
    to scan (``skipped/not_applicable``). The value is kept verbatim —
    privacy/scheme evaluation belongs to :func:`url_send_refusal`.
    """

    if query.type != "url":
        return None
    value = (query.normalized_value or query.value).strip()
    return value or None


def service_send_refusal(egress: Any) -> str | None:
    """Refusal code when the urlscan service is not operator-approved."""

    if "urlscan" not in {service.lower() for service in egress.approved_services}:
        return "service_not_approved_in_egress"
    return None


def url_send_refusal(url: str, egress: Any) -> str | None:
    """Refusal code when this URL must NOT be disclosed to urlscan.

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
    if "urlscan" not in {service.lower() for service in egress.approved_services}:
        return "tool_not_approved_in_egress"
    if hostname not in {host.lower() for host in egress.approved_exact_url_hosts}:
        return "exact_url_host_not_approved"
    return None


def _origin_tuple(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    default_port = {"http": 80, "https": 443}.get(parsed.scheme.lower())
    try:
        port = parsed.port
    except ValueError:
        port = None
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower().rstrip("."),
        port if port is not None else default_port,
    )


def same_origin(url: str, base: str) -> bool:
    """True only when ``url`` has exactly the origin of ``base``."""

    return _origin_tuple(url) == _origin_tuple(base)


def error_cause_for_status(http_status: int) -> str:
    """Deterministic cause for a non-404, non-2xx provider status."""

    if http_status == 429:
        return "rate_limited"
    if http_status in (401, 403):
        return "auth_error"
    return "api_error"


def submission_details(body: Mapping[str, object]) -> tuple[str | None, str | None]:
    """(canonical scan UUID, declared visibility) from a POST 200 body.

    ``None`` means the field is missing, malformed or outside the closed
    visibility vocabulary; the caller then refuses to treat the submission
    as confirmed. Nothing is completed with a plausible default.
    """

    raw_uuid = body.get("uuid")
    scan_id: str | None = None
    if isinstance(raw_uuid, str) and raw_uuid.strip():
        try:
            scan_id = str(uuid_module.UUID(raw_uuid.strip()))
        except (ValueError, AttributeError):
            scan_id = None
    raw_visibility = body.get("visibility")
    visibility: str | None = None
    if isinstance(raw_visibility, str) and raw_visibility.strip().lower() in (
        "public",
        "unlisted",
        "private",
    ):
        visibility = raw_visibility.strip().lower()
    return scan_id, visibility


def _entry_request_url(entry: Mapping[str, object]) -> str | None:
    request = entry.get("request")
    if not isinstance(request, Mapping):
        return None
    inner = request.get("request")
    for container in (inner, request):
        if not isinstance(container, Mapping):
            continue
        for key in ("url", "requestURL"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _entry_request_type(entry: Mapping[str, object]) -> str | None:
    request = entry.get("request")
    if not isinstance(request, Mapping):
        return None
    inner = request.get("request")
    for container in (request, inner):
        if not isinstance(container, Mapping):
            continue
        value = container.get("type")
        if isinstance(value, str):
            return value
    return None


def _entry_redirect_target(entry: Mapping[str, object]) -> tuple[str, str] | None:
    """(target URL, field path inside the entry) for a redirect response.

    The observed urlscan shape nests the captured response under
    ``entry["response"]["response"]``; a flat ``entry["response"]`` shape is
    accepted as a fallback. The returned field path is the exact one used so
    the evidence source_ref resolves in the archived JSON.
    """

    response = entry.get("response")
    if not isinstance(response, Mapping):
        return None
    inner = response.get("response")
    candidates: list[tuple[Mapping[str, object], str]] = []
    if isinstance(inner, Mapping):
        candidates.append((inner, "response/response"))
    candidates.append((response, "response"))
    for container, prefix in candidates:
        for key in ("redirectURL", "redirectUrl"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value, f"{prefix}/{key}"
    return None


def extract_navigation_steps(
    body: Mapping[str, object], submitted_url: str
) -> list[tuple[str, str]]:
    """Demonstrable main-document navigation steps: ``(target, pointer)``.

    Preferred source: the provider's own ``data.redirects`` chain
    (real-observed shape ``{"from", "to", "status"}``), accepted only when
    it forms a consistent chain starting at the exact submitted URL.
    Fallback: the main-document request entries (``request.type ==
    "Document"``) whose redirect responses link the current URL to the
    next one. Sub-resources (images, scripts, XHR, …) can never extend the
    chain. When no step is demonstrable an empty list is returned — no
    intermediate URL is ever invented, and a cycle ends the walk.
    """

    steps = _provider_redirect_steps(body, submitted_url)
    if steps is not None:
        return steps
    return _request_walk_steps(body, submitted_url)


def _provider_redirect_steps(
    body: Mapping[str, object], submitted_url: str
) -> list[tuple[str, str]] | None:
    """Chain from ``data.redirects``; ``None`` when it is not usable."""

    data = body.get("data")
    if not isinstance(data, Mapping):
        return None
    redirects = data.get("redirects")
    if not isinstance(redirects, list) or not redirects:
        return None
    steps: list[tuple[str, str]] = []
    current = submitted_url
    for index, entry in enumerate(redirects):
        if not isinstance(entry, Mapping):
            return None
        source = entry.get("from")
        target = entry.get("to")
        if not isinstance(source, str) or not isinstance(target, str) or not target:
            return None
        if source != current:
            return None  # not a demonstrable chain for THIS submission
        steps.append((target, f"data/redirects/{index}/to"))
        current = target
    return steps


def _request_walk_steps(
    body: Mapping[str, object], submitted_url: str
) -> list[tuple[str, str]]:
    """Fallback chain walk over main-document request redirects."""

    data = body.get("data")
    if not isinstance(data, Mapping):
        return []
    entries = data.get("requests")
    if not isinstance(entries, list):
        return []

    steps: list[tuple[str, str]] = []
    current = submitted_url
    seen = {current}
    for _ in range(_MAX_NAVIGATION_STEPS):
        advanced = False
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                continue
            if _entry_request_url(entry) != current:
                continue
            entry_type = _entry_request_type(entry)
            if entry_type is not None and entry_type != "Document":
                continue
            redirect = _entry_redirect_target(entry)
            if redirect is None:
                continue
            target, field_path = redirect
            steps.append((target, f"data/requests/{index}/{field_path}"))
            if target in seen:
                return steps
            seen.add(target)
            current = target
            advanced = True
            break
        if not advanced:
            break
    return steps


# ---------------------------------------------------------------------------
# Inert DOM extraction (stdlib only; nothing is executed, nothing fetched)
# ---------------------------------------------------------------------------


class _InertDOMCollector(HTMLParser):
    """Collect bounded visible text + form fields from raw HTML.

    ``HTMLParser`` never executes scripts, never resolves URLs and never
    performs I/O: the extraction is pure in-memory string handling. Script,
    style, noscript and template contents are skipped, form controls are
    captured by name/id with their declared type.
    """

    _CONTENT_SKIP_TAGS = {"script", "style", "noscript", "template", "svg"}

    def __init__(self, max_text_chars: int, max_fields: int) -> None:
        super().__init__(convert_charrefs=True)
        self._max_text = max_text_chars
        self._max_fields = max_fields
        self._skip_depth = 0
        self._in_title = False
        self._chunks: list[str] = []
        self._text_len = 0
        self.title_parts: list[str] = []
        self.form_fields: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._CONTENT_SKIP_TAGS:
            self._skip_depth += 1
            return
        if tag == "title":
            self._in_title = True
            return
        if tag in ("input", "select", "textarea", "button") and len(self.form_fields) < self._max_fields:
            attributes = {key.lower(): (value or "") for key, value in attrs}
            name = (attributes.get("name") or attributes.get("id") or "").strip()
            if name:
                self.form_fields.append(
                    {
                        "name": name[:100],
                        "type": (attributes.get("type") or tag)[:50],
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._CONTENT_SKIP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title_parts.append(data)
            return
        text = " ".join(data.split())
        if text and self._text_len < self._max_text:
            self._chunks.append(text)
            self._text_len += len(text) + 1

    def text(self) -> str:
        return " ".join(self._chunks)[: self._max_text]


def extract_dom_facts(html_text: str, source_url: str) -> dict[str, object]:
    """Bounded inert-DOM facts; a parser defect degrades to empty text.

    Nothing here can raise on hostile HTML (``HTMLParser`` is tolerant) and
    nothing is fetched or executed. ``text_excerpt`` is exactly the
    evidence-bound excerpt (so ``#/text_excerpt`` pointers resolve to the
    exact evidence value); ``text_full_bounded`` keeps the larger bounded
    extraction for local reference.
    """

    bounded = html_text[:_DOM_MAX_HTML_CHARS]
    parser = _InertDOMCollector(_DOM_TEXT_STORE_CHARS, _DOM_MAX_FORM_FIELDS_STORED)
    defects: list[str] = []
    try:
        parser.feed(bounded)
        parser.close()
    except Exception:  # noqa: BLE001 — a defect is recorded, never a crash
        defects.append("html_parser_error")
    title = " ".join(" ".join(parser.title_parts).split())[:300]
    full_text = parser.text()
    return {
        "source_url": source_url,
        "title": title,
        "text_excerpt": full_text[:_DOM_EVIDENCE_EXCERPT_CHARS],
        "text_full_bounded": full_text,
        "text_truncated": len(html_text) > len(bounded) or len(full_text) > _DOM_EVIDENCE_EXCERPT_CHARS,
        "form_fields": parser.form_fields,
        "defects": defects,
    }


# ---------------------------------------------------------------------------
# Local submission budget (restart-safe journal; never a provider control)
# ---------------------------------------------------------------------------


class _SubmissionBudget:
    """At most ``max_urls`` submissions per run, persisted per UTC day.

    The journal records factual local counts (run id, visibility, HTTP
    status, scan id) so a restart cannot silently resend the same email's
    URL. Refusal is ``skipped/budget`` with zero requests; the budget is a
    local safety rule, never presented as a provider quota statement.
    """

    def __init__(self, max_per_run: int, journal_path: Path, clock: Callable[[], float]) -> None:
        self._max = max(0, int(max_per_run))
        self._path = Path(journal_path)
        self._clock = clock
        self._day = datetime.now(UTC).date().isoformat()
        self._submissions: list[dict[str, object]] = []
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        if data.get("day_utc") != self._day:
            return  # a previous UTC day no longer applies
        entries = data.get("submissions")
        if isinstance(entries, list):
            self._submissions = [entry for entry in entries if isinstance(entry, dict)]

    def _prune(self) -> None:
        today = datetime.now(UTC).date().isoformat()
        if today != self._day:
            self._day = today
            self._submissions = []

    def allow(self, run_id: str) -> bool:
        self._prune()
        used = sum(1 for entry in self._submissions if entry.get("run_id") == run_id)
        return used < self._max

    def record(
        self,
        run_id: str,
        visibility: str,
        http_status: int | None,
        scan_id: str | None,
    ) -> None:
        """Record one SUBMISSION ATTEMPT (conservative: a failed/ambiguous
        POST also consumes the local budget)."""

        self._prune()
        self._submissions.append(
            {
                "run_id": run_id,
                "visibility": visibility,
                "http_status": http_status,
                "scan_id": scan_id,
                "attempted_at": now_utc_iso(),
            }
        )
        self._submissions = self._submissions[-500:]
        payload = {
            "day_utc": self._day,
            "max_urls_per_run": self._max,
            "submissions": self._submissions,
            "updated_at": now_utc_iso(),
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError:
            # The journal is a budget-survival optimization, not a control:
            # an unwritable path degrades to in-memory counting only.
            pass


# ---------------------------------------------------------------------------
# Transport (requests; exact-bytes capture; same-origin redirects only)
# ---------------------------------------------------------------------------


def _request_raw(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    json_body: Mapping[str, object] | None,
    timeout_s: float,
) -> _Exchange:
    """One HTTP exchange with exact byte capture.

    ``allow_redirects`` is disabled on the client; redirects are handled
    explicitly and ONLY within the approved urlscan origin. A cross-origin
    Location is refused locally and no request is sent to it, so the API key
    can never leave the approved origin.
    """

    if timeout_s <= 0:
        raise UrlscanTransportError("timeout", "no remaining budget for the request")
    session = requests.Session()
    request_count = 0
    current_method = method
    current_url = url
    body: Mapping[str, object] | None = json_body
    try:
        while True:
            try:
                response = session.request(
                    current_method,
                    current_url,
                    headers=dict(headers),
                    json=body,
                    timeout=timeout_s,
                    allow_redirects=False,
                )
            except requests.exceptions.Timeout as error:
                raise UrlscanTransportError(
                    "timeout", f"urlscan request timed out after {timeout_s}s"
                ) from error
            except requests.exceptions.RequestException as error:
                raise UrlscanTransportError(
                    "connection_error", f"urlscan transport error: {error}"
                ) from error
            request_count += 1
            status = int(response.status_code)
            location = response.headers.get("location")
            if (
                status in (301, 302, 303, 307, 308)
                and location
                and request_count <= _MAX_REDIRECT_HOPS
            ):
                target = urljoin(str(response.url), location)
                if not same_origin(target, URLSCAN_ORIGIN):
                    raise UrlscanTransportError(
                        "api_error", "cross_origin_redirect_refused"
                    )
                current_url = target
                if status == 303 or (status in (301, 302) and current_method != "GET"):
                    current_method, body = "GET", None
                continue
            return _Exchange(
                http_status=status,
                content=bytes(response.content),
                headers=dict(response.headers),
                url=str(response.url),
                request_count=request_count,
            )
    finally:
        session.close()


def _api_headers(api_key: str) -> dict[str, str]:
    return {
        "API-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "soc-email-triage-poc/0.1 (urlscan adapter; security validation)",
    }


def _post_scan_exchange(
    origin: str, api_key: str, url: str, visibility: str, timeout_s: float
) -> _Exchange:
    """ONE real submission: ``POST /api/v1/scan/`` (never retried)."""

    return _request_raw(
        "POST",
        origin + SUBMIT_PATH,
        headers={**_api_headers(api_key), "Content-Type": "application/json"},
        json_body={"url": url, "visibility": visibility},
        timeout_s=timeout_s,
    )


def _get_result_exchange(origin: str, api_key: str, scan_id: str, timeout_s: float) -> _Exchange:
    return _request_raw(
        "GET",
        origin + RESULT_PATH.format(scan_id=scan_id),
        headers=_api_headers(api_key),
        json_body=None,
        timeout_s=timeout_s,
    )


def _get_dom_exchange(origin: str, api_key: str, scan_id: str, timeout_s: float) -> _Exchange:
    return _request_raw(
        "GET",
        origin + DOM_PATH.format(scan_id=scan_id),
        headers=_api_headers(api_key),
        json_body=None,
        timeout_s=timeout_s,
    )


def _get_screenshot_exchange(
    origin: str, api_key: str, scan_id: str, timeout_s: float
) -> _Exchange:
    return _request_raw(
        "GET",
        origin + SCREENSHOT_PATH.format(scan_id=scan_id),
        headers=_api_headers(api_key),
        json_body=None,
        timeout_s=timeout_s,
    )


def _run_bounded(fn: Callable[[], _Exchange], timeout_s: float) -> _Exchange:
    """Hard wall-clock bound: never returns later than ``timeout_s``."""

    outcome: dict[str, object] = {}

    def _worker() -> None:
        try:
            outcome["exchange"] = fn()
        except Exception as error:  # noqa: BLE001 — classified below
            outcome["error"] = error

    thread = threading.Thread(target=_worker, daemon=True, name="urlscan-exchange")
    thread.start()
    thread.join(timeout_s)
    if thread.is_alive():
        raise UrlscanTransportError(
            "timeout", f"urlscan exchange exceeded the hard budget of {timeout_s}s"
        )
    error = outcome.get("error")
    if isinstance(error, UrlscanTransportError):
        raise error
    if isinstance(error, BaseException):
        raise UrlscanTransportError(
            "connection_error", f"unexpected transport failure: {error}"
        )
    exchange = outcome.get("exchange")
    if not isinstance(exchange, _Exchange):
        raise UrlscanTransportError("connection_error", "no exchange produced")
    return exchange


# ---------------------------------------------------------------------------
# Captures (restricted data under runs/, git-ignored)
# ---------------------------------------------------------------------------


def _run_scoped_name(context: ToolContext, base: str) -> str:
    run_digest = hashlib.sha256(context.run_id.encode("utf-8")).hexdigest()[:8]
    return f"{base}_{run_digest}"


def _capture_base(context: ToolContext, query: Observable) -> str:
    value_digest = hashlib.sha256(
        (query.normalized_value or query.value).encode("utf-8")
    ).hexdigest()
    return _run_scoped_name(context, f"urlscan_url_{value_digest[:16]}")


def _archive_bytes(
    context: ToolContext,
    name: str,
    raw: bytes,
    metadata: ResponseMetadata,
    *,
    extra_meta: Mapping[str, object] | None = None,
) -> str:
    """Archive EXACT response bytes + factual provenance; return the local
    reference. No request header and no key material is ever stored."""

    body_path = Path(context.capture_dir) / name
    meta_path = Path(context.capture_dir) / f"{name}.meta.json"
    body_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.write_bytes(raw)
    meta: dict[str, object] = {
        "tool": "urlscan",
        "origin": metadata.origin,
        "http_status": metadata.http_status,
        "response_date": metadata.response_date,
        "response_sha256": metadata.response_sha256,
        "collected_at": now_utc_iso(),
        "run_id": context.run_id,
        "mode": context.mode,
    }
    if extra_meta:
        meta.update(dict(extra_meta))
    meta_path.write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return name


def _query_meta(context: ToolContext, query: Observable) -> dict[str, object]:
    return {
        "observable_id": query.id,
        "type": query.type,
        "normalized_value": query.normalized_value,
    }


# ---------------------------------------------------------------------------
# Result normalizer (pure; controlled bodies in, ToolResult out)
# ---------------------------------------------------------------------------


def normalize_result(
    query: Observable,
    body: Mapping[str, object],
    metadata: ResponseMetadata,
    *,
    dom_ref: str | None = None,
    dom_facts: Mapping[str, object] | None = None,
    screenshot: Mapping[str, object] | None = None,
) -> ToolResult:
    """Map one successful urlscan result to the normalized ToolResult.

    Only factual fields already present in the archived result are exposed;
    absent fields stay absent (no counter, URL or step is invented). The
    provider verdict flag is named as the provider's assertion. Sub-resource
    requests never extend the navigation chain. ``page.url`` is the
    observation of this run, not a historical guarantee.
    """

    collected_at = now_utc_iso()
    observed_at = metadata.response_date or collected_at
    base: dict[str, Any] = {
        "tool": "urlscan",
        "query_observable_id": query.id,
        "observables": [],
        "response_sha256": metadata.response_sha256,
        "response_ref": metadata.response_ref,
        "collected_at": collected_at,
        "visibility": None,
        "scan_id": None,
    }

    def _malformed() -> ToolResult:
        return ToolResult(
            **base,
            status="unavailable",
            reason="malformed_response",
            evidence=[],
            mode="live",
        )

    task = body.get("task")
    page = body.get("page")
    data = body.get("data")
    if not isinstance(task, Mapping):
        return _malformed()
    if not isinstance(page, Mapping) and not isinstance(data, Mapping):
        return _malformed()

    scan_id, declared_visibility = submission_details({"uuid": task.get("uuid"), "visibility": task.get("visibility")})
    base["scan_id"] = scan_id
    base["visibility"] = declared_visibility if declared_visibility in ("private", "unlisted") else None

    evidence: list[dict[str, Any]] = []

    def _evidence(predicate: str, value: Any, pointer: str, ref: str) -> None:
        source_ref = f"{ref}#/{pointer}" if pointer else ref
        evidence.append(
            {
                "id": det_id("ev", predicate, str(value), ref, pointer),
                "provenance": "SANDBOX",
                "source_kind": "urlscan",
                "observable_id": query.id,
                "predicate": predicate,
                "value": value,
                "source_ref": source_ref,
                "observed_at": observed_at,
                "match_level": "EXACT",
                "source_group": "urlscan",
            }
        )

    if isinstance(page, Mapping):
        final_url = page.get("url")
        if isinstance(final_url, str) and final_url:
            _evidence("sandbox_final_url", final_url, "page/url", metadata.response_ref or "")
        title = page.get("title")
        if isinstance(title, str) and title.strip():
            _evidence("sandbox_page_title", title, "page/title", metadata.response_ref or "")

    verdicts = body.get("verdicts")
    if isinstance(verdicts, Mapping):
        overall = verdicts.get("overall")
        if isinstance(overall, Mapping):
            malicious = overall.get("malicious")
            if isinstance(malicious, bool):
                _evidence(
                    "sandbox_provider_malicious",
                    malicious,
                    "verdicts/overall/malicious",
                    metadata.response_ref or "",
                )

    submitted = (query.normalized_value or query.value).strip()
    for target, pointer in extract_navigation_steps(body, submitted):
        _evidence("sandbox_redirect", target, pointer, metadata.response_ref or "")

    if dom_ref and isinstance(dom_facts, Mapping):
        excerpt = dom_facts.get("text_excerpt")
        if isinstance(excerpt, str) and excerpt.strip():
            _evidence(
                "sandbox_dom_excerpt",
                excerpt[:_DOM_EVIDENCE_EXCERPT_CHARS],
                "text_excerpt",
                dom_ref,
            )
        title = dom_facts.get("title")
        if isinstance(title, str) and title.strip() and not (
            isinstance(page, Mapping) and isinstance(page.get("title"), str) and page.get("title", "").strip()
        ):
            _evidence("sandbox_page_title", title, "title", dom_ref)
        fields = dom_facts.get("form_fields")
        if isinstance(fields, list):
            for index, field in enumerate(fields[:_DOM_MAX_FORM_FIELDS_EVIDENCE]):
                if not isinstance(field, Mapping):
                    continue
                name = field.get("name")
                if isinstance(name, str) and name:
                    _evidence("sandbox_form_field", name, f"form_fields/{index}/name", dom_ref)

    if isinstance(screenshot, Mapping):
        sha256 = screenshot.get("sha256")
        ref = screenshot.get("ref")
        if isinstance(sha256, str) and sha256 and isinstance(ref, str) and ref:
            _evidence("sandbox_screenshot", sha256, "", ref)

    return ToolResult(
        **base,
        status="ok",
        reason=None,
        evidence=evidence,
        mode="live",
    )


# ---------------------------------------------------------------------------
# ToolResult construction helpers
# ---------------------------------------------------------------------------


def _base_result(query: Observable) -> dict[str, Any]:
    return {
        "tool": "urlscan",
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
    reason_detail: str | None = None,
    **extra: Any,
) -> ToolResult:
    detail = reason if reason_detail is None else f"{reason}: {reason_detail}"
    kwargs: dict[str, Any] = {
        **_base_result(query),
        "status": "skipped",
        "reason": detail,
        "mode": "none",
        "elapsed_ms": elapsed_ms,
        "requests_sent": 0,
    }
    kwargs.update(extra)
    return ToolResult(**kwargs)


def _unavailable(
    query: Observable,
    cause: str,
    elapsed_ms: float,
    reason_detail: str | None = None,
    **extra: Any,
) -> ToolResult:
    detail = cause if reason_detail is None else f"{cause}: {reason_detail}"
    kwargs: dict[str, Any] = {
        **_base_result(query),
        "status": "unavailable",
        "reason": detail,
        "mode": "none",
        "elapsed_ms": elapsed_ms,
        "requests_sent": 0,
    }
    kwargs.update(extra)
    return ToolResult(**kwargs)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class UrlscanAdapter:
    """Real urlscan adapter: one bounded scan per URL observable.

    The API key never leaves the transport call. A submission is attempted
    at most once per run (local journal), an ambiguous POST is never
    retried, and every provider response is archived with its exact bytes.
    """

    def __init__(
        self,
        settings: Settings,
        config: UrlscanToolConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        quota_journal_path: Path | None = None,
    ) -> None:
        self._settings = settings
        self._config = config
        self._clock = clock
        self._sleep = sleep
        self._budget = _SubmissionBudget(
            config.max_urls,
            quota_journal_path or (Path(settings.RUNS_DIR) / "quota" / "urlscan.json"),
            clock,
        )

    # -- internal -----------------------------------------------------------------

    def _api_key(self) -> str:
        assert self._settings.URLSCAN_API_KEY is not None  # gated by the caller
        return self._settings.URLSCAN_API_KEY.get_secret_value()

    def _pending_timeout_cause(self, context: ToolContext) -> str:
        return "deadline" if self._clock() >= context.deadline else "timeout"

    def _parse_json(self, content: bytes) -> Mapping[str, object] | None:
        try:
            parsed = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, Mapping) else None

    # -- public -------------------------------------------------------------------

    def scan(self, query: Observable, context: ToolContext) -> ToolResult:
        """Real scan of one URL observable (single submission, bounded poll)."""

        started = self._clock()

        def _elapsed() -> float:
            return round((self._clock() - started) * 1000.0, 3)

        # --- configuration / applicability gates: ZERO requests ------------------
        if not self._config.enabled:
            return _skip(query, "disabled", _elapsed())
        target = submittable_url(query)
        if target is None:
            return _skip(query, "not_applicable", _elapsed())

        # --- credentials gate: ZERO requests (contract §2.7) ----------------------
        if self._settings.URLSCAN_API_KEY is None:
            return _unavailable(query, "not_configured", _elapsed())

        # --- service-approval gate: ZERO requests ---------------------------------
        service_refusal = service_send_refusal(context.egress)
        if service_refusal is not None:
            return _skip(query, "privacy_policy", _elapsed(), service_refusal)

        # --- URL-specific privacy prefilter: ZERO requests ------------------------
        refusal = url_send_refusal(target, context.egress)
        if refusal is not None:
            return _skip(query, "privacy_policy", _elapsed(), refusal)

        # --- deadline / budget gates ---------------------------------------------
        remaining = context.deadline - self._clock()
        if remaining <= 0:
            return _unavailable(query, "deadline", _elapsed())
        budget_s = min(remaining, float(self._config.phase_timeout_s))
        if budget_s < _MIN_REQUEST_BUDGET_S:
            return _unavailable(query, "deadline", _elapsed())

        # --- local submission budget: ZERO requests -------------------------------
        if not self._budget.allow(context.run_id):
            return _skip(query, "budget", _elapsed(), "max_urls_per_run_reached")

        visibility = visibility_for(context.source_profile, self._config)
        scan_deadline = started + budget_s
        requests_sent = 0
        base = _capture_base(context, query)

        # --- ONE submission; an ambiguous POST is never retried -------------------
        try:
            submit = _run_bounded(
                lambda: _post_scan_exchange(
                    URLSCAN_ORIGIN, self._api_key(), target, visibility, budget_s
                ),
                budget_s,
            )
        except UrlscanTransportError as error:
            # Ambiguous by nature: do NOT resend. The attempt consumes the
            # local budget so the same run can never double-submit.
            self._budget.record(context.run_id, visibility, None, None)
            return _unavailable(
                query,
                error.kind,
                _elapsed(),
                error.detail,
                mode=context.mode,
                requests_sent=1,
                visibility=visibility,
            )

        requests_sent += submit.request_count
        submit_meta = ResponseMetadata(
            origin=URLSCAN_ORIGIN,
            http_status=submit.http_status,
            response_date=submit.headers.get("Date"),
            response_sha256=hashlib.sha256(submit.content).hexdigest(),
        )
        submit_ref = _archive_bytes(
            context,
            f"{base}.submit.json",
            submit.content,
            submit_meta,
            extra_meta={
                "phase": "submit",
                "visibility": visibility,
                "query": _query_meta(context, query),
            },
        )
        submit_meta = submit_meta.model_copy(update={"response_ref": submit_ref})

        if submit.http_status != 200:
            cause = error_cause_for_status(submit.http_status)
            self._budget.record(context.run_id, visibility, submit.http_status, None)
            return _unavailable(
                query,
                cause,
                _elapsed(),
                f"submit_http_{submit.http_status}",
                mode=context.mode,
                requests_sent=requests_sent,
                visibility=visibility,
                response_ref=submit_ref,
                response_sha256=submit_meta.response_sha256,
            )

        submit_body = self._parse_json(submit.content)
        if submit_body is None:
            self._budget.record(context.run_id, visibility, submit.http_status, None)
            return _unavailable(
                query,
                "malformed_response",
                _elapsed(),
                "submit_body_not_json_object",
                mode=context.mode,
                requests_sent=requests_sent,
                visibility=visibility,
                response_ref=submit_ref,
                response_sha256=submit_meta.response_sha256,
            )
        scan_id, declared_visibility = submission_details(submit_body)
        self._budget.record(context.run_id, visibility, submit.http_status, scan_id)

        if scan_id is None:
            return _unavailable(
                query,
                "malformed_response",
                _elapsed(),
                "submit_missing_or_invalid_uuid",
                mode=context.mode,
                requests_sent=requests_sent,
                visibility=visibility,
                response_ref=submit_ref,
                response_sha256=submit_meta.response_sha256,
            )
        if declared_visibility != visibility:
            # Requested visibility not confirmed: never a silent downgrade.
            return _unavailable(
                query,
                "api_error",
                _elapsed(),
                f"visibility_not_confirmed:{declared_visibility!r}",
                mode=context.mode,
                requests_sent=requests_sent,
                visibility=visibility,
                scan_id=scan_id,
                response_ref=submit_ref,
                response_sha256=submit_meta.response_sha256,
            )

        # --- bounded poll: wait first_poll_s, then poll every poll_interval_s -----
        wait_s = min(float(self._config.first_poll_s), max(0.0, scan_deadline - self._clock()))
        if wait_s > 0:
            self._sleep(wait_s)

        result_body: Mapping[str, object] | None = None
        result_ref = submit_ref
        result_sha256 = submit_meta.response_sha256
        poll_index = 0
        while result_body is None:
            remaining = scan_deadline - self._clock()
            if remaining < _MIN_REQUEST_BUDGET_S:
                return _unavailable(
                    query,
                    self._pending_timeout_cause(context),
                    _elapsed(),
                    "still_pending_after_phase_budget",
                    mode=context.mode,
                    requests_sent=requests_sent,
                    visibility=visibility,
                    scan_id=scan_id,
                    response_ref=result_ref,
                    response_sha256=result_sha256,
                )
            poll_index += 1
            try:
                poll = _run_bounded(
                    lambda r=remaining: _get_result_exchange(
                        URLSCAN_ORIGIN, self._api_key(), scan_id, r
                    ),
                    remaining,
                )
            except UrlscanTransportError as error:
                return _unavailable(
                    query,
                    error.kind,
                    _elapsed(),
                    f"poll_transport:{error.detail}",
                    mode=context.mode,
                    requests_sent=requests_sent + 1,
                    visibility=visibility,
                    scan_id=scan_id,
                    response_ref=result_ref,
                    response_sha256=result_sha256,
                )
            requests_sent += poll.request_count
            poll_meta = ResponseMetadata(
                origin=URLSCAN_ORIGIN,
                http_status=poll.http_status,
                response_date=poll.headers.get("Date"),
                response_sha256=hashlib.sha256(poll.content).hexdigest(),
            )
            poll_ref = _archive_bytes(
                context,
                f"{base}.poll_{poll_index}.json",
                poll.content,
                poll_meta,
                extra_meta={
                    "phase": f"poll_{poll_index}",
                    "visibility": visibility,
                    "scan_id": scan_id,
                    "query": _query_meta(context, query),
                },
            )
            poll_meta = poll_meta.model_copy(update={"response_ref": poll_ref})
            result_ref = poll_ref
            result_sha256 = poll_meta.response_sha256

            if poll.http_status == 200:
                poll_body = self._parse_json(poll.content)
                if poll_body is None:
                    return _unavailable(
                        query,
                        "malformed_response",
                        _elapsed(),
                        "result_body_not_json_object",
                        mode=context.mode,
                        requests_sent=requests_sent,
                        visibility=visibility,
                        scan_id=scan_id,
                        response_ref=poll_ref,
                        response_sha256=result_sha256,
                    )
                result_body = poll_body
                break
            if poll.http_status == 404:
                # PENDING before a result — never not_found. Bounded wait,
                # then another poll strictly inside the remaining budget.
                remaining = scan_deadline - self._clock()
                if remaining < _MIN_REQUEST_BUDGET_S:
                    continue  # loop head returns the timeout cause
                self._sleep(min(float(self._config.poll_interval_s), remaining))
                continue
            # 410 gone / 429 / 401 / 403 / other non-2xx: explicit cause.
            detail = (
                "result_gone_http_410"
                if poll.http_status == 410
                else f"poll_http_{poll.http_status}"
            )
            return _unavailable(
                query,
                error_cause_for_status(poll.http_status),
                _elapsed(),
                detail,
                mode=context.mode,
                requests_sent=requests_sent,
                visibility=visibility,
                scan_id=scan_id,
                response_ref=poll_ref,
                response_sha256=result_sha256,
            )
        assert result_body is not None  # loop invariant

        # --- inert DOM retrieval (after a successful result) ----------------------
        dom_ref: str | None = None
        dom_facts: dict[str, object] | None = None
        remaining = scan_deadline - self._clock()
        if remaining >= _MIN_REQUEST_BUDGET_S:
            try:
                dom = _run_bounded(
                    lambda r=remaining: _get_dom_exchange(
                        URLSCAN_ORIGIN, self._api_key(), scan_id, r
                    ),
                    remaining,
                )
            except UrlscanTransportError:
                dom = None
            if dom is not None:
                requests_sent += dom.request_count
                dom_meta = ResponseMetadata(
                    origin=URLSCAN_ORIGIN,
                    http_status=dom.http_status,
                    response_date=dom.headers.get("Date"),
                    response_sha256=hashlib.sha256(dom.content).hexdigest(),
                )
                # Every DOM exchange is archived (with its real status); the
                # extracted inert facts exist only for a 200 response.
                _archive_bytes(
                    context,
                    f"{base}.dom.response",
                    dom.content,
                    dom_meta,
                    extra_meta={
                        "phase": "dom_response",
                        "scan_id": scan_id,
                        "query": _query_meta(context, query),
                    },
                )
                if dom.http_status == 200:
                    dom_facts = extract_dom_facts(
                        dom.content.decode("utf-8", errors="replace"), str(poll.url)
                    )
                    dom_ref = _archive_bytes(
                        context,
                        f"{base}.dom.json",
                        json.dumps(dom_facts, ensure_ascii=False, sort_keys=True).encode("utf-8"),
                        dom_meta,
                        extra_meta={
                            "phase": "dom_facts",
                            "scan_id": scan_id,
                            "query": _query_meta(context, query),
                        },
                    )

        # --- binary screenshot ONLY when the vision gate is active -----------------
        screenshot: dict[str, object] | None = None
        if self._settings.MODEL_SUPPORTS_VISION:
            remaining = scan_deadline - self._clock()
            if remaining >= _MIN_REQUEST_BUDGET_S:
                try:
                    shot = _run_bounded(
                        lambda r=remaining: _get_screenshot_exchange(
                            URLSCAN_ORIGIN, self._api_key(), scan_id, r
                        ),
                        remaining,
                    )
                except UrlscanTransportError:
                    shot = None
                if shot is not None:
                    requests_sent += shot.request_count
                    if shot.http_status == 200 and shot.content:
                        shot_meta = ResponseMetadata(
                            origin=URLSCAN_ORIGIN,
                            http_status=shot.http_status,
                            response_date=shot.headers.get("Date"),
                            response_sha256=hashlib.sha256(shot.content).hexdigest(),
                        )
                        shot_ref = _archive_bytes(
                            context,
                            f"{base}.screenshot.png",
                            shot.content,
                            shot_meta,
                            extra_meta={
                                "phase": "screenshot",
                                "scan_id": scan_id,
                                "query": _query_meta(context, query),
                            },
                        )
                        screenshot = {
                            "sha256": shot_meta.response_sha256,
                            "bytes": len(shot.content),
                            "ref": shot_ref,
                            "mime_type": shot.headers.get("Content-Type", "image/png"),
                        }
                    # A 404 (or any non-200) screenshot never breaks the result.

        result = normalize_result(
            query,
            result_body,
            ResponseMetadata(
                origin=URLSCAN_ORIGIN,
                http_status=200,
                response_date=poll.headers.get("Date"),
                response_sha256=result_sha256,
                response_ref=result_ref,
            ),
            dom_ref=dom_ref,
            dom_facts=dom_facts,
            screenshot=screenshot,
        )
        return result.model_copy(
            update={
                "elapsed_ms": _elapsed(),
                "requests_sent": requests_sent,
                "mode": context.mode,
                "visibility": visibility,
                "scan_id": scan_id,
            }
        )


__all__ = [
    "DOM_PATH",
    "RESULT_PATH",
    "SCREENSHOT_PATH",
    "SUBMIT_PATH",
    "URLSCAN_ORIGIN",
    "UrlscanAdapter",
    "UrlscanTransportError",
    "error_cause_for_status",
    "extract_dom_facts",
    "extract_navigation_steps",
    "normalize_result",
    "same_origin",
    "service_send_refusal",
    "submission_details",
    "submittable_url",
    "url_send_refusal",
    "visibility_for",
]

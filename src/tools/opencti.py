"""OpenCTI real CTI lookup adapter — read-only GraphQL only (TICKET-07, gate G4).

Contract (docs/architecture.md §1.6, docs/contracts.md §2.7/§2.7.1, TICKET-07):

- Transport: ``pycti`` aligned with the observed server build
  (validated against ``demo.opencti.io`` version 7.260914.0 with
  ``pycti==7.260914.0``), read-only GraphQL only. The only lookup operation
  emitted is pycti's fixed ``query StixCyberObservables`` through
  ``stix_cyber_observable.list(search=value, first=<config>, getAll=False,
  customAttributes=<bounded projection>)``. No mutation, no creation, no
  update, no deletion, no file upload, no graph traversal: introspection
  queries used by :meth:`OpenCTIAdapter.observe_version_and_schema` pass
  through :func:`assert_read_only_query` before any emission.
- Statuses: ``ok`` / ``not_found`` / ``unavailable`` / ``skipped``. Every
  ``unavailable`` carries its closed-vocabulary cause (not_configured,
  access_not_authorized is unused here — no authorization flag exists for
  OpenCTI — timeout, rate_limited, auth_error, api_error,
  malformed_response, deadline); ``skipped`` carries disabled /
  not_applicable / privacy_policy / budget.
- **Exact match is verified LOCALLY**: the provider full-text search is
  fuzzy (observed live: searching a near-miss value returns the real
  exact observable among the first results, and searching an absent value
  returns unrelated candidates). A result is ``ok`` only when a candidate
  matches BOTH the expected entity type for the observable AND its exact
  value / hash algorithm+value. The first search result is never selected
  arbitrarily. Non-exact candidates are never usable as corroboration.
- ``not_found`` means "technically successful search without an exact
  correspondence" — it is never benignity. Presence in OpenCTI, labels,
  scores or references are assertions of the source; they are exposed as
  such and never transformed into "malicious" or "benign" by this adapter.
  ``cti_revoked`` cannot be produced for STIX cyber observables: the
  observed schema (introspection, 7.260914.0) has no ``revoked`` field on
  ``StixCyberObservable`` — nothing is fabricated to fill that gap.
- Bounded projection (``OPENCTI_PROJECTION``): only the fields needed for
  local comparison and factual exposure are requested. No unbounded
  provider JSON reaches the result; evidence pointers resolve into the
  archived raw response.
- Budget: every lookup runs under a hard wall-clock bound equal to the
  EXACT remaining float budget — ``min(remaining deadline,
  phase_timeout_s)`` — never rounded upward and never extended. Below a
  minimal safe send budget the lookup returns ``unavailable/deadline`` with
  ZERO requests. The OpenCTI phase stays ≤ 20 s (docs/contracts.md §2.7).
- The API token exists only inside the transport call; it never enters the
  context, the logs, the captures or the results.
- URL values obey the egress rules (architecture §1.6 "Sorties vers
  tiers"): with a token present, the operator must explicitly approve the
  OpenCTI service (``egress.approved_services`` contains ``opencti``) —
  this is required for EVERY observable type, because OpenCTI is an
  external third party even in read-only mode; without it the lookup is
  ``skipped``/``privacy_policy`` with zero requests and no capture. An
  absent key is checked first and returns ``unavailable/not_configured``
  (contract §2.7). For URLs, service approval is necessary but NOT
  sufficient: a real URL is disclosed only when the policy also allows
  real URLs and the exact URL host, and the URL-specific refusals below
  still apply. Reserved / internal hosts are refused for domains; IPs must
  be global; recipients are never query targets (email/message_id/
  campaign_id have no exact locally-verifiable lookup here and are
  ``skipped``/``not_applicable``).

There is no mock/test/real mode: a fabricated OpenCTI answer is a FAIL
condition of the ticket. Controlled error objects (timeout / connection
failure / malformed body, 401/403/429/5xx numeric statuses) may be fed to
``normalize_response`` for deterministic error mapping — they are local
facts, never provider observations, and never become enrichment.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from ..config import OpenctiToolConfig, Settings
from ..state import Observable, ToolResult
from . import ResponseMetadata, ToolContext, det_id, expurgate, now_utc_iso

#: Observable types with a local exact-comparison rule (TICKET-07).
#: email / message_id / campaign_id are deliberately absent: no exact
#: locally-verifiable comparison exists that would not be speculation, and
#: recipients must never become query targets (docs/decisions.md §4.2 V07).
LOOKUPABLE_TYPES: tuple[str, ...] = ("sha256", "sha1", "md5", "url", "domain", "ipv4", "ipv6")

#: Below this remaining budget a request cannot be sent safely: returning
#: ``unavailable/deadline`` is more honest than starting an exchange already
#: doomed to overrun the frozen deadline (same frozen rule as TICKET-06).
_MIN_REQUEST_BUDGET_S = 0.5

#: Bounded projection requested from ``stixCyberObservables`` (TICKET-07
#: "projection bornée"). Only fields used for local exact comparison or for
#: factual exposure (labels, score, references, dates for the capture) are
#: requested. ``revoked`` is absent from the observed schema on
#: ``StixCyberObservable`` and is therefore never requested. Verified as
#: accepted by the real 7.260914.0 instance at TICKET-07 time.
OPENCTI_PROJECTION = """
    id
    standard_id
    entity_type
    created_at
    updated_at
    objectLabel {
        value
    }
    externalReferences {
        edges {
            node {
                source_name
                url
            }
        }
    }
    observable_value
    x_opencti_score
    ... on DomainName {
        value
    }
    ... on Url {
        value
    }
    ... on IPv4Addr {
        value
    }
    ... on IPv6Addr {
        value
    }
    ... on StixFile {
        hashes {
            algorithm
            hash
        }
    }
    ... on Artifact {
        hashes {
            algorithm
            hash
        }
    }
"""

#: Observable type -> expected GraphQL entity_type (local exact typing).
_ENTITY_TYPE_BY_OBSERVABLE: dict[str, str] = {
    "domain": "Domain-Name",
    "url": "Url",
    "ipv4": "IPv4-Addr",
    "ipv6": "IPv6-Addr",
}

#: STIX types whose ``hashes`` list can carry an exact file hash.
_HASH_ENTITY_TYPES: tuple[str, ...] = ("StixFile", "Artifact")

#: Observable hash type -> normalized algorithm name as returned by OpenCTI
#: (comparison is case-insensitive and hyphen-insensitive).
_HASH_ALGORITHM: dict[str, str] = {"sha256": "sha256", "sha1": "sha1", "md5": "md5"}

#: Hosts/TLDs that must never leave the machine (mirror of the TICKET-06
#: refusal list; the VT module is frozen and cannot be imported safely
#: because its URL refusal is tool-name-bound).
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
#: architecture §1.6 egress rules as TICKET-06).
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

#: The only GraphQL operation kinds the adapter may ever emit.
_MUTATION_RE = re.compile(r"(?i)\b(mutation|subscription)\b")


class OpenCTIReadOnlyViolation(Exception):
    """A non-read-only GraphQL operation was refused BEFORE emission."""


class OpenCTITransportError(Exception):
    """Local transport failure; ``kind`` is a controlled error-object kind."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = expurgate(detail)


@dataclass(frozen=True)
class _Exchange:
    """One real HTTP exchange observed by the capturing session."""

    http_status: int
    content: bytes
    headers: Mapping[str, str]
    request_count: int


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested; no I/O)
# ---------------------------------------------------------------------------


def assert_read_only_query(query_text: str) -> None:
    """Refuse a mutation/subscription BEFORE any emission (TICKET-07).

    The adapter only ever emits the read-only operations built in this
    module (pycti's fixed ``query StixCyberObservables`` and introspection
    ``query`` documents routed through here). Anything carrying a
    ``mutation`` or ``subscription`` keyword is rejected locally with zero
    requests.
    """

    if not isinstance(query_text, str) or not query_text.strip():
        raise OpenCTIReadOnlyViolation("empty GraphQL operation refused")
    if _MUTATION_RE.search(query_text):
        raise OpenCTIReadOnlyViolation("mutation/subscription operation refused before emission")


def search_value_for(query: Observable) -> str | None:
    """Canonical search string for one observable, or ``None``.

    ``None`` means "no exact locally-verifiable lookup exists" (invalid hash
    length, private/reserved host, non-global IP, unsupported type): callers
    return ``skipped/not_applicable`` instead of sending a guess.
    """

    value = (query.normalized_value or query.value).strip()
    if query.type == "sha256":
        return value.lower() if re.fullmatch(r"[0-9a-f]{64}", value, re.IGNORECASE) else None
    if query.type == "sha1":
        return value.lower() if re.fullmatch(r"[0-9a-f]{40}", value, re.IGNORECASE) else None
    if query.type == "md5":
        return value.lower() if re.fullmatch(r"[0-9a-f]{32}", value, re.IGNORECASE) else None
    if query.type == "url":
        # Scheme/host/privacy evaluation belongs to url_send_refusal()
        # (frozen TICKET-06 behavior): any non-empty URL observable reaches
        # that gate, which refuses non-HTTP(S) schemes as privacy_policy.
        return value if value else None
    if query.type == "domain":
        host = value.lower().rstrip(".")
        if not host or "." not in host or host.endswith(_RESERVED_HOST_SUFFIXES):
            return None
        return host
    if query.type in ("ipv4", "ipv6"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        return address.compressed if address.is_global else None
    return None


def service_send_refusal(egress: Any) -> str | None:
    """Refusal code when the OpenCTI service itself is not operator-approved.

    OpenCTI is an external third party for EVERY observable type (domains,
    hashes, public IPs, URLs): no value may be shared while the operator has
    not explicitly approved the service in ``egress.approved_services``.
    This gate is necessary but NOT sufficient for URLs, which additionally
    require ``allow_real_urls`` and an exact approved host (see
    :func:`url_send_refusal`).
    """

    if "opencti" not in {service.lower() for service in egress.approved_services}:
        return "service_not_approved_in_egress"
    return None


def url_send_refusal(url: str, egress: Any) -> str | None:
    """Refusal code when this URL must NOT be disclosed to OpenCTI.

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
    if "opencti" not in {service.lower() for service in egress.approved_services}:
        return "tool_not_approved_in_egress"
    if hostname not in {host.lower() for host in egress.approved_exact_url_hosts}:
        return "exact_url_host_not_approved"
    return None


def _norm_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def candidate_matches(query: Observable, node: Mapping[str, object]) -> bool:
    """Local EXACT comparison: expected type AND exact value/hash.

    Pure function; this is the only place a candidate can become an exact
    match. Full-text relevance, response order or labels can never make a
    candidate exact.
    """

    entity_type = node.get("entity_type")
    if not isinstance(entity_type, str):
        return False

    expected_type = _ENTITY_TYPE_BY_OBSERVABLE.get(query.type)
    if expected_type is not None:
        if entity_type != expected_type:
            return False
        candidate = node.get("value")
        if not isinstance(candidate, str):
            candidate = node.get("observable_value")
        if not isinstance(candidate, str):
            return False
        if query.type == "domain":
            wanted = search_value_for(query)
            return wanted is not None and _norm_domain(candidate) == wanted
        if query.type in ("ipv4", "ipv6"):
            wanted = search_value_for(query)
            if wanted is None:
                return False
            try:
                return ipaddress.ip_address(candidate) == ipaddress.ip_address(wanted)
            except ValueError:
                return False
        # URL: exact equality with the extracted raw value or its documented
        # local normalization; no provider-side renormalization is claimed.
        return candidate in {query.normalized_value, query.value}

    algorithm = _HASH_ALGORITHM.get(query.type)
    if algorithm is not None:
        if entity_type not in _HASH_ENTITY_TYPES:
            return False
        wanted = search_value_for(query)
        if wanted is None:
            return False
        hashes = node.get("hashes")
        if not isinstance(hashes, list):
            return False
        for entry in hashes:
            if not isinstance(entry, Mapping):
                continue
            entry_algorithm = entry.get("algorithm")
            digest = entry.get("hash")
            if not isinstance(entry_algorithm, str) or not isinstance(digest, str):
                continue
            if (
                entry_algorithm.lower().replace("-", "") == algorithm
                and digest.lower() == wanted
            ):
                return True
        return False
    return False


def _graphql_error_cause(body: Mapping[str, object]) -> str:
    """Honest cause for a GraphQL ``errors`` payload.

    Observed live on the demo instance: an expired/reset token yields HTTP
    200 with ``errors[0].name == "AUTH_REQUIRED"`` (``extensions.code``
    AUTH_REQUIRED, ``extensions.data.http_status`` 401). Only a
    provider-declared authentication/authorization error maps to
    ``auth_error``; everything else is ``api_error``. Nothing is inferred
    beyond what the source states.
    """

    errors = body.get("errors")
    if not isinstance(errors, list) or not errors:
        return "api_error"
    first = errors[0]
    if not isinstance(first, Mapping):
        return "api_error"
    name = str(first.get("name") or "").upper()
    extensions = first.get("extensions")
    code = ""
    declared_status: object = None
    if isinstance(extensions, Mapping):
        code = str(extensions.get("code") or "").upper()
        extension_data = extensions.get("data")
        if isinstance(extension_data, Mapping):
            declared_status = extension_data.get("http_status")
    if any(
        token in name or token in code
        for token in ("AUTH_REQUIRED", "UNAUTHENTICATED", "UNAUTHORIZED", "FORBIDDEN")
    ):
        return "auth_error"
    if declared_status in (401, 403):
        return "auth_error"
    return "api_error"


# ---------------------------------------------------------------------------
# Response capture (restricted data under runs/, git-ignored)
# ---------------------------------------------------------------------------


def _run_scoped_name(context: ToolContext, base: str) -> str:
    """Per-run capture name: two runs can never overwrite each other's
    archived evidence (e.g. a valid lookup and an invalid-token probe of the
    same value), so every evidence pointer stays resolvable."""

    run_digest = hashlib.sha256(context.run_id.encode("utf-8")).hexdigest()[:8]
    return f"{base}_{run_digest}"


def _capture_name(context: ToolContext, query: Observable) -> str:
    value_digest = hashlib.sha256(
        (query.normalized_value or query.value).encode("utf-8")
    ).hexdigest()
    return _run_scoped_name(context, f"opencti_{query.type}_{value_digest[:16]}")


def _archive_raw(
    context: ToolContext,
    name: str,
    raw: bytes,
    metadata: ResponseMetadata,
    extra_meta: Mapping[str, object] | None = None,
) -> str:
    """Archive EXACT provider response bytes + factual provenance metadata.

    Returns the local reference (file name inside the capture directory).
    Only factual fields are stored: origin, HTTP status, service date,
    exact-bytes SHA-256, collection context — never any header with key
    material and never the outgoing request payload.
    """

    body_path = Path(context.capture_dir) / f"{name}.json"
    meta_path = Path(context.capture_dir) / f"{name}.meta.json"
    body_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.write_bytes(raw)
    meta: dict[str, object] = {
        "tool": "opencti",
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
    return body_path.name


def _archive_response(
    context: ToolContext,
    query: Observable,
    raw: bytes,
    metadata: ResponseMetadata,
) -> str:
    return _archive_raw(
        context,
        _capture_name(context, query),
        raw,
        metadata,
        extra_meta={
            "query": {
                "observable_id": query.id,
                "type": query.type,
                "normalized_value": query.normalized_value,
            }
        },
    )


# ---------------------------------------------------------------------------
# Normalizer (pure; controlled error objects in, ToolResult out)
# ---------------------------------------------------------------------------


def normalize_response(
    query: Observable,
    body: Mapping[str, object] | None,
    metadata: ResponseMetadata,
) -> ToolResult:
    """Map one provider exchange to the normalized ToolResult (§2.7).

    ``body`` is the parsed provider GraphQL JSON (or ``None`` for
    controlled error objects). A missing/absent field stays absent: no
    counter or value is ever fabricated, non-2xx statuses never become
    evidence, GraphQL errors are provider errors (``api_error``), and the
    fuzzy full-text search never becomes an exact match. When no candidate
    matches exactly, the status is ``not_found`` even if the provider
    returned unrelated or near candidates — presence itself is never a
    positive or negative conclusion.
    """

    collected_at = now_utc_iso()
    observed_at = metadata.response_date or collected_at
    base: dict[str, Any] = {
        "tool": "opencti",
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
        value: Any,
        pointer: str,
        match_level: str,
    ) -> dict[str, Any]:
        return {
            "id": det_id("ev", predicate, str(value), metadata.response_ref, pointer),
            "provenance": "OSINT",
            "source_kind": "opencti",
            "observable_id": query.id,
            "predicate": predicate,  # type: ignore[typeddict-item]
            "value": value,
            "source_ref": f"{metadata.response_ref}#/{pointer}",
            "observed_at": observed_at,
            "match_level": match_level,  # type: ignore[typeddict-item]
            "source_group": "opencti",
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
    if status in (401, 403):
        return _result("unavailable", "auth_error", mode="live")
    if status == 429:
        return _result("unavailable", "rate_limited", mode="live")
    if not 200 <= status < 300:
        return _result("unavailable", "api_error", mode="live")

    # --- 2xx: parse, project, compare locally ----------------------------------
    if not isinstance(body, Mapping):
        return _result("unavailable", "malformed_response", mode="live")
    if body.get("errors"):
        # GraphQL errors are provider-level failures, never evidence. A
        # provider-declared auth error (observed: AUTH_REQUIRED on
        # expired/reset demo tokens) maps to auth_error, not to a generic
        # api_error, and never to fabricated data.
        return _result("unavailable", _graphql_error_cause(body), mode="live")
    data = body.get("data")
    if not isinstance(data, Mapping):
        return _result("unavailable", "malformed_response", mode="live")
    listing = data.get("stixCyberObservables")
    if not isinstance(listing, Mapping):
        return _result("unavailable", "malformed_response", mode="live")
    edges = listing.get("edges")
    if not isinstance(edges, list):
        return _result("unavailable", "malformed_response", mode="live")
    nodes: list[tuple[int, Mapping[str, object]]] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, Mapping):
            return _result("unavailable", "malformed_response", mode="live")
        node = edge.get("node")
        if not isinstance(node, Mapping):
            return _result("unavailable", "malformed_response", mode="live")
        nodes.append((index, node))

    matched: tuple[int, Mapping[str, object]] | None = None
    for index, node in nodes:
        if candidate_matches(query, node):
            matched = (index, node)
            break

    if matched is None:
        if not nodes:
            return _result("not_found", None, mode="live")
        return _result(
            "not_found",
            f"no_exact_match: {len(nodes)} candidate(s) received, none verified locally",
            mode="live",
        )

    index, node = matched
    pointer = f"data/stixCyberObservables/edges/{index}/node"
    evidence: list[dict[str, Any]] = [
        _evidence("cti_exact_match", True, pointer, "EXACT"),
    ]

    labels = node.get("objectLabel")
    if isinstance(labels, list):
        for label_index, label in enumerate(labels):
            if isinstance(label, Mapping) and isinstance(label.get("value"), str):
                evidence.append(
                    _evidence(
                        "cti_label",
                        label["value"],
                        f"{pointer}/objectLabel/{label_index}/value",
                        "EXACT",
                    )
                )

    score = node.get("x_opencti_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        evidence.append(
            _evidence("cti_score", float(score), f"{pointer}/x_opencti_score", "EXACT")
        )

    references = node.get("externalReferences")
    if isinstance(references, Mapping):
        ref_edges = references.get("edges")
        if isinstance(ref_edges, list):
            for ref_index, ref_edge in enumerate(ref_edges):
                if not isinstance(ref_edge, Mapping):
                    continue
                ref_node = ref_edge.get("node")
                if not isinstance(ref_node, Mapping):
                    continue
                url = ref_node.get("url")
                source_name = ref_node.get("source_name")
                if isinstance(url, str) and url:
                    evidence.append(
                        _evidence(
                            "cti_external_reference",
                            url,
                            f"{pointer}/externalReferences/edges/{ref_index}/node/url",
                            "EXACT",
                        )
                    )
                elif isinstance(source_name, str) and source_name:
                    evidence.append(
                        _evidence(
                            "cti_external_reference",
                            source_name,
                            f"{pointer}/externalReferences/edges/{ref_index}/node/source_name",
                            "EXACT",
                        )
                    )

    return _result("ok", None, evidence, mode="live")


# ---------------------------------------------------------------------------
# Transport (pycti, read-only GraphQL) — isolated so tests can inject
# controlled error objects without any provider call (TICKET-06 precedent)
# ---------------------------------------------------------------------------


def _pycti_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("pycti") is not None


def _make_capturing_session() -> Any:
    """A ``requests.Session`` that records each exact HTTP response.

    pycti owns the HTTP layer (headers, auth, GraphQL envelope); this thin
    session simply preserves the EXACT response bytes so the adapter can
    archive a real provider response instead of a re-serialized guess.
    """

    import requests

    class _CapturingSession(requests.Session):
        def __init__(self) -> None:
            super().__init__()
            self.exchanges: list[tuple[int, bytes, Mapping[str, str]]] = []

        def post(self, url: str, **kwargs: Any) -> Any:
            response = super().post(url, **kwargs)
            self.exchanges.append(
                (int(response.status_code), bytes(response.content), dict(response.headers))
            )
            return response

    return _CapturingSession()


def _run_graphql(
    settings: Settings,
    operation: Callable[[Any], None],
    timeout_s: float,
) -> _Exchange:
    """One pycti (read-only) GraphQL exchange with exact-bytes capture.

    ``timeout_s`` is passed to the pycti/requests client as the per-request
    timeout; the caller additionally enforces the same value as a hard
    wall-clock bound. The token exists only in this call. A provider
    exchange that arrived (even with GraphQL errors or a non-2xx status) is
    returned so the normalizer can classify the REAL bytes; only a failure
    without any exchange becomes a controlled transport error object.
    """

    import pycti

    if settings.OPENCTI_API_KEY is None:  # defensive: gated by the caller
        raise OpenCTITransportError("connection_error", "OpenCTI token not configured")

    session = _make_capturing_session()
    client = pycti.OpenCTIApiClient(
        settings.OPENCTI_URL,
        settings.OPENCTI_API_KEY.get_secret_value(),
        log_level="error",
        ssl_verify=True,
        perform_health_check=False,
        requests_timeout=timeout_s,
    )
    client.session = session
    try:
        operation(client)
    except Exception as error:  # noqa: BLE001 — classified below
        if not session.exchanges:
            import requests

            if isinstance(error, requests.exceptions.Timeout):
                raise OpenCTITransportError(
                    "timeout", f"OpenCTI request timed out after {timeout_s}s"
                ) from error
            if isinstance(error, requests.exceptions.RequestException):
                raise OpenCTITransportError(
                    "connection_error", f"OpenCTI transport error: {error}"
                ) from error
            raise OpenCTITransportError(
                "connection_error", f"pycti failure before any exchange: {error}"
            ) from error
        # A real exchange happened (GraphQL errors / non-2xx / error body):
        # keep the provider bytes and let the normalizer decide.
    finally:
        session.close()

    if not session.exchanges:
        raise OpenCTITransportError("connection_error", "no HTTP exchange was captured")
    status_code, content, headers = session.exchanges[-1]
    return _Exchange(
        http_status=status_code,
        content=content,
        headers=headers,
        request_count=len(session.exchanges),
    )


def _run_bounded(fn: Callable[[], _Exchange], timeout_s: float) -> _Exchange:
    """Hard wall-clock bound: never returns later than ``timeout_s``.

    The worker also carries the same value as its per-request timeout, so a
    hung socket self-terminates at the same bound; the daemon thread cannot
    block process exit.
    """

    outcome: dict[str, object] = {}

    def _worker() -> None:
        try:
            outcome["exchange"] = fn()
        except Exception as error:  # noqa: BLE001 — re-raised/classified below
            outcome["error"] = error

    thread = threading.Thread(target=_worker, daemon=True, name="opencti-lookup")
    thread.start()
    thread.join(timeout_s)
    if thread.is_alive():
        raise OpenCTITransportError(
            "timeout", f"OpenCTI lookup exceeded the hard budget of {timeout_s}s"
        )
    error = outcome.get("error")
    if isinstance(error, OpenCTITransportError):
        raise error
    if isinstance(error, OpenCTIReadOnlyViolation):
        raise error
    if isinstance(error, BaseException):
        raise OpenCTITransportError(
            "connection_error", f"unexpected transport failure: {error}"
        )
    exchange = outcome.get("exchange")
    if not isinstance(exchange, _Exchange):
        raise OpenCTITransportError("connection_error", "no exchange produced")
    return exchange


def _opencti_list_exchange(
    settings: Settings,
    search_value: str,
    first: int,
    timeout_s: float,
) -> _Exchange:
    """The frozen read-only lookup: ``stix_cyber_observable.list(search=…,
    first=…, getAll=False, customAttributes=…)``."""

    def _operation(client: Any) -> None:
        client.stix_cyber_observable.list(
            search=search_value,
            first=first,
            getAll=False,
            customAttributes=OPENCTI_PROJECTION,
        )

    return _run_graphql(settings, _operation, timeout_s)


def _opencti_query_exchange(
    settings: Settings,
    query_text: str,
    timeout_s: float,
) -> _Exchange:
    """Read-only introspection/diagnostic query, refused if not a query."""

    assert_read_only_query(query_text)

    def _operation(client: Any) -> None:
        client.query(query_text)

    return _run_graphql(settings, _operation, timeout_s)


# ---------------------------------------------------------------------------
# ToolResult construction helpers
# ---------------------------------------------------------------------------


def _base_result(query: Observable) -> dict[str, Any]:
    return {
        "tool": "opencti",
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


class OpenCTIAdapter:
    """Real OpenCTI read-only CTI adapter; one observable per ``lookup``.

    The API token never leaves the transport call. ``lookup`` performs ONE
    bounded ``list`` search and verifies the exact match locally;
    ``observe_version_and_schema`` captures the minimal observed
    platform/schema facts (same read-only transport).
    """

    def __init__(
        self,
        settings: Settings,
        config: OpenctiToolConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._config = config
        self._clock = clock

    def lookup(self, query: Observable, context: ToolContext) -> ToolResult:
        started = self._clock()

        def _elapsed() -> float:
            return round((self._clock() - started) * 1000.0, 3)

        # --- configuration gate: ZERO requests -----------------------------------
        if not self._config.enabled:
            return _skip(query, "disabled", _elapsed())

        # --- exact-comparison availability for this observable --------------------
        if query.type not in LOOKUPABLE_TYPES:
            return _skip(query, "not_applicable", _elapsed())
        search_value = search_value_for(query)
        if search_value is None:
            return _skip(query, "not_applicable", _elapsed())

        # --- dependency gate (zero requests when the transport is missing) --------
        if not _pycti_available():
            return _unavailable(
                query,
                "api_error",
                _elapsed(),
                reason_detail="pycti transport dependency not installed",
            )

        # --- credentials gate: ZERO requests --------------------------------------
        # Contract §2.7 ordering: an absent key is unavailable/not_configured,
        # checked BEFORE the egress service policy (no value could be sent
        # without a key anyway).
        if self._settings.OPENCTI_API_KEY is None:
            return _unavailable(query, "not_configured", _elapsed())

        # --- service-approval gate (zero requests for EVERY observable type) ------
        # OpenCTI is an external third party even in read-only mode: with a
        # token present, no domain/hash/IP/URL value may be shared until the
        # operator explicitly approves the service. This gate is necessary
        # for URLs but not sufficient — the URL-specific controls below
        # still apply, and it always precedes the transport.
        service_refusal = service_send_refusal(context.egress)
        if service_refusal is not None:
            return _skip(query, "privacy_policy", _elapsed(), reason_detail=service_refusal)

        # --- URL-specific controls (additional; never replaced by approval) --------
        if query.type == "url":
            refusal = url_send_refusal(search_value, context.egress)
            if refusal is not None:
                return _skip(query, "privacy_policy", _elapsed(), reason_detail=refusal)
        # Reserved/internal domains are already refused by search_value_for
        # (skipped/not_applicable), mirroring the TICKET-06 frozen behavior.

        # --- deadline / budget gates ---------------------------------------------
        remaining = context.deadline - self._clock()
        if remaining <= 0:
            return _unavailable(query, "deadline", _elapsed())
        budget_s = min(remaining, float(self._config.phase_timeout_s))
        if budget_s < _MIN_REQUEST_BUDGET_S:
            return _unavailable(query, "deadline", _elapsed())

        try:
            exchange = _run_bounded(
                lambda: _opencti_list_exchange(
                    self._settings, search_value, self._config.first, budget_s
                ),
                budget_s,
            )
        except OpenCTITransportError as error:
            metadata = ResponseMetadata(
                origin=self._settings.OPENCTI_URL,
                http_status=None,
                error_kind=error.kind,  # type: ignore[arg-type]
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

        metadata = ResponseMetadata(
            origin=self._settings.OPENCTI_URL,
            http_status=exchange.http_status,
            response_date=exchange.headers.get("Date"),
            response_sha256=hashlib.sha256(exchange.content).hexdigest(),
        )
        response_ref = _archive_response(context, query, exchange.content, metadata)
        metadata = metadata.model_copy(update={"response_ref": response_ref})

        body: Mapping[str, object] | None = None
        if exchange.http_status == 200:
            try:
                parsed = json.loads(exchange.content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, dict):
                body = parsed
            else:
                metadata = metadata.model_copy(update={"error_kind": "malformed"})
        # Non-2xx: the STATUS drives the cause; an error body, when present,
        # is archived for traceability only and never becomes evidence.
        result = normalize_response(query, body, metadata)
        return result.model_copy(
            update={
                "elapsed_ms": _elapsed(),
                "requests_sent": exchange.request_count,
                "mode": context.mode,
            }
        )

    # ------------------------------------------------------------------
    # Observed version/schema capture (read-only introspection)
    # ------------------------------------------------------------------

    _ABOUT_QUERY = "query { about { version } }"
    _SCHEMA_STIX_CYBER_OBSERVABLE_QUERY = (
        'query { __type(name: "StixCyberObservable") { fields { name } } }'
    )
    _SCHEMA_STIX_FILE_QUERY = 'query { __type(name: "StixFile") { fields { name } } }'

    def observe_version_and_schema(self, context: ToolContext) -> dict[str, object]:
        """Capture the minimal REAL platform version and schema facts.

        Three read-only introspection queries; every raw response is
        archived (exact bytes). Returns a factual dict; a missing token or
        transport failure yields an explicit ``unavailable`` status with
        its cause — never fabricated values.
        """

        if not self._config.enabled:
            return {"status": "unavailable", "cause": "disabled", "requests_sent": 0}
        if not _pycti_available():
            return {
                "status": "unavailable",
                "cause": "api_error",
                "detail": "pycti transport dependency not installed",
                "requests_sent": 0,
            }
        # Contract §2.7 ordering: absent key => unavailable/not_configured,
        # checked before the egress service policy.
        if self._settings.OPENCTI_API_KEY is None:
            return {"status": "unavailable", "cause": "not_configured", "requests_sent": 0}
        service_refusal = service_send_refusal(context.egress)
        if service_refusal is not None:
            # Same privacy contract as lookup: no provider request without
            # explicit operator approval of the OpenCTI service.
            return {
                "status": "skipped",
                "reason": f"privacy_policy: {service_refusal}",
                "requests_sent": 0,
            }

        observations: dict[str, object] = {}
        refs: list[str] = []
        requests_sent = 0
        queries = (
            ("about", self._ABOUT_QUERY),
            ("stix_cyber_observable", self._SCHEMA_STIX_CYBER_OBSERVABLE_QUERY),
            ("stix_file", self._SCHEMA_STIX_FILE_QUERY),
        )
        for name, query_text in queries:
            remaining = context.deadline - self._clock()
            if remaining <= 0:
                return {
                    "status": "unavailable",
                    "cause": "deadline",
                    "requests_sent": requests_sent,
                }
            budget_s = min(remaining, float(self._config.phase_timeout_s))
            if budget_s < _MIN_REQUEST_BUDGET_S:
                return {
                    "status": "unavailable",
                    "cause": "deadline",
                    "requests_sent": requests_sent,
                }
            try:
                exchange = _run_bounded(
                    lambda q=query_text, b=budget_s: _opencti_query_exchange(
                        self._settings, q, b
                    ),
                    budget_s,
                )
            except OpenCTITransportError as error:
                return {
                    "status": "unavailable",
                    "cause": error.kind,
                    "detail": error.detail,
                    "requests_sent": requests_sent + 1,
                }
            requests_sent += exchange.request_count
            metadata = ResponseMetadata(
                origin=self._settings.OPENCTI_URL,
                http_status=exchange.http_status,
                response_date=exchange.headers.get("Date"),
                response_sha256=hashlib.sha256(exchange.content).hexdigest(),
            )
            ref = _archive_raw(
                context,
                _run_scoped_name(context, f"opencti_schema_{name}"),
                exchange.content,
                metadata,
            )
            refs.append(ref)
            if exchange.http_status != 200:
                return {
                    "status": "unavailable",
                    "cause": "auth_error" if exchange.http_status in (401, 403) else "api_error",
                    "http_status": exchange.http_status,
                    "requests_sent": requests_sent,
                    "archived": refs,
                }
            try:
                payload = json.loads(exchange.content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {
                    "status": "unavailable",
                    "cause": "malformed_response",
                    "requests_sent": requests_sent,
                    "archived": refs,
                }
            if not isinstance(payload, Mapping):
                return {
                    "status": "unavailable",
                    "cause": "malformed_response",
                    "requests_sent": requests_sent,
                    "archived": refs,
                }
            declared_errors = payload.get("errors")
            if declared_errors:
                return {
                    "status": "unavailable",
                    "cause": _graphql_error_cause(payload),
                    "requests_sent": requests_sent,
                    "archived": refs,
                }
            observations[name] = payload.get("data")

        about = observations.get("about")
        version: object = None
        if isinstance(about, Mapping):
            about_block = about.get("about")
            if isinstance(about_block, Mapping):
                version = about_block.get("version")
        sco_fields = _fields_of(observations.get("stix_cyber_observable"))
        file_fields = _fields_of(observations.get("stix_file"))
        return {
            "status": "ok",
            "version": version,
            "stix_cyber_observable_fields": sco_fields,
            "stix_file_fields": file_fields,
            "revoked_on_stix_cyber_observable": "revoked" in sco_fields,
            "hashes_on_stix_file": "hashes" in file_fields,
            "requests_sent": requests_sent,
            "archived": refs,
        }


def _fields_of(data: object) -> list[str]:
    if not isinstance(data, Mapping):
        return []
    type_block = data.get("__type")
    if not isinstance(type_block, Mapping):
        return []
    fields = type_block.get("fields")
    if not isinstance(fields, list):
        return []
    return sorted(
        field["name"]
        for field in fields
        if isinstance(field, Mapping) and isinstance(field.get("name"), str)
    )


__all__ = [
    "LOOKUPABLE_TYPES",
    "OPENCTI_PROJECTION",
    "OpenCTIAdapter",
    "OpenCTIReadOnlyViolation",
    "OpenCTITransportError",
    "assert_read_only_query",
    "candidate_matches",
    "normalize_response",
    "search_value_for",
    "service_send_refusal",
    "url_send_refusal",
]

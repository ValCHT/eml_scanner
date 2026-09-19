"""OpenCTI adapter tests (TICKET-07, docs/tickets/TICKET-07.md, gate G4).

Non-live coverage (no network, no credentials):
- real adapter without key → explicit ``unavailable`` with its cause and
  ZERO requests (never a skipped mandatory test);
- disabled tool → ``skipped``; unsupported observable types (email /
  message_id / campaign_id, invalid values) → ``skipped``/not_applicable;
- deadline and exact remaining-float budget gates (same frozen rule as
  TICKET-06), phase_timeout_s cap;
- controlled error objects (timeout / connection failure / malformed body,
  401/403/429/5xx statuses, real-shaped GraphQL AUTH_REQUIRED payload)
  fed to the REAL normalizer → deterministic causes, never evidence;
- fuzzy full-text search is NEVER an exact match: local type + value /
  hash-algorithm comparison only, first result never selected arbitrarily,
  near-miss values rejected, missing fields stay absent (no fabricated 0);
- egress/privacy refusal rules for URLs (zero requests on refusal) and
  open policy reaches the transport;
- bounded projection (no unbounded provider JSON), read-only guard
  refusing mutations/subscriptions before emission, source invariant
  (no create/update/delete/upload path), pycti-missing explicit
  unavailable, capture of EXACT provider bytes without key material;
- ToolResult/Evidence validation against the frozen triage_report schema;
- packaging: the built wheel ships and installs ``src.tools.opencti``.

Live coverage (explicit ``--live``):
- real instance validation: observed version/schema capture, one REAL
  known exact match (operator-provided known observable), one REAL real
  no-match search, one REAL near-miss search + local validator on the REAL
  captured response, and a real invalid-token exchange (reset/expiry path)
  that must be an explicit ``unavailable/auth_error`` — never fabricated;
- one REAL short client timeout with a hard local bound (RFC 5737
  unreachable documentation address; no fake server, no fabricated
  provider response).
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from src.config import EgressConfig, Settings, ToolsConfig, load_settings, load_yaml_config
from src.state import Observable
from src.tools import ResponseMetadata, ToolContext
from src.tools import opencti as opencti_module
from src.tools.opencti import (
    LOOKUPABLE_TYPES,
    OPENCTI_PROJECTION,
    OpenCTIAdapter,
    OpenCTIReadOnlyViolation,
    OpenCTITransportError,
    assert_read_only_query,
    candidate_matches,
    normalize_response,
    search_value_for,
    service_send_refusal,
    url_send_refusal,
)

pytestmark = pytest.mark.g4

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads(
    (PROJECT_ROOT / "schemas" / "triage_report.schema.json").read_text(encoding="utf-8")
)

#: Placeholder credential for adapter tests. It is NOT a secret: a
#: synthetic non-real string used only to reach code paths past the key
#: gate; it is never asserted to work against the real service.
PLACEHOLDER_KEY = "placeholder-key-not-a-real-credential"


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Any network attempt fails non-live tests (live tests bypass this)."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in a non-live test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


@pytest.fixture()
def tools_config(project_root: Path) -> ToolsConfig:
    return load_yaml_config(project_root / "configs" / "tools.yaml", ToolsConfig)


@pytest.fixture()
def lookup_context(tmp_path: Path) -> ToolContext:
    return ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=EgressConfig(
            allow_real_urls=False,
            approved_services=[],
            approved_exact_url_hosts=[],
            trusted_authserv_ids=[],
            shared_hosts=[],
            trusted_cti_sources=[],
        ),
        capture_dir=tmp_path / "captures",
        mode="live",
    )


@pytest.fixture()
def approved_context(lookup_context: ToolContext) -> ToolContext:
    """Same context with the OpenCTI service explicitly operator-approved.

    OpenCTI is an external third party for every observable type; only an
    explicit operator approval allows a provider request. Tests that must
    reach the transport/credential/deadline gates use this context — the
    default ``approved_services=[]`` remains safe-by-default.
    """

    egress = lookup_context.egress.model_copy(
        update={"approved_services": ["opencti"]}
    )
    return lookup_context.model_copy(update={"egress": egress})


def _placeholder_settings(**overrides: Any) -> Settings:
    """Settings with a placeholder token reaching the transport gates."""

    values: dict[str, Any] = {"OPENCTI_API_KEY": SecretStr(PLACEHOLDER_KEY)}
    values.update(overrides)
    return Settings(**values)


def _approved_egress(**overrides: Any) -> EgressConfig:
    """Egress with the OpenCTI service explicitly operator-approved.

    Required for any test that must reach the provider transport: OpenCTI
    is an external third party for every observable type.
    """

    values: dict[str, Any] = {"allow_real_urls": False, "approved_services": ["opencti"]}
    values.update(overrides)
    return EgressConfig(**values)


def _tools_approved_egress(tools_config: ToolsConfig) -> EgressConfig:
    """Operator egress with the OpenCTI service explicitly approved.

    Used ONLY by the official live/smoke runs against the
    operator-selected public OpenCTI demo instance. ``configs/tools.yaml``
    is deliberately not changed: the default ``approved_services=[]``
    remains safe-by-default.
    """

    approved = sorted(
        {service.lower() for service in tools_config.egress.approved_services} | {"opencti"}
    )
    return tools_config.egress.model_copy(update={"approved_services": approved})


def _obs(obs_type: str, value: str, *, normalized: str | None = None, **overrides: Any) -> Observable:
    defaults: dict[str, Any] = {
        "id": f"obs_{obs_type}_{uuid.uuid4().hex[:8]}",
        "value": value,
        "normalized_value": normalized if normalized is not None else value,
        "type": obs_type,
        "roles": [],
        "provenance": "INTERNE",
        "source_ref": "test",
    }
    defaults.update(overrides)
    return Observable(**defaults)


def _domain_observable(value: str, **overrides: Any) -> Observable:
    return _obs("domain", value, roles=["link_target"], **overrides)


def _node(entity_type: str, value: str | None, **extra: Any) -> dict[str, Any]:
    node: dict[str, Any] = {
        "entity_type": entity_type,
        "observable_value": value,
    }
    if value is not None:
        node["value"] = value
    node.update(extra)
    return node


def _graphql_body(*nodes: dict[str, Any]) -> dict[str, Any]:
    return {
        "data": {
            "stixCyberObservables": {
                "edges": [{"node": node} for node in nodes],
            }
        }
    }


def _meta(
    http_status: int | None = 200,
    *,
    response_ref: str | None = "opencti_test_capture.json",
    response_date: str | None = "Fri, 19 Sep 2026 10:00:00 GMT",
    error_kind: str | None = None,
) -> ResponseMetadata:
    return ResponseMetadata(
        origin="https://demo.opencti.io",
        http_status=http_status,
        response_date=response_date,
        response_sha256="a" * 64 if response_ref else None,
        response_ref=response_ref,
        error_kind=error_kind,  # type: ignore[arg-type]
    )


def _unknown_sha256() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def _near_miss_domain(value: str) -> str:
    """A value one character away from the known exact observable."""

    return value[:-1] + ("m" if value.endswith("n") else "x")


def _pointer_get(document: object, pointer: str) -> object:
    current = document
    for part in pointer.split("/"):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            return None
    return current


# ---------------------------------------------------------------------------
# Real adapter without key / without rights (mandatory, never skipped)
# ---------------------------------------------------------------------------


def test_lookup_without_key_is_explicit_unavailable_with_zero_requests(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext
) -> None:
    """Contract §2.7 ordering regression A: token absent + safe default
    ``approved_services=[]`` => ``unavailable/not_configured`` (NOT
    privacy_policy), zero requests."""

    adapter = OpenCTIAdapter(settings_no_secrets, tools_config.opencti)
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), lookup_context)
    assert result.status == "unavailable"
    assert result.reason is not None and "not_configured" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"
    assert result.evidence == [] and result.observables == []
    assert result.response_sha256 is None and result.response_ref is None


def test_disabled_tool_is_skipped_with_reason_and_zero_requests(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext
) -> None:
    config = tools_config.opencti.model_copy(update={"enabled": False})
    adapter = OpenCTIAdapter(settings_no_secrets, config)
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), lookup_context)
    assert result.status == "skipped"
    assert result.reason is not None and "disabled" in result.reason
    assert result.requests_sent == 0


def test_unsupported_observable_types_are_skipped_not_applicable(
    tools_config: ToolsConfig, lookup_context: ToolContext
) -> None:
    """email / message_id / campaign_id have no exact locally-verifiable
    lookup here: recipients and personal identifiers are never query
    targets (docs/decisions.md §4.2 V07)."""

    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    for obs_type, value in (
        ("email", "victim@corp.example.net"),
        ("message_id", "<abc@corp.example.net>"),
        ("campaign_id", "campaign-2026-09"),
    ):
        result = adapter.lookup(_obs(obs_type, value), lookup_context)
        assert result.status == "skipped", obs_type
        assert result.reason is not None and "not_applicable" in result.reason
        assert result.requests_sent == 0


def test_invalid_values_for_lookupable_types_are_not_applicable(
    tools_config: ToolsConfig, lookup_context: ToolContext
) -> None:
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    for obs_type, value in (
        ("sha256", "xyz"),
        ("sha1", "a" * 39),
        ("md5", "g" * 32),
        ("domain", "localhost"),
        ("domain", "printer.corp"),
        ("domain", "single-label"),
        ("ipv4", "10.0.0.9"),
        ("ipv6", "::1"),
    ):
        result = adapter.lookup(_obs(obs_type, value), lookup_context)
        assert result.status == "skipped", (obs_type, value)
        assert result.reason is not None and "not_applicable" in result.reason
        assert result.requests_sent == 0


def test_search_value_normalization_rules() -> None:
    assert search_value_for(_obs("domain", "TheTollRoads-PayTollTH.XIN.")) == (
        "thetollroads-paytollth.xin"
    )
    assert search_value_for(_obs("ipv6", "2001:4860:4860:0000:0000:0000:0000:8888")) == (
        "2001:4860:4860::8888"
    )
    assert search_value_for(_obs("sha256", "AB" * 32)) == "ab" * 32
    assert search_value_for(_obs("sha1", "CD" * 20)) == "cd" * 20
    assert search_value_for(_obs("md5", "EF" * 16)) == "ef" * 16
    url = "https://Example.com/Path?b=1"
    assert search_value_for(_obs("url", url)) == url
    assert search_value_for(_obs("url", "")) is None
    for obs_type, value in (
        ("domain", "host.test"),
        ("domain", "x.example"),
        ("ipv4", "192.168.1.1"),
        ("ipv4", "127.0.0.1"),
        ("sha256", "not-hex"),
        ("email", "user@example.com"),
        ("message_id", "<x@y>"),
        ("campaign_id", "c1"),
    ):
        assert search_value_for(_obs(obs_type, value)) is None, (obs_type, value)


# ---------------------------------------------------------------------------
# Deadline and hard budget (controlled transport objects only)
# ---------------------------------------------------------------------------


def test_expired_deadline_is_unavailable_deadline_with_zero_requests(
    tools_config: ToolsConfig, approved_context: ToolContext
) -> None:
    approved_context.deadline = time.monotonic() - 1.0
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), approved_context)
    assert result.status == "unavailable"
    assert result.reason is not None and "deadline" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"


def test_near_deadline_returns_unavailable_deadline_without_sending(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below the minimal safe send budget the transport is never reached."""

    def _forbidden(*args: object, **kwargs: object) -> object:
        pytest.fail("transport must never be reached when too little time remains")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _forbidden)
    fixed_clock = 1000.0
    adapter = OpenCTIAdapter(
        _placeholder_settings(), tools_config.opencti, clock=lambda: fixed_clock
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 0.3,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), context)
    assert result.status == "unavailable"
    assert result.reason is not None and "deadline" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"


def test_request_budget_is_exact_remaining_float_and_phase_capped(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hard bound is the EXACT remaining float budget —
    min(remaining, phase_timeout_s) — never rounded upward. Controlled
    timeout object only; no real OpenCTI request."""

    captured: dict[str, float] = {}

    def _controlled_timeout(
        settings: Settings, search_value: str, first: int, timeout_s: float
    ) -> object:
        captured["timeout_s"] = timeout_s
        raise OpenCTITransportError("timeout", "controlled timeout object (no provider call)")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _controlled_timeout)
    fixed_clock = 1000.0
    adapter = OpenCTIAdapter(
        _placeholder_settings(), tools_config.opencti, clock=lambda: fixed_clock
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 10.25,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), context)
    assert captured["timeout_s"] == pytest.approx(10.25)
    assert result.status == "unavailable"
    assert result.reason is not None and "timeout" in result.reason
    assert result.requests_sent == 1
    assert result.mode == "live"

    captured.clear()
    capped_config = tools_config.opencti.model_copy(update={"phase_timeout_s": 2.5})
    capped_adapter = OpenCTIAdapter(
        _placeholder_settings(), capped_config, clock=lambda: fixed_clock
    )
    capped_result = capped_adapter.lookup(
        _domain_observable("thetollroads-paytollth.xin"), context
    )
    assert captured["timeout_s"] == pytest.approx(2.5)
    assert capped_result.status == "unavailable"


def test_unexpected_transport_failure_is_a_controlled_error_not_a_provider_answer(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("local transport exploded with no exchange")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _boom)
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 30.0,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), context)
    assert result.status == "unavailable"
    assert result.reason is not None and "api_error" in result.reason
    assert result.evidence == []
    assert result.requests_sent == 1
    assert result.mode == "live"


# ---------------------------------------------------------------------------
# Normalizer: controlled error objects and malformed bodies
# ---------------------------------------------------------------------------


def test_normalizer_controlled_error_objects() -> None:
    query = _domain_observable("thetollroads-paytollth.xin")
    cases = (
        (_meta(http_status=None, response_ref=None, error_kind="timeout"), "timeout", "none"),
        (
            _meta(http_status=None, response_ref=None, error_kind="connection_error"),
            "api_error",
            "none",
        ),
        (
            _meta(http_status=None, response_ref=None, error_kind="malformed"),
            "malformed_response",
            "none",
        ),
        (_meta(http_status=401), "auth_error", "live"),
        (_meta(http_status=403), "auth_error", "live"),
        (_meta(http_status=429), "rate_limited", "live"),
        (_meta(http_status=500), "api_error", "live"),
        (_meta(http_status=503), "api_error", "live"),
    )
    for metadata, cause, mode in cases:
        result = normalize_response(query, None, metadata)
        assert result.status == "unavailable", (cause, result)
        assert result.reason is not None and result.reason.split(":", 1)[0].strip() == cause
        assert result.evidence == []
        assert result.mode == mode
        assert result.response_sha256 is None if metadata.response_ref is None else True


def test_normalizer_graphql_auth_required_payload_is_auth_error() -> None:
    """Real observed shape: HTTP 200 with errors[0].name == AUTH_REQUIRED
    (demo token reset/expired). Only a provider-declared auth error maps
    to auth_error; a generic GraphQL error stays api_error."""

    query = _domain_observable("thetollroads-paytollth.xin")
    auth_body = {
        "errors": [
            {
                "message": "You must be logged in to do this.",
                "name": "AUTH_REQUIRED",
                "extensions": {"code": "AUTH_REQUIRED", "data": {"http_status": 401}},
            }
        ],
        "data": {"stixCyberObservables": None},
    }
    result = normalize_response(query, auth_body, _meta(http_status=200))
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.split(":", 1)[0].strip() == "auth_error"
    assert result.evidence == []

    declared_status_body = {
        "errors": [{"message": "nope", "extensions": {"data": {"http_status": 403}}}],
        "data": None,
    }
    result = normalize_response(query, declared_status_body, _meta(http_status=200))
    assert result.status == "unavailable"
    assert result.reason is not None and "auth_error" in result.reason

    generic_body = {
        "errors": [{"message": "Bad request", "name": "BAD_USER_INPUT"}],
        "data": None,
    }
    result = normalize_response(query, generic_body, _meta(http_status=200))
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.split(":", 1)[0].strip() == "api_error"
    assert result.evidence == []


def test_normalizer_malformed_bodies_are_never_evidence() -> None:
    query = _domain_observable("thetollroads-paytollth.xin")
    malformed: list[object] = [
        None,
        [],
        {},
        {"data": None},
        {"data": {}},
        {"data": {"stixCyberObservables": None}},
        {"data": {"stixCyberObservables": {"edges": "not-a-list"}}},
        {"data": {"stixCyberObservables": {"edges": [None]}}},
        {"data": {"stixCyberObservables": {"edges": [{"node": "x"}]}}},
    ]
    for body in malformed:
        result = normalize_response(query, body, _meta(http_status=200))  # type: ignore[arg-type]
        assert result.status == "unavailable", body
        assert result.reason is not None and result.reason.split(":", 1)[0].strip() in (
            "malformed_response",
            "api_error",
        )
        assert result.evidence == []


# ---------------------------------------------------------------------------
# Local exact comparison: search results are never taken at face value
# ---------------------------------------------------------------------------


def test_exact_match_requires_local_type_and_value_not_first_result() -> None:
    value = "thetollroads-paytollth.xin"
    query = _domain_observable(value)
    body = _graphql_body(
        # index 0: fuzzy hit with the right value but the WRONG entity type
        _node("Software", value, objectLabel=[{"value": "should-not-be-used"}]),
        # index 1: right type, different value
        _node("Domain-Name", "thetollroads-paytollau.xin"),
        # index 2: the real exact candidate
        _node(
            "Domain-Name",
            value,
            objectLabel=[{"value": "domain spoofing"}, {"value": "e-zpass"}],
            x_opencti_score=50,
        ),
    )
    result = normalize_response(query, body, _meta())
    assert result.status == "ok"
    exact = [e for e in result.evidence if e.predicate == "cti_exact_match"]
    assert len(exact) == 1
    assert exact[0].match_level == "EXACT" and exact[0].value is True
    assert exact[0].source_ref.endswith("#/data/stixCyberObservables/edges/2/node")
    label_values = [e.value for e in result.evidence if e.predicate == "cti_label"]
    assert label_values == ["domain spoofing", "e-zpass"]
    assert "should-not-be-used" not in label_values
    scores = [e.value for e in result.evidence if e.predicate == "cti_score"]
    assert scores == [50.0]
    assert all(e.provenance == "OSINT" and e.source_kind == "opencti" for e in result.evidence)


def test_no_exact_candidate_is_not_found_never_an_arbitrary_pick() -> None:
    value = "thetollroads-paytollth.xin"
    query = _domain_observable(value)
    fuzzy = _graphql_body(
        _node("Domain-Name", "thetollroads-paytollzxh.world"),
        _node("Email-Addr", "someone@example.org"),
        _node("Software", value),  # right value, wrong type: NOT an exact match
    )
    result = normalize_response(query, fuzzy, _meta())
    assert result.status == "not_found"
    assert result.reason is not None and "no_exact_match" in result.reason
    assert result.evidence == []

    empty = normalize_response(
        query, {"data": {"stixCyberObservables": {"edges": []}}}, _meta()
    )
    assert empty.status == "not_found"
    assert empty.reason is None
    assert empty.evidence == []


def test_near_miss_values_never_become_exact_match() -> None:
    known = "thetollroads-paytollth.xin"
    near = _near_miss_domain(known)
    assert near != known

    cases: list[tuple[Observable, dict[str, Any]]] = [
        (_domain_observable(near), _graphql_body(_node("Domain-Name", known))),
        (
            _obs("url", "https://example.com/a"),
            _graphql_body(_node("Url", "https://example.com/b")),
        ),
        (
            _obs("ipv4", "93.184.216.34"),
            _graphql_body(_node("IPv4-Addr", "93.184.216.35")),
        ),
        (
            _obs("sha256", "a" * 64),
            _graphql_body(_node("StixFile", "file", hashes=[{"algorithm": "SHA-256", "hash": "b" * 64}])),
        ),
    ]
    for query, body in cases:
        result = normalize_response(query, body, _meta())
        assert result.status == "not_found", (query.type, query.value)
        assert result.evidence == []
        assert not candidate_matches(query, body["data"]["stixCyberObservables"]["edges"][0]["node"])


def test_positive_local_comparators_by_type() -> None:
    domain = _obs("domain", "TheTollRoads-PayTollTH.XIN")
    assert candidate_matches(domain, _node("Domain-Name", "thetollroads-paytollth.xin"))
    assert not candidate_matches(domain, _node("Hostname", "thetollroads-paytollth.xin"))

    ip = _obs("ipv6", "2001:4860:4860:0000:0000:0000:0000:8888")
    assert candidate_matches(ip, _node("IPv6-Addr", "2001:4860:4860::8888"))
    assert not candidate_matches(ip, _node("IPv6-Addr", "2001:4860:4860::8889"))

    url = _obs("url", "https://example.com/Path")
    assert candidate_matches(url, _node("Url", "https://example.com/Path"))
    assert not candidate_matches(url, _node("Url", "https://example.com/path"))


def test_hash_comparator_algorithm_and_value() -> None:
    digest = "AB" * 32  # uppercase SHA-256
    file_node = _node(
        "StixFile",
        "file.bin",
        hashes=[
            {"algorithm": "SHA-256", "hash": digest},
            {"algorithm": "SHA-1", "hash": "cd" * 20},
        ],
    )
    assert candidate_matches(_obs("sha256", digest.lower()), file_node)
    assert candidate_matches(_obs("sha1", "CD" * 20), file_node)
    assert not candidate_matches(_obs("md5", "ef" * 16), file_node)
    assert not candidate_matches(_obs("sha256", "b" * 64), file_node)
    assert not candidate_matches(_obs("sha256", digest.lower()), _node("Software", "file.bin"))

    artifact_node = _node(
        "Artifact", "raw", hashes=[{"algorithm": "MD5", "hash": "ef" * 16}]
    )
    assert candidate_matches(_obs("md5", "EF" * 16), artifact_node)

    # malformed hash entries are ignored, never treated as matches
    malformed = _node("StixFile", "f", hashes=[None, {"algorithm": "SHA-256"}, {"hash": digest}])
    assert not candidate_matches(_obs("sha256", digest.lower()), malformed)


def test_missing_fields_stay_absent() -> None:
    value = "thetollroads-paytollth.xin"
    result = normalize_response(
        _domain_observable(value), _graphql_body(_node("Domain-Name", value)), _meta()
    )
    assert result.status == "ok"
    predicates = {e.predicate for e in result.evidence}
    assert predicates == {"cti_exact_match"}
    assert result.response_ref == "opencti_test_capture.json"
    assert result.response_sha256 == "a" * 64

    zero_score = normalize_response(
        _domain_observable(value),
        _graphql_body(_node("Domain-Name", value, x_opencti_score=None, objectLabel=[])),
        _meta(),
    )
    assert [e.predicate for e in zero_score.evidence] == ["cti_exact_match"]
    # a boolean is not a numeric score
    bool_score = normalize_response(
        _domain_observable(value),
        _graphql_body(_node("Domain-Name", value, x_opencti_score=True)),
        _meta(),
    )
    assert [e.predicate for e in bool_score.evidence] == ["cti_exact_match"]

    refs = normalize_response(
        _domain_observable(value),
        _graphql_body(
            _node(
                "Domain-Name",
                value,
                externalReferences={
                    "edges": [
                        {"node": {"url": "https://feed.example/1"}},
                        {"node": {"source_name": "feed-two"}},
                        {"node": {}},
                    ]
                },
            )
        ),
        _meta(),
    )
    ref_values = [e.value for e in refs.evidence if e.predicate == "cti_external_reference"]
    assert ref_values == ["https://feed.example/1", "feed-two"]


def test_revoked_is_never_fabricated() -> None:
    """The observed schema has no ``revoked`` field on StixCyberObservable;
    the adapter never emits cti_revoked for an SCO, even if a stray field
    appears in a body."""

    value = "thetollroads-paytollth.xin"
    result = normalize_response(
        _domain_observable(value),
        _graphql_body(_node("Domain-Name", value, revoked=True)),
        _meta(),
    )
    assert all(e.predicate != "cti_revoked" for e in result.evidence)
    assert "revoked" not in OPENCTI_PROJECTION


# ---------------------------------------------------------------------------
# Projection, read-only guard, dependency gate
# ---------------------------------------------------------------------------


def test_projection_is_bounded_and_passed_to_the_search(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for required in ("id", "standard_id", "entity_type", "created_at", "updated_at",
                     "objectLabel", "externalReferences", "observable_value",
                     "x_opencti_score", "... on DomainName", "... on StixFile", "hashes"):
        assert required in OPENCTI_PROJECTION, required
    for forbidden in ("toStix", "createdBy", "objectMarking", "indicators", "*"):
        assert forbidden not in OPENCTI_PROJECTION, forbidden

    calls: list[dict[str, Any]] = []

    class _FakeObservableApi:
        def list(self, **kwargs: Any) -> list[dict[str, Any]]:
            calls.append(kwargs)
            return []

    class _FakeClient:
        def __init__(self) -> None:
            self.stix_cyber_observable = _FakeObservableApi()
            self.session: object = None

    value = "thetollroads-paytollth.xin"
    body = _graphql_body(_node("Domain-Name", value)).copy()
    body_bytes = json.dumps(body).encode("utf-8")

    def _fake_run_graphql(settings: Settings, operation: Any, timeout_s: float) -> Any:
        fake = _FakeClient()
        operation(fake)
        assert fake.session is None  # not used by the fake path
        return opencti_module._Exchange(
            http_status=200, content=body_bytes, headers={}, request_count=1
        )

    monkeypatch.setattr(opencti_module, "_run_graphql", _fake_run_graphql)
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 30.0,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_domain_observable(value), context)
    assert result.status == "ok"
    assert len(calls) == 1
    assert calls[0]["search"] == value
    assert calls[0]["first"] == tools_config.opencti.first == 10
    assert calls[0]["getAll"] is False
    assert calls[0]["customAttributes"] == OPENCTI_PROJECTION


def test_read_only_guard_refuses_mutations_before_emission(tools_config: ToolsConfig) -> None:
    assert_read_only_query("query { about { version } }")
    assert_read_only_query("{ about { version } }")
    for bad in (
        'mutation { deleteEverything }',
        'mutation Delete($id: ID!) { stixCyberObservableEdit(id: $id) { delete } }',
        'subscription { stixCyberObservable }',
        'query A { x } mutation B { y }',
        "",
    ):
        with pytest.raises(OpenCTIReadOnlyViolation):
            assert_read_only_query(bad)
    with pytest.raises(OpenCTIReadOnlyViolation):
        opencti_module._opencti_query_exchange(
            _placeholder_settings(), "mutation { deleteEverything }", 5.0
        )


def test_no_mutation_creation_update_paths_in_adapter_source() -> None:
    source = inspect.getsource(opencti_module)
    for forbidden in (
        ".create(",
        ".delete(",
        ".upload(",
        ".add(",
        "stix2.",
        "stixCyberObservableEdit",
        "stixCyberObservableAdd",
        "stixCyberObservableDelete",
        "file_upload",
    ):
        assert forbidden not in source, forbidden


def test_pycti_missing_is_explicit_unavailable(
    tools_config: ToolsConfig, approved_context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(opencti_module, "_pycti_available", lambda: False)
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), approved_context)
    assert result.status == "unavailable"
    assert result.reason is not None and "api_error" in result.reason
    assert "pycti" in result.reason
    assert result.requests_sent == 0

    observation = adapter.observe_version_and_schema(approved_context)
    assert observation["status"] == "unavailable"
    assert observation["cause"] == "api_error"


def test_observe_version_and_schema_unconfigured(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext
) -> None:
    """Same ordering for the diagnostic path: token absent + no service
    approval => unavailable/not_configured, zero requests."""

    adapter = OpenCTIAdapter(settings_no_secrets, tools_config.opencti)
    observation = adapter.observe_version_and_schema(lookup_context)
    assert observation["status"] == "unavailable"
    assert observation["cause"] == "not_configured"
    assert observation["requests_sent"] == 0


def test_contract_gate_ordering_token_then_service_approval(
    tools_config: ToolsConfig,
    settings_no_secrets: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Frozen contract order (docs/contracts.md §2.7/§2.7.1), identical for
    ``lookup`` and ``observe_version_and_schema``:

    A) token absent + ``approved_services=[]`` => ``unavailable/not_configured``;
    B) token present + ``approved_services=[]`` => ``skipped/privacy_policy``;
    C) token present + ``opencti`` approved => existing normal path unchanged
    (controlled error object; no real call).

    The service-approval check still always precedes any provider request.
    """

    def _forbidden(*args: object, **kwargs: object) -> object:
        pytest.fail("transport must never be reached without token + service approval")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _forbidden)

    def _context(egress: EgressConfig) -> ToolContext:
        return ToolContext(
            run_id=str(uuid.uuid4()),
            source_profile="fixture",
            deadline=time.monotonic() + 60.0,
            egress=egress,
            capture_dir=tmp_path / "captures",
            mode="live",
        )

    unapproved = EgressConfig(allow_real_urls=False)
    query = _domain_observable("thetollroads-paytollth.xin")

    # A) token absent + no approval => not_configured (contract §2.7)
    no_key = OpenCTIAdapter(settings_no_secrets, tools_config.opencti)
    result_a = no_key.lookup(query, _context(unapproved))
    assert result_a.status == "unavailable"
    assert result_a.reason == "not_configured"
    assert result_a.requests_sent == 0
    observation_a = no_key.observe_version_and_schema(_context(unapproved))
    assert observation_a["status"] == "unavailable"
    assert observation_a["cause"] == "not_configured"
    assert observation_a["requests_sent"] == 0

    # B) token present + no approval => privacy_policy, zero requests, no capture
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    result_b = adapter.lookup(query, _context(unapproved))
    assert result_b.status == "skipped"
    assert result_b.reason == "privacy_policy: service_not_approved_in_egress"
    assert result_b.requests_sent == 0
    observation_b = adapter.observe_version_and_schema(_context(unapproved))
    assert observation_b["status"] == "skipped"
    assert observation_b["reason"] == "privacy_policy: service_not_approved_in_egress"
    assert observation_b["requests_sent"] == 0
    assert not (tmp_path / "captures").exists()

    # C) token + approval => the normal path reaches the transport
    def _controlled_timeout(*args: object, **kwargs: object) -> object:
        raise OpenCTITransportError("timeout", "controlled timeout object (no provider call)")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _controlled_timeout)
    result_c = adapter.lookup(query, _context(_approved_egress()))
    assert result_c.status == "unavailable"
    assert result_c.reason is not None and "timeout" in result_c.reason
    assert result_c.requests_sent == 1


# ---------------------------------------------------------------------------
# Egress / privacy rules (zero requests on refusal)
# ---------------------------------------------------------------------------


def test_service_approval_required_for_all_observable_types(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OpenCTI is an external third party for EVERY observable type:
    domains, hashes and public IPs are refused with skipped/privacy_policy,
    ZERO requests and no provider capture while
    ``egress.approved_services == []``. The transport is never reached."""

    def _forbidden(*args: object, **kwargs: object) -> object:
        pytest.fail("transport must never be reached without service approval")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _forbidden)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=EgressConfig(allow_real_urls=False),  # safe default: no approval
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    assert service_send_refusal(context.egress) == "service_not_approved_in_egress"
    for obs_type, value in (
        ("domain", "thetollroads-paytollth.xin"),
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("ipv4", "93.184.216.34"),
        ("ipv6", "2001:4860:4860::8888"),
    ):
        result = adapter.lookup(_obs(obs_type, value), context)
        assert result.status == "skipped", (obs_type, value)
        assert result.reason == "privacy_policy: service_not_approved_in_egress", (obs_type, value)
        assert result.requests_sent == 0
        assert result.mode == "none"
        assert result.evidence == []
        assert result.response_ref is None and result.response_sha256 is None
    assert not context.capture_dir.exists()  # no provider capture was written


def test_observe_version_requires_service_approval(
    tools_config: ToolsConfig, lookup_context: ToolContext
) -> None:
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    observation = adapter.observe_version_and_schema(lookup_context)
    assert observation["status"] == "skipped"
    assert observation["reason"] == "privacy_policy: service_not_approved_in_egress"
    assert observation["requests_sent"] == 0
    assert not lookup_context.capture_dir.exists()


def test_url_privacy_refusals_zero_requests(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    """With the OpenCTI service approved, every URL-specific control still
    applies (service approval is necessary but NOT sufficient). Refusals
    precede the transport: zero requests, no capture."""

    egress = _approved_egress(allow_real_urls=False)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=egress,
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    refusals: dict[str, set[str]] = {
        "https://user:pass@example.com/": {"userinfo_present"},
        "https://example.com/?token=abcdef": {"credential_like_parameter"},
        "https://example.com/reset-password": {"action_effect_url"},
        "https://example.com/track?email=user@example.com": {"personal_identifier"},
        "http://localhost/admin": {"internal_or_reserved_host"},
        "https://service.test/": {"internal_or_reserved_host"},
        "https://10.0.0.5/x": {"non_global_ip"},
        "ftp://example.com/file": {"scheme_not_http_s"},
    }
    for url, expected in refusals.items():
        refusal = url_send_refusal(url, egress)
        assert refusal in expected, (url, refusal)
        result = adapter.lookup(_obs("url", url, roles=["link_target"]), context)
        assert result.status == "skipped", url
        assert result.reason is not None and "privacy_policy" in result.reason
        assert result.requests_sent == 0

    # a flawless URL is still refused while allow_real_urls=false
    clean = adapter.lookup(
        _obs("url", "https://example.com/normal-page", roles=["link_target"]), context
    )
    assert clean.status == "skipped"
    assert clean.reason == "privacy_policy: egress_allow_real_urls_false"
    assert clean.requests_sent == 0


def test_url_requires_exact_host_approval_after_service_approval(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    """Service approval + allow_real_urls is still not enough: the exact URL
    host must be operator-approved too, and URL flaws always refuse."""

    egress = _approved_egress(allow_real_urls=True)  # no approved exact host
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=egress,
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    result = adapter.lookup(
        _obs("url", "https://example.com/normal-page", roles=["link_target"]), context
    )
    assert result.status == "skipped"
    assert result.reason == "privacy_policy: exact_url_host_not_approved"
    assert result.requests_sent == 0

    # even with the exact host approved, a URL flaw refuses first
    egress_full = egress.model_copy(update={"approved_exact_url_hosts": ["example.com"]})
    context.egress = egress_full
    flawed = adapter.lookup(
        _obs("url", "https://example.com/?token=abcdef", roles=["link_target"]), context
    )
    assert flawed.status == "skipped"
    assert flawed.reason == "privacy_policy: credential_like_parameter"
    assert flawed.requests_sent == 0


def test_url_lookup_refused_by_default_egress_policy(
    tools_config: ToolsConfig, lookup_context: ToolContext
) -> None:
    """Token present + default egress (no service approval): even a clean
    URL is refused at the service-approval gate before any URL control."""

    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    result = adapter.lookup(
        _obs("url", "https://example.com/normal-page", roles=["link_target"]), lookup_context
    )
    assert result.status == "skipped"
    assert result.reason == "privacy_policy: service_not_approved_in_egress"
    assert result.requests_sent == 0


def test_approved_egress_url_reaches_transport(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With an explicitly approved URL host/service the egress gate opens:
    the controlled transport error object then proves the request path was
    reached (no real call)."""

    def _controlled_timeout(*args: object, **kwargs: object) -> object:
        raise OpenCTITransportError("timeout", "controlled timeout object (no provider call)")

    monkeypatch.setattr(opencti_module, "_opencti_list_exchange", _controlled_timeout)
    egress = EgressConfig(
        allow_real_urls=True,
        approved_services=["opencti"],
        approved_exact_url_hosts=["example.com"],
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 30.0,
        egress=egress,
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    adapter = OpenCTIAdapter(_placeholder_settings(), tools_config.opencti)
    result = adapter.lookup(
        _obs("url", "https://example.com/normal-page", roles=["link_target"]), context
    )
    assert result.status == "unavailable"
    assert result.reason is not None and "timeout" in result.reason
    assert result.requests_sent == 1

    not_approved = egress.model_copy(update={"approved_services": ["virustotal"]})
    context.egress = not_approved
    refused = adapter.lookup(
        _obs("url", "https://example.com/normal-page", roles=["link_target"]), context
    )
    assert refused.status == "skipped"
    assert refused.reason == "privacy_policy: service_not_approved_in_egress"
    assert refused.requests_sent == 0


# ---------------------------------------------------------------------------
# Capture (exact bytes + provenance, never key material)
# ---------------------------------------------------------------------------


def test_capture_writes_exact_bytes_and_metadata_without_keys(tmp_path: Path) -> None:
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    query = _domain_observable("thetollroads-paytollth.xin")
    raw = b'{"data": {"stixCyberObservables": {"edges": []}}}'
    metadata = ResponseMetadata(
        origin="https://demo.opencti.io",
        http_status=200,
        response_date="Fri, 19 Sep 2026 10:00:00 GMT",
        response_sha256=hashlib.sha256(raw).hexdigest(),
    )
    ref = opencti_module._archive_response(context, query, raw, metadata)
    body_path = context.capture_dir / ref
    assert body_path.read_bytes() == raw
    meta = json.loads(
        (context.capture_dir / f"{Path(ref).stem}.meta.json").read_text(encoding="utf-8")
    )
    assert meta["response_sha256"] == hashlib.sha256(raw).hexdigest()
    assert meta["http_status"] == 200
    assert meta["tool"] == "opencti"
    assert meta["query"]["normalized_value"] == "thetollroads-paytollth.xin"
    serialized = json.dumps(meta)
    for forbidden in ("OPENCTI_API_KEY", "Authorization", "Bearer", "placeholder"):
        assert forbidden not in serialized


# ---------------------------------------------------------------------------
# Frozen schema conformance
# ---------------------------------------------------------------------------


def test_toolresult_conforms_to_frozen_schema() -> None:
    value = "thetollroads-paytollth.xin"
    query = _domain_observable(value)
    ok = normalize_response(
        query,
        _graphql_body(
            _node(
                "Domain-Name",
                value,
                objectLabel=[{"value": "domain spoofing"}],
                x_opencti_score=50,
                externalReferences={"edges": [{"node": {"url": "https://feed.example/1"}}]},
            )
        ),
        _meta(),
    )
    not_found = normalize_response(query, _graphql_body(), _meta())
    unavailable = normalize_response(query, None, _meta(http_status=429))
    for result in (ok, not_found, unavailable):
        dump = result.model_dump(mode="json")
        errors = _schema_validate(dump, SCHEMA["$defs"]["ToolResult"], root=SCHEMA)
        assert errors == [], (result.status, errors)
        for evidence in dump["evidence"]:
            assert _schema_validate(evidence, SCHEMA["$defs"]["Evidence"], root=SCHEMA) == []


# ---------------------------------------------------------------------------
# Minimal local JSON-Schema checker for the frozen triage_report $defs.
# src/llm.validate_against_schema does not support list-typed "type" (it is
# out of FILES ALLOWED for this ticket), so the test carries its own.
# ---------------------------------------------------------------------------


def _schema_validate(value: Any, schema: dict[str, Any], root: dict[str, Any] | None = None) -> list[str]:
    root = root or schema
    errors: list[str] = []
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target: Any = root
        for part in ref[2:].split("/"):
            target = target[part] if isinstance(target, dict) else None
        if not isinstance(target, dict):
            return [f"unresolved $ref {ref!r}"]
        return _schema_validate(value, target, root)

    expected = schema.get("type")
    if expected is not None:
        kinds = [expected] if isinstance(expected, str) else list(expected)
        checkers = {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "boolean": lambda v: isinstance(v, bool),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "null": lambda v: v is None,
        }
        if not any(checkers.get(kind, lambda v: True)(value) for kind in kinds):
            errors.append(f"expected one of {kinds}, got {type(value).__name__}")
            return errors
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and value not in enum_values:
        errors.append(f"value {value!r} not in enum")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
            errors.append(f"value {value} below minimum")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(
                f"unexpected property {key!r}" for key in value if key not in properties
            )
        for key, sub in properties.items():
            if key in value and isinstance(sub, dict):
                errors.extend(_schema_validate(value[key], sub, root))
        errors.extend(
            f"missing required property {key!r}"
            for key in schema.get("required", [])
            if key not in value
        )
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                errors.extend(_schema_validate(item, items, root))
    return errors


# ---------------------------------------------------------------------------
# Packaging regression: src.tools.opencti must ship in the wheel
# ---------------------------------------------------------------------------


def test_built_wheel_contains_and_installs_src_tools(tmp_path: Path) -> None:
    """A built wheel must include ``src.tools.opencti`` and it must import
    from an INSTALLED copy located OUTSIDE the repository checkout. No
    network: local wheel build and disk install only."""

    wheel_dir = tmp_path / "wheels"
    build = subprocess.run(
        [
            sys.executable, "-m", "pip", "wheel", str(PROJECT_ROOT),
            "--no-deps", "--no-build-isolation", "-w", str(wheel_dir), "--quiet",
        ],
        cwd=PROJECT_ROOT, capture_output=True, text=True, shell=False,
    )
    assert build.returncode == 0, build.stderr[-2000:]
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    names = zipfile.ZipFile(wheels[0]).namelist()
    assert "src/tools/__init__.py" in names
    assert "src/tools/opencti.py" in names

    target = tmp_path / "installed"
    install = subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--no-index", "--no-deps", "--target", str(target),
            str(wheels[0]), "--quiet",
        ],
        capture_output=True, text=True, shell=False,
    )
    assert install.returncode == 0, install.stderr[-2000:]

    probe_code = (
        "import src.tools, src.tools.opencti as cti\n"
        f"assert src.tools.__file__.startswith({str(target)!r})\n"
        f"assert cti.__file__.startswith({str(target)!r})\n"
        "assert hasattr(cti, 'OpenCTIAdapter') and hasattr(cti, 'assert_read_only_query')\n"
        "assert hasattr(cti, 'OPENCTI_PROJECTION')\n"
        "print('PACKAGED_OK')\n"
    )
    probe = subprocess.run(
        [sys.executable, "-c", probe_code],
        capture_output=True, text=True, shell=False,
        cwd=tmp_path,  # NOT the repository root
        env={**os.environ, "PYTHONPATH": str(target)},
    )
    assert probe.returncode == 0, probe.stderr[-2000:]
    assert "PACKAGED_OK" in probe.stdout


# ---------------------------------------------------------------------------
# Live: real instance — known exact match, real no-match, near-miss,
# observed version/schema, invalid-token (reset/expiry) path
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_opencti_real_instance(tmp_path: Path) -> None:
    """Run the REAL adapter against the configured instance; never skip.

    - Without a token: records the real unconfigured behavior (explicit
      unavailable, zero requests).
    - With a token: captures the observed version/schema, performs one REAL
      exact known match, one REAL no-match search, one REAL near-miss
      search and validates the near-miss against the REAL captured exact
      response locally. Assertions demand an exact match only because the
      operator precondition provides a known observable; nothing is
      fabricated when it is absent (limitation recorded instead).
    """

    out_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "opencti"
    out_dir.mkdir(parents=True, exist_ok=True)
    settings = load_settings(None)
    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    adapter = OpenCTIAdapter(settings, tools_config.opencti)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + tools_config.opencti.phase_timeout_s,
        egress=_tools_approved_egress(tools_config),
        capture_dir=out_dir,
        mode="live",
    )
    results: list[dict[str, object]] = []
    limitations: list[str] = []

    if settings.OPENCTI_API_KEY is None:
        result = adapter.lookup(
            _domain_observable("ticket07-unconfigured-probe.org"), context
        )
        results.append(result.model_dump(mode="json"))
        assert result.status == "unavailable"
        assert result.reason is not None and "not_configured" in result.reason
        assert result.requests_sent == 0
        (out_dir / "live_unconfigured_result.json").write_text(
            json.dumps(results[0], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print("live opencti: no token — real adapter returned explicit unavailable")
        return

    observation = adapter.observe_version_and_schema(context)
    assert observation["status"] == "ok", observation
    assert isinstance(observation["version"], str) and observation["version"]
    assert observation["revoked_on_stix_cyber_observable"] is False
    assert observation["hashes_on_stix_file"] is True
    limitations.append(
        "observed StixCyberObservable schema has no 'revoked' field: cti_revoked "
        "cannot be produced for cyber observables (nothing fabricated)"
    )
    (out_dir / "schema_observation.json").write_text(
        json.dumps(observation, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )

    known = settings.LIVE_CTI_KNOWN_VALUE
    known_type = settings.LIVE_CTI_KNOWN_TYPE
    exact_match_validated = False
    no_match_validated = False
    if known and known_type:
        known_query = _obs(known_type, known, source_ref="live:known_observable")
        known_result = adapter.lookup(known_query, context)
        results.append(known_result.model_dump(mode="json"))
        assert known_result.status == "ok", (known_result.status, known_result.reason)
        exact_evidence = [
            e
            for e in known_result.evidence
            if e.predicate == "cti_exact_match" and e.match_level == "EXACT" and e.value is True
        ]
        assert len(exact_evidence) == 1
        assert known_result.requests_sent == 1 and known_result.mode == "live"
        assert known_result.response_ref is not None
        capture_path = out_dir / known_result.response_ref
        raw = capture_path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == known_result.response_sha256
        captured_body = json.loads(raw.decode("utf-8"))
        pointer = exact_evidence[0].source_ref.split("#/", 1)[1]
        matched_node = _pointer_get(captured_body, pointer)
        assert isinstance(matched_node, dict)
        assert matched_node.get("value") == known
        exact_match_validated = True

        near = _near_miss_domain(known)
        near_query = _obs(known_type, near, source_ref="live:near_miss")
        # Local validator on the REAL captured exact response: the exact
        # known node must never satisfy the near-miss query.
        local_validator = normalize_response(
            near_query,
            captured_body,
            ResponseMetadata(
                origin=settings.OPENCTI_URL,
                http_status=200,
                response_date=known_result.collected_at,
                response_sha256=known_result.response_sha256,
                response_ref=known_result.response_ref,
            ),
        )
        assert local_validator.status == "not_found"
        assert local_validator.evidence == []

        near_result = adapter.lookup(near_query, context)
        results.append(near_result.model_dump(mode="json"))
        assert near_result.status in ("ok", "not_found")
        if near_result.status == "not_found":
            assert near_result.evidence == []
        else:
            assert any(e.predicate == "cti_exact_match" for e in near_result.evidence)
            assert near_result.response_ref is not None
            near_body = json.loads((out_dir / near_result.response_ref).read_bytes())
            near_nodes = [
                edge["node"]
                for edge in near_body["data"]["stixCyberObservables"]["edges"]
            ]
            assert any(node.get("value") == near for node in near_nodes)
    else:
        limitations.append(
            "LIVE_CTI_KNOWN_VALUE/LIVE_CTI_KNOWN_TYPE not configured: no real "
            "exact-match validation was possible (never fabricated)"
        )

    unknown = _unknown_sha256()
    unknown_result = adapter.lookup(
        _obs("sha256", unknown, roles=["attachment"], source_ref="live:unknown_hash"),
        context,
    )
    results.append(unknown_result.model_dump(mode="json"))
    assert unknown_result.status == "not_found", unknown_result
    assert unknown_result.evidence == []
    assert unknown_result.requests_sent == 1
    no_match_validated = True

    (out_dir / "live_result.json").write_text(
        json.dumps(
            {
                "results": results,
                "exact_match_validated": exact_match_validated,
                "no_match_validated": no_match_validated,
                "platform_version": observation["version"],
                "mutations_sent": 0,
                "limitations": limitations,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


@pytest.mark.live
def test_live_opencti_invalid_token_is_unavailable_auth_error(tmp_path: Path) -> None:
    """REAL exchange with a non-real placeholder token: the instance must be
    reported as ``unavailable/auth_error`` (demo reset/expired token path),
    never as a fabricated observation. The real response is archived."""

    out_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "opencti"
    out_dir.mkdir(parents=True, exist_ok=True)
    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    settings = load_settings(None)
    invalid = Settings(
        OPENCTI_URL=settings.OPENCTI_URL,
        OPENCTI_API_KEY=SecretStr(PLACEHOLDER_KEY),
    )
    adapter = OpenCTIAdapter(invalid, tools_config.opencti)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + tools_config.opencti.phase_timeout_s,
        egress=_tools_approved_egress(tools_config),
        capture_dir=out_dir,
        mode="live",
    )
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), context)
    assert result.status == "unavailable", result
    assert result.reason is not None and result.reason.split(":", 1)[0].strip() == "auth_error"
    assert result.evidence == []
    assert result.requests_sent == 1
    assert result.mode == "live"
    assert result.response_ref is not None  # the REAL provider response is kept
    (out_dir / "live_invalid_token_result.json").write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


@pytest.mark.live
def test_live_opencti_short_timeout_real_local_bound(tmp_path: Path) -> None:
    """REAL short timeout with the hard local bound: no fake server, no
    fabricated provider response. A reserved RFC 5737 documentation address
    is unreachable by design; only a local client timeout is observed.

    (``tmp_path`` captures: a timeout has no provider response to archive).
    """

    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    unreachable = Settings(
        OPENCTI_URL="https://192.0.2.1",
        OPENCTI_API_KEY=SecretStr(PLACEHOLDER_KEY),
    )
    adapter = OpenCTIAdapter(unreachable, tools_config.opencti)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 0.75,
        egress=_tools_approved_egress(tools_config),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    started = time.monotonic()
    result = adapter.lookup(_domain_observable("thetollroads-paytollth.xin"), context)
    elapsed = time.monotonic() - started
    assert result.status == "unavailable", result
    assert result.reason is not None and result.reason.split(":", 1)[0].strip() == "timeout"
    assert result.requests_sent == 1
    assert result.mode == "live"
    assert result.response_ref is None
    assert elapsed < 5.0

    out_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "opencti"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "live_timeout_result.json").write_text(
        json.dumps(
            {
                "result": result.model_dump(mode="json"),
                "elapsed_s": round(elapsed, 3),
                "method": (
                    "real client-side timeout within the hard local budget; "
                    "unreachable RFC 5737 address; no fake server, no fabricated response"
                ),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

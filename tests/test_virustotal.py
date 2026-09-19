"""VirusTotal adapter tests (TICKET-06, docs/tickets/TICKET-06.md, gate G4).

Non-live coverage (no network, no credentials):
- real adapter without key/rights → explicit ``unavailable`` with its cause
  and ZERO requests (never a skipped mandatory test);
- disabled tool → ``skipped``; unsupported observable types (sha1/md5/
  email/message_id/campaign_id) → ``skipped``/not_applicable, zero requests;
- deadline and local rate limiter gates (4/60 s, 500/day UTC journal);
- egress/privacy refusal rules for URLs (zero requests on refusal);
- endpoint mapping: the four GET endpoints only, ``vt.url_id`` for URLs,
  and a source invariant that no POST/scan/upload/download path exists;
- controlled error objects (timeout, connection failure, 401/403/429/404,
  corrupted bodies) fed to the real normalizer → deterministic causes, no
  evidence on any non-ok status (a corrupted copy can never become an
  enrichment or a metric);
- missing fields stay absent (no fabricated zeros), real denominator
  (engine_total sums every returned category), URL-response mismatch
  downgrades to GENERIC;
- ToolResult validation against the frozen triage_report schema;
- deterministic target plan (§1.6 priority, max_targets, no triple hash).

Live coverage (explicit ``--live``): the real adapter against the real
service when the environment provides the key and the authorization flag;
otherwise the SAME test records the real unconfigured behavior (explicit
unavailable, zero requests, vt_nominal_validated=false) and never skips.
"""

from __future__ import annotations

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

from src.config import (
    EgressConfig,
    Settings,
    ToolsConfig,
    load_settings,
    load_yaml_config,
)
from src.state import Link, Observable, ParsedEmail
from src.tools import ResponseMetadata, ToolContext
from src.tools import virustotal as vt_adapter_module
from src.tools.virustotal import (
    VTTransportError,
    VirusTotalAdapter,
    endpoint_for,
    normalize_response,
    plan_vt_targets,
    url_send_refusal,
)

import vt  # vt-py: the transport dependency of the adapter (TICKET-06 scope)

pytestmark = pytest.mark.g4

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads(
    (PROJECT_ROOT / "schemas" / "triage_report.schema.json").read_text(encoding="utf-8")
)

#: Placeholder credential for adapter tests. It is NOT a secret: it is a
#: synthetic non-real string used only to reach code paths past the key
#: gate, and it is never asserted to work against the real service.
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
def quota_journal(tmp_path: Path) -> Path:
    return tmp_path / "quota" / "virustotal.json"


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


def _sha256_observable(value: str, **overrides: Any) -> Observable:
    defaults: dict[str, Any] = {
        "id": "obs_sha256_test",
        "value": value,
        "normalized_value": value,
        "type": "sha256",
        "roles": ["attachment"],
        "provenance": "INTERNE",
        "source_ref": "part1:attachment",
    }
    defaults.update(overrides)
    return Observable(**defaults)


def _url_observable(url: str, source_ref: str, roles: list[str]) -> Observable:
    return Observable(
        id=f"obs_url_{abs(hash(url)) % 10**8}",
        value=url,
        normalized_value=url,
        type="url",
        roles=roles,  # type: ignore[arg-type]
        provenance="INTERNE",
        source_ref=source_ref,
    )


def _obs(obs_type: str, value: str, source_ref: str, roles: list[str]) -> Observable:
    return Observable(
        id=f"obs_{obs_type}_{abs(hash(value)) % 10**8}",
        value=value,
        normalized_value=value,
        type=obs_type,  # type: ignore[arg-type]
        roles=roles,  # type: ignore[arg-type]
        provenance="INTERNE",
        source_ref=source_ref,
    )


# ---------------------------------------------------------------------------
# Real adapter without key / without rights (mandatory, never skipped)
# ---------------------------------------------------------------------------


def test_lookup_without_key_is_explicit_unavailable_with_zero_requests(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext, quota_journal: Path
) -> None:
    adapter = VirusTotalAdapter(
        settings_no_secrets, tools_config.virustotal, quota_journal_path=quota_journal
    )
    result = adapter.lookup(_sha256_observable("a" * 64), lookup_context)
    assert result.status == "unavailable"
    assert result.reason is not None and "not_configured" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"
    assert result.evidence == [] and result.observables == []
    assert result.response_sha256 is None and result.response_ref is None


def test_lookup_with_key_but_unauthorized_is_explicit_access_not_authorized(
    tools_config: ToolsConfig, lookup_context: ToolContext, quota_journal: Path
) -> None:
    settings = Settings(VT_API_KEY=SecretStr(PLACEHOLDER_KEY))
    assert settings.VT_ACCESS_AUTHORIZED is False
    adapter = VirusTotalAdapter(settings, tools_config.virustotal, quota_journal_path=quota_journal)
    result = adapter.lookup(_sha256_observable("a" * 64), lookup_context)
    assert result.status == "unavailable"
    assert result.reason is not None and "access_not_authorized" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"


def test_disabled_tool_is_skipped_with_reason_and_zero_requests(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext, quota_journal: Path
) -> None:
    config = tools_config.virustotal.model_copy(update={"enabled": False})
    adapter = VirusTotalAdapter(settings_no_secrets, config, quota_journal_path=quota_journal)
    result = adapter.lookup(_sha256_observable("a" * 64), lookup_context)
    assert result.status == "skipped"
    assert result.reason is not None and "disabled" in result.reason
    assert result.requests_sent == 0


def test_unsupported_observable_types_are_skipped_not_applicable(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext, quota_journal: Path
) -> None:
    adapter = VirusTotalAdapter(settings_no_secrets, tools_config.virustotal, quota_journal_path=quota_journal)
    for obs_type in ("sha1", "md5", "email", "message_id", "campaign_id"):
        query = Observable(
            id=f"obs_{obs_type}",
            value="x" * 40,
            normalized_value="x" * 40,
            type=obs_type,  # type: ignore[arg-type]
            provenance="INTERNE",
            source_ref="test",
        )
        assert endpoint_for(query) is None, obs_type
        result = adapter.lookup(query, lookup_context)
        assert result.status == "skipped", obs_type
        assert result.reason is not None and "not_applicable" in result.reason
        assert result.requests_sent == 0


def test_expired_deadline_is_unavailable_deadline_with_zero_requests(
    tools_config: ToolsConfig, lookup_context: ToolContext, quota_journal: Path
) -> None:
    """With credentials configured, an expired deadline refuses the request
    before any send (zero requests). Unconfigured adapters answer
    not_configured first (request-dependent gates go first)."""

    lookup_context.deadline = time.monotonic() - 1.0
    adapter = VirusTotalAdapter(_authorized_settings(), tools_config.virustotal, quota_journal_path=quota_journal)
    result = adapter.lookup(_sha256_observable("a" * 64), lookup_context)
    assert result.status == "unavailable"
    assert result.reason is not None and "deadline" in result.reason
    assert result.requests_sent == 0


def test_near_deadline_returns_unavailable_deadline_without_sending(
    tools_config: ToolsConfig, tmp_path: Path, quota_journal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deterministic near-deadline regression (PR #9 blocker 2): when less
    than the minimal safe send budget remains, the lookup returns
    ``unavailable/deadline`` with ZERO requests — the transport is never
    reached and no doomed exchange may overrun the frozen deadline. No real
    VT request is made (controlled error object, fixed injected clock)."""

    def _forbidden(*args: object, **kwargs: object) -> tuple[int, bytes, dict]:
        pytest.fail("transport must never be reached when too little time remains")

    monkeypatch.setattr(vt_adapter_module, "_vt_get_raw", _forbidden)
    fixed_clock = 1000.0
    adapter = VirusTotalAdapter(
        _authorized_settings(),
        tools_config.virustotal,
        clock=lambda: fixed_clock,
        quota_journal_path=quota_journal,
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 0.3,  # 0.3 s remaining < minimal safe budget
        egress=EgressConfig(allow_real_urls=False),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_sha256_observable("a" * 64), context)
    assert result.status == "unavailable"
    assert result.reason is not None and "deadline" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"


def test_request_budget_is_exact_remaining_float_and_phase_capped(
    tools_config: ToolsConfig, tmp_path: Path, quota_journal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The request timeout is the EXACT remaining float budget — never
    rounded upward (old behavior: ceil + max(1, ...) + 2 s grace), and the
    phase_timeout_s cap still applies. Controlled timeout objects only; no
    real VT request."""

    captured: dict[str, float] = {}

    def _controlled_timeout(apikey: str, endpoint: str, timeout_s: float) -> tuple[int, bytes, dict]:
        captured["timeout_s"] = timeout_s
        raise VTTransportError("timeout", "controlled timeout object (no provider call)")

    monkeypatch.setattr(vt_adapter_module, "_vt_get_raw", _controlled_timeout)
    fixed_clock = 1000.0
    adapter = VirusTotalAdapter(
        _authorized_settings(),
        tools_config.virustotal,
        clock=lambda: fixed_clock,
        quota_journal_path=quota_journal,
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 10.25,  # would have been ceil'd to 11 before
        egress=EgressConfig(allow_real_urls=False),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_sha256_observable("e" * 64), context)
    assert captured["timeout_s"] == pytest.approx(10.25)  # exact float, never rounded up
    assert captured["timeout_s"] <= 10.25
    assert result.status == "unavailable"
    assert result.reason is not None and "timeout" in result.reason
    assert result.requests_sent == 1
    assert result.mode == "live"

    # Smaller phase_timeout_s wins over a longer remaining deadline.
    captured.clear()
    capped_config = tools_config.virustotal.model_copy(update={"phase_timeout_s": 2.5})
    capped_adapter = VirusTotalAdapter(
        _authorized_settings(),
        capped_config,
        clock=lambda: fixed_clock,
        quota_journal_path=quota_journal,
    )
    capped_context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 10.25,
        egress=EgressConfig(allow_real_urls=False),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    capped_result = capped_adapter.lookup(_sha256_observable("f" * 64), capped_context)
    assert captured["timeout_s"] == pytest.approx(2.5)  # min(remaining, phase budget)
    assert capped_result.status == "unavailable"


# ---------------------------------------------------------------------------
# Local rate limiter and quota journal (no wait, no request on refusal)
# ---------------------------------------------------------------------------


def _authorized_settings() -> Settings:
    """Placeholder-credential settings that pass the key/authorization gates.

    Used ONLY with a controlled transport error object (no provider call)
    or with a limiter refusal that precedes the transport.
    """

    return Settings(
        VT_API_KEY=SecretStr(PLACEHOLDER_KEY),
        VT_ACCESS_AUTHORIZED=True,
    )


def test_local_rate_limiter_blocks_after_limit_without_sending(
    tools_config: ToolsConfig, tmp_path: Path, quota_journal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """4 controlled transport errors (timeout objects) fill the window; the
    5th lookup is refused locally with zero requests (never waits)."""

    config = tools_config.virustotal.model_copy(update={"requests_per_minute": 4})

    def _controlled_timeout(*args: object, **kwargs: object) -> tuple[int, bytes, dict]:
        raise VTTransportError("timeout", "controlled timeout object (no provider call)")

    monkeypatch.setattr(vt_adapter_module, "_vt_get_raw", _controlled_timeout)
    adapter = VirusTotalAdapter(
        _authorized_settings(), config, quota_journal_path=quota_journal
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=EgressConfig(allow_real_urls=False),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    for attempt in range(1, 5):
        result = adapter.lookup(_sha256_observable("b" * 64), context)
        assert result.status == "unavailable" and "timeout" in (result.reason or ""), attempt
        assert result.requests_sent == 1, attempt
    fifth = adapter.lookup(_sha256_observable("c" * 64), context)
    assert fifth.status == "unavailable"
    assert fifth.reason is not None and "rate_limited" in fifth.reason
    assert fifth.requests_sent == 0
    data = json.loads(quota_journal.read_text(encoding="utf-8"))
    assert data["day_count"] == 4 and data["last_http_status"] is None


def test_daily_quota_exhaustion_blocks_without_sending(
    tools_config: ToolsConfig, tmp_path: Path, quota_journal: Path
) -> None:
    journal = quota_journal
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.write_text(
        json.dumps(
            {
                "day_utc": time.strftime("%Y-%m-%d", time.gmtime()),
                "day_count": 500,
                "window_requests_monotonic": [],
            }
        ),
        encoding="utf-8",
    )
    adapter = VirusTotalAdapter(
        _authorized_settings(),
        tools_config.virustotal,
        quota_journal_path=journal,
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=EgressConfig(allow_real_urls=False),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.lookup(_sha256_observable("d" * 64), context)
    assert result.status == "unavailable"
    assert result.reason is not None and "rate_limited" in result.reason
    assert result.requests_sent == 0


# ---------------------------------------------------------------------------
# Egress / privacy rules for URL and domain lookups (zero requests on refusal)
# ---------------------------------------------------------------------------


def test_url_privacy_refusals_zero_requests(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext, quota_journal: Path
) -> None:
    adapter = VirusTotalAdapter(settings_no_secrets, tools_config.virustotal, quota_journal_path=quota_journal)
    refusals: dict[str, set[str]] = {
        "https://user:pass@example.com/": {"userinfo_present"},
        "https://example.com/?token=abcdef": {"credential_like_parameter"},
        "https://example.com/?api_key=abcdef": {"credential_like_parameter"},
        "https://example.com/reset-password": {"action_effect_url"},
        "https://example.com/unsubscribe?mail=user@example.com": {
            "action_effect_url",
            "personal_identifier",
        },
        "https://example.com/track?email=user@example.com": {"personal_identifier"},
        "http://localhost/admin": {"internal_or_reserved_host"},
        "https://service.test/": {"internal_or_reserved_host"},
        "https://10.0.0.5/x": {"non_global_ip"},
        "ftp://example.com/file": {"scheme_not_http_s"},
    }
    for url, expected in refusals.items():
        refusal = url_send_refusal(url, lookup_context.egress)
        assert refusal in expected, (url, refusal)
        query = _url_observable(url, "part1:link:abc", ["link_target"])
        result = adapter.lookup(query, lookup_context)
        assert result.status == "skipped", url
        assert result.reason is not None and "privacy_policy" in result.reason
        assert result.requests_sent == 0


def test_url_lookup_refused_by_default_egress_policy(
    tools_config: ToolsConfig, settings_no_secrets: Settings, lookup_context: ToolContext, quota_journal: Path
) -> None:
    adapter = VirusTotalAdapter(settings_no_secrets, tools_config.virustotal, quota_journal_path=quota_journal)
    query = _url_observable("https://example.com/normal-page", "part1:link:abc", ["link_target"])
    result = adapter.lookup(query, lookup_context)
    assert result.status == "skipped"
    assert result.reason is not None and "privacy_policy" in result.reason
    assert result.requests_sent == 0


def test_egress_approved_url_reaches_transport_and_never_waits_on_timeout(
    tools_config: ToolsConfig, tmp_path: Path, quota_journal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approved path must hit the GET transport with the exact vt.url_id
    endpoint; a controlled timeout object maps to unavailable/timeout with
    exactly one request (no wait, no fabricated answer)."""

    captured: dict[str, Any] = {}

    def _controlled_timeout(apikey: str, endpoint: str, timeout_s: int) -> tuple[int, bytes, dict]:
        captured["apikey"] = apikey
        captured["endpoint"] = endpoint
        captured["timeout_s"] = timeout_s
        raise VTTransportError("timeout", "controlled timeout object (no provider call)")

    monkeypatch.setattr(vt_adapter_module, "_vt_get_raw", _controlled_timeout)
    adapter = VirusTotalAdapter(
        _authorized_settings(), tools_config.virustotal, quota_journal_path=quota_journal
    )
    egress = EgressConfig(
        allow_real_urls=True,
        approved_services=["virustotal"],
        approved_exact_url_hosts=["example.com"],
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=egress,
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    url = "https://example.com/normal-page"
    query = _url_observable(url, "part1:link:abc", ["link_target"])
    result = adapter.lookup(query, context)
    assert captured["endpoint"] == f"/urls/{vt.url_id(url)}"
    assert captured["timeout_s"] <= 20
    assert result.status == "unavailable"
    assert result.reason is not None and "timeout" in result.reason
    assert result.requests_sent == 1
    assert result.mode == "live"
    # The key exists only in the transport call, never in the context/result.
    assert captured["apikey"] == PLACEHOLDER_KEY
    assert not result.model_dump_json().count(PLACEHOLDER_KEY)


# ---------------------------------------------------------------------------
# Endpoint mapping and GET-only invariant
# ---------------------------------------------------------------------------


def test_endpoint_mapping_four_get_types_only() -> None:
    sha = "e" * 64
    url = "https://example.com/p"
    assert endpoint_for(_sha256_observable(sha)) == ("GET", f"/files/{sha}")
    assert endpoint_for(
        _obs("url", url, "s", ["link_target"])
    ) == ("GET", f"/urls/{vt.url_id(url)}")
    assert endpoint_for(
        _obs("domain", "Example.COM.", "s", ["sender"])
    ) == ("GET", "/domains/example.com")
    assert endpoint_for(
        _obs("ipv4", "93.184.216.34", "s", ["transport_ip"])
    ) == ("GET", "/ip_addresses/93.184.216.34")
    assert endpoint_for(
        _obs("ipv6", "2606:4700::1111", "s", ["transport_ip"])
    ) == ("GET", "/ip_addresses/2606:4700::1111")
    # Non-global IPs and every type without a frozen endpoint: refused.
    assert endpoint_for(_obs("ipv4", "10.0.0.9", "s", ["transport_ip"])) is None
    assert endpoint_for(_obs("ipv4", "203.0.113.7", "s", ["transport_ip"])) is None  # TEST-NET
    assert endpoint_for(_obs("ipv6", "2001:db8::1", "s", ["transport_ip"])) is None
    assert endpoint_for(_obs("domain", "corp.internal", "s", ["sender"])) is None
    assert endpoint_for(_obs("sha1", "a" * 40, "s", ["attachment"])) is None
    assert endpoint_for(_obs("md5", "b" * 32, "s", ["attachment"])) is None
    assert endpoint_for(_obs("email", "a@b.example", "s", ["sender"])) is None
    assert endpoint_for(_obs("message_id", "<x@y>", "s", [])) is None
    assert endpoint_for(_obs("campaign_id", "camp-1", "s", ["campaign_id"])) is None


def test_no_post_scan_upload_download_in_adapter() -> None:
    """GET-only invariant: the adapter source contains no vt-py POST/scan/
    upload/download path, and the transport is the only GET usage."""

    source = inspect.getsource(vt_adapter_module)
    for forbidden in (
        "post_async", "post_json", "post_object", ".post(",
        "scan_file", "scan_url", "download_file", "download_zip",
        "patch_async", "patch_object", "delete_async", ".delete(",
    ):
        assert forbidden not in source, forbidden
    assert "get_async" in source


# ---------------------------------------------------------------------------
# Normalizer: controlled error objects and missing fields (never fabricated)
# ---------------------------------------------------------------------------


def _meta(**overrides: Any) -> ResponseMetadata:
    return ResponseMetadata(origin="https://www.virustotal.com/api/v3", **overrides)


def test_normalizer_controlled_error_objects() -> None:
    query = _sha256_observable("a" * 64)
    cases = [
        (_meta(http_status=429), "unavailable", "rate_limited"),
        (_meta(http_status=401), "unavailable", "auth_error"),
        (_meta(http_status=403), "unavailable", "auth_error"),
        (_meta(http_status=500), "unavailable", "api_error"),
        (_meta(error_kind="timeout"), "unavailable", "timeout"),
        (_meta(error_kind="connection_error"), "unavailable", "api_error"),
        (_meta(error_kind="malformed"), "unavailable", "malformed_response"),
        (_meta(http_status=404), "not_found", None),
    ]
    for metadata, expected_status, expected_cause in cases:
        result = normalize_response(query, None, metadata=metadata)
        assert result.status == expected_status, metadata
        if expected_cause is None:
            assert result.reason is None
        else:
            assert result.reason == expected_cause
        assert result.evidence == []  # no benign-looking observation from errors
        assert result.observables == []


def test_normalizer_malformed_bodies_are_never_evidence() -> None:
    """A corrupted/controlled copy fed ONLY to the normalizer can never
    become an enrichment, an evidence or a metric (gates §5.2)."""

    query = _sha256_observable("a" * 64)
    for body in ([], "string", 42, {"error": {"code": "weird"}}, {}):
        result = normalize_response(query, body, _meta(http_status=200))  # type: ignore[arg-type]
        assert result.status == "unavailable"
        assert result.reason == "malformed_response"
        assert result.evidence == []
        assert result.observables == []


def test_normalizer_missing_fields_stay_absent_no_fabricated_zeros() -> None:
    query = _sha256_observable("a" * 64)
    body = {"data": {"attributes": {}}}
    result = normalize_response(query, body, _meta(http_status=200))
    assert result.status == "ok"
    assert result.evidence == []  # no fabricated 0/None observations
    body2 = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}
    result2 = normalize_response(query, body2, _meta(http_status=200))
    assert result2.status == "ok"
    by_predicate = {
        evidence.predicate: evidence.value for evidence in result2.evidence
    }
    assert set(by_predicate) == {"vt_malicious_count", "vt_engine_total"}
    assert by_predicate["vt_malicious_count"] == 3
    assert by_predicate["vt_engine_total"] == 3  # real denominator: sum of returned categories


def test_normalizer_real_denominator_includes_unknown_categories() -> None:
    query = _sha256_observable("a" * 64)
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 0,
                    "undetected": 62,
                    "timeout": 3,  # category without a dedicated predicate
                }
            }
        }
    }
    result = normalize_response(query, body, _meta(http_status=200))
    by_predicate = {
        evidence.predicate: evidence.value for evidence in result.evidence
    }
    assert by_predicate["vt_engine_total"] == 75  # 10+0+62+3, the REAL denominator
    assert by_predicate["vt_malicious_count"] == 10
    assert "vt_harmless_count" not in by_predicate  # absent stays absent


def test_normalizer_url_response_mismatch_downgrades_to_generic() -> None:
    query = _obs("url", "https://example.com/a", "s", ["link_target"])
    body = {
        "data": {
            "attributes": {
                "url": "https://other.example.net/b",
                "last_analysis_stats": {"malicious": 1, "harmless": 9},
            }
        }
    }
    result = normalize_response(query, body, _meta(http_status=200))
    assert result.status == "ok"
    assert result.reason == "url_response_mismatch"
    assert all(evidence.match_level == "GENERIC" for evidence in result.evidence)
    body_exact = {
        "data": {
            "attributes": {
                "url": "https://example.com/a",
                "last_analysis_stats": {"malicious": 1, "harmless": 9},
            }
        }
    }
    exact = normalize_response(query, body_exact, _meta(http_status=200))
    assert all(evidence.match_level == "EXACT" for evidence in exact.evidence)


def test_normalizer_non_integer_stats_is_malformed() -> None:
    query = _sha256_observable("a" * 64)
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": "many"}}}}
    result = normalize_response(query, body, _meta(http_status=200))
    assert result.status == "unavailable"
    assert result.reason == "malformed_response"
    assert result.evidence == []


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
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and any_of:
        if not any(not _schema_validate(value, variant, root) for variant in any_of):
            errors.append("does not match any variant of anyOf")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(
                f"unexpected property {key!r}"
                for key in value
                if key not in properties
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


def test_toolresult_conforms_to_frozen_schema() -> None:
    query = _sha256_observable("a" * 64)
    body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "harmless": 8},
                "last_analysis_date": 1758271000,
            }
        }
    }
    for result in (
        normalize_response(query, body, _meta(http_status=200)),
        normalize_response(query, None, _meta(http_status=429)),
    ):
        dump = result.model_dump(mode="json")
        errors = _schema_validate(dump, SCHEMA["$defs"]["ToolResult"], root=SCHEMA)
        assert errors == [], (result.status, errors)
        for evidence in dump["evidence"]:
            assert _schema_validate(evidence, SCHEMA["$defs"]["Evidence"], root=SCHEMA) == []


# ---------------------------------------------------------------------------
# Response capture (exact bytes + provenance, never key material)
# ---------------------------------------------------------------------------


def test_capture_writes_exact_bytes_and_metadata_without_keys(tmp_path: Path) -> None:
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 60.0,
        egress=EgressConfig(allow_real_urls=False),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    query = _sha256_observable("f" * 64)
    raw = b'{"data": {"attributes": {}}}'
    metadata = ResponseMetadata(
        origin="https://www.virustotal.com/api/v3",
        http_status=200,
        response_date="Fri, 19 Sep 2026 10:00:00 GMT",
        response_sha256="f" * 64,
    )
    ref = vt_adapter_module._archive_response(context, query, raw, metadata)
    body_path = context.capture_dir / ref
    assert body_path.read_bytes() == raw  # EXACT bytes preserved
    meta = json.loads(
        (context.capture_dir / f"{Path(ref).stem}.meta.json").read_text(encoding="utf-8")
    )
    assert meta["response_sha256"] == "f" * 64
    assert meta["http_status"] == 200
    assert meta["query"]["normalized_value"] == "f" * 64
    serialized = json.dumps(meta)
    assert "apikey" not in serialized.lower()
    assert "VT_API_KEY" not in serialized


# ---------------------------------------------------------------------------
# Deterministic target plan (internal data only, §1.6 priority)
# ---------------------------------------------------------------------------


def _link(
    link_id: str,
    part_id: str,
    url: str,
    role: str,
    *,
    mismatch: bool = False,
) -> Link:
    return Link(
        id=link_id,
        part_id=part_id,
        raw_value=url,
        normalized_value=url,
        role=role,  # type: ignore[arg-type]
        hostname="host.example.org",
        href_display_mismatch=mismatch,
    )


def _parsed_with_links(*links: Link) -> ParsedEmail:
    return ParsedEmail(
        email_sha256="0" * 64,
        raw_size_bytes=1,
        input_format="rfc822",
        links=list(links),
    )


def _target_ref(link: Link) -> str:
    """Same deterministic source_ref convention as the parser (§2.4)."""

    return f"{link.part_id}:link:{link.id[:16]}"


def test_plan_priority_and_remote_resource_exclusion() -> None:
    """Normative order: attachment SHA-256 → mismatch href/form URLs → other
    relevant href/visible/form/QR URLs in MIME order → sender/reply-to
    domains → eligible public IPs. A decorative remote_resource URL is
    never a target."""

    links = [
        _link("mism1234567890ab", "part1", "https://evil.example.org/1", "href", mismatch=True),
        _link("plain234567890abc", "part1", "https://plain.example.org/2", "href"),
        _link("img34567890abcd", "part1", "https://remote.example.org/img.png", "remote_resource"),
        _link("qr4567890abcde", "part1", "https://qr.example.org/scan", "qr_url"),
    ]
    parsed = _parsed_with_links(*links)
    observables = [
        _obs("domain", "newsletter-xyz.org", "headers:from", ["sender"]),
        _obs("url", "https://plain.example.org/2", _target_ref(links[1]), ["link_target"]),
        _obs("url", "https://evil.example.org/1", _target_ref(links[0]), ["link_target"]),
        _obs("url", "https://remote.example.org/img.png", _target_ref(links[2]), ["link_target"]),
        _obs("url", "https://qr.example.org/scan", _target_ref(links[3]), ["link_target"]),
        _obs("sha256", "a" * 64, "part2:attachment", ["attachment"]),
        _obs("sha1", "b" * 40, "part2:attachment", ["attachment"]),  # same file: never planned
        _obs("ipv4", "10.0.0.9", "header:5:received", ["transport_ip"]),  # private: refused
        _obs("ipv4", "93.184.216.34", "header:6:received", ["transport_ip"]),
    ]
    targets = plan_vt_targets(parsed, observables, max_targets=4)
    values = [target.normalized_value for target in targets]
    assert values == [
        "a" * 64,                          # SHA-256 attachment first
        "https://evil.example.org/1",      # href with display mismatch
        "https://plain.example.org/2",     # other relevant href, MIME order
        "https://qr.example.org/scan",     # QR URLs are eligible too
    ]
    assert "https://remote.example.org/img.png" not in values  # remote_resource NEVER planned
    assert "b" * 40 not in values          # no sha1 lookup for the same file
    assert "10.0.0.9" not in values        # private IP never planned
    assert "newsletter-xyz.org" not in values  # cap reached before domains/IPs


def test_plan_excludes_decorative_remote_resource_url() -> None:
    """Explicit regression: a decorative ``<img src=...>`` (Link.role ==
    'remote_resource') must never become a VT target — not even when it is
    the only URL in the email and the cap is large."""

    link = _link("imgonly123456789", "part1", "https://tracking-mx.org/pixel.png", "remote_resource")
    parsed = _parsed_with_links(link)
    url_only = [
        _obs("url", "https://tracking-mx.org/pixel.png", _target_ref(link), ["link_target"]),
    ]
    assert plan_vt_targets(parsed, url_only, max_targets=6) == []
    with_attachment = [
        _obs("sha256", "c" * 64, "part2:attachment", ["attachment"]),
        url_only[0],
    ]
    targets = plan_vt_targets(parsed, with_attachment, max_targets=6)
    assert [target.normalized_value for target in targets] == ["c" * 64]


def test_plan_domains_and_public_ips_reached_when_not_capped() -> None:
    """sender/reply-to domains are planned; return_path domains are not
    (normative plan), private IPs are refused, public IPs are eligible."""

    parsed = _parsed_with_links()  # no links → no URL eligible
    observables = [
        _obs("sha256", "a" * 64, "part1:attachment", ["attachment"]),
        _obs("domain", "corp-sender.org", "headers:from", ["sender"]),
        _obs("domain", "reply.example.net", "headers:reply-to", ["reply_to"]),
        _obs("domain", "bounce.mailfrom.org", "headers:return-path", ["return_path"]),
        _obs("ipv4", "10.0.0.9", "header:5:received", ["transport_ip"]),
        _obs("ipv4", "93.184.216.34", "header:6:received", ["transport_ip"]),
    ]
    targets = plan_vt_targets(parsed, observables, max_targets=6)
    values = [target.normalized_value for target in targets]
    assert values == [
        "a" * 64,
        "corp-sender.org",       # exact sender domain
        "reply.example.net",     # exact reply-to domain
        "93.184.216.34",         # public transport IP (private refused; cap allows)
    ]
    assert "bounce.mailfrom.org" not in values  # return_path: not a normative target


def test_plan_caps_at_max_targets_and_respects_mime_order() -> None:
    links = [
        _link(f"lid{i:013d}", "part1", f"https://host{i}.example.org/{i}", "href")
        for i in range(6)
    ]
    parsed = _parsed_with_links(*links)
    urls = [
        _obs("url", f"https://host{i}.example.org/{i}", _target_ref(links[i]), ["link_target"])
        for i in range(6)
    ]
    targets = plan_vt_targets(parsed, urls, max_targets=4)
    assert [target.normalized_value for target in targets] == [
        f"https://host{i}.example.org/{i}" for i in range(4)
    ]


def test_plan_excludes_recipients_and_emails() -> None:
    recipient = _obs("email", "victim@corp.example.net", "headers:to", ["recipient"])
    sender = _obs("email", "sender@corp.example.net", "headers:from", ["sender"])
    targets = plan_vt_targets(None, [recipient, sender], max_targets=4)
    assert targets == []  # no endpoint for email observables; recipients never IOC


# ---------------------------------------------------------------------------
# Packaging regression (PR #9 blocker 1): src.tools must ship in the wheel
# ---------------------------------------------------------------------------


def test_built_wheel_contains_and_installs_src_tools(tmp_path: Path) -> None:
    """A built wheel must include ``src.tools`` and ``src.tools.virustotal``,
    and they must import from an INSTALLED copy located OUTSIDE the
    repository checkout (never from the repo's ``src/``). No network: the
    wheel is built locally (``--no-deps --no-build-isolation``) and
    installed from disk (``--no-index --no-deps``)."""

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
    assert "src/tools/virustotal.py" in names

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

    # Import in a subprocess whose cwd/PYTHONPATH EXCLUDE the repository
    # checkout: the imported package must be the installed copy.
    probe_code = (
        "import src.tools, src.tools.virustotal as vt\n"
        f"assert src.tools.__file__.startswith({str(target)!r})\n"
        f"assert vt.__file__.startswith({str(target)!r})\n"
        "assert hasattr(vt, 'VirusTotalAdapter') and hasattr(vt, 'plan_vt_targets')\n"
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
# Live: real adapter against the real service (or explicit unavailable)
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_virustotal_real_adapter(tmp_path: Path) -> None:
    """Run the REAL adapter; never skip.

    - Without key/rights: records the real unconfigured behavior (explicit
      unavailable, cause, zero requests, vt_nominal_validated=false).
    - With key + authorization: performs REAL GET lookups (unknown hash
      probe; configured known hash when set), archives authentic captures
      under runs/gates/G4/virustotal/ and never fabricates an outcome.
    """

    out_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "virustotal"
    out_dir.mkdir(parents=True, exist_ok=True)
    settings = load_settings(None)
    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    adapter = VirusTotalAdapter(settings, tools_config.virustotal)
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + tools_config.virustotal.phase_timeout_s,
        egress=tools_config.egress,
        capture_dir=out_dir,
        mode="live",
    )

    configured = settings.VT_API_KEY is not None and settings.VT_ACCESS_AUTHORIZED
    unknown = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, real hash string
    results: list[dict[str, object]] = []
    vt_nominal_validated = False

    result = adapter.lookup(_sha256_observable(unknown), context)
    results.append(result.model_dump(mode="json"))
    if not configured:
        assert result.status == "unavailable"
        assert result.reason is not None and result.reason.split(":", 1)[0].strip() in (
            "not_configured",
            "access_not_authorized",
        )
        assert result.requests_sent == 0
        (out_dir / "live_unconfigured_result.json").write_text(
            json.dumps(results[0], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(
            "live virustotal: no key/rights — real adapter returned explicit "
            f"unavailable ({result.reason}); vt_nominal_validated=false"
        )
        return

    assert result.status in ("ok", "not_found", "unavailable"), result
    assert result.requests_sent == 1
    if result.status == "unavailable":
        assert result.reason is not None and result.reason.split(":", 1)[0].strip() in (
            "timeout",
            "rate_limited",
            "auth_error",
            "api_error",
            "deadline",
            "malformed_response",
        )

    known = settings.LIVE_VT_KNOWN_SHA256
    if known:
        known_result = adapter.lookup(_sha256_observable(known), context)
        results.append(known_result.model_dump(mode="json"))
        vt_nominal_validated = known_result.status == "ok"
        assert known_result.status in ("ok", "not_found", "unavailable")

    (out_dir / "live_result.json").write_text(
        json.dumps(
            {
                "results": results,
                "vt_nominal_validated": vt_nominal_validated,
                "limitations": []
                if vt_nominal_validated
                else ["no real known-hash ok response observed in this live run"],
                "post_requests_sent": 0,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

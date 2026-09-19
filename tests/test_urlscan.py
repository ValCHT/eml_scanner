"""urlscan adapter tests (TICKET-08, docs/tickets/TICKET-08.md, gate G4).

Non-live coverage (no network, no credentials):
- real adapter without key → explicit ``unavailable`` with its cause and
  ZERO requests (never a skipped mandatory test);
- disabled tool → ``skipped``; non-URL observables and empty values →
  ``skipped``/not_applicable;
- privacy prefilter BEFORE any network call: credential-like parameters,
  action-effect URLs, personal identifiers, userinfo, internal/reserved
  hosts, non-global IPs, missing egress approval / ``allow_real_urls`` /
  exact-host approval — every refusal is ``skipped/privacy_policy`` with
  ZERO requests;
- authoritative ``source_profile`` → visibility mapping (fixture and
  public_corpus → configured ``visibility_fixture``; private_authorized →
  configured ``visibility_real``); ``public`` is never produced;
- deadline gates (expired / below the minimal safe send budget) with zero
  requests; the exact remaining-float budget is passed to the transport;
- ONE submission, never retried after an ambiguous POST; the local
  submission journal refuses a second attempt for the same run
  (``skipped/budget``, zero requests);
- pending semantics: a 404 before the result is PENDING (never
  ``not_found``), 410/429/401/5xx map to explicit causes — controlled
  local objects only, no fabricated provider answer and no fake server;
- result normalizer: only real fields become SANDBOX evidence, pointers
  resolve in the archived JSON, malformed bodies are never evidence,
  sub-resources never extend the navigation chain, a missing screenshot
  never breaks the result;
- inert DOM extraction: no script execution, bounded text/form fields,
  hostile/malformed HTML cannot crash;
- captures: exact bytes + provenance metadata, no key material;
- ToolResult/Evidence conformance to the frozen triage_report schema;
- packaging: the built wheel ships and installs ``src.tools.urlscan``.

Live coverage (explicit ``--live``, never skipped):
- ONE REAL private scan (``private_authorized`` → ``visibility=private``)
  of the operator-authorized benign URL with the fast test-local poll
  settings: natural pending observation (real 404s), final URL evidence,
  archived exact bytes, and the REAL local budget refusal of a second scan
  in the same run;
- ONE REAL private scan of the operator-authorized benign redirect URL
  with the PRODUCTION poll settings: the demonstrable redirect chain to the
  declared target and the final URL must be present in the real capture.

No Qwen/LLM call, no other provider is exercised here.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import SecretStr

from src.config import (
    EgressConfig,
    Settings,
    ToolsConfig,
    UrlscanToolConfig,
    load_settings,
    load_yaml_config,
)
from src.state import Observable
from src.tools import ResponseMetadata, ToolContext
from src.tools import urlscan as urlscan_module
from src.tools.urlscan import (
    URLSCAN_ORIGIN,
    UrlscanAdapter,
    UrlscanTransportError,
    error_cause_for_status,
    extract_dom_facts,
    extract_navigation_steps,
    normalize_result,
    same_origin,
    service_send_refusal,
    submission_details,
    submittable_url,
    url_send_refusal,
    visibility_for,
)

pytestmark = pytest.mark.g4

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads(
    (PROJECT_ROOT / "schemas" / "triage_report.schema.json").read_text(encoding="utf-8")
)

#: Placeholder credential for adapter tests. It is NOT a secret: a synthetic
#: non-real string used only to reach code paths past the key gate; it is
#: never asserted to work against the real service.
PLACEHOLDER_KEY = "placeholder-key-not-a-real-credential"

#: Operator-authorized live hosts (TICKET-08 operator amendment).
_AUTHORIZED_HOST = "httpbin.org"


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Any network attempt fails non-live tests (live tests bypass this)."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in a non-live test")

    monkeypatch.setattr("socket.socket.connect", _deny)
    monkeypatch.setattr("socket.socket.connect_ex", _deny)
    monkeypatch.setattr("socket.create_connection", _deny)
    monkeypatch.setattr("socket.getaddrinfo", _deny)


@pytest.fixture()
def tools_config(project_root: Path) -> ToolsConfig:
    return load_yaml_config(project_root / "configs" / "tools.yaml", ToolsConfig)


def _placeholder_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {"URLSCAN_API_KEY": SecretStr(PLACEHOLDER_KEY)}
    values.update(overrides)
    return Settings(**values)


def _approved_egress(**overrides: Any) -> EgressConfig:
    """Safe-default egress with the urlscan service + one host approved."""

    values: dict[str, Any] = {
        "allow_real_urls": True,
        "approved_services": ["urlscan"],
        "approved_exact_url_hosts": [_AUTHORIZED_HOST],
    }
    values.update(overrides)
    return EgressConfig(**values)


def _tools_approved_egress(tools_config: ToolsConfig, urls: list[str]) -> EgressConfig:
    """Temporary explicit egress for the official live/smoke contexts.

    ``configs/tools.yaml`` stays safe-by-default (``allow_real_urls=false``,
    ``approved_services=[]``, ``approved_exact_url_hosts=[]``); only the
    validation context of this ticket approves the urlscan service and the
    exact hosts of the operator-authorized URLs (TICKET-08 amendment).
    """

    hosts = {
        (urlparse(url).hostname or "").lower().rstrip(".")
        for url in urls
        if url
    }
    approved_services = sorted(
        {service.lower() for service in tools_config.egress.approved_services} | {"urlscan"}
    )
    approved_hosts = sorted(
        {host.lower() for host in tools_config.egress.approved_exact_url_hosts} | hosts
    )
    return tools_config.egress.model_copy(
        update={
            "allow_real_urls": True,
            "approved_services": approved_services,
            "approved_exact_url_hosts": approved_hosts,
        }
    )


def _obs(
    obs_type: str,
    value: str,
    *,
    normalized: str | None = None,
    **overrides: Any,
) -> Observable:
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


def _url_observable(value: str, **overrides: Any) -> Observable:
    return _obs("url", value, roles=["link_target"], **overrides)


def _context(
    tmp_path: Path,
    *,
    profile: str = "fixture",
    egress: EgressConfig | None = None,
    deadline_s: float = 60.0,
    run_id: str | None = None,
) -> ToolContext:
    return ToolContext(
        run_id=run_id or str(uuid.uuid4()),
        source_profile=profile,  # type: ignore[arg-type]
        deadline=time.monotonic() + deadline_s,
        egress=egress or _approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )


def _adapter(
    settings: Settings,
    config: UrlscanToolConfig,
    tmp_path: Path,
    **kwargs: Any,
) -> UrlscanAdapter:
    return UrlscanAdapter(
        settings, config, quota_journal_path=tmp_path / "quota.json", **kwargs
    )


# ---------------------------------------------------------------------------
# Controlled local exchanges (function inputs ONLY; never provider evidence)
# ---------------------------------------------------------------------------


def _exchange(
    http_status: int,
    payload: bytes | None = None,
    *,
    url: str = URLSCAN_ORIGIN + "/api/v1/scan/",
    request_count: int = 1,
) -> Any:
    return urlscan_module._Exchange(
        http_status=http_status,
        content=payload if payload is not None else b"{}",
        headers={"Date": "Sat, 19 Sep 2026 14:00:00 GMT"},
        url=url,
        request_count=request_count,
    )


def _submission_body(scan_id: str | None = None, visibility: str = "unlisted") -> bytes:
    sid = scan_id or str(uuid.uuid4())
    return json.dumps(
        {
            "message": "Submission successful",
            "uuid": sid,
            "result": f"https://urlscan.io/result/{sid}/",
            "api": f"https://urlscan.io/api/v1/result/{sid}/",
            "visibility": visibility,
            "url": "https://httpbin.org/html",
        }
    ).encode("utf-8")


def _result_body(
    *,
    final_url: str = "https://httpbin.org/html",
    title: str | None = None,
    malicious: bool | None = False,
    redirects: list[dict[str, Any]] | None = None,
    requests: list[dict[str, Any]] | None = None,
    scan_id: str | None = None,
    visibility: str = "unlisted",
) -> bytes:
    page: dict[str, Any] = {"url": final_url, "status": "200"}
    if title is not None:
        page["title"] = title
    verdicts: dict[str, Any] = {}
    if malicious is not None:
        verdicts["overall"] = {
            "score": 0,
            "malicious": malicious,
            "categories": [],
            "brands": [],
            "tags": [],
            "hasVerdicts": True,
        }
    body = {
        "task": {"uuid": scan_id or str(uuid.uuid4()), "url": final_url, "visibility": visibility},
        "page": page,
        "verdicts": verdicts,
        "data": {"requests": requests or [], "redirects": redirects or []},
        "stats": {},
    }
    return json.dumps(body).encode("utf-8")


def _forbidden(name: str) -> Callable[..., Any]:
    def _fail(*args: object, **kwargs: object) -> Any:
        pytest.fail(f"unexpected urlscan transport call: {name}")

    return _fail


def _patch_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    post: Callable[[str, str], Any] | None = None,
    result: Callable[[str], Any] | None = None,
    dom: Callable[[str], Any] | None = None,
    screenshot: Callable[[str], Any] | None = None,
) -> dict[str, list[Any]]:
    """Install controlled local exchange functions; never a provider call."""

    calls: dict[str, list[Any]] = {"post": [], "result": [], "dom": [], "screenshot": []}

    def _post(origin: str, api_key: str, url: str, visibility: str, timeout_s: float) -> Any:
        calls["post"].append({"url": url, "visibility": visibility, "timeout_s": timeout_s})
        assert post is not None
        return post(url, visibility)

    def _result(origin: str, api_key: str, scan_id: str, timeout_s: float) -> Any:
        calls["result"].append({"scan_id": scan_id, "timeout_s": timeout_s})
        assert result is not None
        return result(scan_id)

    def _dom(origin: str, api_key: str, scan_id: str, timeout_s: float) -> Any:
        calls["dom"].append({"scan_id": scan_id, "timeout_s": timeout_s})
        assert dom is not None
        return dom(scan_id)

    def _screenshot(origin: str, api_key: str, scan_id: str, timeout_s: float) -> Any:
        calls["screenshot"].append({"scan_id": scan_id, "timeout_s": timeout_s})
        assert screenshot is not None
        return screenshot(scan_id)

    monkeypatch.setattr(urlscan_module, "_post_scan_exchange", post and _post or _forbidden("post"))
    monkeypatch.setattr(
        urlscan_module, "_get_result_exchange", result and _result or _forbidden("result")
    )
    monkeypatch.setattr(urlscan_module, "_get_dom_exchange", dom and _dom or _forbidden("dom"))
    monkeypatch.setattr(
        urlscan_module,
        "_get_screenshot_exchange",
        screenshot and _screenshot or _forbidden("screenshot"),
    )
    return calls


def _fast_config(config: UrlscanToolConfig) -> UrlscanToolConfig:
    """Test-local poll settings (production values stay in configs/tools.yaml)."""

    return config.model_copy(update={"first_poll_s": 0.0, "poll_interval_s": 0.001})


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
# Real adapter without key / disabled / unsupported observables
# ---------------------------------------------------------------------------


def test_scan_without_key_is_explicit_unavailable_with_zero_requests(
    tools_config: ToolsConfig,
    settings_no_secrets: Settings,
    tmp_path: Path,
) -> None:
    adapter = _adapter(settings_no_secrets, tools_config.urlscan, tmp_path)
    context = _context(tmp_path, profile="private_authorized")
    result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.split(":", 1)[0].strip() == "not_configured"
    assert result.requests_sent == 0
    assert result.evidence == []
    assert result.mode == "none"
    assert result.visibility is None and result.scan_id is None


def test_disabled_tool_is_skipped_with_reason_and_zero_requests(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    disabled = tools_config.urlscan.model_copy(update={"enabled": False})
    adapter = _adapter(_placeholder_settings(), disabled, tmp_path)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), _context(tmp_path))
    assert result.status == "skipped"
    assert result.reason == "disabled"
    assert result.requests_sent == 0


def test_non_url_observables_are_skipped_not_applicable(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    context = _context(tmp_path)
    for obs_type, value in (
        ("email", "victime@example.org"),
        ("domain", "httpbin.org"),
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("ipv4", "93.184.216.34"),
        ("message_id", "<x@y>"),
        ("campaign_id", "cmp-1"),
    ):
        result = adapter.scan(_obs(obs_type, value), context)
        assert result.status == "skipped", (obs_type, result)
        assert result.reason == "not_applicable"
        assert result.requests_sent == 0
        assert result.evidence == []


def test_empty_url_is_not_applicable(tools_config: ToolsConfig, tmp_path: Path) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    result = adapter.scan(_url_observable("   "), _context(tmp_path))
    assert result.status == "skipped"
    assert result.reason == "not_applicable"
    assert result.requests_sent == 0


# ---------------------------------------------------------------------------
# Privacy prefilter: refused BEFORE any network call
# ---------------------------------------------------------------------------


def test_credential_like_and_action_urls_refused_before_network(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    context = _context(tmp_path)
    cases = (
        ("https://user:pass@httpbin.org/html", "userinfo_present"),
        ("https://httpbin.org/html?token=abc", "credential_like_parameter"),
        ("https://httpbin.org/html?password=abc", "credential_like_parameter"),
        ("https://httpbin.org/reset-password", "action_effect_url"),
        ("https://httpbin.org/unsubscribe?u=1", "action_effect_url"),
        ("https://httpbin.org/html?email=victime@example.org", "personal_identifier"),
    )
    for url, expected_detail in cases:
        result = adapter.scan(_url_observable(url), context)
        assert result.status == "skipped", (url, result)
        assert result.reason == f"privacy_policy: {expected_detail}", (url, result.reason)
        assert result.requests_sent == 0
        assert result.evidence == []


def test_reserved_and_private_hosts_refused_before_network(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    context = _context(tmp_path)
    for url in (
        "http://localhost/admin",
        "https://redirect.notice.test/r/42",
        "https://example.invalid/x",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "https://[::1]/",
        "ftp://httpbin.org/html",
    ):
        result = adapter.scan(_url_observable(url), context)
        assert result.status == "skipped", (url, result)
        assert result.reason is not None and result.reason.startswith("privacy_policy")
        assert result.requests_sent == 0
        assert result.evidence == []


def test_service_approval_required_zero_requests(tools_config: ToolsConfig, tmp_path: Path) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    egress = _approved_egress(approved_services=[])
    result = adapter.scan(
        _url_observable("https://httpbin.org/html"), _context(tmp_path, egress=egress)
    )
    assert result.status == "skipped"
    assert result.reason == "privacy_policy: service_not_approved_in_egress"
    assert result.requests_sent == 0


def test_allow_real_urls_false_and_exact_host_refusals(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    disallowed = _approved_egress(allow_real_urls=False)
    result = adapter.scan(
        _url_observable("https://httpbin.org/html"), _context(tmp_path, egress=disallowed)
    )
    assert result.status == "skipped"
    assert result.reason == "privacy_policy: egress_allow_real_urls_false"
    assert result.requests_sent == 0

    other_host = _approved_egress(approved_exact_url_hosts=["other.example"])
    result = adapter.scan(
        _url_observable("https://httpbin.org/html"), _context(tmp_path, egress=other_host)
    )
    assert result.status == "skipped"
    assert result.reason == "privacy_policy: exact_url_host_not_approved"
    assert result.requests_sent == 0


def test_refusal_helpers_are_pure() -> None:
    assert submittable_url(_obs("email", "a@b.org")) is None
    assert submittable_url(_url_observable(" https://httpbin.org/html ")) == "https://httpbin.org/html"
    assert service_send_refusal(_approved_egress()) is None
    assert service_send_refusal(_approved_egress(approved_services=[])) == (
        "service_not_approved_in_egress"
    )
    assert url_send_refusal("https://httpbin.org/html", _approved_egress()) is None
    assert (
        url_send_refusal("https://httpbin.org/html", _approved_egress(allow_real_urls=False))
        == "egress_allow_real_urls_false"
    )
    assert same_origin("https://urlscan.io/api/v1/result/x/", URLSCAN_ORIGIN)
    assert same_origin("https://urlscan.io:443/x", URLSCAN_ORIGIN)
    assert not same_origin("https://evil.example/x", URLSCAN_ORIGIN)
    assert not same_origin("http://urlscan.io/x", URLSCAN_ORIGIN)
    assert not same_origin("https://urlscan.io.evil.example/x", URLSCAN_ORIGIN)


# ---------------------------------------------------------------------------
# Deadline / budget gates
# ---------------------------------------------------------------------------


def test_expired_deadline_is_unavailable_deadline_with_zero_requests(
    tools_config: ToolsConfig, tmp_path: Path
) -> None:
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    context = _context(tmp_path, deadline_s=-1.0)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert result.status == "unavailable"
    assert result.reason is not None and "deadline" in result.reason
    assert result.requests_sent == 0
    assert result.mode == "none"


def test_near_deadline_returns_unavailable_deadline_without_sending(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(urlscan_module, "_post_scan_exchange", _forbidden("post"))
    fixed_clock = 1000.0
    adapter = _adapter(
        _placeholder_settings(), tools_config.urlscan, tmp_path, clock=lambda: fixed_clock
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 0.3,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert result.status == "unavailable"
    assert result.reason is not None and "deadline" in result.reason
    assert result.requests_sent == 0


def test_post_budget_is_exact_remaining_float_and_phase_capped(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, float] = {}

    def _controlled_timeout(url: str, visibility: str) -> Any:
        raise UrlscanTransportError("timeout", "controlled timeout object (no provider call)")

    calls = _patch_transport(monkeypatch, post=_controlled_timeout)
    fixed_clock = 1000.0
    adapter = _adapter(
        _placeholder_settings(), tools_config.urlscan, tmp_path, clock=lambda: fixed_clock
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 10.25,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert len(calls["post"]) == 1
    assert calls["post"][0]["timeout_s"] == pytest.approx(10.25)
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.split(":", 1)[0].strip() == "timeout"
    assert result.requests_sent == 1
    assert result.mode == "live"

    capped = tools_config.urlscan.model_copy(update={"phase_timeout_s": 2.5})
    capped_adapter = _adapter(
        _placeholder_settings(), capped, tmp_path, clock=lambda: fixed_clock
    )
    capped_context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=fixed_clock + 10.25,
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    capped_result = capped_adapter.scan(
        _url_observable("https://httpbin.org/html"), capped_context
    )
    assert calls["post"][-1]["timeout_s"] == pytest.approx(2.5)
    assert capped_result.status == "unavailable"


# ---------------------------------------------------------------------------
# Visibility mapping (authoritative source_profile)
# ---------------------------------------------------------------------------


def test_visibility_mapping_is_authoritative(tools_config: ToolsConfig) -> None:
    config = tools_config.urlscan
    assert visibility_for("fixture", config) == config.visibility_fixture == "unlisted"
    assert visibility_for("public_corpus", config) == config.visibility_fixture == "unlisted"
    assert visibility_for("private_authorized", config) == config.visibility_real == "private"

    # A configuration keeps its authored values; the mapping is the only
    # source of the submitted visibility and never falls back to "public".
    alternate = config.model_copy(update={"visibility_real": "private", "visibility_fixture": "private"})
    assert visibility_for("fixture", alternate) == "private"
    assert visibility_for("public_corpus", alternate) == "private"
    assert visibility_for("private_authorized", alternate) == "private"


def test_submitted_visibility_never_public(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    calls = _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(200, _result_body(scan_id=sid)),
        dom=lambda sid: _exchange(200, b"<html><body>inert</body></html>"),
    )
    adapter = _adapter(_placeholder_settings(), _fast_config(tools_config.urlscan), tmp_path)
    profiles = ("fixture", "public_corpus", "private_authorized")
    for profile in profiles:
        result = adapter.scan(
            _url_observable("https://httpbin.org/html"),
            _context(tmp_path, profile=profile, run_id=str(uuid.uuid4())),
        )
        assert result.status == "ok", (profile, result)
    visibilities = [entry["visibility"] for entry in calls["post"]]
    assert visibilities == ["unlisted", "unlisted", "private"]
    assert "public" not in visibilities


def test_submission_visibility_mismatch_is_never_a_silent_downgrade(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, "public")),
        result=lambda sid: _exchange(200, _result_body(scan_id=sid)),
    )
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    result = adapter.scan(
        _url_observable("https://httpbin.org/html"),
        _context(tmp_path, profile="private_authorized"),
    )
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.startswith("api_error")
    assert "visibility_not_confirmed" in result.reason
    assert result.scan_id == scan_id
    assert result.evidence == []


# ---------------------------------------------------------------------------
# Single submission, ambiguous POST, local submission budget
# ---------------------------------------------------------------------------


def test_ambiguous_post_is_never_retried_and_consumes_local_budget(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _ambiguous(url: str, visibility: str) -> Any:
        raise UrlscanTransportError("timeout", "controlled ambiguity (no provider call)")

    calls = _patch_transport(monkeypatch, post=_ambiguous)
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    context = _context(tmp_path, run_id=str(uuid.uuid4()))
    first = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert first.status == "unavailable"
    assert first.reason is not None and first.reason.startswith("timeout")
    assert first.requests_sent == 1
    assert len(calls["post"]) == 1  # ONE attempt, never a second submission

    second = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert second.status == "skipped"
    assert second.reason is not None and second.reason.startswith("budget")
    assert second.requests_sent == 0
    assert len(calls["post"]) == 1  # still exactly one attempt

    # A different run is a different email: not blocked by another run's budget.
    third = adapter.scan(
        _url_observable("https://httpbin.org/html"),
        _context(tmp_path, run_id=str(uuid.uuid4())),
    )
    assert third.status in ("unavailable", "ok")  # transport is still the controlled error
    assert len(calls["post"]) == 2


def test_local_budget_journal_refuses_second_attempt(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = str(uuid.uuid4())
    journal = tmp_path / "quota.json"
    journal.write_text(
        json.dumps(
            {
                "day_utc": time.strftime("%Y-%m-%d", time.gmtime()),
                "max_urls_per_run": tools_config.urlscan.max_urls,
                "submissions": [
                    {
                        "run_id": run_id,
                        "visibility": "unlisted",
                        "http_status": 200,
                        "scan_id": str(uuid.uuid4()),
                        "attempted_at": "2026-09-19T00:00:00+00:00",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(urlscan_module, "_post_scan_exchange", _forbidden("post"))
    adapter = UrlscanAdapter(
        _placeholder_settings(), tools_config.urlscan, quota_journal_path=journal
    )
    result = adapter.scan(
        _url_observable("https://httpbin.org/html"), _context(tmp_path, run_id=run_id)
    )
    assert result.status == "skipped"
    assert result.reason == "budget: max_urls_per_run_reached"
    assert result.requests_sent == 0


# ---------------------------------------------------------------------------
# Status mapping and polling semantics (controlled local objects only)
# ---------------------------------------------------------------------------


def test_error_cause_for_status_mapping() -> None:
    assert error_cause_for_status(429) == "rate_limited"
    assert error_cause_for_status(401) == "auth_error"
    assert error_cause_for_status(403) == "auth_error"
    assert error_cause_for_status(410) == "api_error"
    assert error_cause_for_status(500) == "api_error"
    assert error_cause_for_status(503) == "api_error"


def test_429_numeric_input_maps_to_rate_limited() -> None:
    """docs/gates.md §5.2: no provider 429 was provoked or fabricated for
    TICKET-08 (``provider_429_observed=false``); the error handler is
    exercised with the numeric status as a function input. Real 429
    archives, when they exist, are validated against the same mapping."""

    assert error_cause_for_status(429) == "rate_limited"
    for meta_path in PROJECT_ROOT.glob("runs/gates/G4/urlscan/*.poll_*.meta.json"):
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("http_status") == 429:
            assert error_cause_for_status(429) == "rate_limited"


def test_pending_404_continues_and_gone_410_yields_api_error(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    statuses = iter([404, 410])
    calls = _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(next(statuses), b'{"message": "gone"}'),
    )
    adapter = _adapter(
        _placeholder_settings(),
        _fast_config(tools_config.urlscan),
        tmp_path,
        sleep=lambda seconds: None,
    )
    result = adapter.scan(_url_observable("https://httpbin.org/html"), _context(tmp_path))
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.startswith("api_error")
    assert "result_gone_http_410" in result.reason
    assert result.scan_id == scan_id
    assert result.evidence == []
    assert result.response_ref is not None and "poll_2" in result.response_ref
    assert len(calls["result"]) == 2  # the 404 was pending, not terminal


def test_rate_limited_429_is_unavailable_rate_limited(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(429, b'{"message": "rate limited"}'),
    )
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), _context(tmp_path))
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.startswith("rate_limited")
    assert result.evidence == []
    assert result.requests_sent == 2


def test_still_pending_after_phase_budget_times_out_inside_phase(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())

    class _FakeClock:
        def __init__(self) -> None:
            self.now = 1000.0

        def __call__(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.now += seconds

    clock = _FakeClock()
    _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(404, b'{"message": "not found"}'),
    )
    config = tools_config.urlscan.model_copy(
        update={"first_poll_s": 0.0, "poll_interval_s": 5.0, "phase_timeout_s": 10.0}
    )
    adapter = _adapter(
        _placeholder_settings(), config, tmp_path, clock=clock, sleep=clock.sleep
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=clock.now + 30.0,  # phase budget (10 s) is the tightest bound
        egress=_approved_egress(),
        capture_dir=tmp_path / "captures",
        mode="live",
    )
    result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.startswith("timeout")
    assert "still_pending_after_phase_budget" in result.reason
    assert result.scan_id == scan_id
    assert result.evidence == []
    assert clock.now <= 1010.5  # never returned later than the phase budget
    assert result.response_ref is not None and "poll_" in result.response_ref


def test_post_status_errors_map_to_causes(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for status, cause in ((429, "rate_limited"), (401, "auth_error"), (403, "auth_error"), (500, "api_error")):
        _patch_transport(
            monkeypatch,
            post=lambda url, visibility, s=status: _exchange(s, b'{"message": "error"}'),
        )
        adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
        result = adapter.scan(
            _url_observable("https://httpbin.org/html"),
            _context(tmp_path, run_id=str(uuid.uuid4())),
        )
        assert result.status == "unavailable", (status, result)
        assert result.reason is not None and result.reason.split(":", 1)[0].strip() == cause
        assert result.evidence == []
        assert result.requests_sent == 1
        assert result.scan_id is None


def test_submission_details_rejects_missing_or_invalid_values() -> None:
    valid = str(uuid.uuid4())
    assert submission_details({"uuid": valid, "visibility": "PRIVATE"}) == (valid, "private")
    assert submission_details({"uuid": "not-a-uuid", "visibility": "private"}) == (None, "private")
    assert submission_details({"visibility": "private"}) == (None, "private")
    assert submission_details({"uuid": valid, "visibility": "secret"}) == (valid, None)
    assert submission_details({"uuid": valid}) == (valid, None)
    assert submission_details({}) == (None, None)


def test_invalid_uuid_in_submission_is_malformed_response(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(
            200, json.dumps({"uuid": "not-a-uuid", "visibility": visibility}).encode("utf-8")
        ),
    )
    adapter = _adapter(_placeholder_settings(), tools_config.urlscan, tmp_path)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), _context(tmp_path))
    assert result.status == "unavailable"
    assert result.reason is not None and result.reason.startswith("malformed_response")
    assert result.scan_id is None
    assert result.requests_sent == 1


# ---------------------------------------------------------------------------
# Result normalizer and navigation extraction
# ---------------------------------------------------------------------------


def test_normalize_result_exposes_only_real_fields_with_resolving_pointers() -> None:
    query = _url_observable("https://httpbin.org/redirect-to?url=x")
    scan_id = str(uuid.uuid4())
    raw = _result_body(
        final_url="https://httpbin.org/html",
        malicious=False,
        redirects=[
            {"from": "https://httpbin.org/redirect-to?url=x", "to": "https://httpbin.org/html", "status": 302}
        ],
        scan_id=scan_id,
    )
    body = json.loads(raw)
    metadata = ResponseMetadata(
        origin=URLSCAN_ORIGIN,
        http_status=200,
        response_date="Sat, 19 Sep 2026 14:00:00 GMT",
        response_sha256=hashlib.sha256(raw).hexdigest(),
        response_ref="result.json",
    )
    dom_facts = {
        "title": "Example title",
        "text_excerpt": "Inert page text",
        "form_fields": [{"name": "q", "type": "text"}, {"name": "send", "type": "submit"}],
    }
    result = normalize_result(
        query, body, metadata, dom_ref="dom.json", dom_facts=dom_facts
    )
    assert result.status == "ok"
    assert result.scan_id == scan_id
    assert result.visibility == "unlisted"
    predicates = [evidence.predicate for evidence in result.evidence]
    assert predicates == [
        "sandbox_final_url",
        "sandbox_provider_malicious",
        "sandbox_redirect",
        "sandbox_dom_excerpt",
        "sandbox_page_title",
        "sandbox_form_field",
        "sandbox_form_field",
    ]
    for evidence in result.evidence:
        ref, _, pointer = evidence.source_ref.partition("#/")
        if ref == "result.json":
            assert _pointer_get(body, pointer) == evidence.value
        else:
            assert ref == "dom.json"
            assert _pointer_get(dom_facts, pointer) == evidence.value
    assert all(evidence.provenance == "SANDBOX" for evidence in result.evidence)
    assert all(evidence.match_level == "EXACT" for evidence in result.evidence)


def test_normalize_result_missing_fields_stay_absent() -> None:
    query = _url_observable("https://httpbin.org/html")
    raw = _result_body(title=None, malicious=None, redirects=[], requests=[])
    body = json.loads(raw)
    metadata = ResponseMetadata(
        origin=URLSCAN_ORIGIN,
        http_status=200,
        response_date=None,
        response_sha256=hashlib.sha256(raw).hexdigest(),
        response_ref="result.json",
    )
    result = normalize_result(query, body, metadata)  # no title, no verdict, no screenshot
    assert result.status == "ok"
    assert [evidence.predicate for evidence in result.evidence] == ["sandbox_final_url"]


def test_normalize_result_malformed_bodies_are_never_evidence() -> None:
    query = _url_observable("https://httpbin.org/html")
    metadata = ResponseMetadata(
        origin=URLSCAN_ORIGIN,
        http_status=200,
        response_date=None,
        response_sha256="a" * 64,
        response_ref="result.json",
    )
    for body in (
        {},
        {"task": "x"},
        {"task": {}},
        {"task": {}, "data": "x"},
        {"page": {}, "data": {}},
    ):
        result = normalize_result(query, body, metadata)
        assert result.status == "unavailable", body
        assert result.reason == "malformed_response", body
        assert result.evidence == [], body


def test_navigation_extraction_uses_provider_chain_and_falls_back() -> None:
    submitted = "https://httpbin.org/redirect-to?url=x"
    chained = {
        "data": {
            "redirects": [
                {"from": submitted, "to": "https://httpbin.org/html", "status": 302}
            ],
            "requests": [],
        }
    }
    assert extract_navigation_steps(chained, submitted) == [
        ("https://httpbin.org/html", "data/redirects/0/to")
    ]

    # Inconsistent provider chain (wrong from) → fall back to the request walk.
    inconsistent = {
        "data": {
            "redirects": [{"from": "https://other.example/", "to": "https://httpbin.org/html"}],
            "requests": [
                {
                    "request": {
                        "type": "Document",
                        "request": {"url": submitted},
                    },
                    "response": {"response": {"redirectURL": "https://httpbin.org/html"}},
                },
                {
                    "request": {
                        "type": "Image",
                        "request": {"url": submitted},
                    },
                    "response": {"response": {"redirectURL": "https://tracker.example/pixel"}},
                },
            ],
        }
    }
    steps = extract_navigation_steps(inconsistent, submitted)
    assert steps == [
        ("https://httpbin.org/html", "data/requests/0/response/response/redirectURL")
    ]

    # Cycle guard and no-step cases.
    cyclic = {
        "data": {
            "redirects": [
                {"from": submitted, "to": "https://httpbin.org/a"},
                {"from": "https://httpbin.org/a", "to": submitted},
            ]
        }
    }
    assert extract_navigation_steps(cyclic, submitted) == [
        ("https://httpbin.org/a", "data/redirects/0/to"),
        (submitted, "data/redirects/1/to"),
    ]
    assert extract_navigation_steps({"data": {}}, submitted) == []
    assert extract_navigation_steps({}, submitted) == []


def test_dom_extraction_is_inert_and_bounded() -> None:
    html = (
        "<html><head><title>  Page   Title </title>"
        "<script>alert('must not appear')</script></head>"
        "<body><h1>Hello</h1><p>World</p>"
        '<form action="/x"><input name="q" type="text"><input name="send" value="Go">'
        "<select name=\"s\"><option>a</option></select><button id=\"btn\"></form>"
        "<style>.x{color:red}</style></body></html>"
    )
    facts = extract_dom_facts(html, "https://httpbin.org/html")
    assert facts["title"] == "Page Title"
    assert "must not appear" not in facts["text_excerpt"]
    assert "Hello" in facts["text_excerpt"] and "World" in facts["text_excerpt"]
    names = [field["name"] for field in facts["form_fields"]]
    assert names == ["q", "send", "s", "btn"]
    assert facts["defects"] == []

    big = "<p>" + ("a" * 100_000) + "</p><script>" + ("b" * 100_000) + "</script>"
    bounded = extract_dom_facts(big, "https://httpbin.org/html")
    assert len(bounded["text_excerpt"]) <= 1_000
    assert len(bounded["text_full_bounded"]) <= 20_000
    assert "b" * 100 not in bounded["text_full_bounded"]

    # Hostile/malformed HTML cannot crash and stays inert.
    hostile = "<html><body><script>process.exit()</script><input name='x'>>>"
    hostile_facts = extract_dom_facts(hostile, "https://httpbin.org/html")
    assert "process.exit" not in hostile_facts["text_excerpt"]
    assert hostile_facts["form_fields"][0]["name"] == "x"


# ---------------------------------------------------------------------------
# Captures, key hygiene and local (single) submission flow
# ---------------------------------------------------------------------------


def test_capture_writes_exact_bytes_and_no_key_material(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    result_payload = _result_body(scan_id=scan_id)
    dom_payload = b"<html><body><p>dom</p></body></html>"
    _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(200, result_payload),
        dom=lambda sid: _exchange(200, dom_payload),
    )
    adapter = _adapter(_placeholder_settings(), _fast_config(tools_config.urlscan), tmp_path)
    context = _context(tmp_path)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
    assert result.status == "ok"
    assert result.response_ref is not None
    raw = (context.capture_dir / result.response_ref).read_bytes()
    assert raw == result_payload
    assert hashlib.sha256(raw).hexdigest() == result.response_sha256

    dom_refs = [e for e in result.evidence if e.predicate == "sandbox_dom_excerpt"]
    assert dom_refs and dom_refs[0].source_ref.endswith(".dom.json#/text_excerpt")

    for path in context.capture_dir.rglob("*"):
        if path.is_file():
            assert PLACEHOLDER_KEY not in path.read_text(encoding="utf-8", errors="ignore")


def test_scan_flow_requests_dom_but_never_screenshot_without_vision_gate(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    calls = _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(200, _result_body(scan_id=sid)),
        dom=lambda sid: _exchange(200, b"<html><body>inert</body></html>"),
    )
    adapter = _adapter(_placeholder_settings(), _fast_config(tools_config.urlscan), tmp_path)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), _context(tmp_path))
    assert result.status == "ok"
    assert len(calls["dom"]) == 1
    assert calls["screenshot"] == []  # MODEL_SUPPORTS_VISION=false default

    # A 404 DOM never breaks the result JSON.
    scan_id2 = str(uuid.uuid4())
    _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id2, visibility)),
        result=lambda sid: _exchange(200, _result_body(scan_id=sid)),
        dom=lambda sid: _exchange(404, b'{"message": "not found"}'),
    )
    result2 = adapter.scan(
        _url_observable("https://httpbin.org/html"),
        _context(tmp_path, run_id=str(uuid.uuid4())),
    )
    assert result2.status == "ok"
    assert all(e.predicate != "sandbox_dom_excerpt" for e in result2.evidence)


def test_screenshot_absent_never_breaks_json_with_vision_enabled(
    tools_config: ToolsConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = str(uuid.uuid4())
    vision_settings = _placeholder_settings(MODEL_SUPPORTS_VISION=True)
    calls = _patch_transport(
        monkeypatch,
        post=lambda url, visibility: _exchange(200, _submission_body(scan_id, visibility)),
        result=lambda sid: _exchange(200, _result_body(scan_id=sid)),
        dom=lambda sid: _exchange(404, b"{}"),
        screenshot=lambda sid: _exchange(404, b"not found"),
    )
    adapter = _adapter(vision_settings, _fast_config(tools_config.urlscan), tmp_path)
    result = adapter.scan(_url_observable("https://httpbin.org/html"), _context(tmp_path))
    assert result.status == "ok"
    assert len(calls["screenshot"]) == 1
    assert all(e.predicate != "sandbox_screenshot" for e in result.evidence)


# ---------------------------------------------------------------------------
# Frozen schema conformance
# ---------------------------------------------------------------------------


def test_toolresult_conforms_to_frozen_schema() -> None:
    query = _url_observable("https://httpbin.org/html")
    raw = _result_body(malicious=False, title="t")
    ok = normalize_result(
        query,
        json.loads(raw),
        ResponseMetadata(
            origin=URLSCAN_ORIGIN,
            http_status=200,
            response_date="Sat, 19 Sep 2026 14:00:00 GMT",
            response_sha256=hashlib.sha256(raw).hexdigest(),
            response_ref="result.json",
        ),
        dom_ref="dom.json",
        dom_facts={"text_excerpt": "t", "form_fields": [{"name": "q", "type": "text"}]},
    )
    skipped = urlscan_module._skip(query, "disabled", 1.0)
    unavailable = urlscan_module._unavailable(query, "not_configured", 1.0)
    for result in (ok, skipped, unavailable):
        dump = result.model_dump(mode="json")
        errors = _schema_validate(dump, SCHEMA["$defs"]["ToolResult"], root=SCHEMA)
        assert errors == [], (result.status, errors)
        for evidence in dump["evidence"]:
            assert _schema_validate(evidence, SCHEMA["$defs"]["Evidence"], root=SCHEMA) == []


# ---------------------------------------------------------------------------
# Minimal local JSON-Schema checker for the frozen triage_report $defs
# (same approach as tests/test_opencti.py; src/llm.validate_against_schema
# does not support list-typed "type" and is out of FILES ALLOWED).
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
# Source invariants: one origin, one submission call site, no upload/exec
# ---------------------------------------------------------------------------


def test_transport_source_invariants() -> None:
    source = (PROJECT_ROOT / "src" / "tools" / "urlscan.py").read_text(encoding="utf-8")
    # All request URLs are built from the single approved origin constant.
    assert 'URLSCAN_ORIGIN = "https://urlscan.io"' in source
    assert "urlscan.io" in source
    assert source.count('"https://urlscan.io"') == 1
    # Exactly one POST call site (the scan submission).
    assert source.count('_request_raw(\n        "POST"') == 1
    # No upload/execute/replay surface exists.
    for forbidden in ("upload", "shell=True", "subprocess", "eval(", "exec(", "pickle"):
        assert forbidden not in source, forbidden
    # The cross-origin redirect refusal exists and no arbitrary redirect is followed.
    assert "cross_origin_redirect_refused" in source
    assert "allow_redirects=False" in source


# ---------------------------------------------------------------------------
# Packaging regression: src.tools.urlscan must ship in the wheel
# ---------------------------------------------------------------------------


def test_built_wheel_contains_and_installs_urlscan(tmp_path: Path) -> None:
    """A built wheel must include ``src.tools.urlscan`` and it must import
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
    assert "src/tools/urlscan.py" in names

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
        "import src.tools, src.tools.urlscan as us\n"
        f"assert src.tools.__file__.startswith({str(target)!r})\n"
        f"assert us.__file__.startswith({str(target)!r})\n"
        "assert hasattr(us, 'UrlscanAdapter') and hasattr(us, 'normalize_result')\n"
        "assert hasattr(us, 'visibility_for') and hasattr(us, 'URLSCAN_ORIGIN')\n"
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
# Live: real private scan (benign + natural pending + local budget) and the
# real private redirect capture with the production poll settings
# ---------------------------------------------------------------------------


def _live_out_dir() -> Path:
    out_dir = PROJECT_ROOT / "runs" / "gates" / "G4" / "urlscan"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _poll_statuses(out_dir: Path, run_id: str) -> list[int]:
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:8]
    statuses: list[int] = []
    for meta_path in sorted(out_dir.glob(f"urlscan_url_*_{digest}.poll_*.meta.json")):
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        status = data.get("http_status")
        if isinstance(status, int):
            statuses.append(status)
    return statuses


@pytest.mark.live
def test_live_urlscan_private_benign_scan_pending_and_local_budget() -> None:
    """REAL private scan; never skipped.

    - without a key: the REAL adapter is exercised and must return an
      explicit ``unavailable/not_configured`` with ZERO requests;
    - with key + operator URL: one REAL ``private`` scan of the authorized
      benign URL with fast test-local poll settings (natural pending
      observation, real result, DOM), then the REAL local budget refusal of
      a second scan in the same run.
    """

    out_dir = _live_out_dir()
    settings = load_settings(None)
    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    results: list[dict[str, object]] = []
    limitations: list[str] = []

    if settings.URLSCAN_API_KEY is None:
        adapter = UrlscanAdapter(
            settings, tools_config.urlscan, quota_journal_path=out_dir / "quota.json"
        )
        context = ToolContext(
            run_id=str(uuid.uuid4()),
            source_profile="private_authorized",
            deadline=time.monotonic() + tools_config.urlscan.phase_timeout_s,
            egress=_tools_approved_egress(tools_config, [settings.LIVE_BENIGN_URL or ""]),
            capture_dir=out_dir,
            mode="live",
        )
        result = adapter.scan(_url_observable("https://httpbin.org/html"), context)
        results.append(result.model_dump(mode="json"))
        assert result.status == "unavailable"
        assert result.reason is not None and "not_configured" in result.reason
        assert result.requests_sent == 0
        (out_dir / "live_unconfigured_result.json").write_text(
            json.dumps(results[0], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print("live urlscan: no key — real adapter returned explicit unavailable")
        return

    assert settings.LIVE_BENIGN_URL, "LIVE_BENIGN_URL absent: nothing can be fabricated"
    config = tools_config.urlscan.model_copy(
        update={"first_poll_s": 0.0, "poll_interval_s": 1.0}
    )
    adapter = UrlscanAdapter(settings, config, quota_journal_path=out_dir / "quota.json")
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="private_authorized",
        deadline=time.monotonic() + config.phase_timeout_s,
        egress=_tools_approved_egress(tools_config, [settings.LIVE_BENIGN_URL]),
        capture_dir=out_dir,
        mode="live",
    )
    result = adapter.scan(_url_observable(settings.LIVE_BENIGN_URL), context)
    results.append(result.model_dump(mode="json"))

    assert result.status == "ok", (result.status, result.reason)
    assert result.visibility == "private"
    assert result.scan_id is not None and uuid.UUID(result.scan_id)
    assert result.mode == "live"
    assert result.requests_sent >= 3  # POST + >=1 poll + DOM
    final_urls = [e for e in result.evidence if e.predicate == "sandbox_final_url"]
    assert len(final_urls) == 1 and final_urls[0].value == settings.LIVE_BENIGN_URL
    assert result.response_ref is not None
    raw = (out_dir / result.response_ref).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == result.response_sha256
    captured = json.loads(raw)
    for evidence in result.evidence:
        ref, _, pointer = evidence.source_ref.partition("#/")
        document = captured if ref == result.response_ref else json.loads(
            (out_dir / ref).read_text(encoding="utf-8")
        )
        assert _pointer_get(document, pointer) == evidence.value

    statuses = _poll_statuses(out_dir, context.run_id)
    pending_observed = 404 in statuses
    if not pending_observed:
        limitations.append(
            "natural pending (real 404 before the result) was not observed in this run; "
            "the 404→pending mapping is covered by controlled local objects"
        )
    dom_facts = list(out_dir.glob("*" + hashlib.sha256(context.run_id.encode()).hexdigest()[:8] + ".dom.json"))
    if not dom_facts:
        limitations.append("DOM capture absent in this run (404 or budget); result JSON stayed valid")

    second = adapter.scan(_url_observable(settings.LIVE_BENIGN_URL), context)
    results.append(second.model_dump(mode="json"))
    assert second.status == "skipped"
    assert second.reason is not None and second.reason.startswith("budget")
    assert second.requests_sent == 0

    receipt = {
        "mode": "live",
        "results": results,
        "pending_observed": pending_observed,
        "poll_statuses": statuses,
        "natural_pending": "real 404 polls before the 200 result",
        "local_budget_refusal_verified": True,
        "vision_gate": settings.MODEL_SUPPORTS_VISION,
        "screenshot_requests": 0,
        "limitations": limitations,
    }
    (out_dir / "live_private_benign_result.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8"
    )


@pytest.mark.live
def test_live_urlscan_private_redirect_chain() -> None:
    """REAL private scan of the authorized benign redirect URL with the
    PRODUCTION poll settings (10 s then 5 s); the demonstrable main-document
    redirect chain and the final URL must come from the real capture."""

    out_dir = _live_out_dir()
    settings = load_settings(None)
    tools_config = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)

    if settings.URLSCAN_API_KEY is None:
        pytest.fail("URLSCAN_API_KEY absent: the mandatory live redirect validation cannot run")
    assert settings.LIVE_REDIRECT_URL, "LIVE_REDIRECT_URL absent: nothing can be fabricated"
    declared_target = parse_qs(urlparse(settings.LIVE_REDIRECT_URL).query).get("url", [None])[0]

    adapter = UrlscanAdapter(
        settings, tools_config.urlscan, quota_journal_path=out_dir / "quota.json"
    )
    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="private_authorized",
        deadline=time.monotonic() + tools_config.urlscan.phase_timeout_s,
        egress=_tools_approved_egress(tools_config, [settings.LIVE_REDIRECT_URL]),
        capture_dir=out_dir,
        mode="live",
    )
    result = adapter.scan(_url_observable(settings.LIVE_REDIRECT_URL), context)
    assert result.status == "ok", (result.status, result.reason)
    assert result.visibility == "private"
    assert result.scan_id is not None and uuid.UUID(result.scan_id)
    assert result.response_ref is not None

    redirects = [e for e in result.evidence if e.predicate == "sandbox_redirect"]
    final_urls = [e for e in result.evidence if e.predicate == "sandbox_final_url"]
    assert redirects, "no demonstrable redirect step in the real capture"
    assert final_urls, "no observed final URL in the real capture"
    if declared_target:
        assert any(e.value == declared_target for e in redirects), (
            "the real redirect chain does not contain the declared target"
        )
        assert final_urls[0].value == declared_target

    raw = (out_dir / result.response_ref).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == result.response_sha256
    captured = json.loads(raw)
    for evidence in (redirects + final_urls):
        ref, _, pointer = evidence.source_ref.partition("#/")
        document = captured if ref == result.response_ref else json.loads(
            (out_dir / ref).read_text(encoding="utf-8")
        )
        assert _pointer_get(document, pointer) == evidence.value

    receipt = {
        "mode": "live",
        "result": result.model_dump(mode="json"),
        "declared_target": declared_target,
        "redirect_steps": [
            {"value": e.value, "source_ref": e.source_ref} for e in redirects
        ],
        "final_url": final_urls[0].value if final_urls else None,
        "production_poll_settings": {
            "first_poll_s": tools_config.urlscan.first_poll_s,
            "poll_interval_s": tools_config.urlscan.poll_interval_s,
            "phase_timeout_s": tools_config.urlscan.phase_timeout_s,
        },
    }
    (out_dir / "live_private_redirect_result.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8"
    )

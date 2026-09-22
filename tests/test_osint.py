"""TICKET-19D-OSINT §35–§36 — offline OSINT adapter + contract tests.

No real network: every provider exchange goes through an injected fake
transport. Fakes return CONTROLLED responses to the normalizers; nothing
here is presented as a live provider observation. Real observations come
only from ``scripts/smoke_osint.py``.
"""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from src.agent.tools import tool_schema_sha256
from src.config import EgressConfig, OsintToolConfig, load_settings
from src.state import Evidence, Observable, ToolResult
from src.tools import ToolContext
from src.tools.osint import (
    CT_ORIGIN,
    PSL_VERSION,
    RDAP_ORIGIN,
    THREATFOX_URL,
    OsintAdapter,
    _applicable_sources,
    _normalize_target,
    _registrable_domain,
)

# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """OSINT offline tests must never touch the network."""

    if request.config.getoption("--live"):
        return

    def _deny(*args: object, **kwargs: object) -> None:
        pytest.fail("network access attempted in an offline OSINT test")

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)


class ManualClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _config(**overrides: Any) -> OsintToolConfig:
    values = {
        "enabled": True,
        "phase_timeout_s": 40.0,
        "threatfox_timeout_s": 10.0,
        "rdap_timeout_s": 10.0,
        "dns_timeout_s": 5.0,
        "ct_timeout_s": 10.0,
        "max_ct_response_bytes": 2097152,
        "max_ct_names": 20,
        "max_dns_values_per_type": 10,
    }
    values.update(overrides)
    return OsintToolConfig(**values)


_OBS_N = 0


def _observable(type_: str, value: str, normalized: str | None = None) -> Observable:
    global _OBS_N
    _OBS_N += 1
    return Observable(
        id=f"obs_osint_{_OBS_N:04d}",
        value=value,
        normalized_value=normalized if normalized is not None else value,
        type=type_,  # type: ignore[arg-type]
        provenance="INTERNE",
        source_ref="part:1",
    )


def _context(tmp_path: Path, clock: ManualClock, budget: float = 60.0) -> ToolContext:
    capture = tmp_path / "captures"
    capture.mkdir(parents=True, exist_ok=True)
    return ToolContext(
        run_id="run-osint-test",
        source_profile="fixture",
        deadline=clock() + budget,
        egress=EgressConfig(
            allow_real_urls=False,
            approved_services=[],
            approved_exact_url_hosts=[],
            trusted_authserv_ids=[],
            shared_hosts=[],
            trusted_cti_sources=[],
        ),
        capture_dir=capture,
        mode="live",
    )


def _settings_no_key(clean_env: None) -> Any:
    settings = load_settings(None)
    assert settings.ABUSECH_API_KEY is None
    return settings


def _settings_with_key(monkeypatch: pytest.MonkeyPatch, clean_env: None) -> Any:
    monkeypatch.setenv("ABUSECH_API_KEY", "test-abusech-key-xyz")
    settings = load_settings(None)
    assert settings.ABUSECH_API_KEY is not None
    return settings


class FakePost:
    """Canned ThreatFox POST transport: records calls, never sends."""

    def __init__(self, responder: Any) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responder = responder

    def __call__(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> Any:
        self.calls.append({"url": url, "body": body, "headers": dict(headers), "timeout": timeout})
        return self._responder(url, body, headers, timeout)


class FakeGet:
    """Canned RDAP/CT GET transport: records calls, never sends."""

    def __init__(self, responder: Any) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responder = responder

    def __call__(self, url: str, timeout: float) -> Any:
        self.calls.append({"url": url, "timeout": timeout})
        return self._responder(url, timeout)


class FakeDns:
    """Canned DNS transport keyed by (name, rdtype); unmapped = NoAnswer."""

    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.calls: list[dict[str, Any]] = []
        self._answers = answers

    def __call__(self, name: str, rdtype: str, lifetime: float) -> list[str]:
        self.calls.append({"name": name, "rdtype": rdtype, "lifetime": lifetime})
        if (name, rdtype) not in self._answers:
            raise _noanswer()
        outcome = self._answers[(name, rdtype)]
        if isinstance(outcome, Exception):
            raise outcome
        return list(outcome)


def _nxdomain() -> Exception:
    import dns.resolver

    return dns.resolver.NXDOMAIN()


def _noanswer() -> Exception:
    import dns.resolver

    return dns.resolver.NoAnswer()


def _lifetime_expired() -> Exception:
    import dns.exception

    return dns.exception.Timeout()


def _not_found_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> Any:
    return 200, {"Date": "Mon, 22 Sep 2026 00:00:00 GMT"}, json.dumps({"query_status": "no_result", "data": []}).encode()


def _not_found_get(url: str, timeout: float) -> Any:
    if url.startswith(RDAP_ORIGIN):
        return 404, {}, b'{"title":"Not Found"}'
    return 200, {}, b"[]"


def _quiet_adapter(
    settings: Any,
    tmp_path: Path,
    clock: ManualClock,
    *,
    config: OsintToolConfig | None = None,
    post: Any = None,
    get: Any = None,
    dns: Any = None,
) -> tuple[OsintAdapter, ToolContext]:
    context = _context(tmp_path, clock)
    adapter = OsintAdapter(
        settings,
        config or _config(),
        clock=clock,
        threatfox_post=post or FakePost(_not_found_post),
        http_get=get or FakeGet(_not_found_get),
        dns_resolve=dns or FakeDns({}),
    )
    return adapter, context


def _captures_text(context: ToolContext) -> str:
    return "".join(
        path.read_bytes().decode("utf-8", errors="replace")
        for path in sorted(Path(context.capture_dir).iterdir())
        if path.is_file()
    )


# ---------------------------------------------------------------------------
# §35.1 normalization
# ---------------------------------------------------------------------------


def test_domain_lowercase_and_trailing_dot() -> None:
    target = _normalize_target(_observable("domain", "WWW.Example.COM."))
    assert target == {"ok": True, "kind": "domain", "normalized": "www.example.com", "registrable": "example.com"}


def test_domain_idn_punycode() -> None:
    target = _normalize_target(_observable("domain", "münchen.de"))
    assert target["ok"] is True
    assert target["normalized"] == "xn--mnchen-3ya.de"


def test_domain_invalid_idn_refused() -> None:
    target = _normalize_target(_observable("domain", "exa mple.com"))
    assert target == {"ok": False, "reason": "invalid_observable"}


@pytest.mark.parametrize(
    "host",
    ["localhost", "db.localhost", "x.test", "x.invalid", "x.local", "x.example", "x.internal", "x.corp", "x.home.arpa"],
)
def test_reserved_hosts_refused(host: str) -> None:
    assert _normalize_target(_observable("domain", host)) == {"ok": False, "reason": "invalid_observable"}


def test_example_com_accepted() -> None:
    target = _normalize_target(_observable("domain", "example.com"))
    assert target["ok"] is True and target["normalized"] == "example.com"


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "fe80::1"])
def test_non_global_ip_refused(ip: str) -> None:
    kind = "ipv6" if ":" in ip else "ipv4"
    assert _normalize_target(_observable(kind, ip)) == {"ok": False, "reason": "non_global_ip"}


def test_global_ip_normalized() -> None:
    assert _normalize_target(_observable("ipv4", "1.1.1.1"))["normalized"] == "1.1.1.1"


@pytest.mark.parametrize("value", ["abc", "z" * 32, "A" * 31, "aa"])
def test_invalid_md5_refused(value: str) -> None:
    assert _normalize_target(_observable("md5", value)) == {"ok": False, "reason": "invalid_observable"}


@pytest.mark.parametrize("value", ["abc", "f" * 63, "g" * 64])
def test_invalid_sha256_refused(value: str) -> None:
    assert _normalize_target(_observable("sha256", value)) == {"ok": False, "reason": "invalid_observable"}


def test_hash_lowercased() -> None:
    target = _normalize_target(_observable("md5", "D41D8CD98F00B204E9800998ECF8427E"))
    assert target == {"ok": True, "kind": "md5", "normalized": "d41d8cd98f00b204e9800998ecf8427e"}


# ---------------------------------------------------------------------------
# §35.2 registrable domain (bundled PSL only)
# ---------------------------------------------------------------------------


def test_registrable_subdomain_com() -> None:
    assert _registrable_domain("www.example.com") == "example.com"


def test_registrable_co_uk() -> None:
    assert _registrable_domain("www.example.co.uk") == "example.co.uk"


def test_registrable_private_psl_suffix() -> None:
    # A genuinely private PSL section: the registrable domain keeps the
    # private label (foo.blogspot.com, not blogspot.com).
    assert _registrable_domain("foo.blogspot.com") == "foo.blogspot.com"
    assert _registrable_domain("bar.foo.blogspot.com") == "foo.blogspot.com"


def test_registrable_none_for_public_suffix() -> None:
    assert _registrable_domain("co.uk") is None


def test_no_psl_network_download(no_network: None) -> None:
    # The bundled list answers without any transport (socket is denied).
    assert _registrable_domain("deep.sub.example.co.uk") == "example.co.uk"


# ---------------------------------------------------------------------------
# §35.3 routing
# ---------------------------------------------------------------------------


def test_routing_domain_hits_four_sources_with_exact_targets(
    tmp_path: Path, clean_env: None
) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock)
    query = _observable("domain", "WWW.Example.COM.")
    result = adapter.lookup(query, context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert set(bundle["sources"]) == {"threatfox", "rdap", "dns", "certificate_transparency"}
    assert bundle["observable_id"] == query.id
    assert bundle["normalized_target"] == "www.example.com"
    assert bundle["registrable_domain"] == "example.com"
    assert bundle["sources"]["threatfox"]["query_target"] == "www.example.com"
    assert bundle["sources"]["rdap"]["query_target"] == "example.com"
    assert bundle["sources"]["dns"]["query_target"] == "www.example.com"
    assert bundle["sources"]["certificate_transparency"]["query_target"] == "example.com"


def test_routing_ipv4_threatfox_plus_rdap(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock)
    result = adapter.lookup(_observable("ipv4", "1.1.1.1"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert set(bundle["sources"]) == {"threatfox", "rdap"}


def test_routing_ipv6_threatfox_plus_rdap(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock)
    result = adapter.lookup(_observable("ipv6", "2606:4700:4700::1111"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert set(bundle["sources"]) == {"threatfox", "rdap"}


def test_routing_hashes_threatfox_only(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock)
    for kind, value in (("md5", "d41d8cd98f00b204e9800998ecf8427e"), ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")):
        result = adapter.lookup(_observable(kind, value), context)
        bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
        assert set(bundle["sources"]) == {"threatfox"}


@pytest.mark.parametrize("kind", ["url", "sha1", "email", "message_id", "campaign_id"])
def test_routing_unsupported_skipped_zero_requests(
    tmp_path: Path, clean_env: None, kind: str
) -> None:
    clock = ManualClock()
    post, get, dns = FakePost(_not_found_post), FakeGet(_not_found_get), FakeDns({})
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, post=post, get=get, dns=dns)
    value = "https://example.com/evil" if kind == "url" else "some-value"
    result = adapter.lookup(_observable(kind, value), context)
    assert result.status == "skipped"
    assert result.reason == "not_applicable"
    assert result.requests_sent == 0
    assert result.evidence == [] and result.observables == []
    assert post.calls == [] and get.calls == [] and dns.calls == []


def test_url_never_converted_to_domain(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock)
    result = adapter.lookup(_observable("url", "https://www.example.com/login"), context)
    assert result.status == "skipped" and result.requests_sent == 0


def test_applicable_sources_matrix() -> None:
    assert _applicable_sources("domain") == ("threatfox", "rdap", "dns", "certificate_transparency")
    assert _applicable_sources("ipv4") == ("threatfox", "rdap")
    assert _applicable_sources("ipv6") == ("threatfox", "rdap")
    assert _applicable_sources("md5") == ("threatfox",)
    assert _applicable_sources("sha256") == ("threatfox",)


# ---------------------------------------------------------------------------
# §35.4 ThreatFox
# ---------------------------------------------------------------------------


def test_threatfox_absent_key_unavailable_zero_requests(
    tmp_path: Path, clean_env: None
) -> None:
    clock = ManualClock()
    post = FakePost(_not_found_post)
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, post=post)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert post.calls == []
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["threatfox"]["status"] == "unavailable"
    assert bundle["sources"]["threatfox"]["reason"] == "not_configured"
    assert bundle["sources"]["threatfox"]["requests_sent"] == 0


def test_threatfox_search_ioc_exact_match_and_auth(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    post = FakePost(_not_found_post)
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env), tmp_path, clock, post=post
    )
    adapter.lookup(_observable("domain", "Example.COM."), context)
    assert len(post.calls) == 1
    call = post.calls[0]
    assert call["url"] == THREATFOX_URL
    assert json.loads(call["body"]) == {"query": "search_ioc", "search_term": "example.com", "exact_match": True}
    assert call["headers"]["Auth-Key"] == "test-abusech-key-xyz"
    assert call["headers"]["Content-Type"] == "application/json"
    assert "exact_match" in json.loads(call["body"]) and json.loads(call["body"])["exact_match"] is True


def test_threatfox_search_hash_body(tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = ManualClock()
    post = FakePost(_not_found_post)
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env), tmp_path, clock, post=post
    )
    adapter.lookup(_observable("md5", "d41d8cd98f00b204e9800998ecf8427e"), context)
    assert json.loads(post.calls[0]["body"]) == {"query": "search_hash", "hash": "d41d8cd98f00b204e9800998ecf8427e"}


def test_threatfox_secret_never_persisted(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    post = FakePost(_not_found_post)
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env), tmp_path, clock, post=post
    )
    adapter.lookup(_observable("domain", "example.com"), context)
    assert "test-abusech-key-xyz" not in _captures_text(context)


def _threatfox_hitResponder(results: list[dict[str, Any]]) -> Any:
    def _respond(url: str, body: bytes, headers: dict[str, str], timeout: float) -> Any:
        assert url == THREATFOX_URL
        assert b"submit_ioc" not in body and b"get_iocs" not in body
        return 200, {"Date": "Mon, 22 Sep 2026 00:00:00 GMT"}, json.dumps({"query_status": "ok", "data": results}).encode()

    return _respond


def _threatfox_entry(index: int) -> dict[str, Any]:
    return {
        "threat_type": "botnet_cc",
        "threat_type_desc": "Botnet C&C",
        "malware_printable": f"Evil-{index}",
        "confidence_level": 90,
        "first_seen": "2024-01-01 00:00:00",
        "last_seen": "2024-06-01 00:00:00",
        "reporter": "abuse 않았습니다",
        "comment": "never projected",
        "reference": "https://example.invalid/ref",
        "tags": ["a", "b"],
        "malware_aliases": "Alias",
    }


def test_threatfox_hit_projects_at_most_five_results(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env),
        tmp_path,
        clock,
        post=FakePost(_threatfox_hitResponder([_threatfox_entry(i) for i in range(7)])),
    )
    result = adapter.lookup(_observable("domain", "evil-example.com"), context)
    assert result.status == "ok"
    matches = [e for e in result.evidence if e.predicate == "osint_threatfox_match"]
    assert len(matches) == 5
    assert all(e.source_group == "threatfox" and e.provenance == "OSINT" and e.source_kind == "osint" for e in result.evidence)
    assert {e.predicate for e in result.evidence} <= {
        "osint_threatfox_match", "osint_threatfox_threat_type", "osint_threatfox_malware",
        "osint_threatfox_confidence", "osint_threatfox_first_seen", "osint_threatfox_last_seen",
    }


def test_threatfox_forbidden_fields_never_projected(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env),
        tmp_path,
        clock,
        post=FakePost(_threatfox_hitResponder([_threatfox_entry(0)])),
    )
    result = adapter.lookup(_observable("domain", "evil-example.com"), context)
    text = json.dumps([e.model_dump(mode="json") for e in result.evidence], ensure_ascii=False)
    assert "abuse 않았습니다" not in text and "never projected" not in text
    assert "example.invalid" not in text and "Alias" not in text


@pytest.mark.parametrize(
    "http_status,reason",
    [(401, "auth_error"), (403, "auth_error"), (429, "rate_limited"), (500, "api_error")],
)
def test_threatfox_http_errors(tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch, http_status: int, reason: str) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env),
        tmp_path,
        clock,
        post=FakePost(lambda u, b, h, t: (http_status, {}, b"{}")),
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["threatfox"] == {
        "status": "unavailable", "reason": reason, "requests_sent": 1,
        "query_target": "example.com", "response_ref": bundle["sources"]["threatfox"]["response_ref"],
        "response_sha256": bundle["sources"]["threatfox"]["response_sha256"],
        "collected_at": bundle["sources"]["threatfox"]["collected_at"],
    }
    assert all(e.predicate != "osint_threatfox_match" for e in result.evidence)


def test_threatfox_timeout_and_malformed(tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    import socket as socketlib

    clock = ManualClock()
    settings = _settings_with_key(monkeypatch, clean_env)

    def _boom(url: str, body: bytes, headers: dict[str, str], timeout: float) -> Any:
        raise socketlib.timeout("timed out")

    adapter, context = _quiet_adapter(settings, tmp_path, clock, post=FakePost(_boom))
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["threatfox"]["reason"] == "timeout"

    adapter2, context2 = _quiet_adapter(
        settings, tmp_path, clock, post=FakePost(lambda u, b, h, t: (200, {}, b"{not json"))
    )
    result2 = adapter2.lookup(_observable("domain", "example.com"), context2)
    bundle2 = json.loads((Path(context2.capture_dir) / str(result2.response_ref)).read_bytes())
    assert bundle2["sources"]["threatfox"]["reason"] == "malformed_response"


def test_threatfox_no_result_is_not_found_without_evidence(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env), tmp_path, clock, post=FakePost(_not_found_post)
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["threatfox"]["status"] == "not_found"
    assert not [e for e in result.evidence if e.source_group == "threatfox"]


# ---------------------------------------------------------------------------
# §35.5 RDAP
# ---------------------------------------------------------------------------


def _rdap_domain_doc(**overrides: Any) -> dict[str, Any]:
    doc = {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2019-04-12T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-04-12T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-02T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
            }
        ],
        "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
    }
    doc.update(overrides)
    return doc


def test_rdap_domain_projection(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    get = FakeGet(lambda u, t: (200, {"Date": "Mon, 22 Sep 2026 00:00:00 GMT"}, json.dumps(_rdap_domain_doc()).encode()))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert get.calls[0]["url"] == f"{RDAP_ORIGIN}/domain/example.com"
    by_pred = {e.predicate: e.value for e in result.evidence if e.source_group == "rdap"}
    assert by_pred["osint_rdap_registration_date"] == "2019-04-12T00:00:00Z"
    assert by_pred["osint_rdap_expiration_date"] == "2027-04-12T00:00:00Z"
    assert by_pred["osint_rdap_last_changed"] == "2024-01-02T00:00:00Z"
    assert by_pred["osint_rdap_registrar"] == "Example Registrar"
    assert by_pred["osint_rdap_status"] == "active"
    assert sorted(e.value for e in result.evidence if e.predicate == "osint_rdap_nameserver") == [
        "a.iana-servers.net", "b.iana-servers.net",
    ]


def test_rdap_status_and_nameservers_capped_at_ten(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    doc = _rdap_domain_doc(
        status=[f"s{i}" for i in range(12)],
        nameservers=[{"ldhName": f"ns{i}.example.com"} for i in range(12)],
    )
    get = FakeGet(lambda u, t: (200, {}, json.dumps(doc).encode()))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert sum(1 for e in result.evidence if e.predicate == "osint_rdap_status") == 10
    assert sum(1 for e in result.evidence if e.predicate == "osint_rdap_nameserver") == 10


def test_rdap_ip_paths(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    seen: list[str] = []

    def _respond(url: str, timeout: float) -> Any:
        seen.append(url)
        return 200, {}, json.dumps({"objectClassName": "ip network", "events": []}).encode()

    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=FakeGet(_respond))
    adapter.lookup(_observable("ipv4", "1.1.1.1"), context)
    adapter.lookup(_observable("ipv6", "2606:4700:4700::1111"), context)
    assert seen == [
        f"{RDAP_ORIGIN}/ip/1.1.1.1",
        f"{RDAP_ORIGIN}/ip/{__import__('urllib.parse', fromlist=['quote']).quote('2606:4700:4700::1111', safe='')}",
    ]


def test_rdap_valid_https_redirect_followed_once(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    calls: list[str] = []

    def _respond(url: str, timeout: float) -> Any:
        calls.append(url)
        if len(calls) == 1:
            return 301, {"Location": "https://auth.example.net/rdap/domain/example.com"}, b""
        return 200, {}, json.dumps(_rdap_domain_doc()).encode()

    fake = FakeGet(_respond)
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=fake)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert fake.calls[0]["url"] == f"{RDAP_ORIGIN}/domain/example.com"
    assert fake.calls[1]["url"] == "https://auth.example.net/rdap/domain/example.com"
    assert result.status == "ok"
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["rdap"]["authority_host"] == "auth.example.net"
    assert bundle["sources"]["rdap"]["bootstrap_host"] == "rdap.org"


@pytest.mark.parametrize("location", ["http://auth.example.net/x", "https://localhost/x", "https://x.test/x", "/relative"])
def test_rdap_unsafe_redirect_refused(tmp_path: Path, clean_env: None, location: str) -> None:
    clock = ManualClock()
    get = FakeGet(lambda u, t: (301, {"Location": location}, b"") if "rdap.org" in u else (200, {}, b"{}"))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert get.calls[0]["url"] == f"{RDAP_ORIGIN}/domain/example.com"
    assert all(not call["url"].startswith(RDAP_ORIGIN) for call in get.calls[1:])
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["rdap"]["status"] == "unavailable"
    assert bundle["sources"]["rdap"]["reason"] == "unsafe_redirect"


def test_rdap_second_redirect_refused(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    get = FakeGet(lambda u, t: (301, {"Location": "https://auth.example.net/next"}, b""))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert [call["url"] for call in get.calls[:2]] == [
        f"{RDAP_ORIGIN}/domain/example.com",
        "https://auth.example.net/next",
    ]
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["rdap"]["reason"] == "redirect_limit"


def test_rdap_lowercase_header_names_followed(tmp_path: Path, clean_env: None) -> None:
    """Live-smoke lesson: real servers (Cloudflare) send lowercase
    ``location``/``date``; header lookup must be case-insensitive."""

    clock = ManualClock()
    calls: list[str] = []

    def _respond(url: str, timeout: float) -> Any:
        calls.append(url)
        if len(calls) == 1:
            return 301, {"location": "https://auth.example.net/rdap/domain/example.com"}, b""
        return 200, {"date": "Mon, 22 Sep 2026 00:00:00 GMT"}, json.dumps(_rdap_domain_doc()).encode()

    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=FakeGet(_respond))
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert calls[0].startswith(RDAP_ORIGIN)
    assert calls[1] == "https://auth.example.net/rdap/domain/example.com"
    assert result.status == "ok"
    rdap_evidence = [e for e in result.evidence if e.source_group == "rdap"]
    assert rdap_evidence and all(e.observed_at == "Mon, 22 Sep 2026 00:00:00 GMT" for e in rdap_evidence)


def test_rdap_404_timeout_malformed(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    settings = _settings_no_key(clean_env)

    adapter, context = _quiet_adapter(settings, tmp_path, clock, get=FakeGet(lambda u, t: (404, {}, b"{}")))
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["rdap"]["status"] == "not_found"

    import socket as socketlib

    def _boom(url: str, timeout: float) -> Any:
        raise socketlib.timeout("timed out")

    adapter2, context2 = _quiet_adapter(settings, tmp_path, clock, get=FakeGet(_boom))
    result2 = adapter2.lookup(_observable("domain", "example.com"), context2)
    bundle2 = json.loads((Path(context2.capture_dir) / str(result2.response_ref)).read_bytes())
    assert bundle2["sources"]["rdap"]["reason"] == "timeout"

    adapter3, context3 = _quiet_adapter(settings, tmp_path, clock, get=FakeGet(lambda u, t: (200, {}, b"nope")))
    result3 = adapter3.lookup(_observable("domain", "example.com"), context3)
    bundle3 = json.loads((Path(context3.capture_dir) / str(result3.response_ref)).read_bytes())
    assert bundle3["sources"]["rdap"]["reason"] == "malformed_response"


def test_rdap_skipped_without_registrable_domain(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    get = FakeGet(lambda u, t: (200, {}, b"{}"))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    query = _observable("domain", "co.uk")
    assert query.normalized_value == "co.uk"
    result = adapter.lookup(query, context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["rdap"]["status"] == "skipped"
    assert bundle["sources"]["rdap"]["reason"] == "no_registrable_domain"
    assert bundle["sources"]["rdap"]["requests_sent"] == 0


# ---------------------------------------------------------------------------
# §35.6 DNS
# ---------------------------------------------------------------------------


def test_dns_all_types_projected(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    dns = FakeDns(
        {
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
            ("example.com", "MX"): ["mail.example.com"],
            ("example.com", "NS"): ["a.iana-servers.net"],
            ("example.com", "TXT"): ["v=spf1 -all"],
        }
    )
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, dns=dns)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert [c["rdtype"] for c in dns.calls] == ["A", "AAAA", "MX", "NS", "TXT"]
    by_pred = {e.predicate: e.value for e in result.evidence if e.source_group == "dns"}
    assert by_pred == {
        "osint_dns_a": "93.184.216.34",
        "osint_dns_aaaa": "2606:2800:220:1:248:1893:25c8:1946",
        "osint_dns_mx": "mail.example.com",
        "osint_dns_ns": "a.iana-servers.net",
        "osint_dns_txt": "v=spf1 -all",
    }


def test_dns_nxdomain_and_noanswer_are_not_found(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_no_key(clean_env), tmp_path, clock, dns=FakeDns({("example.com", "A"): _nxdomain()})
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert result.status in ("not_found", "unavailable")
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["dns"]["status"] == "not_found"


def test_dns_timeout_unavailable(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_no_key(clean_env), tmp_path, clock, dns=FakeDns({("example.com", "A"): _lifetime_expired()})
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["dns"]["status"] == "unavailable"
    assert bundle["sources"]["dns"]["reason"] == "timeout"


def test_dns_total_budget_shared(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()

    def _slow(name: str, rdtype: str, lifetime: float) -> list[str]:
        assert lifetime <= 5.0
        clock.advance(4.0)
        return ["93.184.216.34"] if rdtype == "A" else (_ for _ in ()).throw(_noanswer())

    adapter, context = _quiet_adapter(
        _settings_no_key(clean_env), tmp_path, clock, dns=FakeDns({}), config=_config(dns_timeout_s=5.0)
    )
    adapter._dns_resolve = _slow  # type: ignore[method-assign]
    result = adapter.lookup(_observable("domain", "example.com"), context)
    # A answered, then the shared 5 s budget is exhausted: remaining types
    # cannot start safely.
    assert any(e.predicate == "osint_dns_a" for e in result.evidence)


def test_dns_max_ten_values_per_type(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    dns = FakeDns({("example.com", "A"): [f"10.0.0.{i}" for i in range(15)]})
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, dns=dns)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert sum(1 for e in result.evidence if e.predicate == "osint_dns_a") == 10


def test_dns_txt_over_512_not_partially_projected(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    dns = FakeDns({("example.com", "TXT"): ["short", "y" * 600]})
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, dns=dns)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    values = [e.value for e in result.evidence if e.predicate == "osint_dns_txt"]
    assert values == ["short"]
    capture = json.loads((Path(context.capture_dir) / ("osint_dns_" + _digest_of(result, "example.com") + ".json")).read_bytes())
    assert capture["types"]["TXT"]["omitted_over_512"] == 1


def _digest_of(result: ToolResult, normalized: str) -> str:
    assert result.query_observable_id is not None
    return hashlib.sha256(f"{result.query_observable_id}|{normalized}".encode()).hexdigest()[:16]


def test_dns_no_axfr_or_any(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    dns = FakeDns({("example.com", "A"): ["93.184.216.34"]})
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, dns=dns)
    adapter.lookup(_observable("domain", "example.com"), context)
    assert {c["rdtype"] for c in dns.calls} <= {"A", "AAAA", "MX", "NS", "TXT"}


# ---------------------------------------------------------------------------
# §35.7 CT
# ---------------------------------------------------------------------------


def _ct_entries(count: int, names: list[str] | None = None) -> list[dict[str, Any]]:
    entries = []
    for i in range(count):
        entries.append(
            {
                "issuer_ca_id": 1,
                "not_before": f"2024-01-{(i % 28) + 1:02d}T00:00:00",
                "name_value": "\n".join(names or [f"host{i}.example.com", "example.com"]),
            }
        )
    return entries


def test_ct_query_has_deduplicate(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    seen: list[str] = []

    def _respond(url: str, timeout: float) -> Any:
        seen.append(url)
        return 200, {}, json.dumps([]).encode()

    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=FakeGet(_respond))
    adapter.lookup(_observable("domain", "www.example.com"), context)
    ct_calls = [u for u in seen if u.startswith(CT_ORIGIN)]
    assert len(ct_calls) == 1
    parsed = dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(ct_calls[0].split("?", 1)[1]))
    assert ct_calls[0].startswith(CT_ORIGIN)
    assert parsed["q"] == "%.example.com" and parsed["output"] == "json" and parsed["deduplicate"] == "Y"


def test_ct_nominal_projection(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    get = FakeGet(lambda u, t: (200, {"Date": "Mon, 22 Sep 2026 00:00:00 GMT"}, json.dumps(_ct_entries(3)).encode()))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    result = adapter.lookup(_observable("domain", "www.example.com"), context)
    by_pred = {e.predicate: e.value for e in result.evidence if e.source_group == "certificate_transparency"}
    assert by_pred["osint_ct_certificate_count"] == 3.0
    assert by_pred["osint_ct_first_not_before"] == "2024-01-01T00:00:00"
    assert by_pred["osint_ct_last_not_before"] == "2024-01-03T00:00:00"
    names = sorted(e.value for e in result.evidence if e.predicate == "osint_ct_dns_name")
    assert names == sorted({"example.com", "host0.example.com", "host1.example.com", "host2.example.com"})
    ordered = [e.value for e in result.evidence if e.predicate == "osint_ct_dns_name"]
    assert ordered == sorted(ordered)


def test_ct_empty_is_not_found(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_no_key(clean_env), tmp_path, clock, get=FakeGet(lambda u, t: (200, {}, b"[]"))
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["certificate_transparency"]["status"] == "not_found"


def test_ct_names_dedup_sorted_capped_at_twenty(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    names = [f"host{i:02d}.example.com" for i in range(25)] + ["example.com", "example.com"]
    get = FakeGet(lambda u, t: (200, {}, json.dumps(_ct_entries(1, names)).encode()))
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=get)
    result = adapter.lookup(_observable("domain", "example.com"), context)
    projected = [e.value for e in result.evidence if e.predicate == "osint_ct_dns_name"]
    assert len(projected) == 20
    assert projected == sorted(projected)
    assert len(set(projected)) == 20


def test_ct_exact_limit_allowed_over_limit_refused(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    limit = 2097152
    body_ok = json.dumps([{"not_before": "2024-01-01T00:00:00", "name_value": "example.com"}]).encode()
    body_ok = body_ok + b" " * (limit - len(body_ok))
    assert len(body_ok) == limit
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock, get=FakeGet(lambda u, t: (200, {}, body_ok)))
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["certificate_transparency"]["status"] == "ok"

    adapter2, context2 = _quiet_adapter(
        _settings_no_key(clean_env), tmp_path, clock, get=FakeGet(lambda u, t: (200, {}, body_ok + b" "))
    )
    result2 = adapter2.lookup(_observable("domain", "example.com"), context2)
    bundle2 = json.loads((Path(context2.capture_dir) / str(result2.response_ref)).read_bytes())
    assert bundle2["sources"]["certificate_transparency"]["status"] == "unavailable"
    assert bundle2["sources"]["certificate_transparency"]["reason"] == "response_over_limit"
    assert not [e for e in result2.evidence if e.source_group == "certificate_transparency"]


def test_ct_malformed_and_no_pivot(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_no_key(clean_env), tmp_path, clock, get=FakeGet(lambda u, t: (200, {}, b"nope"))
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    bundle = json.loads((Path(context.capture_dir) / str(result.response_ref)).read_bytes())
    assert bundle["sources"]["certificate_transparency"]["reason"] == "malformed_response"
    assert result.observables == []


# ---------------------------------------------------------------------------
# §35.8 aggregate
# ---------------------------------------------------------------------------


def test_aggregate_ok_when_one_source_positive(tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env),
        tmp_path,
        clock,
        post=FakePost(_threatfox_hitResponder([_threatfox_entry(0)])),
        get=FakeGet(_not_found_get),
        dns=FakeDns({}),
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert result.tool == "osint"
    assert result.status == "ok"
    assert result.reason == (
        "sources:threatfox=ok;rdap=not_found;dns=not_found;certificate_transparency=not_found"
    )
    assert result.observables == []
    bundle_bytes = (Path(context.capture_dir) / str(result.response_ref)).read_bytes()
    assert result.response_sha256 == hashlib.sha256(bundle_bytes).hexdigest()
    assert result.response_ref == f"osint_bundle_{_digest_of(result, 'example.com')}.json"
    bundle = json.loads(bundle_bytes)
    assert bundle["registrable_domain"] == "example.com"
    assert result.requests_sent == sum(s["requests_sent"] for s in bundle["sources"].values())


def test_aggregate_unavailable_when_no_positive_and_one_down(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env),
        tmp_path,
        clock,
        post=FakePost(lambda u, b, h, t: (500, {}, b"{}")),
        get=FakeGet(_not_found_get),
        dns=FakeDns({}),
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert result.status == "unavailable"
    assert result.evidence == []
    assert "threatfox=unavailable" in (result.reason or "")


def test_aggregate_not_found_when_all_absent(
    tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env), tmp_path, clock
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert result.status == "not_found"
    assert result.reason == (
        "sources:threatfox=not_found;rdap=not_found;dns=not_found;certificate_transparency=not_found"
    )
    assert result.evidence == []


def test_aggregate_skipped_for_url(tmp_path: Path, clean_env: None) -> None:
    clock = ManualClock()
    adapter, context = _quiet_adapter(_settings_no_key(clean_env), tmp_path, clock)
    result = adapter.lookup(_observable("url", "https://example.com/x"), context)
    assert result.status == "skipped" and result.requests_sent == 0
    assert result.response_ref is None


def test_no_pivot_anywhere(tmp_path: Path, clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = ManualClock()
    doc = _rdap_domain_doc(nameservers=[{"ldhName": "ns1.evil.example"}])
    adapter, context = _quiet_adapter(
        _settings_with_key(monkeypatch, clean_env),
        tmp_path,
        clock,
        post=FakePost(_threatfox_hitResponder([_threatfox_entry(0)])),
        get=FakeGet(lambda u, t: (200, {}, json.dumps(doc).encode() if "rdap" in u else json.dumps(_ct_entries(2)).encode())),
        dns=FakeDns({("example.com", "A"): ["93.184.216.34"]}),
    )
    result = adapter.lookup(_observable("domain", "example.com"), context)
    assert result.status == "ok" and result.observables == []


# ---------------------------------------------------------------------------
# §36 contracts
# ---------------------------------------------------------------------------


def test_tool_result_osint_valid() -> None:
    result = ToolResult(tool="osint", query_observable_id="obs_1", status="ok", mode="live", requests_sent=1)
    assert result.tool == "osint"


def test_evidence_osint_valid() -> None:
    evidence = Evidence(
        id="ev_probe",
        provenance="OSINT",
        source_kind="osint",
        observable_id="obs_1",
        predicate="osint_dns_a",
        value="1.1.1.1",
        source_ref="cap.json#/dns/a/0",
        observed_at="2026-09-22T00:00:00+00:00",
        match_level="EXACT",
        source_group="dns",
    )
    assert evidence.provenance == "OSINT" and evidence.source_kind == "osint"


@pytest.mark.parametrize(
    "predicate",
    [
        "osint_threatfox_match", "osint_threatfox_threat_type", "osint_threatfox_malware",
        "osint_threatfox_confidence", "osint_threatfox_first_seen", "osint_threatfox_last_seen",
        "osint_rdap_registration_date", "osint_rdap_expiration_date", "osint_rdap_last_changed",
        "osint_rdap_registrar", "osint_rdap_status", "osint_rdap_nameserver",
        "osint_dns_a", "osint_dns_aaaa", "osint_dns_mx", "osint_dns_ns", "osint_dns_txt",
        "osint_ct_certificate_count", "osint_ct_first_not_before", "osint_ct_last_not_before",
        "osint_ct_dns_name",
    ],
)
def test_all_osint_predicates_valid(predicate: str) -> None:
    Evidence(
        id="ev_probe",
        provenance="OSINT",
        source_kind="osint",
        observable_id="obs_1",
        predicate=predicate,  # type: ignore[arg-type]
        value="v",
        source_ref="cap.json#/x",
        observed_at="2026-09-22T00:00:00+00:00",
        match_level="EXACT",
        source_group="dns",
    )


def test_state_and_triage_report_schema_in_sync(project_root: Path) -> None:
    from typing import get_args

    from src.state import Evidence as StateEvidence
    from src.state import ToolResult as StateToolResult

    schema = json.loads((project_root / "schemas" / "triage_report.schema.json").read_text(encoding="utf-8"))
    defs = schema["$defs"]
    assert set(get_args(StateToolResult.model_fields["tool"].annotation)) >= set(defs["ToolResult"]["properties"]["tool"]["enum"])
    assert set(defs["ToolResult"]["properties"]["tool"]["enum"]) >= {"virustotal", "opencti", "urlscan", "osint"}
    assert set(defs["Evidence"]["properties"]["source_kind"]["enum"]) >= {"parser", "virustotal", "opencti", "urlscan", "osint"}
    state_predicates = set(get_args(StateEvidence.model_fields["predicate"].annotation))
    schema_predicates = set(defs["Evidence"]["properties"]["predicate"]["enum"])
    assert state_predicates == schema_predicates


def test_assessment_schema_unchanged(project_root: Path) -> None:
    digest = hashlib.sha256((project_root / "schemas" / "assessment.schema.json").read_bytes()).hexdigest()
    assert digest == "eeb646dcff9c1514c7e01cefcd900437bc372ecb9696c087b4878692c37021a2"


def test_psl_version_archived() -> None:
    assert PSL_VERSION == "1.0.2.20260921"


def test_core_context_tool_hash_is_t19d_frozen() -> None:
    assert tool_schema_sha256() == "d2b97f27ed36177a5db9c89b3357cf6e5e1bbef4723f8a051f5fb792d9fbabe8"

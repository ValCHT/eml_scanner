"""TICKET-11 StateGraph tests.

Non-live tests exercise the graph plumbing with CONTROLLED objects only
(fake clients/adapters, temporary ``.eml`` inputs): controlled states prove
routing and contracts, they are never counted as business results or as
provider observations.

Live tests (``--live``) use the real official runtime and the real adapters:

- a sequential mini-batch over fixtures whose gate decision is recomputed
  from the really parsed email and the really archived INTERNAL vector;
- a constructed benign message carrying ``LIVE_BENIGN_URL`` through the real
  urlscan enrichment and the real FINAL phase;
- a real bounded network interruption (unroutable TEST-NET origin) proving a
  provider outage is recorded and never fatal.

An autouse fixture denies any socket use in non-live tests.
"""

from __future__ import annotations

import json
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from src.config import (
    EgressConfig,
    GateConfig,
    PolicyConfig,
    Settings,
    ToolsConfig,
    load_settings,
    load_yaml_config,
)
from src.gate import decide_gate
from src.graph import (
    Services,
    build_graph,
    build_services,
    plan_opencti_targets,
    plan_url_targets,
    run_email,
)
from src.parsing import ParseLimits, parse_email
from src.reporting import ReportWriteError, validate_report
from src.state import (
    Assessment,
    CallRecord,
    Evidence,
    Link,
    Observable,
    ParsedEmail,
    ToolResult,
    new_state,
)
from src.tools.opencti import OpenCTIAdapter
from src.tools.virustotal import plan_vt_targets

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
EXPECTED_RUNTIME_MODEL = "Qwen/Qwen3.8-27B"

#: Frozen sequential edges (docs/architecture.md §1.2), START/END included.
EXPECTED_PLAIN_EDGES = {
    ("__start__", "parse_email"),
    ("parse_email", "internal_assessment"),
    ("internal_assessment", "complexity_gate"),
    ("virustotal", "opencti"),
    ("opencti", "urlscan"),
    ("urlscan", "rag_lookup"),
    ("rag_lookup", "merge_evidence"),
    ("merge_evidence", "final_assessment"),
    ("final_assessment", "verify"),
    ("verify", "policy"),
    ("policy", "write_report"),
    ("write_report", "__end__"),
}

EXPECTED_NODES = {
    "parse_email",
    "internal_assessment",
    "complexity_gate",
    "virustotal",
    "opencti",
    "urlscan",
    "rag_lookup",
    "merge_evidence",
    "final_assessment",
    "verify",
    "policy",
    "write_report",
}

GATE_REASON_VOCABULARY = {
    "internal_unavailable",
    "low_confidence",
    "low_margin",
    "urls_present",
    "attachments_present",
    "parse_incomplete",
    "content_truncated",
    "essential_visual_unread",
    "model_requests_context",
}


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


# ---------------------------------------------------------------------------
# Controlled helpers (plumbing only, never business results)
# ---------------------------------------------------------------------------


def _vector_with(label: str, confidence: float) -> dict[str, float]:
    """Exact six-probability vector with ``label`` at ``confidence``."""

    labels = ["spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"]
    labels.remove(label)
    share = round((1.0 - confidence) / len(labels), 9)
    values = {name: share for name in labels}
    values[label] = confidence
    drift = round(1.0 - sum(values.values()), 9)
    values[labels[0]] = round(values[labels[0]] + drift, 9)
    return values


def _assessment_payload(vector: dict[str, float] | None = None) -> dict[str, Any]:
    return {
        "probabilities": vector or _vector_with("legitime", 0.93),
        "observations": [],
        "inferences": [],
        "observable_assessments": [],
        "needs_enrichment": False,
        "missing_information": [],
        "decisive_evidence_ids": [],
    }


class FakeLunaClient:
    """Controlled LLM client: no network, no provider observation."""

    def __init__(
        self,
        phase: str,
        payload: dict[str, Any] | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self._phase = phase
        self._payload = payload if payload is not None else _assessment_payload()
        self._fail = fail
        self.calls: list[dict[str, Any]] = []

    def complete_json(
        self,
        messages: list[dict[str, Any]],
        schema: dict[str, Any],
        effort: str,
        max_output_tokens: int,
        deadline: float,
    ) -> tuple[dict[str, Any] | None, CallRecord]:
        self.calls.append(
            {"effort": effort, "max_output_tokens": max_output_tokens, "deadline": deadline}
        )
        if self._fail:
            return None, CallRecord(
                phase=self._phase,  # type: ignore[arg-type]
                status="error",
                attempts=1,
                requested_model="fake",
                reasoning_effort=effort,
            )
        return dict(self._payload), CallRecord(
            phase=self._phase,  # type: ignore[arg-type]
            status="ok",
            attempts=1,
            requested_model="fake",
            returned_model="fake",
            reasoning_effort=effort,
        )


class FakeToolAdapter:
    """Controlled adapter: records calls, returns a typed skipped/unavailable."""

    def __init__(self, tool: str, result: ToolResult | None = None) -> None:
        self.tool = tool
        self.result = result
        self.calls: list[str] = []

    def lookup(self, query: Observable, context: Any) -> ToolResult:
        self.calls.append(query.id)
        if self.result is not None:
            return self.result.model_copy(update={"query_observable_id": query.id})
        return ToolResult(
            tool=self.tool,  # type: ignore[arg-type]
            query_observable_id=query.id,
            status="skipped",
            reason="disabled",
            mode="none",
        )

    def scan(self, query: Observable, context: Any) -> ToolResult:
        return self.lookup(query, context)


def _configs() -> tuple[ToolsConfig, GateConfig, PolicyConfig]:
    tools = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    gate = load_yaml_config(PROJECT_ROOT / "configs" / "gate.yaml", GateConfig)
    policy = load_yaml_config(PROJECT_ROOT / "configs" / "policy.yaml", PolicyConfig)
    assert isinstance(tools, ToolsConfig)
    assert isinstance(gate, GateConfig)
    assert isinstance(policy, PolicyConfig)
    return tools, gate, policy


def _services(
    tmp_path: Path,
    *,
    luna: FakeLunaClient | None = None,
    luna_final: FakeLunaClient | None = None,
    vt: Any = None,
    cti: Any = None,
    urlscan: Any = None,
    egress: EgressConfig | None = None,
    clock: Any = time.monotonic,
    with_key: bool = True,
) -> Services:
    from pydantic import SecretStr

    settings = load_settings(None).model_copy(
        update={
            "RUNS_DIR": tmp_path / "runs",
            "LITELLM_API_KEY": (
                SecretStr("placeholder-key-not-a-real-credential") if with_key else None
            ),
        }
    )
    tools, gate, policy = _configs()
    run_id = str(uuid.uuid4())
    run_dir = Path(settings.RUNS_DIR) / run_id
    return Services(
        settings=settings,
        tools_config=tools,
        gate_config=gate,
        policy_config=policy,
        vt=vt if vt is not None else FakeToolAdapter("virustotal"),
        cti=cti if cti is not None else FakeToolAdapter("opencti"),
        urlscan=urlscan if urlscan is not None else FakeToolAdapter("urlscan"),
        luna=luna,
        luna_final=luna_final,
        egress=egress if egress is not None else EgressConfig(allow_real_urls=False),
        run_dir=run_dir,
        capture_dir=run_dir / "responses",
        deadline=time.monotonic() + 60.0,
        clock=clock,
        started_monotonic=time.monotonic(),
        mode="recorded",
    )


def _write_eml(path: Path, *, text: str = "Bonjour, message de test.", from_addr: str = "a@example.org") -> Path:
    raw = (
        f"From: {from_addr}\n"
        "To: b@example.org\n"
        "Subject: Test POC\n"
        "Date: Fri, 19 Sep 2026 10:00:00 +0000\n"
        "Message-ID: <test-poc@example.org>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        f"{text}\n"
    )
    path.write_bytes(raw.encode("utf-8"))
    return path


def _invoke(services: Services, email: Path, *, source_profile: str = "fixture") -> tuple[dict[str, Any], dict[str, Any]]:
    state = new_state(email.resolve(), source_profile, "a" * 64)  # type: ignore[arg-type]
    graph = build_graph(services)
    final_state = graph.invoke(state, config={"configurable": {"thread_id": state.run_id}})
    report = json.loads(Path(final_state["report_path"]).read_text(encoding="utf-8"))
    return final_state, report


# ---------------------------------------------------------------------------
# Topology and routing (controlled plumbing)
# ---------------------------------------------------------------------------


def test_graph_has_exactly_one_conditional_edge(tmp_path: Path) -> None:
    services = _services(tmp_path)
    graph = build_graph(services)

    drawable = graph.get_graph()
    conditional = {(edge.source, edge.target) for edge in drawable.edges if edge.conditional}
    assert conditional == {
        ("complexity_gate", "verify"),
        ("complexity_gate", "virustotal"),
    }
    plain = {(edge.source, edge.target) for edge in drawable.edges if not edge.conditional}
    assert plain == EXPECTED_PLAIN_EDGES
    assert set(drawable.nodes) == EXPECTED_NODES | {"__start__", "__end__"}

    branches = graph.builder.branches
    assert set(branches) == {"complexity_gate"}
    specs = [spec for mapping in branches.values() for spec in mapping.values()]
    assert len(specs) == 1
    assert specs[0].ends == {"simple": "verify", "complex": "virustotal"}


def test_routing_simple_uses_one_nominal_call_and_no_tools(tmp_path: Path) -> None:
    luna = FakeLunaClient("internal", _assessment_payload(_vector_with("legitime", 0.96)))
    luna_final = FakeLunaClient("final")
    vt = FakeToolAdapter("virustotal")
    cti = FakeToolAdapter("opencti")
    urlscan = FakeToolAdapter("urlscan")
    services = _services(tmp_path, luna=luna, luna_final=luna_final, vt=vt, cti=cti, urlscan=urlscan)
    email = _write_eml(tmp_path / "simple.eml")

    final_state, report = _invoke(services, email)

    assert final_state["gate"].decision == "simple"
    assert final_state["gate"].reasons == []
    assert len(luna.calls) == 1 and luna.calls[0]["effort"] == "medium"
    assert luna_final.calls == []
    assert vt.calls == [] and cti.calls == [] and urlscan.calls == []
    assert final_state["final_call"] is None
    assert report["final_source"] == "internal_copy"
    assert report["final_probabilities"] == report["internal_probabilities"]
    assert [call["phase"] for call in report["llm_calls"]] == ["internal"]


def test_routing_complex_uses_two_nominal_calls_and_all_tool_nodes(tmp_path: Path) -> None:
    luna = FakeLunaClient("internal", _assessment_payload(_vector_with("phishing", 0.90)))
    luna_final = FakeLunaClient("final", _assessment_payload(_vector_with("phishing", 0.92)))
    vt = FakeToolAdapter("virustotal")
    cti = FakeToolAdapter("opencti")
    urlscan = FakeToolAdapter("urlscan")
    services = _services(tmp_path, luna=luna, luna_final=luna_final, vt=vt, cti=cti, urlscan=urlscan)
    email = _write_eml(
        tmp_path / "complex.eml",
        text="Merci de confirmer ici : https://evil.test/verify?token=abc",
    )

    final_state, report = _invoke(services, email)

    assert final_state["gate"].decision == "complex"
    assert "urls_present" in final_state["gate"].reasons
    assert len(luna.calls) == 1 and luna.calls[0]["effort"] == "medium"
    assert len(luna_final.calls) == 1 and luna_final.calls[0]["effort"] == "xhigh"
    # URL + exact sender domain: the bounded deterministic plan (max 4/provider).
    assert len(vt.calls) == 2 and len(cti.calls) == 2 and len(urlscan.calls) == 1
    assert report["final_source"] == "final_llm"
    assert [call["phase"] for call in report["llm_calls"]] == ["internal", "final"]
    assert report["run_status"] == "ok"


def test_plans_are_bounded_ordered_and_url_only() -> None:
    mismatch = Link(
        id="mismatchlink0001",
        part_id="p1",
        raw_value="https://b.test/mm",
        normalized_value="https://b.test/mm",
        role="href",
        hostname="b.test",
        href_display_mismatch=True,
    )
    plain = Link(
        id="plainlink000002",
        part_id="p1",
        raw_value="https://a.test/plain",
        normalized_value="https://a.test/plain",
        role="href",
        hostname="a.test",
    )
    remote = Link(
        id="remotelink000003",
        part_id="p2",
        raw_value="https://track.test/px.gif",
        normalized_value="https://track.test/px.gif",
        role="remote_resource",
        hostname="track.test",
    )
    parsed = ParsedEmail(
        email_sha256="0" * 64,
        raw_size_bytes=1,
        input_format="rfc822",
        links=[mismatch, plain, remote],
    )

    def _observable(
        index: int, obs_type: str, value: str, source_ref: str, roles: list[str]
    ) -> Observable:
        return Observable(
            id=f"obs_{index:064d}",
            value=value,
            normalized_value=value,
            type=obs_type,  # type: ignore[arg-type]
            roles=roles,  # type: ignore[arg-type]
            provenance="INTERNE",
            source_ref=source_ref,
        )

    observables = [
        _observable(1, "url", "https://a.test/plain", "p1:link:plainlink000002", ["link_target"]),
        _observable(2, "url", "https://b.test/mm", "p1:link:mismatchlink0001", ["link_target"]),
        _observable(3, "url", "https://track.test/px.gif", "p2:link:remotelink000003", ["link_target"]),
        _observable(4, "sha256", "f" * 64, "p3:attachment:9", ["attachment"]),
        _observable(5, "domain", "example.org", "p0:header:from", ["sender"]),
        _observable(6, "email", "b@example.org", "p0:header:to", ["recipient"]),
    ]

    vt_targets = plan_vt_targets(parsed, observables, 4)
    assert [target.type for target in vt_targets] == ["sha256", "url", "url", "domain"]
    assert vt_targets[1].value == "https://b.test/mm"  # mismatch first
    assert all("track.test" not in target.value for target in vt_targets)

    cti_targets = plan_opencti_targets(parsed, observables, 4)
    assert [target.type for target in cti_targets] == ["sha256", "url", "url", "domain"]
    assert cti_targets[1].value == "https://b.test/mm"

    url_targets = plan_url_targets(parsed, observables, 1)
    assert [target.value for target in url_targets] == ["https://b.test/mm"]

    assert plan_vt_targets(parsed, observables, 4) == vt_targets  # deterministic
    assert plan_url_targets(parsed, observables, 1) == url_targets


def test_parse_failure_produces_honest_report(tmp_path: Path) -> None:
    services = _services(tmp_path)  # no clients: nothing may be called
    _, report = _invoke(services, tmp_path / "does-not-exist.eml")

    assert report["run_status"] == "error"
    assert report["email_sha256"] is None
    assert report["internal_verdict"] is None and report["final_verdict"] is None
    assert report["final_probabilities"] is None
    assert report["recommended_action"] == "REVIEW"
    assert report["gate_decision"] == "complex"
    assert "parse_incomplete" in report["gate_reasons"]
    assert any(issue["code"] == "parse_error" for issue in report["verification_warnings"])
    assert validate_report(report) == []


def test_malformed_fixture_does_not_crash_and_stays_honest(tmp_path: Path) -> None:
    luna = FakeLunaClient("internal", _assessment_payload())
    services = _services(tmp_path, luna=luna, luna_final=FakeLunaClient("final"))
    email = FIXTURES / "malformed_reasonable.eml"

    final_state, report = _invoke(services, email)

    assert final_state["parsed"] is not None  # the parser keeps what it can read
    assert report["email_sha256"] is not None
    assert report["run_status"] in ("ok", "degraded")
    assert validate_report(report) == []


def test_tool_outage_is_recorded_and_not_fatal(tmp_path: Path) -> None:
    """A real refusal path (merge refusal) stays explicit and non-fatal."""

    ok_without_proof = ToolResult(
        tool="virustotal",
        query_observable_id=None,
        status="ok",
        mode="recorded",  # no response_ref/response_sha256: positive evidence refused
    )
    vt = FakeToolAdapter("virustotal", ok_without_proof)
    luna = FakeLunaClient("internal", _assessment_payload(_vector_with("phishing", 0.90)))
    services = _services(tmp_path, luna=luna, luna_final=FakeLunaClient("final"), vt=vt)
    email = _write_eml(tmp_path / "merge-refusal.eml", text="https://evil.test/x")

    final_state, report = _invoke(services, email)

    assert any(
        issue["code"] == "evidence_merge_refused" for issue in report["unsupported_claims"]
    )
    assert report["recommended_action"] == "ESCALATE"  # critical integrity violation
    assert report["run_status"] in ("ok", "degraded")


def test_no_llm_attempt_without_credentials(tmp_path: Path) -> None:
    """A missing LITELLM_API_KEY refuses the phase WITHOUT any request."""

    luna = FakeLunaClient("internal")
    luna_final = FakeLunaClient("final")
    services = _services(
        tmp_path, luna=luna, luna_final=luna_final, with_key=False
    )
    email = _write_eml(tmp_path / "keyless.eml")

    _, report = _invoke(services, email)

    assert luna.calls == [] and luna_final.calls == []
    assert any(
        issue["code"] == "internal_not_configured"
        for issue in report["verification_warnings"]
    )
    assert report["run_status"] == "error"
    assert report["final_source"] == "none"
    assert report["llm_calls"] == []


def test_report_write_refusal_is_raised(tmp_path: Path) -> None:
    services = _services(tmp_path, luna=FakeLunaClient("internal"))
    services.run_dir.mkdir(parents=True)
    (services.run_dir / "report.json").write_text("{}", encoding="utf-8")
    email = _write_eml(tmp_path / "simple.eml")

    with pytest.raises(ReportWriteError):
        _invoke(services, email)


def test_timings_and_provenance_are_recorded(tmp_path: Path) -> None:
    services = _services(
        tmp_path,
        luna=FakeLunaClient("internal", _assessment_payload(_vector_with("phishing", 0.90))),
        luna_final=FakeLunaClient("final", _assessment_payload(_vector_with("phishing", 0.90))),
    )
    email = _write_eml(tmp_path / "timings.eml", text="https://evil.test/x")
    _, report = _invoke(services, email)

    timings = report["timings"]
    phase_sum = sum(
        value for name, value in timings.items() if name != "total_ms"
    )
    assert timings["total_ms"] + 0.02 >= phase_sum
    assert timings["total_ms"] > 0
    assert all(value >= 0 for value in timings.values())

    mapping = {"parser": "INTERNE", "virustotal": "OSINT", "opencti": "OSINT", "urlscan": "SANDBOX"}
    for entry in report["evidence"]:
        assert entry["source_kind"] in mapping
        assert entry["provenance"] == mapping[entry["source_kind"]]
    assert report["reproducibility"]["config_sha256"] == "a" * 64
    assert report["reproducibility"]["mode"] == "recorded"


def test_savers_are_per_graph_and_hold_the_run_thread(tmp_path: Path) -> None:
    services = _services(tmp_path, luna=FakeLunaClient("internal"))
    first = build_graph(services)
    second = build_graph(services)
    assert isinstance(first.checkpointer, InMemorySaver)
    assert first.checkpointer is not second.checkpointer

    email = _write_eml(tmp_path / "saver.eml")
    state = new_state(email.resolve(), "fixture", "b" * 64)
    first.invoke(state, config={"configurable": {"thread_id": state.run_id}})
    storage = first.checkpointer.storage
    assert list(storage.keys()) == [state.run_id]
    assert list(second.checkpointer.storage.keys()) == []

    import src.graph as graph_module

    assert not any(isinstance(value, InMemorySaver) for value in vars(graph_module).values())


# ---------------------------------------------------------------------------
# Live tests (real runtime / real services)
# ---------------------------------------------------------------------------


def _require_official_runtime(settings: Settings) -> None:
    if settings.LITELLM_MODEL != EXPECTED_RUNTIME_MODEL:
        pytest.fail(
            "official live tests require LITELLM_MODEL="
            f"{EXPECTED_RUNTIME_MODEL!r}; got {settings.LITELLM_MODEL!r}. "
            "Refusing before any artifact mutation or network access."
        )
    if settings.LITELLM_API_KEY is None:
        pytest.fail(
            "LITELLM_API_KEY absent: the live pipeline requires the real "
            "official runtime (BLOCKED — no simulation possible)"
        )


def _recompute_gate_without_model_flag(parsed: Any, report: dict[str, Any], gate_config: GateConfig):
    probabilities = report.get("internal_probabilities")
    if probabilities is None:
        return None
    assessment = Assessment(
        probabilities=probabilities,
        observations=[],
        inferences=[],
        observable_assessments=[],
        needs_enrichment=False,
        missing_information=[],
        decisive_evidence_ids=[],
    )
    return decide_gate(parsed, assessment, gate_config)


@pytest.mark.live
def test_live_graph_mini_batch_follows_real_gate_decisions(tmp_path: Path) -> None:
    """Sequential real runs over three fixtures; every archived gate decision
    is checked against the really parsed email and the really archived
    INTERNAL vector. The missing live SIMPLE branch is traced, never forced."""

    settings = load_settings(None)
    _require_official_runtime(settings)
    output = PROJECT_ROOT / "runs" / "gates" / "G5" / "live_subset"
    output.mkdir(parents=True, exist_ok=True)
    run_settings = settings.model_copy(update={"RUNS_DIR": output / "runs"})
    tools, gate_config, _ = _configs()
    parse_limits = ParseLimits.from_config(tools.parse_limits)

    rows: list[dict[str, Any]] = []
    for name in ("bec_fraud.eml", "malicious_url_redirect.eml", "attachment_suspicious.eml"):
        fixture = FIXTURES / name
        report = run_email(fixture, run_settings, source_profile="fixture")
        report_path = output / "runs" / report["run_id"] / "report.json"
        assert report_path.is_file(), name
        assert validate_report(report) == [], name

        assert report["gate_decision"] in ("simple", "complex"), name
        assert set(report["gate_reasons"]) <= GATE_REASON_VOCABULARY, name
        if report["gate_decision"] == "simple":
            assert report["gate_reasons"] == [], name
            assert report["final_source"] == "internal_copy", name
            assert [call["phase"] for call in report["llm_calls"]] == ["internal"], name
            internal = report["internal_probabilities"]
            assert internal is not None, name
            ordered = sorted(internal.values(), reverse=True)
            assert ordered[0] >= 0.90 and ordered[0] - ordered[1] >= 0.20, name
        else:
            assert report["gate_reasons"], name
            assert report["final_source"] in ("final_llm", "internal_fallback", "none"), name

        parsed_result = parse_email(fixture, parse_limits)
        assert not hasattr(parsed_result, "error"), name
        recomputed = _recompute_gate_without_model_flag(parsed_result, report, gate_config)
        if report["gate_decision"] == "simple":
            assert recomputed is not None and recomputed.decision == "simple", name
        else:
            if recomputed is not None and recomputed.decision == "simple":
                # The only difference is internal.needs_enrichment.
                assert "model_requests_context" in report["gate_reasons"], name

        rows.append(
            {
                "fixture": name,
                "run_id": report["run_id"],
                "gate_decision": report["gate_decision"],
                "gate_reasons": report["gate_reasons"],
                "final_source": report["final_source"],
                "internal_verdict": report["internal_verdict"],
                "final_verdict": report["final_verdict"],
                "run_status": report["run_status"],
                "report_path": str(report_path.relative_to(PROJECT_ROOT)),
            }
        )

    simple_observed = any(row["gate_decision"] == "simple" for row in rows)
    receipt = {
        "mode": "live",
        "model": settings.LITELLM_MODEL,
        "fixtures": [row["fixture"] for row in rows],
        "rows": rows,
        "simple_path_live_observed": simple_observed,
        "limitations": (
            []
            if simple_observed
            else [
                "No live mini-batch fixture took the SIMPLE branch in this run; "
                "the SIMPLE branch is proven by controlled plumbing tests and by "
                "the frozen R1-R3 recomputation. Non-blocking before G6."
            ]
        ),
    }
    (output / "simple_path_live_observed.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )


@pytest.mark.live
def test_live_benign_url_traverses_real_enrichment_and_final(tmp_path: Path) -> None:
    """A constructed benign message with LIVE_BENIGN_URL goes through the real
    urlscan enrichment and the real FINAL phase. The operator approvals are
    explicit in-memory EgressConfig values; configs/tools.yaml stays
    safe-by-default. One unlisted fixture submission, never public."""

    settings = load_settings(None)
    _require_official_runtime(settings)
    if settings.URLSCAN_API_KEY is None:
        pytest.fail("URLSCAN_API_KEY absent: the real enrichment cannot run")
    if not settings.LIVE_BENIGN_URL:
        pytest.fail("LIVE_BENIGN_URL absent: nothing can be fabricated")

    from urllib.parse import urlparse

    host = (urlparse(settings.LIVE_BENIGN_URL).hostname or "").lower().rstrip(".")
    approved = EgressConfig(
        allow_real_urls=True,
        approved_services=["urlscan"],
        approved_exact_url_hosts=[host],
    )
    email = _write_eml(
        tmp_path / "benign-url.eml",
        text=(
            "Bonjour, voici la page publique de reference demandee : "
            f"{settings.LIVE_BENIGN_URL}"
        ),
        from_addr="sources@example.org",
    )
    started = time.monotonic()
    state = new_state(email.resolve(), "fixture", "c" * 64)
    services = build_services(
        settings.model_copy(update={"RUNS_DIR": tmp_path / "runs"}),
        source_profile="fixture",
        run_id=state.run_id,
        started_monotonic=started,
        egress=approved,
    )
    graph = build_graph(services)
    final_state = graph.invoke(state, config={"configurable": {"thread_id": state.run_id}})
    report = json.loads(Path(final_state["report_path"]).read_text(encoding="utf-8"))

    assert report["gate_decision"] == "complex"
    assert "urls_present" in report["gate_reasons"]
    urlscan_results = report["enrichment"]["urlscan"]
    assert len(urlscan_results) == 1
    result = urlscan_results[0]
    assert result["status"] == "ok", (result["status"], result["reason"])
    assert result["visibility"] == "unlisted"
    final_urls = [
        entry for entry in result["evidence"] if entry["predicate"] == "sandbox_final_url"
    ]
    assert len(final_urls) == 1 and final_urls[0]["value"] == settings.LIVE_BENIGN_URL
    assert final_urls[0]["provenance"] == "SANDBOX"
    assert final_urls[0]["match_level"] == "EXACT"
    assert result["response_ref"]
    captured = services.capture_dir / result["response_ref"]
    assert captured.is_file()
    assert report["final_source"] in ("final_llm", "internal_fallback"), report["final_source"]
    if report["final_source"] == "final_llm":
        assert [call["phase"] for call in report["llm_calls"]] == ["internal", "final"]
        assert report["llm_calls"][-1]["status"] == "ok"
        assert report["llm_calls"][-1]["returned_model"] == EXPECTED_RUNTIME_MODEL
    sandbox_evidence = [
        entry for entry in report["evidence"] if entry["provenance"] == "SANDBOX"
    ]
    assert sandbox_evidence
    assert validate_report(report) == []

    evidence_dir = PROJECT_ROOT / "runs" / "gates" / "G5" / "live_benign_url"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / report["run_id"]
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(services.run_dir, target)
    (evidence_dir / "live_benign_url_summary.json").write_text(
        json.dumps(
            {
                "run_id": report["run_id"],
                "benign_url": settings.LIVE_BENIGN_URL,
                "urlscan_status": result["status"],
                "urlscan_visibility": result["visibility"],
                "final_source": report["final_source"],
                "run_status": report["run_status"],
                "report": str((target / "report.json").relative_to(PROJECT_ROOT)),
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


@pytest.mark.live
def test_live_network_interruption_is_bounded_and_nonfatal(tmp_path: Path) -> None:
    """A REAL bounded network interruption against an unroutable TEST-NET
    origin (RFC 5737, 192.0.2.0/24): the real OpenCTI adapter attempt is
    bounded by the deadline, recorded as ``unavailable`` with a transport
    cause and zero evidence, and the pipeline still completes and writes its
    report. The LLM phases are controlled stubs so this test isolates the
    service interruption (no provider observation is fabricated)."""

    tools, _, _ = _configs()
    interrupt_config = tools.opencti.model_copy(update={"phase_timeout_s": 1.0})
    interrupt_settings = load_settings(None).model_copy(
        update={"OPENCTI_URL": "https://192.0.2.1/", "RUNS_DIR": tmp_path / "runs"}
    )
    adapter = OpenCTIAdapter(interrupt_settings, interrupt_config)
    from src.tools import ToolContext

    context = ToolContext(
        run_id=str(uuid.uuid4()),
        source_profile="fixture",
        deadline=time.monotonic() + 1.0,
        egress=EgressConfig(
            allow_real_urls=False,
            approved_services=["opencti"],
            approved_exact_url_hosts=[],
        ),
        capture_dir=tmp_path / "responses",
        mode="live",
    )
    observable = Observable(
        id="obs_" + "1" * 64,
        value="example.com",
        normalized_value="example.com",
        type="domain",
        roles=["sender"],
        provenance="INTERNE",
        source_ref="p0:header:from",
    )
    started = time.monotonic()
    result = adapter.lookup(observable, context)
    elapsed = time.monotonic() - started

    assert result.status == "unavailable"
    assert result.reason in ("timeout", "deadline", "api_error", "connection_error")
    assert result.requests_sent == 1
    assert result.evidence == [] and result.observables == []
    assert elapsed <= 5.0, f"bounded interruption exceeded 5s: {elapsed:.2f}s"

    # The same outage must not stop the graph from completing a real report.
    # needs_enrichment=True forces the COMPLEX branch so the OpenCTI node runs.
    forced_complex = _assessment_payload(_vector_with("phishing", 0.90))
    forced_complex["needs_enrichment"] = True
    services = _services(
        tmp_path,
        luna=FakeLunaClient("internal", forced_complex),
        luna_final=FakeLunaClient("final", _assessment_payload(_vector_with("phishing", 0.92))),
        cti=adapter,
        egress=EgressConfig(
            allow_real_urls=False,
            approved_services=["opencti"],
            approved_exact_url_hosts=[],
        ),
    )
    email = _write_eml(
        tmp_path / "interruption.eml",
        text="Aucun lien, message suspect.",
        from_addr="sender@example.com",
    )
    run_started = time.monotonic()
    _, report = _invoke(services, email)
    run_elapsed = time.monotonic() - run_started

    outages = [
        entry for entry in report["enrichment"]["opencti"] if entry["status"] == "unavailable"
    ]
    assert outages, report["enrichment"]["opencti"]
    assert outages[0]["reason"] is not None
    assert report["gate_decision"] in ("simple", "complex")
    assert validate_report(report) == []
    assert run_elapsed <= 60.0

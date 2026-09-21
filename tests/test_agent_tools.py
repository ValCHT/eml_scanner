"""T19A/B deterministic tool-execution tests.

Real adapter classes are used where the call is refused BEFORE any network
exchange (egress/privacy/service-approval gates) so the refusal contract is
verified against the real code path without performing a request. Stub
adapters are used for control-flow cases; they are never reported as live
evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.agent.models import DEFAULT_AGENT_LIMITS, AgentLimits
from src.agent.tools import (
    AGENT_TOOLS,
    ProviderAdapterSet,
    ProviderToolExecutor,
    execution_payload,
    normalize_result_payload,
    parse_finalize_arguments,
)
from src.config import ToolsConfig, load_settings, load_yaml_config
from src.evidence import merge_evidence
from src.parsing import ParseLimits, ParsedEmail, parse_email
from src.state import Assessment, Evidence, Observable, ToolResult
from src.tools import ToolContext
from src.tools.opencti import OpenCTIAdapter
from src.tools.urlscan import UrlscanAdapter
from src.tools.virustotal import VirusTotalAdapter

CANARY = "akml-canary-0123456789abcdefDONOTLEAK"
OBSERVED_AT = "2026-09-21T12:00:00+00:00"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def parsed_email(project_root: Path) -> ParsedEmail:
    parsed = parse_email(
        project_root / "tests" / "fixtures" / "malicious_url_redirect.eml",
        ParseLimits(),
    )
    assert isinstance(parsed, ParsedEmail)
    return parsed


@pytest.fixture()
def phishing_simple_email(project_root: Path) -> ParsedEmail:
    parsed = parse_email(
        project_root / "tests" / "fixtures" / "phishing_simple.eml",
        ParseLimits(),
    )
    assert isinstance(parsed, ParsedEmail)
    return parsed


@pytest.fixture()
def tools_config(project_root: Path) -> ToolsConfig:
    config = load_yaml_config(project_root / "configs" / "tools.yaml", ToolsConfig)
    assert isinstance(config, ToolsConfig)
    return config


def _observable_by(parsed: ParsedEmail, **criteria: Any) -> Observable:
    for observable in parsed.observables:
        if all(getattr(observable, key) == value for key, value in criteria.items()):
            return observable
    raise AssertionError(f"no observable matching {criteria!r}")


def _observable_by_role(parsed: ParsedEmail, role: str) -> Observable:
    for observable in parsed.observables:
        if role in observable.roles:
            return observable
    raise AssertionError(f"no observable carrying role {role!r}")


def make_ok_result(
    tool: str,
    observable_id: str,
    *,
    evidence: list[Evidence] | None = None,
    observables: list[Observable] | None = None,
) -> ToolResult:
    return ToolResult(
        tool=tool,  # type: ignore[arg-type]
        query_observable_id=observable_id,
        status="ok",
        evidence=evidence or [],
        observables=observables or [],
        response_sha256="a" * 64,
        response_ref=f"{tool}/capture.json",
        collected_at=OBSERVED_AT,
        mode="live",
        elapsed_ms=1.0,
        requests_sent=1,
    )


def make_evidence(
    prefix: str,
    *,
    observable_id: str | None,
    source_kind: str = "virustotal",
    provenance: str = "OSINT",
    value: Any = 1.0,
) -> Evidence:
    return Evidence(
        id=f"ev_{prefix}",
        provenance=provenance,  # type: ignore[arg-type]
        source_kind=source_kind,  # type: ignore[arg-type]
        observable_id=observable_id,
        predicate="vt_malicious_count",  # type: ignore[arg-type]
        value=value,
        source_ref="response.json:/data/attributes/last_analysis_stats/malicious",
        observed_at=OBSERVED_AT,
        match_level="EXACT",
        source_group="virustotal",
    )


class RecordingAdapter:
    """Stub typed adapter: records every call and returns canned results."""

    def __init__(self, factory: Any):
        self.calls: list[tuple[Observable, ToolContext]] = []
        self._factory = factory

    def _invoke(self, query: Observable, context: ToolContext) -> ToolResult:
        self.calls.append((query, context))
        return self._factory(query, context)

    def lookup(self, query: Observable, context: ToolContext) -> ToolResult:
        return self._invoke(query, context)

    def scan(self, query: Observable, context: ToolContext) -> ToolResult:
        return self._invoke(query, context)


def _unavailable(query: Observable, _context: ToolContext, reason: str = "timeout") -> ToolResult:
    return ToolResult(
        tool="virustotal",
        query_observable_id=query.id,
        status="unavailable",
        reason=reason,
        mode="none",
        requests_sent=0,
    )


def _executor(
    parsed: ParsedEmail,
    adapters: ProviderAdapterSet,
    tools_config: ToolsConfig,
    *,
    egress: Any = None,
    limits: AgentLimits | None = None,
) -> ProviderToolExecutor:
    import time

    return ProviderToolExecutor(
        parsed=parsed,
        adapters=adapters,
        tools_config=tools_config,
        run_id="run-test",
        source_profile="fixture",
        egress=egress if egress is not None else tools_config.egress,
        capture_dir=Path("."),
        deadline=time.monotonic() + 60,
        limits=limits if limits is not None else DEFAULT_AGENT_LIMITS,
    )


def _call(tool: str, observable_id: str, call_id: str = "call_1") -> Any:
    from src.agent.models import ToolCall

    return ToolCall(
        call_id=call_id,
        name=tool,
        arguments_raw=json.dumps({"observable_id": observable_id}),
        arguments={"observable_id": observable_id},
    )


# ---------------------------------------------------------------------------
# Schema contract
# ---------------------------------------------------------------------------


def test_exact_tool_set_and_observable_id_only() -> None:
    names = [tool["function"]["name"] for tool in AGENT_TOOLS]
    assert names == [
        "lookup_virustotal",
        "lookup_opencti",
        "scan_urlscan",
        "finalize_assessment",
    ]
    for tool in AGENT_TOOLS:
        function = tool["function"]
        parameters = function["parameters"]
        assert parameters["additionalProperties"] is False
        if function["name"] == "finalize_assessment":
            assert parameters["required"] == ["assessment"]
            assert set(parameters["properties"]) == {"assessment"}
        else:
            assert parameters["required"] == ["observable_id"]
            assert set(parameters["properties"]) == {"observable_id"}


# ---------------------------------------------------------------------------
# Execution and typed refusals
# ---------------------------------------------------------------------------


def test_valid_observable_executes_against_the_typed_adapter(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    url = _observable_by(parsed_email, type="url")
    vt = RecordingAdapter(lambda query, _ctx: make_ok_result("virustotal", query.id))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    execution = executor.execute(_call("lookup_virustotal", url.id))
    assert execution.outcome == "executed"
    assert execution.provider_status == "ok"
    assert [query.id for query, _ctx in vt.calls] == [url.id]
    assert executor.provider_tool_call_count == 1


def test_unknown_observable_id_is_a_typed_refusal_with_zero_provider_request(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    vt = RecordingAdapter(lambda query, _ctx: make_ok_result("virustotal", query.id))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    execution = executor.execute(_call("lookup_virustotal", "obs_invented_by_the_model"))
    assert execution.outcome == "refused"
    assert execution.refusal_reason == "unknown_observable_id"
    assert vt.calls == []
    assert executor.provider_tool_call_count == 0


def test_wrong_observable_type_is_preserved_honestly(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    domain = _observable_by(parsed_email, type="domain")

    def urlscan_factory(query: Observable, _ctx: ToolContext) -> ToolResult:
        # Same honest behavior as the real submittable_url() gate.
        return ToolResult(
            tool="urlscan",
            query_observable_id=query.id,
            status="skipped",
            reason="not_applicable",
            mode="none",
        )

    urlscan = RecordingAdapter(urlscan_factory)
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=urlscan, opencti=urlscan, urlscan=urlscan),
        tools_config,
    )
    execution = executor.execute(_call("scan_urlscan", domain.id))
    assert execution.outcome == "executed"
    assert execution.provider_status == "skipped"
    assert execution.result is not None and execution.result.reason == "not_applicable"
    assert len(urlscan.calls) == 1


def test_adapter_unavailable_is_preserved(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    domain = _observable_by(parsed_email, type="domain")
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    execution = executor.execute(_call("lookup_virustotal", domain.id))
    assert execution.outcome == "executed"
    assert execution.provider_status == "unavailable"
    assert execution.result is not None and execution.result.reason == "timeout"


def test_adapter_exception_becomes_honest_unavailable_never_a_crash(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    domain = _observable_by(parsed_email, type="domain")

    def boom(_query: Observable, _ctx: ToolContext) -> ToolResult:
        raise RuntimeError("adapter exploded")

    vt = RecordingAdapter(boom)
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    execution = executor.execute(_call("lookup_virustotal", domain.id))
    assert execution.outcome == "executed"
    assert execution.provider_status == "unavailable"
    assert execution.result is not None and execution.result.reason == "api_error"
    assert executor.adapter_exceptions


def test_duplicate_tool_call_refused_without_another_provider_request(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    domain = _observable_by(parsed_email, type="domain")
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    first = executor.execute(_call("lookup_virustotal", domain.id, call_id="call_1"))
    second = executor.execute(_call("lookup_virustotal", domain.id, call_id="call_2"))
    assert first.outcome == "executed"
    assert second.outcome == "refused"
    assert second.refusal_reason == "duplicate_tool_call"
    assert len(vt.calls) == 1
    assert executor.provider_tool_call_count == 1
    assert executor.duplicate_refusal_count == 1


def test_urlscan_is_limited_to_one_call(
    phishing_simple_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    urls = [o for o in phishing_simple_email.observables if o.type == "url"]
    assert len(urls) >= 2
    urlscan = RecordingAdapter(
        lambda query, _ctx: ToolResult(
            tool="urlscan",
            query_observable_id=query.id,
            status="unavailable",
            reason="timeout",
            mode="live",
            requests_sent=1,
        )
    )
    executor = _executor(
        phishing_simple_email,
        ProviderAdapterSet(virustotal=urlscan, opencti=urlscan, urlscan=urlscan),
        tools_config,
    )
    first = executor.execute(_call("scan_urlscan", urls[0].id))
    second = executor.execute(_call("scan_urlscan", urls[1].id))
    assert first.outcome == "executed"
    assert second.outcome == "refused"
    assert second.refusal_reason == "urlscan_budget_exhausted"
    assert len(urlscan.calls) == 1
    payload = json.loads(execution_payload(second, 12_000, DEFAULT_AGENT_LIMITS))
    assert payload["message"] == (
        "urlscan budget exhausted (at most 1 submission): no provider call was "
        "made; finalize with the evidence already available"
    )


def test_provider_tool_budget_is_four(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    observables = [
        _observable_by(parsed_email, type="domain"),
        _observable_by(parsed_email, type="ipv4"),
        _observable_by(parsed_email, type="url"),
        _observable_by(parsed_email, type="message_id"),
        _observable_by(parsed_email, type="email", value="livraison@suivi-colis.example"),
    ]
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    outcomes = [
        executor.execute(_call("lookup_virustotal", observable.id, call_id=f"c{i}"))
        for i, observable in enumerate(observables)
    ]
    assert [execution.outcome for execution in outcomes] == [
        "executed",
        "executed",
        "executed",
        "executed",
        "refused",
    ]
    assert outcomes[-1].refusal_reason == "tool_budget_exhausted"
    assert executor.provider_tool_call_count == 4
    payload = json.loads(execution_payload(outcomes[-1], 12_000, DEFAULT_AGENT_LIMITS))
    assert payload["message"] == (
        "provider tool-call budget exhausted (at most 4 provider calls in total): "
        "no provider call was made; finalize with the evidence already available"
    )


def test_tool_budget_refusal_message_matches_applied_limits(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    """PR #17 review: a model-visible refusal derives its numbers from the
    exact AgentLimits the executor enforces, never from the defaults."""

    observables = [
        _observable_by(parsed_email, type="domain"),
        _observable_by(parsed_email, type="ipv4"),
    ]
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    limits = AgentLimits(max_tool_calls=1)
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
        limits=limits,
    )
    first = executor.execute(
        _call("lookup_virustotal", observables[0].id, call_id="c0")
    )
    second = executor.execute(
        _call("lookup_virustotal", observables[1].id, call_id="c1")
    )
    assert first.outcome == "executed"
    assert second.outcome == "refused"
    assert second.refusal_reason == "tool_budget_exhausted"
    assert executor.provider_tool_call_count == 1
    payload = json.loads(
        execution_payload(second, limits.max_tool_result_chars, limits)
    )
    assert "at most 1 provider calls in total" in payload["message"]
    assert "at most 4" not in payload["message"]


def test_urlscan_limit_is_structurally_frozen_to_one() -> None:
    """PR #17 review: max_urlscan_calls cannot take a non-default value, so
    every model-visible urlscan text matches the enforced limit by
    construction."""

    with pytest.raises(ValueError, match="max_urlscan_calls"):
        AgentLimits(max_urlscan_calls=2)
    scan_tool = next(
        tool for tool in AGENT_TOOLS if tool["function"]["name"] == "scan_urlscan"
    )
    assert (
        "at most one submission exists per run"
        in scan_tool["function"]["description"]
    )
    from src.agent.prompt import build_agent_system_prompt

    assert "at most one submission per run" in build_agent_system_prompt()


def test_recipient_observable_is_never_a_query_target(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    recipient = _observable_by_role(parsed_email, "recipient")
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    execution = executor.execute(_call("lookup_opencti", recipient.id))
    assert execution.outcome == "refused"
    assert execution.refusal_reason == "recipient_not_a_query_target"
    assert vt.calls == []


def test_no_arbitrary_ioc_argument_is_ever_accepted(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    from src.agent.models import ToolCall

    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    arbitrary = ToolCall(
        call_id="call_1",
        name="lookup_virustotal",
        arguments_raw='{"url": "http://evil.invalid/steal"}',
        arguments={"url": "http://evil.invalid/steal"},
    )
    execution = executor.execute(arbitrary)
    assert execution.outcome == "refused"
    assert execution.refusal_reason == "unexpected_argument"
    assert vt.calls == []
    assert executor.provider_tool_call_count == 0


def test_unknown_tool_and_finalize_are_refused_by_the_executor(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    unknown = executor.execute(_call("run_shell", "obs_x"))
    finalize = executor.execute(_call("finalize_assessment", "obs_x"))
    assert unknown.refusal_reason == "unknown_tool"
    assert finalize.refusal_reason == "not_an_investigation_tool"
    assert vt.calls == []


def test_malformed_arguments_and_missing_call_id_are_refused(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    from src.agent.models import ToolCall

    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    malformed = ToolCall(
        call_id="call_1",
        name="lookup_virustotal",
        arguments_raw="{not json",
        arguments=None,
        arguments_error="arguments_not_valid_json",
    )
    missing_id = ToolCall(
        call_id=None,
        name="lookup_virustotal",
        arguments_raw='{"observable_id": "obs_x"}',
        arguments={"observable_id": "obs_x"},
    )
    assert executor.execute(malformed).refusal_reason == "malformed_arguments"
    assert executor.execute(missing_id).refusal_reason == "missing_tool_call_id"
    assert vt.calls == []


def test_tool_discovered_observable_is_evidence_only_never_a_query_target(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    domain = _observable_by(parsed_email, type="domain")
    discovered = Observable(
        id="obs_tooldiscovered_1",
        value="cdn.example.net",
        normalized_value="cdn.example.net",
        type="domain",
        roles=["tool_discovery"],
        provenance="OSINT",
        source_ref="response.json:/data/relationships/0",
    )
    evidence = make_evidence("tooldiscovered_1", observable_id=discovered.id)
    vt = RecordingAdapter(
        lambda query, _ctx: make_ok_result(
            "virustotal",
            query.id,
            evidence=[evidence],
            observables=[discovered],
        )
    )
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    first = executor.execute(_call("lookup_virustotal", domain.id))
    assert first.outcome == "executed"
    # The discovered observable is NOT selectable: the executor registry is
    # the original parser registry only (no recursive pivot in T19B).
    pivot = executor.execute(_call("lookup_opencti", discovered.id, call_id="call_2"))
    assert pivot.outcome == "refused"
    assert pivot.refusal_reason == "unknown_observable_id"
    assert len(vt.calls) == 1


def test_egress_and_service_refusals_are_preserved_by_the_real_adapters(
    parsed_email: ParsedEmail,
    tools_config: ToolsConfig,
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """Real adapters, real gates, zero network: refusals stay typed."""

    monkeypatch.setenv("OPENCTI_API_KEY", CANARY)
    monkeypatch.setenv("URLSCAN_API_KEY", CANARY)
    settings = load_settings(None)
    url = _observable_by(parsed_email, type="url")

    vt = VirusTotalAdapter(
        settings, tools_config.virustotal, quota_journal_path=tmp_path / "vt.json"
    )
    cti = OpenCTIAdapter(settings, tools_config.opencti)
    urlscan = UrlscanAdapter(
        settings, tools_config.urlscan, quota_journal_path=tmp_path / "urlscan.json"
    )
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=cti, urlscan=urlscan),
        tools_config,
    )
    vt_execution = executor.execute(_call("lookup_virustotal", url.id, call_id="c1"))
    assert vt_execution.provider_status == "skipped"
    assert vt_execution.result is not None
    assert str(vt_execution.result.reason).startswith("privacy_policy")
    assert vt_execution.result.requests_sent == 0

    cti_execution = executor.execute(_call("lookup_opencti", url.id, call_id="c2"))
    assert cti_execution.provider_status == "skipped"
    assert cti_execution.result is not None
    assert str(cti_execution.result.reason).startswith("privacy_policy")
    assert cti_execution.result.requests_sent == 0

    urlscan_execution = executor.execute(_call("scan_urlscan", url.id, call_id="c3"))
    assert urlscan_execution.provider_status == "skipped"
    assert urlscan_execution.result is not None
    assert str(urlscan_execution.result.reason).startswith("privacy_policy")
    assert urlscan_execution.result.requests_sent == 0


# ---------------------------------------------------------------------------
# Model-facing payloads
# ---------------------------------------------------------------------------


def test_normalized_payload_is_canonical_and_mid_field_never_cut(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    long_value = "x" * 900
    evidence = [
        make_evidence(f"bulk_{index:02d}", observable_id=None, value=long_value)
        for index in range(30)
    ]
    result = make_ok_result("virustotal", parsed_email.observables[0].id, evidence=evidence)
    payload = normalize_result_payload(result, max_chars=3000)
    assert len(payload) <= 3000
    decoded = json.loads(payload)
    assert decoded["truncated"] is True
    assert len(decoded["evidence"]) <= 20
    for entry in decoded["evidence"]:
        assert isinstance(entry["value"], str) and len(entry["value"]) == 900


def test_small_normalized_payload_is_the_whole_tool_result(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    result = make_ok_result(
        "virustotal",
        parsed_email.observables[0].id,
        evidence=[make_evidence("small", observable_id=None)],
    )
    payload = normalize_result_payload(result)
    assert json.loads(payload) == result.model_dump(mode="json")


def test_refusal_payload_is_typed_json(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    vt = RecordingAdapter(lambda query, _ctx: _unavailable(query, _ctx))
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    execution = executor.execute(_call("lookup_virustotal", "obs_unknown"))
    payload = json.loads(execution_payload(execution))
    assert payload["refused"] is True
    assert payload["reason"] == "unknown_observable_id"


# ---------------------------------------------------------------------------
# finalize_assessment validation
# ---------------------------------------------------------------------------


def _valid_assessment() -> dict[str, Any]:
    return {
        "probabilities": {
            "spear_phishing": 0.0,
            "phishing": 0.9,
            "fraude": 0.0,
            "menace": 0.0,
            "spam": 0.0,
            "legitime": 0.1,
        },
        "observations": [],
        "inferences": [],
        "observable_assessments": [],
        "needs_enrichment": False,
        "missing_information": [],
        "decisive_evidence_ids": [],
    }


def test_finalize_valid_assessment_is_accepted_exactly_as_src_state() -> None:
    assessment, issues = parse_finalize_arguments({"assessment": _valid_assessment()})
    assert issues == []
    assert isinstance(assessment, Assessment)
    assert assessment == Assessment.model_validate(_valid_assessment())


def test_finalize_invalid_probability_sum_is_rejected() -> None:
    candidate = _valid_assessment()
    candidate["probabilities"]["phishing"] = 0.5  # sum != 1
    assessment, issues = parse_finalize_arguments({"assessment": candidate})
    assert assessment is None
    assert issues


def test_finalize_unknown_field_and_missing_assessment_are_rejected() -> None:
    candidate = _valid_assessment()
    candidate["extra_field"] = True
    assessment, issues = parse_finalize_arguments({"assessment": candidate})
    assert assessment is None
    assert issues
    assessment, issues = parse_finalize_arguments({"verdict": "phishing"})
    assert assessment is None
    assert any("unexpected argument" in issue for issue in issues)
    assessment, issues = parse_finalize_arguments({"assessment": _valid_assessment(), "note": "x"})
    assert assessment is None
    assert any("unexpected argument" in issue for issue in issues)


def test_finalize_non_object_arguments_are_rejected() -> None:
    assessment, issues = parse_finalize_arguments(None)
    assert assessment is None and issues
    assessment, issues = parse_finalize_arguments({"assessment": "legitime"})
    assert assessment is None and issues


# ---------------------------------------------------------------------------
# End-to-end reuse: a merged ok result passes the existing evidence merge
# ---------------------------------------------------------------------------


def test_executor_result_merges_with_the_existing_evidence_module(
    parsed_email: ParsedEmail, tools_config: ToolsConfig
) -> None:
    domain = _observable_by(parsed_email, type="domain")
    evidence = make_evidence("merge_case", observable_id=domain.id)
    vt = RecordingAdapter(
        lambda query, _ctx: make_ok_result("virustotal", query.id, evidence=[evidence])
    )
    executor = _executor(
        parsed_email,
        ProviderAdapterSet(virustotal=vt, opencti=vt, urlscan=vt),
        tools_config,
    )
    executor.execute(_call("lookup_virustotal", domain.id))
    from src.state import Enrichment

    enrichment = Enrichment(virustotal=executor.results, opencti=[], urlscan=[], rag=[])
    merged_evidence, merged_observables, visuals = merge_evidence(parsed_email, enrichment)
    assert evidence.id in merged_evidence
    assert domain.id in merged_observables
    assert visuals == list(parsed_email.images)

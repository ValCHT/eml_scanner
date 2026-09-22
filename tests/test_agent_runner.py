"""T19B deterministic runner tests: the bounded agentic control loop.

Stub clients/adapters are used ONLY here, to drive deterministic control
flow. Nothing in this file is reported as live evidence: real observations
come from ``scripts/smoke_agentic.py``.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from src.agent.models import (
    DEFAULT_AGENT_LIMITS,
    AgentLimits,
    AgentLLMResponse,
    ToolCall,
)
from src.agent.runner import run_agentic_email
from src.agent.tools import AGENT_TOOLS, ProviderAdapterSet
from src.config import Settings, load_settings
from src.parsing import ParseLimits, ParsedEmail, parse_email
from src.state import Evidence, Observable, ToolResult
from src.tools import ToolContext

OBSERVED_AT = "2026-09-21T12:00:00+00:00"
STUB_MODEL = "stub/model-not-live"


# ---------------------------------------------------------------------------
# Fixtures and fakes
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner_settings(project_root: Path, tmp_path: Path, clean_env: None) -> Settings:
    settings = load_settings(None)
    return settings.model_copy(
        update={
            "CONFIG_DIR": project_root / "configs",
            "RUNS_DIR": tmp_path / "runs",
        }
    )


@pytest.fixture()
def parsed_email(project_root: Path) -> ParsedEmail:
    parsed = parse_email(
        project_root / "tests" / "fixtures" / "malicious_url_redirect.eml",
        ParseLimits(),
    )
    assert isinstance(parsed, ParsedEmail)
    return parsed


class ScriptedClient:
    """Deterministic stub: returns canned native responses, records calls."""

    def __init__(
        self,
        responses: list[AgentLLMResponse],
        *,
        on_call: Any = None,
    ) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self._on_call = on_call

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        deadline: float,
        max_output_tokens: int,
        turn_index: int,
        effort: str = "medium",
        tool_choice: str = "auto",
    ) -> AgentLLMResponse:
        self.calls.append(
            {
                "messages": copy.deepcopy(messages),
                "tools": tools,
                "deadline": deadline,
                "max_output_tokens": max_output_tokens,
                "turn_index": turn_index,
                "effort": effort,
            }
        )
        if self._on_call is not None:
            self._on_call(turn_index)
        if not self.responses:
            return AgentLLMResponse(
                status="error",
                requested_model=STUB_MODEL,
                error="script_exhausted",
            )
        return self.responses.pop(0)


class RecordingAdapter:
    def __init__(self, factory: Any):
        self.calls: list[Observable] = []
        self._factory = factory

    def _invoke(self, query: Observable, context: ToolContext) -> ToolResult:
        self.calls.append(query)
        return self._factory(query, context)

    def lookup(self, query: Observable, context: ToolContext) -> ToolResult:
        return self._invoke(query, context)

    def scan(self, query: Observable, context: ToolContext) -> ToolResult:
        return self._invoke(query, context)


class ManualClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _tool_response(
    tool: str,
    observable_id: str | None = None,
    *,
    call_id: str = "call_1",
    arguments: dict[str, Any] | None = None,
    content: str | None = None,
) -> AgentLLMResponse:
    if arguments is None:
        arguments = {"observable_id": observable_id}
    return AgentLLMResponse(
        status="ok",
        requested_model=STUB_MODEL,
        returned_model=STUB_MODEL,
        finish_reason="tool_calls" if tool else "stop",
        content=content,
        tool_calls=[]
        if tool is None
        else [
            ToolCall(
                call_id=call_id,
                name=tool,
                arguments_raw=json.dumps(arguments, sort_keys=True),
                arguments=arguments,
            )
        ],
    )


def _text_response(content: str = "thinking out loud") -> AgentLLMResponse:
    return AgentLLMResponse(
        status="ok",
        requested_model=STUB_MODEL,
        returned_model=STUB_MODEL,
        finish_reason="stop",
        content=content,
        tool_calls=[],
    )


def _valid_assessment(**overrides: Any) -> dict[str, Any]:
    assessment: dict[str, Any] = {
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
    assessment.update(overrides)
    return assessment


def _finalize_response(
    assessment: dict[str, Any] | None = None,
    *,
    call_id: str = "final_1",
) -> AgentLLMResponse:
    return _tool_response(
        "finalize_assessment",
        None,
        call_id=call_id,
        arguments={"assessment": assessment or _valid_assessment()},
    )


def _idless_finalize_response(
    assessment: dict[str, Any] | None = None,
) -> AgentLLMResponse:
    """Schema-valid finalize with NO provider tool_call_id (protocol error)."""

    arguments = {"assessment": assessment or _valid_assessment()}
    return AgentLLMResponse(
        status="ok",
        requested_model=STUB_MODEL,
        returned_model=STUB_MODEL,
        finish_reason="tool_calls",
        tool_calls=[
            ToolCall(
                call_id=None,
                name="finalize_assessment",
                arguments_raw=json.dumps(arguments),
                arguments=arguments,
            )
        ],
    )


def _ok_result(
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
        response_sha256="b" * 64,
        response_ref=f"{tool}/capture.json",
        collected_at=OBSERVED_AT,
        mode="live",
        elapsed_ms=1.0,
        requests_sent=1,
    )


def _unavailable_result(tool: str, observable_id: str) -> ToolResult:
    return ToolResult(
        tool=tool,  # type: ignore[arg-type]
        query_observable_id=observable_id,
        status="unavailable",
        reason="timeout",
        mode="none",
        requests_sent=0,
    )


def _adapters(
    *,
    vt: Any = None,
    cti: Any = None,
    urlscan: Any = None,
) -> ProviderAdapterSet:
    default = RecordingAdapter(lambda query, _ctx: _unavailable_result("virustotal", query.id))
    return ProviderAdapterSet(
        virustotal=vt or default,
        opencti=cti or default,
        urlscan=urlscan or default,
    )


def _url_and_domain(parsed: ParsedEmail) -> tuple[str, str]:
    url = next(o for o in parsed.observables if o.type == "url")
    domain = next(o for o in parsed.observables if o.type == "domain")
    return url.id, domain.id


def _run(
    settings: Settings,
    client: Any,
    adapters: ProviderAdapterSet,
    tmp_path: Path,
    *,
    email_name: str = "malicious_url_redirect.eml",
    source_profile: str = "fixture",
    **kwargs: Any,
) -> Any:
    email_path = settings.CONFIG_DIR.parent / "tests" / "fixtures" / email_name
    return run_agentic_email(
        email_path,
        settings,
        source_profile=source_profile,  # type: ignore[arg-type]
        client=client,
        adapters=adapters,
        run_root=tmp_path / "agentic",
        sample_id=kwargs.pop("sample_id", "test_sample"),
        **kwargs,
    )


def _tool_messages(client: ScriptedClient, call_index: int = -1) -> list[dict[str, Any]]:
    messages = client.calls[call_index]["messages"]
    return [message for message in messages if message.get("role") == "tool"]


# ---------------------------------------------------------------------------
# Control flow
# ---------------------------------------------------------------------------


def test_finalize_immediately_with_zero_tools(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    assert result.status == "finalized"
    assert result.llm_turn_count == 1
    assert result.provider_tool_call_count == 0
    assert result.verdict == "phishing"
    assert result.action == "ESCALATE"
    assert result.assessment is not None


def test_one_tool_then_finalize(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, _ = _url_and_domain(parsed_email)
    vt = RecordingAdapter(lambda query, _ctx: _ok_result("virustotal", query.id))
    client = ScriptedClient(
        [_tool_response("lookup_virustotal", url_id), _finalize_response()]
    )
    result = _run(runner_settings, client, _adapters(vt=vt), tmp_path)
    assert result.status == "finalized"
    assert result.provider_tool_call_count == 1
    assert [query.id for query in vt.calls] == [url_id]
    tool_messages = _tool_messages(client)
    assert len(tool_messages) == 1
    assert tool_messages[0]["tool_call_id"] == "call_1"


def test_multiple_tools_processed_in_returned_order(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, domain_id = _url_and_domain(parsed_email)
    vt = RecordingAdapter(lambda query, _ctx: _ok_result("virustotal", query.id))
    cti = RecordingAdapter(lambda query, _ctx: _ok_result("opencti", query.id))
    client = ScriptedClient(
        [
            AgentLLMResponse(
                status="ok",
                requested_model=STUB_MODEL,
                returned_model=STUB_MODEL,
                finish_reason="tool_calls",
                tool_calls=[
                    ToolCall("c1", "lookup_virustotal", '{"observable_id": "%s"}' % url_id, {"observable_id": url_id}),
                    ToolCall("c2", "lookup_opencti", '{"observable_id": "%s"}' % domain_id, {"observable_id": domain_id}),
                ],
            ),
            _finalize_response(),
        ]
    )
    result = _run(runner_settings, client, _adapters(vt=vt, cti=cti), tmp_path)
    assert result.status == "finalized"
    assert result.provider_tool_call_count == 2
    tool_messages = _tool_messages(client)
    assert [message["tool_call_id"] for message in tool_messages] == ["c1", "c2"]
    assistant = [
        message
        for message in client.calls[1]["messages"]
        if message.get("role") == "assistant"
    ][-1]
    assert [call["id"] for call in assistant["tool_calls"]] == ["c1", "c2"]


def test_provider_unavailable_is_consumed_and_loop_continues(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, _ = _url_and_domain(parsed_email)
    vt = RecordingAdapter(lambda query, _ctx: _unavailable_result("virustotal", query.id))
    client = ScriptedClient(
        [_tool_response("lookup_virustotal", url_id), _finalize_response()]
    )
    result = _run(runner_settings, client, _adapters(vt=vt), tmp_path)
    assert result.status == "finalized"
    tool_message = _tool_messages(client)[0]
    payload = json.loads(tool_message["content"])
    assert payload["status"] == "unavailable"
    assert payload["reason"] == "timeout"


def test_duplicate_request_is_refused_without_provider_consumption(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, _ = _url_and_domain(parsed_email)
    vt = RecordingAdapter(lambda query, _ctx: _unavailable_result("virustotal", query.id))
    client = ScriptedClient(
        [
            AgentLLMResponse(
                status="ok",
                requested_model=STUB_MODEL,
                returned_model=STUB_MODEL,
                finish_reason="tool_calls",
                tool_calls=[
                    ToolCall("c1", "lookup_virustotal", '{"observable_id": "%s"}' % url_id, {"observable_id": url_id}),
                    ToolCall("c2", "lookup_virustotal", '{"observable_id": "%s"}' % url_id, {"observable_id": url_id}),
                ],
            ),
            _finalize_response(),
        ]
    )
    result = _run(runner_settings, client, _adapters(vt=vt), tmp_path)
    assert result.status == "finalized"
    assert result.provider_tool_call_count == 1
    assert result.duplicate_tool_refusal_count == 1
    payloads = [json.loads(message["content"]) for message in _tool_messages(client)]
    assert payloads[1]["refused"] is True
    assert payloads[1]["reason"] == "duplicate_tool_call"


def test_provider_tool_calls_never_exceed_four(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    domain = next(o for o in parsed_email.observables if o.type == "domain")
    ipv4 = next(o for o in parsed_email.observables if o.type == "ipv4")
    url = next(o for o in parsed_email.observables if o.type == "url")
    message_id = next(o for o in parsed_email.observables if o.type == "message_id")
    sender = next(o for o in parsed_email.observables if o.type == "email" and "sender" in o.roles)
    ids = [domain.id, ipv4.id, url.id, message_id.id, sender.id]
    vt = RecordingAdapter(lambda query, _ctx: _unavailable_result("virustotal", query.id))
    client = ScriptedClient(
        [
            AgentLLMResponse(
                status="ok",
                requested_model=STUB_MODEL,
                returned_model=STUB_MODEL,
                finish_reason="tool_calls",
                tool_calls=[
                    ToolCall(
                        f"c{index}",
                        "lookup_virustotal",
                        json.dumps({"observable_id": observable_id}),
                        {"observable_id": observable_id},
                    )
                    for index, observable_id in enumerate(ids)
                ],
            ),
            _finalize_response(),
        ]
    )
    result = _run(runner_settings, client, _adapters(vt=vt), tmp_path)
    assert result.status == "finalized"
    assert result.provider_tool_call_count == 4
    assert len(vt.calls) == 4
    payloads = [json.loads(message["content"]) for message in _tool_messages(client)]
    assert payloads[-1]["refused"] is True
    assert payloads[-1]["reason"] == "tool_budget_exhausted"
    assert payloads[-1]["message"] == (
        "provider tool-call budget exhausted (at most 4 provider calls in total): "
        "no provider call was made; finalize with the evidence already available"
    )


def test_custom_tool_budget_is_reflected_in_the_model_visible_refusal(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    """PR #17 review: with a non-default max_tool_calls, the refusal the model
    receives announces the applied budget, never the default one."""

    domain = next(o for o in parsed_email.observables if o.type == "domain")
    ipv4 = next(o for o in parsed_email.observables if o.type == "ipv4")
    vt = RecordingAdapter(
        lambda query, _ctx: _unavailable_result("virustotal", query.id)
    )
    client = ScriptedClient(
        [
            AgentLLMResponse(
                status="ok",
                requested_model=STUB_MODEL,
                returned_model=STUB_MODEL,
                finish_reason="tool_calls",
                tool_calls=[
                    ToolCall(
                        "c0",
                        "lookup_virustotal",
                        json.dumps({"observable_id": domain.id}),
                        {"observable_id": domain.id},
                    ),
                    ToolCall(
                        "c1",
                        "lookup_virustotal",
                        json.dumps({"observable_id": ipv4.id}),
                        {"observable_id": ipv4.id},
                    ),
                ],
            ),
            _finalize_response(),
        ]
    )
    result = _run(
        runner_settings,
        client,
        _adapters(vt=vt),
        tmp_path,
        limits=AgentLimits(max_tool_calls=1),
    )
    assert result.status == "finalized"
    assert result.provider_tool_call_count == 1
    payloads = [json.loads(message["content"]) for message in _tool_messages(client)]
    assert payloads[-1]["refused"] is True
    assert payloads[-1]["reason"] == "tool_budget_exhausted"
    assert "at most 1 provider calls in total" in payloads[-1]["message"]
    assert "at most 4" not in payloads[-1]["message"]


def test_llm_turns_never_exceed_five(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_text_response() for _ in range(5)])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    assert result.status == "incomplete"
    assert result.llm_turn_count == 5
    assert result.assessment is None
    assert result.action == "REVIEW"
    assert result.agent_error == "turn_budget_exhausted"


def test_no_final_assessment_is_review_never_a_fabricated_verdict(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_text_response(), _text_response()])
    result = _run(
        runner_settings,
        client,
        _adapters(),
        tmp_path,
        limits=AgentLimits(
            max_llm_turns=2,
            max_tool_calls=DEFAULT_AGENT_LIMITS.max_tool_calls,
            max_urlscan_calls=DEFAULT_AGENT_LIMITS.max_urlscan_calls,
            max_agent_seconds=DEFAULT_AGENT_LIMITS.max_agent_seconds,
            max_single_llm_seconds=DEFAULT_AGENT_LIMITS.max_single_llm_seconds,
            max_tool_result_chars=DEFAULT_AGENT_LIMITS.max_tool_result_chars,
        ),
    )
    assert result.status == "incomplete"
    assert result.assessment is None
    assert result.verdict is None
    assert result.action == "REVIEW"
    assert any("no_final_assessment" in str(reason) or "invalid_or_missing" in str(reason) for reason in result.policy_reasons)


def test_deadline_reached_stops_incomplete_and_reviews(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, _ = _url_and_domain(parsed_email)
    clock = ManualClock()
    vt = RecordingAdapter(lambda query, _ctx: _unavailable_result("virustotal", query.id))

    def advance(turn_index: int) -> None:
        clock.advance(100.0)

    client = ScriptedClient([_tool_response("lookup_virustotal", url_id)], on_call=advance)
    result = _run(
        runner_settings,
        client,
        _adapters(vt=vt),
        tmp_path,
        clock=clock,
        limits=AgentLimits(max_agent_seconds=50.0),
    )
    assert result.status == "incomplete"
    assert result.assessment is None
    assert result.action == "REVIEW"
    assert result.agent_error == "deadline_exceeded"
    assert result.llm_turn_count == 1


def test_invalid_finalize_is_rejected_then_a_valid_one_finalizes(
    runner_settings: Settings, tmp_path: Path
) -> None:
    invalid = _valid_assessment()
    invalid["probabilities"]["phishing"] = 0.5  # sum != 1
    client = ScriptedClient(
        [
            _finalize_response(invalid, call_id="bad_1"),
            _finalize_response(call_id="good_1"),
        ]
    )
    result = _run(runner_settings, client, _adapters(), tmp_path)
    assert result.status == "finalized"
    assert result.assessment is not None
    final_document = json.loads((result.run_dir / "final.json").read_text(encoding="utf-8"))
    assert [attempt["valid"] for attempt in final_document["finalize_attempts"]] == [
        False,
        True,
    ]
    payload = json.loads(_tool_messages(client)[0]["content"])
    assert payload["refused"] is True
    assert payload["reason"] == "invalid_assessment"


def test_invalid_finalize_only_never_becomes_a_verdict(
    runner_settings: Settings, tmp_path: Path
) -> None:
    invalid = _valid_assessment()
    invalid["probabilities"]["phishing"] = 0.5
    client = ScriptedClient([_finalize_response(invalid)])
    result = _run(
        runner_settings,
        client,
        _adapters(),
        tmp_path,
        limits=AgentLimits(max_llm_turns=1),
    )
    assert result.status == "incomplete"
    assert result.assessment is None
    assert result.action == "REVIEW"


def test_finalize_with_unknown_evidence_reference_is_escalated(
    runner_settings: Settings, tmp_path: Path
) -> None:
    assessment = _valid_assessment(observations=["ev_does_not_exist"])
    client = ScriptedClient([_finalize_response(assessment)])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    assert result.status == "finalized"
    assert result.action == "ESCALATE"
    assert any("unsupported_claim" in str(reason) for reason in result.policy_reasons)


def test_no_llm_key_means_zero_request_and_review(
    runner_settings: Settings, tmp_path: Path
) -> None:
    assert runner_settings.LITELLM_API_KEY is None
    result = _run(runner_settings, None, _adapters(), tmp_path)
    assert result.status == "error"
    assert result.llm_error is True
    assert result.agent_error == "llm_not_configured"
    assert result.llm_turn_count == 0
    assert result.action == "REVIEW"


def test_parse_failure_is_explicit_and_reviewed(
    runner_settings: Settings, tmp_path: Path
) -> None:
    result = run_agentic_email(
        tmp_path / "missing.eml",
        runner_settings,
        source_profile="fixture",
        client=ScriptedClient([_finalize_response()]),
        adapters=_adapters(),
        run_root=tmp_path / "agentic",
        sample_id="missing",
    )
    assert result.status == "error"
    assert result.parse_error is not None
    assert result.assessment is None
    assert result.action == "REVIEW"
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["parse_error"]


def test_finalize_without_tool_call_id_is_refused_and_never_finalizes(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """PR #17 blocker 2: schema-valid finalize + call_id=None must be a typed
    protocol refusal, never a terminal success. The loop may continue if
    budget remains, but only a later attributable finalize can end the run."""

    client = ScriptedClient(
        [
            _idless_finalize_response(),
            _finalize_response(call_id="good_1"),
        ]
    )
    result = _run(runner_settings, client, _adapters(), tmp_path)
    assert result.status == "finalized"
    final_document = json.loads((result.run_dir / "final.json").read_text(encoding="utf-8"))
    attempts = final_document["finalize_attempts"]
    assert [attempt["valid"] for attempt in attempts] == [False, True]
    assert attempts[0]["call_id"] is None
    assert any(
        "missing_tool_call_id" in issue for issue in attempts[0]["issues"]
    )
    # The id-less call is never echoed as an attributable assistant tool_call
    # and the model receives a typed protocol-error message.
    second_call_messages = client.calls[1]["messages"]
    assistant_messages = [
        message for message in second_call_messages if message.get("role") == "assistant"
    ]
    assert assistant_messages[-1].get("tool_calls", []) == []
    assert any(
        message.get("role") == "user"
        and "agent_protocol_error" in str(message.get("content"))
        for message in second_call_messages
    )
    # No provider lookup was executed either.
    assert result.provider_tool_call_count == 0


def test_finalize_without_tool_call_id_alone_is_incomplete_review(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_idless_finalize_response()])
    result = _run(
        runner_settings,
        client,
        _adapters(),
        tmp_path,
        limits=AgentLimits(max_llm_turns=1),
    )
    assert result.status == "incomplete"
    assert result.assessment is None
    assert result.verdict is None
    assert result.action == "REVIEW"
    final_document = json.loads((result.run_dir / "final.json").read_text(encoding="utf-8"))
    assert final_document["verification"]["accepted"] is False
    assert final_document["assessment"] is None


def test_custom_limits_drive_the_prompt_hash_and_the_manifest(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """PR #17 blocker 3: prompt text/hash and archived limits must be the
    exact AgentLimits the run enforced (T19E auditability)."""

    from src.agent.prompt import agent_system_prompt_sha256

    custom = AgentLimits(
        max_llm_turns=4,
        max_tool_calls=2,
        max_urlscan_calls=1,
        max_agent_seconds=120.0,
        max_single_llm_seconds=45.0,
        max_tool_result_chars=4000,
    )
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path, limits=custom)
    system_prompt = " ".join(client.calls[0]["messages"][0]["content"].split())
    assert "at most 4 assistant turns" in system_prompt
    assert "at most 2 provider calls in total" in system_prompt
    assert "within 120 seconds" in system_prompt
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["limits"] == {
        "max_llm_turns": 4,
        "max_tool_calls": 2,
        "max_urlscan_calls": 1,
        "max_agent_seconds": 120.0,
        "max_single_llm_seconds": 45.0,
        "max_tool_result_chars": 4000,
    }
    assert manifest["effective_prompt_sha256"] == agent_system_prompt_sha256(custom)
    assert manifest["effective_prompt_sha256"] != agent_system_prompt_sha256()
    assert manifest["effective_prompt_sha256"] == result.prompt_sha256


# ---------------------------------------------------------------------------
# T19D §4 — runtime contract fingerprints
# ---------------------------------------------------------------------------


def _canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def test_manifest_archives_the_runtime_contract_fingerprints(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """T19D §4: the manifest pins exactly the contract the run transmitted.

    ``tool_schema_sha256`` is recomputed here from the tools list really handed
    to the model, ``assessment_schema_sha256`` from the frozen schema FILE
    bytes, and ``runtime_contract_sha256`` from exactly the eight declared
    contract fields.
    """

    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))

    transmitted_tools = client.calls[0]["tools"]
    assert [tool["function"]["name"] for tool in transmitted_tools] == [
        "lookup_virustotal",
        "lookup_opencti",
        "scan_urlscan",
        "finalize_assessment",
    ]
    assert manifest["tool_schema_sha256"] == _canonical_sha256(transmitted_tools)

    frozen_schema_bytes = (
        runner_settings.CONFIG_DIR.parent / "schemas" / "assessment.schema.json"
    ).read_bytes()
    assert manifest["assessment_schema_sha256"] == hashlib.sha256(
        frozen_schema_bytes
    ).hexdigest()

    contract = {
        "architecture": manifest["architecture"],
        "model": manifest["model_requested"],
        "reasoning_effort": manifest["reasoning_effort"],
        "max_output_tokens_per_turn": manifest["max_output_tokens_per_turn"],
        "limits": manifest["limits"],
        "effective_prompt_sha256": manifest["effective_prompt_sha256"],
        "tool_schema_sha256": manifest["tool_schema_sha256"],
        "assessment_schema_sha256": manifest["assessment_schema_sha256"],
    }
    assert manifest["runtime_contract_sha256"] == _canonical_sha256(contract)


def test_same_runtime_contract_gives_the_same_fingerprint(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """T19D §4.4: no timestamp/run_id/email/result enters the contract hash."""

    first = _run(
        runner_settings, ScriptedClient([_finalize_response()]), _adapters(), tmp_path
    )
    second = _run(
        runner_settings, ScriptedClient([_finalize_response()]), _adapters(), tmp_path
    )
    first_manifest = json.loads((first.run_dir / "manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads(
        (second.run_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert first_manifest["run_id"] != second_manifest["run_id"]
    assert (
        first_manifest["runtime_contract_sha256"]
        == second_manifest["runtime_contract_sha256"]
    )

    changed_limits = _run(
        runner_settings,
        ScriptedClient([_finalize_response()]),
        _adapters(),
        tmp_path,
        limits=AgentLimits(max_tool_calls=3),
    )
    changed_manifest = json.loads(
        (changed_limits.run_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert (
        changed_manifest["runtime_contract_sha256"]
        != first_manifest["runtime_contract_sha256"]
    )


# ---------------------------------------------------------------------------
# T19D §3 — AgentLimits are injectable and really applied
# ---------------------------------------------------------------------------


def test_non_default_max_single_llm_seconds_bounds_every_llm_request(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """The per-request deadline is the applied limit, bounded by the run budget."""

    clock = ManualClock()
    client = ScriptedClient([_text_response(), _text_response(), _text_response()])
    result = _run(
        runner_settings,
        client,
        _adapters(),
        tmp_path,
        clock=clock,
        limits=AgentLimits(max_llm_turns=2, max_single_llm_seconds=45.0),
    )
    assert result.status == "incomplete"
    assert result.llm_turn_count == 2  # max_llm_turns=2 really applied
    assert [call["deadline"] for call in client.calls] == [45.0, 45.0]

    # A smaller whole-run budget bounds the same per-request deadline too.
    bounded_client = ScriptedClient([_text_response()])
    _run(
        runner_settings,
        bounded_client,
        _adapters(),
        tmp_path,
        clock=ManualClock(),
        limits=AgentLimits(max_agent_seconds=30.0, max_single_llm_seconds=90.0),
    )
    assert bounded_client.calls[0]["deadline"] == 30.0


def test_non_default_max_tool_result_chars_bounds_the_model_visible_payload(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    """The role=tool payload obeys the applied ``max_tool_result_chars``."""

    url_id, _ = _url_and_domain(parsed_email)
    evidence = [
        Evidence(
            id=f"ev_bulk_{index:03d}",
            provenance="OSINT",
            source_kind="virustotal",
            observable_id=url_id,
            predicate="vt_malicious_count",
            value=float(index),
            source_ref=f"response.json:/data/attributes/{index}",
            observed_at=OBSERVED_AT,
            match_level="EXACT",
            source_group="virustotal",
        )
        for index in range(60)
    ]
    vt = RecordingAdapter(
        lambda query, _ctx: _ok_result("virustotal", query.id, evidence=evidence)
    )
    client = ScriptedClient(
        [_tool_response("lookup_virustotal", url_id), _finalize_response()]
    )
    result = _run(
        runner_settings,
        client,
        _adapters(vt=vt),
        tmp_path,
        limits=AgentLimits(max_tool_result_chars=2000),
    )
    payload = _tool_messages(client)[0]["content"]
    assert len(payload) <= 2000
    assert json.loads(payload)["truncated"] is True
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["limits"]["max_tool_result_chars"] == 2000


def test_max_urlscan_calls_stays_structurally_frozen_to_one() -> None:
    """T19D §3 exception: the urlscan budget remains exactly 1."""

    assert AgentLimits().max_urlscan_calls == 1
    with pytest.raises(ValueError, match="max_urlscan_calls"):
        AgentLimits(max_urlscan_calls=2)


def test_non_fixture_trace_keeps_only_prose_length_and_hash(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """PR #17 security hardening: free-form model prose is not persisted for
    public_corpus/private_authorized, only its length and SHA-256."""

    import hashlib

    marker = "QUOTED-EMAIL-PROSE-MUST-NOT-BE-PERSISTED"
    client = ScriptedClient([_text_response(marker), _text_response(marker)])
    result = _run(
        runner_settings,
        client,
        _adapters(),
        tmp_path,
        source_profile="public_corpus",
        limits=AgentLimits(max_llm_turns=2),
    )
    trace_text = (result.run_dir / "trace.jsonl").read_text(encoding="utf-8")
    assert marker not in trace_text
    events = [
        json.loads(line) for line in trace_text.splitlines() if line.strip()
    ]
    llm_turns = [event for event in events if event["event"] == "llm_turn"]
    assert llm_turns
    for event in llm_turns:
        assert event["content_excerpt"] is None
        assert event["content_chars"] == len(marker)
        assert event["content_sha256"] == hashlib.sha256(
            marker.encode("utf-8")
        ).hexdigest()
    # The protocol still carries the full prose in memory (nudge was sent).
    assert _tool_messages(client) == []
    assert any(
        message.get("role") == "user" and "finalize_assessment" in str(message.get("content"))
        for message in client.calls[1]["messages"]
    )


def test_fixture_trace_keeps_the_bounded_excerpt(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_text_response("fixture prose"), _finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    events = [
        json.loads(line)
        for line in (result.run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    llm_turn = next(event for event in events if event["event"] == "llm_turn")
    assert llm_turn["content_excerpt"] == "fixture prose"


# ---------------------------------------------------------------------------
# Scope guards: no RAG, no Vision, no recursive pivot
# ---------------------------------------------------------------------------


def test_agent_tool_set_excludes_rag_vision_and_qr() -> None:
    names = {tool["function"]["name"] for tool in AGENT_TOOLS}
    assert names == {
        "lookup_virustotal",
        "lookup_opencti",
        "scan_urlscan",
        "finalize_assessment",
    }
    assert not any(
        keyword in name for name in names for keyword in ("rag", "vision", "qr")
    )


def test_initial_context_has_no_rag_and_no_visual_pixels(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    envelope = json.loads(client.calls[0]["messages"][1]["content"])
    assert envelope["RAG_CONTEXT"] == []
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert envelope["INTERNAL_ASSESSMENT"] is None
    assert envelope["TOOL_STATUS"] == []
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["rag_enabled"] is False
    assert manifest["vision_enabled"] is False


def test_rag_or_vision_tool_name_is_refused_as_unknown(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient(
        [_tool_response("lookup_rag", "obs_x"), _finalize_response()]
    )
    result = _run(runner_settings, client, _adapters(), tmp_path)
    assert result.status == "finalized"
    payload = json.loads(_tool_messages(client)[0]["content"])
    assert payload["refused"] is True
    assert payload["reason"] == "unknown_tool"


def test_tool_discovered_observable_never_becomes_a_pivot_target(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, _ = _url_and_domain(parsed_email)
    discovered = Observable(
        id="obs_tooldiscovered_runner_1",
        value="payload-host.example.net",
        normalized_value="payload-host.example.net",
        type="domain",
        roles=["tool_discovery"],
        provenance="OSINT",
        source_ref="response.json:/data/relationships/0",
    )
    evidence = Evidence(
        id="ev_tooldiscovered_runner_1",
        provenance="OSINT",
        source_kind="virustotal",
        observable_id=discovered.id,
        predicate="vt_malicious_count",
        value=3.0,
        source_ref="response.json:/data/attributes/last_analysis_stats/malicious",
        observed_at=OBSERVED_AT,
        match_level="EXACT",
        source_group="virustotal",
    )
    vt = RecordingAdapter(
        lambda query, _ctx: _ok_result(
            "virustotal", query.id, evidence=[evidence], observables=[discovered]
        )
    )
    client = ScriptedClient(
        [
            _tool_response("lookup_virustotal", url_id),
            _tool_response("lookup_opencti", discovered.id, call_id="c2"),
            _finalize_response(),
        ]
    )
    result = _run(runner_settings, client, _adapters(vt=vt), tmp_path)
    assert result.status == "finalized"
    assert result.provider_tool_call_count == 1
    payloads = [json.loads(message["content"]) for message in _tool_messages(client)]
    assert payloads[1]["refused"] is True
    assert payloads[1]["reason"] == "unknown_observable_id"
    final_document = json.loads((result.run_dir / "final.json").read_text(encoding="utf-8"))
    # The discovered observable stays evidence-only in the merged registry.
    assert final_document["merged_registries"]["observable_count"] == (
        len(parsed_email.observables) + 1
    )


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


def test_artifacts_are_written_with_smoke_scope_and_chronological_trace(
    runner_settings: Settings, tmp_path: Path, parsed_email: ParsedEmail
) -> None:
    url_id, _ = _url_and_domain(parsed_email)
    vt = RecordingAdapter(lambda query, _ctx: _unavailable_result("virustotal", query.id))
    client = ScriptedClient(
        [_tool_response("lookup_virustotal", url_id), _finalize_response()]
    )
    result = _run(runner_settings, client, _adapters(vt=vt), tmp_path)
    for name in ("manifest.json", "trace.jsonl", "final.json", "summary.txt"):
        assert (result.run_dir / name).is_file(), name
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["architecture"] == "agentic_core_v2"
    assert manifest["run_kind"] == "t19c_agentic_runtime"
    assert manifest["measurement_scope"] == "smoke"
    assert manifest["performance_claims_allowed"] is False
    assert manifest["limits"]["max_llm_turns"] == 5
    assert manifest["limits"]["max_tool_calls"] == 4
    assert manifest["limits"]["max_urlscan_calls"] == 1
    assert manifest["limits"]["max_agent_seconds"] == 300.0
    assert manifest["effective_prompt_sha256"] == result.prompt_sha256
    assert manifest["final_status"] == "finalized"
    assert manifest["final_action"] == "ESCALATE"
    assert manifest["tool_counts_by_provider"]["virustotal"] == 1
    assert manifest["tool_statuses_by_provider"]["virustotal"]["unavailable"] == 1
    events = [
        json.loads(line)
        for line in (result.run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kinds = [event["event"] for event in events]
    for required in (
        "llm_turn",
        "tool_request",
        "tool_validation",
        "provider_execution",
        "tool_result",
        "finalization",
    ):
        assert required in kinds
    assert kinds.index("tool_request") < kinds.index("tool_validation")
    assert kinds.index("tool_validation") < kinds.index("provider_execution")
    assert kinds.index("provider_execution") < kinds.index("tool_result")
    assert kinds.index("tool_result") < kinds.index("finalization")
    summary = (result.run_dir / "summary.txt").read_text(encoding="utf-8")
    assert "performance_claims_allowed=false" in summary
    assert "smoke" in summary

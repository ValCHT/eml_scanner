"""TICKET-19C offline convergence tests: agentic loop + T15 RAG + T16 QR/Vision.

Everything here is OFFLINE and deterministic: stub clients/adapters/RAG drive
the control flow only. No provider observation is fabricated and no test
reads ``gold_test``. Real observations come from the bounded smokes
(``scripts/smoke_agentic.py``) only.

Covered matrix (T19C §11): text only; text+RAG; text+QR; text+Vision;
text+QR+Vision; text+RAG+QR+Vision; RAG absent -> no RAG guidance; Vision
absent -> no visual guidance; pixels disabled -> never sent; QR-only -> no
pixels sent; Vision-only -> no QR decoder call when QR is disabled;
finalize_assessment exposes the full frozen Assessment schema; the three
investigation tools remain the only provider tools; V1 prompt bytes are
unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from src.agent.models import (
    CONVERGED_ARCHITECTURE_NAME,
    AgentLLMResponse,
    ToolCall,
)
from src.agent.prompt import (
    build_agent_system_prompt,
    load_agentic_prompt,
)
from src.agent.runner import run_agentic_email
from src.agent.tools import AGENT_TOOLS, ProviderAdapterSet, assessment_schema
from src.config import Settings, load_settings
from src.prompts import load_final_prompt, load_internal_prompt
from src.state import RagCase, ToolResult
from src.tools import ToolContext
from src.tools.rag import RagUnavailableError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STUB_MODEL = "stub/model-not-live"

#: Frozen V1 prompt digests (T19C must never modify these bytes).
V1_PROMPT_SHA256 = {
    "internal_assessment.txt": (
        "60dc6ee00e0eabfd063638af7f62f9aeb00a919305277d99b64820809469b9ae"
    ),
    "final_assessment.txt": (
        "cfc9ba52a8426e524223cbfbfda53b874f2c4beac5379688bbcb772f6e14f6f7"
    ),
}


# ---------------------------------------------------------------------------
# Fixtures and stubs
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


class ScriptedClient:
    """Deterministic stub: canned native responses, records every call."""

    def __init__(self, responses: list[AgentLLMResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

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
        if not self.responses:
            return AgentLLMResponse(
                status="error", requested_model=STUB_MODEL, error="script_exhausted"
            )
        return self.responses.pop(0)


class RecordingAdapter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def lookup(self, query: Any, context: ToolContext) -> ToolResult:
        self.calls.append(query.id)
        return ToolResult(
            tool="virustotal",
            query_observable_id=query.id,
            status="unavailable",
            reason="timeout",
            mode="none",
            requests_sent=0,
        )

    scan = lookup


class StubRagAdapter:
    """Deterministic T15 stand-in: no Chroma, no embedding model."""

    def __init__(self, cases: list[RagCase] | None = None, error: Exception | None = None):
        self.cases = list(cases or [])
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def search(self, query: str, exclusions: Any = None, k: int = 3) -> list[RagCase]:
        self.calls.append(
            {"query": query, "exclusions": set(exclusions or ()), "k": k}
        )
        if self.error is not None:
            raise self.error
        return list(self.cases)[:k]


def _rag_case(
    case_id: str = "rag_case_001",
    *,
    family_group: str = "family_a",
    duplicate_group: str = "dup_a",
) -> RagCase:
    return RagCase(
        case_id=case_id,
        public_source_url="https://example.org/public/case",
        dataset="public_fixture",
        record_sha256="a" * 64,
        validated_label="phishing",
        analyst_validation_ref="ref-001",
        campaign_id=None,
        duplicate_group=duplicate_group,
        family_group=family_group,
        text_excerpt="public analogue text",
        analyst_rationale="analyst rationale",
        distance=0.12,
        embedding_model_id="all-MiniLM-L6-v2@sha256:0000000000000000",
        is_public=True,
        split="rag_reference",
    )


def _adapters(vt: Any | None = None) -> ProviderAdapterSet:
    default = RecordingAdapter()
    return ProviderAdapterSet(
        virustotal=vt or default,
        opencti=default,
        urlscan=default,
    )


def _tool_response(
    tool: str,
    observable_id: str | None = None,
    *,
    call_id: str = "call_1",
) -> AgentLLMResponse:
    arguments = {"observable_id": observable_id}
    return AgentLLMResponse(
        status="ok",
        requested_model=STUB_MODEL,
        returned_model=STUB_MODEL,
        finish_reason="tool_calls",
        tool_calls=[
            ToolCall(
                call_id=call_id,
                name=tool,
                arguments_raw=json.dumps(arguments, sort_keys=True),
                arguments=arguments,
            )
        ],
    )


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


def _finalize_response(call_id: str = "final_1") -> AgentLLMResponse:
    arguments = {"assessment": _valid_assessment()}
    return AgentLLMResponse(
        status="ok",
        requested_model=STUB_MODEL,
        returned_model=STUB_MODEL,
        finish_reason="tool_calls",
        tool_calls=[
            ToolCall(
                call_id=call_id,
                name="finalize_assessment",
                arguments_raw=json.dumps(arguments, sort_keys=True),
                arguments=arguments,
            )
        ],
    )


def _run(
    settings: Settings,
    client: Any,
    adapters: ProviderAdapterSet,
    tmp_path: Path,
    *,
    email_name: str = "malicious_url_redirect.eml",
    **kwargs: Any,
) -> Any:
    return run_agentic_email(
        PROJECT_ROOT / "tests" / "fixtures" / email_name,
        settings,
        source_profile="fixture",
        client=client,
        adapters=adapters,
        run_root=tmp_path / "agentic",
        sample_id="t19c_sample",
        **kwargs,
    )


def _initial(client: ScriptedClient) -> tuple[Any, str]:
    """(user message, system prompt) of the first request."""

    return client.calls[0]["messages"][1], client.calls[0]["messages"][0]["content"]


def _envelope(message: dict[str, Any]) -> dict[str, Any]:
    content = message["content"]
    if isinstance(content, str):
        return json.loads(content)
    text_parts = [part for part in content if part.get("type") == "text"]
    assert len(text_parts) == 1
    return json.loads(text_parts[0]["text"])


def _manifest(result: Any) -> dict[str, Any]:
    return json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))


def _verification_codes(result: Any) -> list[str]:
    document = json.loads((result.run_dir / "final.json").read_text(encoding="utf-8"))
    return [issue["code"] for issue in document["verification"]["issues"]]


def _qr_observable_id(envelope: dict[str, Any]) -> str:
    matches = [
        observable["id"]
        for observable in envelope["OBSERVABLE_REGISTRY"].values()
        if observable["type"] == "url"
        and observable["normalized_value"] == "https://qr.notice.test/verify"
    ]
    assert len(matches) == 1
    return matches[0]


# ---------------------------------------------------------------------------
# text only
# ---------------------------------------------------------------------------


def test_text_only_has_no_rag_and_no_visual_guidance(
    runner_settings: Settings, tmp_path: Path
) -> None:
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path)
    message, system = _initial(client)
    assert isinstance(message["content"], str)  # no multipart without pixels
    envelope = _envelope(message)
    assert envelope["RAG_CONTEXT"] == []
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert envelope["INTERNAL_ASSESSMENT"] is None
    assert envelope["TOOL_STATUS"] == []
    assert "RAG GUIDANCE" not in system
    assert "VISUAL GUIDANCE" not in system
    manifest = _manifest(result)
    assert manifest["architecture"] == CONVERGED_ARCHITECTURE_NAME
    assert manifest["run_kind"] == "t19c_agentic_runtime"
    assert manifest["rag_enabled"] is False
    assert manifest["rag_case_count"] == 0
    assert manifest["vision_enabled"] is False
    assert manifest["qr_decode_enabled"] is False
    assert manifest["visual_count_sent"] == 0
    assert manifest["qr_payload_count"] == 0
    assert manifest["prompt_guidance"] == {"rag": False, "visuals": False}
    assert result.status == "finalized"


# ---------------------------------------------------------------------------
# text + RAG
# ---------------------------------------------------------------------------


def test_text_plus_rag_adds_context_and_conditional_guidance(
    runner_settings: Settings, tmp_path: Path
) -> None:
    rag = StubRagAdapter([_rag_case()])
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path, rag=rag)
    message, system = _initial(client)
    envelope = _envelope(message)
    assert [case["case_id"] for case in envelope["RAG_CONTEXT"]] == ["rag_case_001"]
    assert envelope["RAG_CONTEXT"][0]["validated_label"] == "phishing"
    assert "RAG GUIDANCE" in system
    assert "analogies" in system
    assert "VISUAL GUIDANCE" not in system
    assert rag.calls and rag.calls[0]["k"] == 3
    assert rag.calls[0]["query"]  # deterministic subject/body projection
    manifest = _manifest(result)
    assert manifest["rag_enabled"] is True
    assert manifest["rag_case_count"] == 1
    assert manifest["prompt_guidance"] == {"rag": True, "visuals": False}
    assert "rag_contamination" not in _verification_codes(result)
    assert result.status == "finalized"


def test_rag_empty_result_adds_no_guidance(
    runner_settings: Settings, tmp_path: Path
) -> None:
    rag = StubRagAdapter([])
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path, rag=rag)
    message, system = _initial(client)
    assert _envelope(message)["RAG_CONTEXT"] == []
    assert "RAG GUIDANCE" not in system
    manifest = _manifest(result)
    assert manifest["rag_enabled"] is True
    assert manifest["rag_case_count"] == 0
    assert manifest["prompt_guidance"]["rag"] is False


def test_rag_failure_is_fail_closed_never_fabricated(
    runner_settings: Settings, tmp_path: Path
) -> None:
    rag = StubRagAdapter(error=RagUnavailableError("chromadb missing"))
    client = ScriptedClient([_finalize_response()])
    result = _run(runner_settings, client, _adapters(), tmp_path, rag=rag)
    message, system = _initial(client)
    assert _envelope(message)["RAG_CONTEXT"] == []
    assert "RAG GUIDANCE" not in system
    manifest = _manifest(result)
    assert manifest["rag_enabled"] is True
    assert manifest["rag_case_count"] == 0
    assert manifest["rag_lookup_error"].startswith("rag_unavailable:")
    assert result.status == "finalized"


def test_rag_exclusions_and_identity_reach_the_adapter_and_the_verifier(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """The current email identity is excluded at retrieval AND re-checked by
    V15: a neighbour of the current family is never silently admissible."""

    rag = StubRagAdapter([_rag_case(family_group="family_current")])
    client = ScriptedClient([_finalize_response()])
    result = _run(
        runner_settings,
        client,
        _adapters(),
        tmp_path,
        rag=rag,
        rag_exclusions={"family_current", "dup_current"},
        current_family_group="family_current",
    )
    assert rag.calls[0]["exclusions"] == {"family_current", "dup_current"}
    # The adapter returned a same-family case (it should not have); V15
    # records the contamination instead of accepting it silently.
    assert "rag_contamination" in _verification_codes(result)


# ---------------------------------------------------------------------------
# text + QR
# ---------------------------------------------------------------------------


def test_text_plus_qr_flows_through_the_existing_registries_without_pixels(
    runner_settings: Settings, tmp_path: Path
) -> None:
    settings = runner_settings.model_copy(update={"QR_DECODE_ENABLED": True})
    client = ScriptedClient([_finalize_response()])
    result = _run(settings, client, _adapters(), tmp_path, email_name="qr_phishing.eml")
    message, system = _initial(client)
    assert isinstance(message["content"], str)  # QR-only: no pixel is staged
    envelope = _envelope(message)
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert "VISUAL GUIDANCE" not in system
    assert "RAG GUIDANCE" not in system
    qr_observable_id = _qr_observable_id(envelope)
    assert qr_observable_id.startswith("obs_")
    qr_evidence = [
        entry
        for entry in envelope["EVIDENCE_REGISTRY"].values()
        if entry["predicate"] == "qr_payload"
    ]
    assert [entry["value"] for entry in qr_evidence] == ["https://qr.notice.test/verify"]
    assert all(entry["provenance"] == "INTERNE" for entry in qr_evidence)
    manifest = _manifest(result)
    assert manifest["qr_decode_enabled"] is True
    assert manifest["vision_enabled"] is False
    assert manifest["visual_count_sent"] == 0
    assert manifest["qr_payload_count"] == 1
    assert manifest["qr_observable_count"] == 1
    assert result.status == "finalized"


def test_qr_url_observable_is_an_investigable_query_target(
    runner_settings: Settings, tmp_path: Path
) -> None:
    settings = runner_settings.model_copy(update={"QR_DECODE_ENABLED": True})
    probe_client = ScriptedClient([_finalize_response()])
    _run(settings, probe_client, _adapters(), tmp_path, email_name="qr_phishing.eml")
    qr_observable_id = _qr_observable_id(_envelope(_initial(probe_client)[0]))

    vt = RecordingAdapter()
    client = ScriptedClient(
        [_tool_response("lookup_virustotal", qr_observable_id), _finalize_response()]
    )
    result = _run(settings, client, _adapters(vt=vt), tmp_path, email_name="qr_phishing.eml")
    assert result.status == "finalized"
    assert vt.calls == [qr_observable_id]


# ---------------------------------------------------------------------------
# text + Vision
# ---------------------------------------------------------------------------


def test_text_plus_vision_attaches_pixels_to_the_same_request(
    runner_settings: Settings, tmp_path: Path
) -> None:
    settings = runner_settings.model_copy(update={"MODEL_SUPPORTS_VISION": True})
    client = ScriptedClient([_finalize_response()])
    result = _run(
        settings,
        client,
        _adapters(),
        tmp_path,
        email_name="vision/benign_image.eml",
    )
    message, system = _initial(client)
    assert isinstance(message["content"], list)
    text_parts = [part for part in message["content"] if part["type"] == "text"]
    image_parts = [part for part in message["content"] if part["type"] == "image_url"]
    assert len(text_parts) == 1 and len(image_parts) == 1
    envelope = json.loads(text_parts[0]["text"])
    assert len(envelope["SUPPLIED_VISUAL_IDS"]) == 1
    assert image_parts[0]["image_url"]["url"].startswith("data:image/png;base64,")
    assert "VISUAL GUIDANCE" in system
    assert "SUPPLIED_VISUAL_IDS" in system
    assert "RAG GUIDANCE" not in system
    manifest = _manifest(result)
    assert manifest["vision_enabled"] is True
    assert manifest["visual_count_sent"] == 1
    assert manifest["prompt_guidance"] == {"rag": False, "visuals": True}
    assert result.status == "finalized"


def test_vision_only_never_executes_the_qr_decoder(
    runner_settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = runner_settings.model_copy(update={"MODEL_SUPPORTS_VISION": True})
    decoder_calls: list[Any] = []

    def _forbidden(*args: Any, **kwargs: Any) -> list[str]:
        decoder_calls.append(args)
        raise AssertionError("QR decoder must not run while QR is disabled")

    monkeypatch.setattr("src.vision.decode_qr", _forbidden)
    client = ScriptedClient([_finalize_response()])
    result = _run(settings, client, _adapters(), tmp_path, email_name="qr_phishing.eml")
    assert decoder_calls == []
    manifest = _manifest(result)
    assert manifest["qr_decode_enabled"] is False
    assert manifest["qr_payload_count"] == 0
    assert manifest["qr_observable_count"] == 0
    assert manifest["visual_count_sent"] == 1


# ---------------------------------------------------------------------------
# text + QR + Vision / text + RAG + QR + Vision
# ---------------------------------------------------------------------------


def test_text_plus_qr_plus_vision_keeps_pixels_across_turns(
    runner_settings: Settings, tmp_path: Path
) -> None:
    settings = runner_settings.model_copy(
        update={"MODEL_SUPPORTS_VISION": True, "QR_DECODE_ENABLED": True}
    )
    probe_client = ScriptedClient([_finalize_response()])
    _run(settings, probe_client, _adapters(), tmp_path, email_name="qr_phishing.eml")
    qr_observable_id = _qr_observable_id(_envelope(_initial(probe_client)[0]))

    client = ScriptedClient(
        [_tool_response("lookup_virustotal", qr_observable_id), _finalize_response()]
    )
    result = _run(settings, client, _adapters(), tmp_path, email_name="qr_phishing.eml")
    assert result.status == "finalized"
    first_message, system = _initial(client)
    assert isinstance(first_message["content"], list)
    assert "VISUAL GUIDANCE" in system
    # The pixels stay part of the SAME conversation on the following turn.
    second_user = client.calls[1]["messages"][1]
    assert isinstance(second_user["content"], list)
    assert any(part["type"] == "image_url" for part in second_user["content"])
    envelope = _envelope(first_message)
    assert envelope["SUPPLIED_VISUAL_IDS"]
    assert _qr_observable_id(envelope) == qr_observable_id
    manifest = _manifest(result)
    assert manifest["vision_enabled"] is True
    assert manifest["qr_decode_enabled"] is True
    assert manifest["visual_count_sent"] == 1
    assert manifest["qr_payload_count"] == 1


def test_text_plus_rag_plus_qr_plus_vision_converged(
    runner_settings: Settings, tmp_path: Path
) -> None:
    settings = runner_settings.model_copy(
        update={"MODEL_SUPPORTS_VISION": True, "QR_DECODE_ENABLED": True}
    )
    rag = StubRagAdapter([_rag_case()])
    client = ScriptedClient([_finalize_response()])
    result = _run(
        settings,
        client,
        _adapters(),
        tmp_path,
        email_name="qr_phishing.eml",
        rag=rag,
    )
    message, system = _initial(client)
    envelope = _envelope(message)
    assert [case["case_id"] for case in envelope["RAG_CONTEXT"]] == ["rag_case_001"]
    assert envelope["SUPPLIED_VISUAL_IDS"]
    assert _qr_observable_id(envelope)
    assert "RAG GUIDANCE" in system
    assert "VISUAL GUIDANCE" in system
    manifest = _manifest(result)
    assert manifest["rag_enabled"] is True
    assert manifest["rag_case_count"] == 1
    assert manifest["vision_enabled"] is True
    assert manifest["qr_decode_enabled"] is True
    assert manifest["visual_count_sent"] == 1
    assert manifest["qr_payload_count"] == 1
    assert manifest["prompt_guidance"] == {"rag": True, "visuals": True}
    assert result.status == "finalized"


# ---------------------------------------------------------------------------
# Tool set / finalize schema / frozen V1 bytes
# ---------------------------------------------------------------------------


def _frozen_assessment_schema() -> dict[str, Any]:
    return json.loads(
        (PROJECT_ROOT / "schemas" / "assessment.schema.json").read_text(encoding="utf-8")
    )


def _collect_refs(node: Any, refs: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                refs.append(value)
            else:
                _collect_refs(value, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_refs(item, refs)


def _resolve_local_ref(document: dict[str, Any], ref: str) -> Any:
    """Resolve a local JSON pointer ``#/...`` against the tool schema."""

    assert ref.startswith("#/"), ref
    node: Any = document
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        assert isinstance(node, dict) and token in node, ref
        node = node[token]
    return node


def test_finalize_exposes_the_complete_frozen_assessment_schema() -> None:
    finalize = next(
        tool for tool in AGENT_TOOLS if tool["function"]["name"] == "finalize_assessment"
    )
    parameters = finalize["function"]["parameters"]
    assert parameters["required"] == ["assessment"]
    assert parameters["additionalProperties"] is False
    frozen = _frozen_assessment_schema()
    # The loader still returns the frozen file VERBATIM (never rewritten).
    assert assessment_schema() == frozen
    exposed = parameters["properties"]["assessment"]
    # The frozen file is embedded unchanged except for its root-only keywords.
    assert exposed == {
        key: value for key, value in frozen.items() if key not in ("$schema", "$defs")
    }
    assert "$schema" not in exposed
    assert exposed["type"] == "object"
    assert exposed["additionalProperties"] is False
    assert set(exposed["required"]) == {
        "probabilities",
        "observations",
        "inferences",
        "observable_assessments",
        "needs_enrichment",
        "missing_information",
        "decisive_evidence_ids",
    }
    # The frozen `$defs` are hoisted to the tool root (PR #19 blocker 1).
    assert parameters["$defs"] == frozen["$defs"]


def test_finalize_tool_parameters_have_resolvable_local_refs() -> None:
    """PR #19 blocker 1: every `#/$defs/...` reference written by the frozen
    schema must resolve inside the tool parameters, not at an absent root."""

    finalize = next(
        tool for tool in AGENT_TOOLS if tool["function"]["name"] == "finalize_assessment"
    )
    parameters = finalize["function"]["parameters"]
    refs: list[str] = []
    _collect_refs(parameters, refs)
    assert refs  # the frozen schema is not flattened into nothing
    for ref in refs:
        resolved = _resolve_local_ref(parameters, ref)
        assert resolved is not None
    # Every frozen definition is reachable through the hoisted root `$defs`.
    for name in _frozen_assessment_schema()["$defs"]:
        assert _resolve_local_ref(parameters, f"#/$defs/{name}") is not None


def test_only_the_three_investigation_tools_plus_finalize_are_provider_tools(
    runner_settings: Settings, tmp_path: Path
) -> None:
    names = [tool["function"]["name"] for tool in AGENT_TOOLS]
    assert names == [
        "lookup_virustotal",
        "lookup_opencti",
        "scan_urlscan",
        "finalize_assessment",
    ]
    assert not any(
        keyword in name for name in names for keyword in ("rag", "vision", "qr")
    )
    for tool in AGENT_TOOLS:
        function = tool["function"]
        if function["name"] == "finalize_assessment":
            assert set(function["parameters"]["properties"]) == {"assessment"}
        else:
            assert set(function["parameters"]["properties"]) == {"observable_id"}
            assert function["parameters"]["required"] == ["observable_id"]

    client = ScriptedClient([_finalize_response()])
    _run(runner_settings, client, _adapters(), tmp_path)
    assert client.calls[0]["tools"] is AGENT_TOOLS


def test_index_row_carries_the_per_sample_effective_prompt_sha256(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """PR #19 blocker 2: the T19C prompt carries conditional RAG/visual
    guidance, so the smoke index archives the hash PER SAMPLE; no batch-wide
    value could be true for every sample."""

    text_only = _run(
        runner_settings,
        ScriptedClient([_finalize_response()]),
        _adapters(),
        tmp_path,
    )
    with_rag = _run(
        runner_settings,
        ScriptedClient([_finalize_response()]),
        _adapters(),
        tmp_path,
        rag=StubRagAdapter([_rag_case()]),
    )
    assert text_only.prompt_sha256 != with_rag.prompt_sha256
    assert text_only.to_index_row()["effective_prompt_sha256"] == text_only.prompt_sha256
    assert with_rag.to_index_row()["effective_prompt_sha256"] == with_rag.prompt_sha256


def test_runtime_contract_hash_follows_the_conditional_prompt_guidance(
    runner_settings: Settings, tmp_path: Path
) -> None:
    """T19D §9: the RAG/visual guidance changes ``effective_prompt_sha256``
    and therefore ``runtime_contract_sha256``; the tool/schema hashes and the
    applied limits stay identical (same runtime, different context)."""

    text_only = _run(
        runner_settings,
        ScriptedClient([_finalize_response()]),
        _adapters(),
        tmp_path,
    )
    with_rag = _run(
        runner_settings,
        ScriptedClient([_finalize_response()]),
        _adapters(),
        tmp_path,
        rag=StubRagAdapter([_rag_case()]),
    )
    vision_settings = runner_settings.model_copy(update={"MODEL_SUPPORTS_VISION": True})
    with_visuals = _run(
        vision_settings,
        ScriptedClient([_finalize_response()]),
        _adapters(),
        tmp_path,
        email_name="vision/benign_image.eml",
    )

    text_manifest = _manifest(text_only)
    rag_manifest = _manifest(with_rag)
    visual_manifest = _manifest(with_visuals)
    assert (
        rag_manifest["effective_prompt_sha256"]
        != text_manifest["effective_prompt_sha256"]
    )
    assert (
        visual_manifest["effective_prompt_sha256"]
        != text_manifest["effective_prompt_sha256"]
    )
    assert (
        rag_manifest["runtime_contract_sha256"]
        != text_manifest["runtime_contract_sha256"]
    )
    assert (
        visual_manifest["runtime_contract_sha256"]
        != text_manifest["runtime_contract_sha256"]
    )
    for key in (
        "tool_schema_sha256",
        "assessment_schema_sha256",
        "limits",
        "reasoning_effort",
        "max_output_tokens_per_turn",
    ):
        assert rag_manifest[key] == text_manifest[key]
        assert visual_manifest[key] == text_manifest[key]


def test_v1_prompt_bytes_are_unchanged() -> None:
    for name, expected in V1_PROMPT_SHA256.items():
        data = (PROJECT_ROOT / "prompts" / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected, name
    assert load_internal_prompt().startswith("Tu es un analyste SOC")
    assert load_final_prompt().startswith("Tu es un analyste SOC")
    # The agentic runtime uses a SEPARATE prompt file (V2 material).
    agentic = load_agentic_prompt()
    assert agentic != load_final_prompt()
    assert agentic != load_internal_prompt()
    assert "ROLE / OBJECTIVE" in agentic


def test_dedicated_prompt_has_no_generic_reasoning_instructions() -> None:
    prompt = build_agent_system_prompt().lower()
    for forbidden in (
        "step by step",
        "think step",
        "reason carefully",
        "double check",
        "double-check",
        "explore alternatives",
        "few-shot",
        "few shot",
    ):
        assert forbidden not in prompt


def test_dedicated_prompt_states_the_non_schema_assessment_limits() -> None:
    """The frozen JSON Schema cannot express the sum/size constraints enforced
    by the Pydantic model: the prompt must still state them."""

    normalized = " ".join(build_agent_system_prompt().split())
    for fragment in (
        "au plus six",
        "240 caractères maximum",
        "au plus trois IDs existants",
        "somme 1 à 0,000001 près",
    ):
        assert fragment in normalized

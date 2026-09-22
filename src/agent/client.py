"""Native OpenAI-compatible tool-calling client (TICKET-19A).

Real Chat Completions transport against the exact endpoint configured in
``Settings.LITELLM_CHAT_URL`` with the exact ``LITELLM_MODEL`` and the
opaque ``LITELLM_API_KEY`` credential. The payload carries ``tools`` and
``tool_choice="auto"`` and the response is parsed for the REAL native
structure ``message.tool_calls[].{id,function.name,function.arguments}``.

No approximation counts as native tool calling:

- a text/XML/JSON-planner fallback does not exist;
- a provider that does not return ``message.tool_calls`` yields an explicit
  error (the capability smoke then reports
  ``BLOCKED_PROVIDER_NATIVE_TOOL_CALLING``);
- malformed arguments, missing call IDs, unknown tool names, abnormal
  ``finish_reason`` and model substitution are explicit outcomes — never
  repaired.

Security: authentication headers are built here from Settings and never
enter messages, captures or trace. Only hashes/usage/model names are
archived; the exact request body is persisted ONLY when the caller
explicitly allows it (``source_profile=fixture``), following the repository
minimization rule. ``src/llm.py`` is NOT modified: error classes and the
expurgation helper are reused read-only.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import Settings
from ..llm import LLMError, LLMTransportError, expurgate
from .models import AGENT_REASONING_EFFORT, AgentLLMResponse, ToolCall

#: ``finish_reason`` values tolerated for an agentic turn.
_OK_FINISH_REASONS = ("stop", "tool_calls")


def _json_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical serialization of the request body (one serialization only)."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")


class AgentChatClient:
    """Real OpenAI-compatible client with native tool calling; no mock mode."""

    def __init__(
        self,
        settings: Settings,
        *,
        capture_dir: Path | None = None,
        clock: Any = time.monotonic,
        persist_request_body: bool = False,
    ) -> None:
        self._settings = settings
        self._capture_dir = Path(capture_dir) if capture_dir is not None else None
        self._clock = clock
        self._persist_request_body = persist_request_body

    # -- request construction ------------------------------------------------

    def build_payload(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        effort: str,
        max_output_tokens: int,
        tool_choice: str = "auto",
    ) -> dict[str, Any]:
        """Payload with native tools; no response_format and no legacy params."""

        return {
            "model": self._settings.LITELLM_MODEL,
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
            "reasoning_effort": effort,
            "max_completion_tokens": max_output_tokens,
        }

    def build_headers(self) -> dict[str, str]:
        """Auth headers built here, outside messages; never logged/archived."""

        headers = {"Content-Type": "application/json"}
        key = self._settings.LITELLM_API_KEY
        if key is not None:
            headers["Authorization"] = f"Bearer {key.get_secret_value()}"
        return headers

    # -- transport -----------------------------------------------------------

    def _post_bytes(self, url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, method="POST")
        for name, value in self.build_headers().items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            detail = b""
            try:
                detail = error.read()
            except Exception:  # pragma: no cover - best effort only
                pass
            snippet = expurgate(detail.decode("utf-8", "replace")[:200])
            raise LLMTransportError(f"HTTP {error.code} from endpoint: {snippet}") from error
        except (socket.timeout, TimeoutError) as error:
            raise LLMTransportError(
                f"request timed out after {timeout_s:.3f}s"
            ) from error
        except urllib.error.URLError as error:
            raise LLMTransportError(
                f"connection failed: {expurgate(str(error.reason))}"
            ) from error
        except OSError as error:
            raise LLMTransportError(
                f"network I/O failure: {expurgate(str(error))}"
            ) from error

    # -- native tool-call parsing --------------------------------------------

    @staticmethod
    def _parse_tool_calls(message: dict[str, Any]) -> list[ToolCall]:
        """Parse the REAL native ``message.tool_calls`` list, never repaired.

        Each entry keeps its provider ``id`` and function ``name`` verbatim.
        ``arguments`` is parsed from the provider JSON string (a mapping is
        tolerated as the same native structure); any malformed value is
        recorded in ``arguments_error`` and refused downstream.
        """

        raw_calls = message.get("tool_calls")
        if not isinstance(raw_calls, list):
            return []
        calls: list[ToolCall] = []
        for entry in raw_calls:
            if not isinstance(entry, dict):
                calls.append(
                    ToolCall(
                        call_id=None,
                        name=None,
                        arguments_raw=None,
                        arguments=None,
                        arguments_error="tool_call_entry_not_an_object",
                    )
                )
                continue
            call_id = entry.get("id")
            call_id = call_id if isinstance(call_id, str) and call_id else None
            call_type = entry.get("type")
            function = entry.get("function")
            name: str | None = None
            arguments_raw: str | None = None
            arguments: dict[str, Any] | None = None
            error: str | None = None
            if call_type is not None and call_type != "function":
                error = f"unsupported_tool_call_type:{call_type}"
            if not isinstance(function, dict):
                error = error or "tool_call_function_missing"
            else:
                raw_name = function.get("name")
                if isinstance(raw_name, str) and raw_name:
                    name = raw_name
                else:
                    error = error or "tool_call_name_missing"
                raw_arguments = function.get("arguments")
                if isinstance(raw_arguments, str):
                    arguments_raw = raw_arguments
                    try:
                        parsed_arguments = json.loads(raw_arguments)
                    except json.JSONDecodeError:
                        error = error or "arguments_not_valid_json"
                    else:
                        if isinstance(parsed_arguments, dict):
                            arguments = parsed_arguments
                        else:
                            error = error or "arguments_not_an_object"
                elif isinstance(raw_arguments, dict):
                    # Same native call, provider serialized as an object.
                    arguments = raw_arguments
                    arguments_raw = json.dumps(
                        raw_arguments, ensure_ascii=False, sort_keys=True
                    )
                elif raw_arguments is None:
                    error = error or "arguments_missing"
                else:
                    error = error or "arguments_not_a_string"
            calls.append(
                ToolCall(
                    call_id=call_id,
                    name=name,
                    arguments_raw=arguments_raw,
                    arguments=arguments,
                    arguments_error=error,
                )
            )
        return calls

    @staticmethod
    def _observe_reasoning_content(
        message: dict[str, Any],
    ) -> tuple[bool, int | None, str | None]:
        """Passive observation of a native provider reasoning text field (T19D §5).

        When the provider returns an explicit ``reasoning_content`` string, only
        its presence, character count and SHA-256 are derived. The text is never
        persisted, never interpreted and never reinjected into a later turn; a
        provider that returns nothing yields ``(False, None, None)`` and the
        runtime continues normally.
        """

        raw = message.get("reasoning_content")
        if not isinstance(raw, str) or not raw:
            return False, None, None
        return True, len(raw), hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_usage(usage: dict[str, Any] | None) -> dict[str, int | None]:
        if not usage:
            return {
                "input_tokens": None,
                "cached_input_tokens": None,
                "output_tokens": None,
                "reasoning_tokens": None,
            }
        prompt_details = usage.get("prompt_tokens_details")
        completion_details = usage.get("completion_tokens_details")
        return {
            "input_tokens": usage.get("prompt_tokens"),
            "cached_input_tokens": (
                prompt_details.get("cached_tokens")
                if isinstance(prompt_details, dict)
                else None
            ),
            "output_tokens": usage.get("completion_tokens"),
            "reasoning_tokens": (
                completion_details.get("reasoning_tokens")
                if isinstance(completion_details, dict)
                else None
            ),
        }

    @staticmethod
    def _extract_response(
        body: bytes, requested_model: str
    ) -> AgentLLMResponse:
        """Parse a 200 body; every anomaly is an explicit error outcome."""

        response = AgentLLMResponse(
            status="error", requested_model=requested_model, attempts=1
        )
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            response.error = f"response_not_valid_json:{error}"
            return response
        if not isinstance(data, dict):
            response.error = f"unexpected_response_type:{type(data).__name__}"
            return response
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            response.error = "response_has_no_choices"
            return response
        choice = choices[0]
        if not isinstance(choice, dict):
            response.error = f"unexpected_choice_type:{type(choice).__name__}"
            return response
        finish_reason = choice.get("finish_reason")
        response.finish_reason = finish_reason if isinstance(finish_reason, str) else None
        message = choice.get("message")
        if not isinstance(message, dict):
            response.error = f"unexpected_message_type:{type(message).__name__}"
            return response

        response.returned_model = (
            data.get("model") if isinstance(data.get("model"), str) else None
        )
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        normalized_usage = AgentChatClient._normalize_usage(usage)
        response.input_tokens = normalized_usage["input_tokens"]
        response.cached_input_tokens = normalized_usage["cached_input_tokens"]
        response.output_tokens = normalized_usage["output_tokens"]
        response.reasoning_tokens = normalized_usage["reasoning_tokens"]

        refusal = message.get("refusal")
        if refusal:
            response.error = f"model_refused:{expurgate(str(refusal))[:200]}"
            return response
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            response.error = f"unexpected_content_type:{type(content).__name__}"
            return response
        response.content = content
        response.tool_calls = AgentChatClient._parse_tool_calls(message)
        (
            response.reasoning_content_present,
            response.reasoning_content_chars,
            response.reasoning_content_sha256,
        ) = AgentChatClient._observe_reasoning_content(message)

        if finish_reason not in _OK_FINISH_REASONS and not (
            finish_reason is None and response.tool_calls
        ):
            response.error = f"abnormal_finish_reason:{finish_reason!r}"
            return response
        if finish_reason == "tool_calls" and not response.tool_calls:
            response.error = "tool_calls_finish_without_tool_calls"
            return response
        if response.returned_model is None:
            response.error = "provider_did_not_report_model"
            return response
        if response.returned_model != requested_model:
            response.error = (
                "model_substitution_refused: requested "
                f"{requested_model!r}, returned {response.returned_model!r}"
            )
            return response
        response.status = "ok"
        return response

    # -- capture helpers (metadata only; never request headers) ----------------

    def _capture_meta(
        self,
        turn_index: int,
        request_sha256: str,
        request_bytes: int,
        response: AgentLLMResponse,
        response_bytes: int | None,
    ) -> None:
        if self._capture_dir is None:
            return
        self._capture_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "turn_index": turn_index,
            "requested_model": response.requested_model,
            "returned_model": response.returned_model,
            "finish_reason": response.finish_reason,
            "request_sha256": request_sha256,
            "request_bytes": request_bytes,
            "response_sha256": response.response_sha256,
            "response_bytes": response_bytes,
            # T19D §5: reasoning-metadata observation only — presence, length
            # and hash; the reasoning text itself is never written to disk.
            "reasoning_content_present": response.reasoning_content_present,
            "reasoning_content_chars": response.reasoning_content_chars,
            "reasoning_content_sha256": response.reasoning_content_sha256,
            "usage": {
                "input_tokens": response.input_tokens,
                "cached_input_tokens": response.cached_input_tokens,
                "output_tokens": response.output_tokens,
                "reasoning_tokens": response.reasoning_tokens,
            },
            "tool_call_names": [call.name for call in response.tool_calls],
            "status": response.status,
        }
        (self._capture_dir / f"agent_turn_{turn_index}_meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

    def _capture_error(self, turn_index: int, error: str) -> None:
        if self._capture_dir is None:
            return
        self._capture_dir.mkdir(parents=True, exist_ok=True)
        (self._capture_dir / f"agent_turn_{turn_index}_error.txt").write_text(
            expurgate(error), encoding="utf-8"
        )

    # -- public contract -------------------------------------------------------

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        deadline: float,
        max_output_tokens: int,
        turn_index: int,
        effort: str = AGENT_REASONING_EFFORT,
        tool_choice: str = "auto",
    ) -> AgentLLMResponse:
        """One real bounded request; returns the parsed native turn or error.

        Exactly one request per call (the bounded loop provides the turns):
        no retry, no fallback model, no fallback transport. The deadline is
        the monotonic bound of this single request.
        """

        started = self._clock()
        response = AgentLLMResponse(
            status="error",
            requested_model=self._settings.LITELLM_MODEL,
            attempts=0,
        )
        if self._settings.LITELLM_API_KEY is None:
            response.error = "llm_not_configured"
            response.elapsed_ms = round((self._clock() - started) * 1000.0, 3)
            self._capture_error(turn_index, response.error)
            return response
        remaining = deadline - self._clock()
        if remaining <= 0:
            response.error = "deadline_expired_before_request"
            response.elapsed_ms = round((self._clock() - started) * 1000.0, 3)
            self._capture_error(turn_index, response.error)
            return response

        payload = self.build_payload(
            messages,
            tools,
            effort=effort,
            max_output_tokens=max_output_tokens,
            tool_choice=tool_choice,
        )
        body = _json_bytes(payload)
        response.request_sha256 = hashlib.sha256(body).hexdigest()
        if self._capture_dir is not None and self._persist_request_body:
            self._capture_dir.mkdir(parents=True, exist_ok=True)
            (self._capture_dir / f"agent_turn_{turn_index}_request.json").write_bytes(body)

        try:
            status, raw = self._post_bytes(
                self._settings.LITELLM_CHAT_URL, body, timeout_s=remaining
            )
        except LLMError as error:
            response.error = f"{type(error).__name__}:{expurgate(str(error))[:300]}"
            response.elapsed_ms = round((self._clock() - started) * 1000.0, 3)
            self._capture_error(turn_index, response.error)
            self._capture_meta(
                turn_index,
                response.request_sha256,
                len(body),
                response,
                None,
            )
            return response

        response.attempts = 1
        response.response_sha256 = hashlib.sha256(raw).hexdigest()
        if status != 200:
            response.error = f"unexpected_http_status:{status}"
        else:
            response = self._extract_response(raw, self._settings.LITELLM_MODEL)
            response.request_sha256 = hashlib.sha256(body).hexdigest()
            response.response_sha256 = hashlib.sha256(raw).hexdigest()
            response.attempts = 1
        response.elapsed_ms = round((self._clock() - started) * 1000.0, 3)
        if response.status != "ok":
            self._capture_error(turn_index, str(response.error))
        self._capture_meta(turn_index, response.request_sha256, len(body), response, len(raw))
        return response


__all__ = ["AgentChatClient"]

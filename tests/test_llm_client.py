"""Client LLM tests (TICKET-02): contract, errors, secret hygiene.

Real requests are only performed by tests marked ``live`` (explicit
``--live``) or by ``scripts/smoke.py``. Everything here is local: error
processing functions are fed canned BYTES as data (docs/gates.md §5.2
authorizes function-level tests of error paths without a fake server and
without pretending a provider answered).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.config import load_settings
from src.llm import (
    LLMInvalidResponse,
    LLMRefused,
    LLMTimeout,
    LunaClient,
    expurgate,
    validate_against_schema,
)

pytestmark = pytest.mark.g0

#: Local canary secret used to prove no secret value reaches logs/artifacts.
CANARY = "sk-canary-0123456789abcdefDONOTLEAK"

OK_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}


def _client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> LunaClient:
    """Client with a canary key against an unresolvable endpoint (no network)."""

    monkeypatch.setenv("LITELLM_API_KEY", CANARY)
    monkeypatch.setenv("LITELLM_CHAT_URL", "https://endpoint.invalid/chat/completions")
    monkeypatch.setenv("LITELLM_MODEL", "openai/gpt-5.6-luna")
    settings = load_settings(None)
    return LunaClient(settings, capture_dir=tmp_path / "captures")


# ---------------------------------------------------------------------------
# Payload hygiene: no secret in the payload, headers outside messages
# ---------------------------------------------------------------------------


def test_payload_and_messages_contain_no_secret(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    messages = [{"role": "user", "content": "ping"}]
    payload = client.build_payload(messages, OK_SCHEMA, "medium", 128)
    serialized = json.dumps(payload)
    assert CANARY not in serialized
    assert "Authorization" not in serialized
    assert payload["model"] == "openai/gpt-5.6-luna"
    assert payload["response_format"]["json_schema"]["strict"] is True
    assert "tools" not in payload and "temperature" not in payload and "top_k" not in payload
    # headers are built by the client from Settings, never part of messages
    headers = client.build_headers()
    assert headers["Authorization"] == f"Bearer {CANARY}"
    assert all("Authorization" not in json.dumps(m) for m in messages)


def test_serialized_body_has_stable_hash(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit/hash path serializes once; identical inputs, identical bytes."""

    import hashlib

    from src.llm import _json_bytes

    client = _client(monkeypatch, tmp_path)
    body = _json_bytes(client.build_payload([{"role": "user", "content": "ping"}], OK_SCHEMA, "medium", 128))
    again = _json_bytes(client.build_payload([{"role": "user", "content": "ping"}], OK_SCHEMA, "medium", 128))
    assert body == again
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(again).hexdigest()


# ---------------------------------------------------------------------------
# Minimal schema validator: invalid JSON / shapes are rejected
# ---------------------------------------------------------------------------


def test_validator_rejects_missing_and_unexpected_fields() -> None:
    errors = validate_against_schema({"other": True}, OK_SCHEMA)
    assert any("missing required" in e for e in errors)
    errors = validate_against_schema({"ok": True, "extra": 1}, OK_SCHEMA)
    assert any("unexpected property" in e for e in errors)
    errors = validate_against_schema({"ok": "yes"}, OK_SCHEMA)
    assert any("expected boolean" in e for e in errors)


def test_validator_rejects_wrong_container_types() -> None:
    assert validate_against_schema([1, 2], OK_SCHEMA)
    assert validate_against_schema("text", OK_SCHEMA)
    errors = validate_against_schema({"ok": True}, {"type": "unsupported"})
    assert any("unsupported schema type" in e for e in errors)


# ---------------------------------------------------------------------------
# Response processing: refusals, finish_reason, invalid JSON, bad types
# ---------------------------------------------------------------------------


def _response_bytes(content: str, **overrides: object) -> bytes:
    body: dict[str, object] = {
        "model": "openai/gpt-5.6-luna",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
    }
    body.update(overrides)
    return json.dumps(body).encode("utf-8")


def test_extract_accepts_valid_content(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    result, model, usage, fenced = client._extract_result(
        _response_bytes('{"ok": true}'), OK_SCHEMA
    )
    assert result == {"ok": True}
    assert fenced is False
    assert model == "openai/gpt-5.6-luna"
    assert usage["input_tokens"] == 3 and usage["output_tokens"] == 2


def test_extract_rejects_invalid_json_content(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMInvalidResponse, match="not valid JSON"):
        client._extract_result(_response_bytes("{not json"), OK_SCHEMA)


def test_extract_rejects_abnormal_finish_reason(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMInvalidResponse, match="finish_reason"):
        client._extract_result(
            _response_bytes('{"ok": true}', **{"choices": [{"finish_reason": "length", "message": {"content": '{"ok": true}'}}]}),
            OK_SCHEMA,
        )


def test_extract_rejects_refusal(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    body = json.dumps(
        {
            "model": "openai/gpt-5.6-luna",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": None, "refusal": "cannot help with this"},
                }
            ],
        }
    ).encode("utf-8")
    with pytest.raises(LLMRefused):
        client._extract_result(body, OK_SCHEMA)


def test_extract_rejects_unexpected_types(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMInvalidResponse, match="unexpected response type"):
        client._extract_result(b"[1,2,3]", OK_SCHEMA)
    with pytest.raises(LLMInvalidResponse, match="no choices"):
        client._extract_result(b"{}", OK_SCHEMA)
    with pytest.raises(LLMInvalidResponse, match="not valid JSON"):
        client._extract_result(b"not json at all", OK_SCHEMA)


def test_extract_rejects_schema_violation(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMInvalidResponse, match="schema violation"):
        client._extract_result(_response_bytes('{"ok": "not-a-bool"}'), OK_SCHEMA)


def test_extract_accepts_fenced_json_and_stays_schema_valid(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Traced fence tolerance: fully validated, flagged, never a silent pass."""

    client = _client(monkeypatch, tmp_path)
    result, model, usage, fenced = client._extract_result(
        _response_bytes('```json\n{"ok": true}\n```'), OK_SCHEMA
    )
    assert result == {"ok": True}  # no marker injected into the result
    assert fenced is True
    assert model == "openai/gpt-5.6-luna"
    assert usage["input_tokens"] == 3


def test_extract_rejects_fenced_invalid_json(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMInvalidResponse, match="fenced content is not valid JSON"):
        client._extract_result(_response_bytes("```json\n{broken\n```"), OK_SCHEMA)


def test_extract_rejects_fenced_schema_violation(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fenced payload is validated EXACTLY like a raw one: no escape hatch."""

    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMInvalidResponse, match="schema violation"):
        client._extract_result(_response_bytes('```json\n{"ok": "yes"}\n```'), OK_SCHEMA)


def test_fenced_live_path_leaves_trace_artifact(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """complete_json traces the fence deviation in the capture directory."""

    import time as _time

    calls: dict[str, str] = {}

    client = _client(monkeypatch, tmp_path)

    def _fake_post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
        calls["url"] = url
        return 200, _response_bytes('```json\n{"ok": true}\n```')

    client._post_bytes = _fake_post  # type: ignore[method-assign]
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="low",
        max_output_tokens=128,
        deadline=_time.monotonic() + 10.0,
    )
    assert result == {"ok": True}
    assert record.status == "ok"
    trace = tmp_path / "captures" / "attempt_1_trace_fence_extracted.txt"
    assert trace.is_file()
    assert calls["url"] == "https://endpoint.invalid/chat/completions"


# ---------------------------------------------------------------------------
# Deadline handling: a real timeout without any request sent
# ---------------------------------------------------------------------------


def test_timeout_expired_deadline_sends_nothing(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real deadline semantics: no attempt runs after the deadline, no network."""

    client = _client(monkeypatch, tmp_path)
    with pytest.raises(LLMTimeout, match="deadline expired"):
        client.complete_json(
            messages=[{"role": "user", "content": "ping"}],
            schema=OK_SCHEMA,
            effort="medium",
            max_output_tokens=128,
            deadline=0.0,  # already expired on any monotonic clock
        )
    # nothing was sent: no capture, no request hash recorded on disk
    assert not (tmp_path / "captures").exists() or not any((tmp_path / "captures").iterdir())


# ---------------------------------------------------------------------------
# Secret hygiene: canary never appears in errors, captures or logs
# ---------------------------------------------------------------------------


def test_canary_never_leaks_in_errors_or_captures(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unresolvable endpoint: real transport error, canary value absent."""

    import glob

    client = _client(monkeypatch, tmp_path)
    with pytest.raises(Exception) as excinfo:  # noqa: PT011 - any failure class
        client.complete_json(
            messages=[{"role": "user", "content": "ping"}],
            schema=OK_SCHEMA,
            effort="medium",
            max_output_tokens=128,
            deadline=_client_deadline(),
        )
    assert CANARY not in str(excinfo.value)
    assert expurgate(f"Bearer {CANARY}") == "[REDACTED]"
    for path in glob.glob(str(tmp_path / "captures" / "*")):
        assert CANARY not in Path(path).read_text(encoding="utf-8", errors="replace")


def _client_deadline() -> float:
    import time

    return time.monotonic() + 5.0


# ---------------------------------------------------------------------------
# CLI errors are readable (no tracebacks, no secrets)
# ---------------------------------------------------------------------------


def test_smoke_cli_error_readable_without_key(
    clean_env: None, project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without --if-configured and without a key: explicit non-zero error.

    The status stays ``live_pending`` (truthful) but it is NOT presented as a
    success: the CLI exits non-zero with a readable explanation.
    """

    import os

    proc = subprocess.run(
        [sys.executable, "scripts/smoke.py", "luna"],
        cwd=project_root, shell=False, capture_output=True, text=True,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(project_root)},
    )
    assert proc.returncode != 0
    assert CANARY not in proc.stdout + proc.stderr
    assert '"status": "live_pending"' in proc.stdout  # truthful status, never simulated
    assert "FAILED" in proc.stdout + proc.stderr  # and never a fake success
    assert not proc.stdout.startswith("Traceback")  # readable, no raw traceback


@pytest.mark.live
def test_real_request_when_configured(clean_env: None) -> None:
    """Real request when credentials exist (docs/gates.md §5.2: explicit --live)."""

    import time as _time

    settings = load_settings(None)
    if settings.LITELLM_API_KEY is None:
        pytest.skip("LITELLM_API_KEY absent: nothing live to prove (never simulated)")
    client = LunaClient(settings, phase="internal")
    result, record = client.complete_json(
        messages=[{"role": "user", "content": 'Reply {"ok": true}'}],
        schema=OK_SCHEMA,
        effort="medium",
        max_output_tokens=128,
        deadline=_time.monotonic() + 60.0,
    )
    assert result is not None and result.get("ok") is True
    assert record.status == "ok" and record.returned_model

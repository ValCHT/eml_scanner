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
    """Real deadline semantics: no attempt runs after the deadline, no network.

    Blocker 1 contract: the public method returns ``(None, record)`` with
    ``record.status="error"`` — it never raises.
    """

    client = _client(monkeypatch, tmp_path)
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="medium",
        max_output_tokens=128,
        deadline=0.0,  # already expired on any monotonic clock
    )
    assert result is None
    assert record.status == "error"
    assert record.phase == "internal"
    assert record.requested_model == "openai/gpt-5.6-luna"
    assert record.reasoning_effort == "medium"
    assert record.attempts == 0  # no attempt was ever launched
    assert record.request_sha256 is None  # nothing was ever sent
    # nothing was sent: no capture, no artifact written
    assert not (tmp_path / "captures").exists() or not any((tmp_path / "captures").iterdir())


# ---------------------------------------------------------------------------
# Secret hygiene: canary never appears in errors, captures or logs
# ---------------------------------------------------------------------------


def test_canary_never_leaks_in_errors_or_captures(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unresolvable endpoint: real transport error, canary value absent.

    Blocker 1 contract: the transport failure returns ``(None, record)``
    instead of raising; the canary never reaches the record or artifacts.
    """

    import glob

    client = _client(monkeypatch, tmp_path)
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="medium",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    assert result is None
    assert record.status == "error"
    assert CANARY not in str(record.model_dump())
    assert expurgate(f"Bearer {CANARY}") == "[REDACTED]"
    for path in glob.glob(str(tmp_path / "captures" / "*")):
        assert CANARY not in Path(path).read_text(encoding="utf-8", errors="replace")


def _client_deadline() -> float:
    import time

    return time.monotonic() + 5.0


# ---------------------------------------------------------------------------
# Blocker 1: complete_json NEVER raises — (None, record) on every failure
# ---------------------------------------------------------------------------


def _refusal_body() -> bytes:
    return json.dumps(
        {
            "model": "openai/gpt-5.6-luna",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": None, "refusal": "no"},
                }
            ],
        }
    ).encode("utf-8")


def _failure_cases() -> list[str]:
    """Parametrized failure modes; ids only, bodies built inside the test.

    Keep this function ABOVE the parametrized test (the decorator evaluates
    at definition time).
    """

    return ["timeout", "transport", "refusal", "invalid_json", "schema_invalid"]


@pytest.mark.parametrize("failure_case", _failure_cases())
def test_complete_json_returns_none_record_on_every_failure_mode(
    clean_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_case: str,
) -> None:
    """Parametrized: timeout, transport, refusal, invalid JSON, bad schema.

    The frozen public contract holds in EVERY case: ``(None, CallRecord)``
    with ``status="error"``, never a raised exception.
    """

    import time as _time

    from src.llm import LLMTimeout, LLMTransportError
    from src.state import CallRecord

    client = _client(monkeypatch, tmp_path)

    if failure_case == "timeout":
        def _post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
            raise LLMTimeout("deadline")
    elif failure_case == "transport":
        def _post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
            raise LLMTransportError("boom")
    elif failure_case == "refusal":
        body_bytes: bytes = _refusal_body()
        def _post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
            return 200, body_bytes
    elif failure_case == "invalid_json":
        body_bytes = _response_bytes("definitely not json")
        def _post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
            return 200, body_bytes
    else:  # schema_invalid
        body_bytes = _response_bytes('{"ok": "not-a-bool"}')
        def _post(url: str, body: bytes, timeout_s: float) -> tuple[int, bytes]:
            return 200, body_bytes

    client._post_bytes = _post  # type: ignore[method-assign]
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="medium",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    assert result is None, f"failure mode {failure_case} must return None"
    assert isinstance(record, CallRecord)
    assert record.status == "error"
    assert record.phase == "internal"
    assert record.requested_model == "openai/gpt-5.6-luna"
    assert record.reasoning_effort == "medium"
    assert record.attempts == 2  # MAX_LLM_ATTEMPTS default: both attempts ran
    assert record.request_sha256 is not None  # a request was really sent
    assert record.response_refs  # error artifacts are referenced
    for ref in record.response_refs:
        assert (tmp_path / "captures" / ref).is_file()
    assert CANARY not in str(record.model_dump())


# ---------------------------------------------------------------------------
# Blocker 2: metadata-only persistence; hash of the EXACT provider bytes
# ---------------------------------------------------------------------------


def test_no_raw_response_persisted_and_hash_of_exact_provider_bytes(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No attempt_*_response.json raw body anywhere; meta carries the real hash.

    ``response_sha256`` is computed on the raw provider bytes BEFORE parsing,
    not on the normalized result.
    """

    import hashlib

    client = _client(monkeypatch, tmp_path)
    raw = _response_bytes('{"ok": true}')
    client._post_bytes = lambda url, body, timeout_s: (200, raw)  # type: ignore[method-assign]
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="low",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    assert result == {"ok": True} and record.status == "ok"
    captures = tmp_path / "captures"
    # NO raw provider response is ever on disk:
    assert not list(captures.glob("attempt_*_response.json"))
    # the raw body content is absent from every artifact:
    for artifact in captures.iterdir():
        assert b'"prompt_tokens"' not in artifact.read_bytes()
    # the meta file carries the hash of the EXACT raw bytes:
    metas = list(captures.glob("attempt_*_response_meta.json"))
    assert len(metas) == 1
    meta = json.loads(metas[0].read_text(encoding="utf-8"))
    assert meta["response_sha256"] == hashlib.sha256(raw).hexdigest()
    assert meta["response_sha256"] != hashlib.sha256(
        json.dumps({"ok": True}, sort_keys=True).encode("utf-8")
    )  # NOT a hash of the normalized result
    assert meta["response_bytes"] == len(raw)
    assert meta["returned_model"] == "openai/gpt-5.6-luna"
    assert meta["usage"]["input_tokens"] == 3
    assert meta["fence_extracted"] is False


def test_smoke_payload_reflects_client_metadata_hash(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The smoke reads the client's real raw-bytes hash (never a result hash)."""

    import hashlib
    import importlib.util
    import types

    client = _client(monkeypatch, tmp_path)
    raw = _response_bytes('{"ok": true}')
    client._post_bytes = lambda url, body, timeout_s: (200, raw)  # type: ignore[method-assign]
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="low",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    # load scripts/smoke.py the same way a ``python scripts/smoke.py`` run does
    spec = importlib.util.spec_from_file_location(
        "smoke_module", Path(__file__).resolve().parent.parent / "scripts" / "smoke.py"
    )
    assert spec and spec.loader
    smoke = importlib.util.module_from_spec(spec)  # defines __file__ properly
    spec.loader.exec_module(smoke)  # noqa: S101 - test context
    payload = smoke._public_payload(result, record, tmp_path / "captures")
    assert payload["response_sha256"] == hashlib.sha256(raw).hexdigest()
    assert payload["response_bytes"] == len(raw)


# ---------------------------------------------------------------------------
# Blocker 3: no-model-fallback enforced on the returned model
# ---------------------------------------------------------------------------


def test_model_identical_is_accepted(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Returned model == requested model: normal success path."""

    client = _client(monkeypatch, tmp_path)  # requested: openai/gpt-5.6-luna
    client._post_bytes = lambda url, body, timeout_s: (  # type: ignore[method-assign]
        200, _response_bytes('{"ok": true}')
    )
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="low",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    assert result == {"ok": True} and record.status == "ok"
    assert record.returned_model == record.requested_model


def test_model_missing_is_rejected(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No ``model`` field in the provider response: NO success declared."""

    body = json.loads(_response_bytes('{"ok": true}').decode("utf-8"))
    body.pop("model")
    client = _client(monkeypatch, tmp_path)
    client._post_bytes = lambda url, body_, timeout_s: (  # type: ignore[method-assign]
        200, json.dumps(body).encode("utf-8")
    )
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="low",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    assert result is None and record.status == "error"
    assert record.returned_model is None


def test_model_substitution_is_rejected(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Silent model substitution: explicit refusal of the success path."""

    body = json.loads(_response_bytes('{"ok": true}').decode("utf-8"))
    body["model"] = "totally-different/model"
    client = _client(monkeypatch, tmp_path)
    client._post_bytes = lambda url, body_, timeout_s: (  # type: ignore[method-assign]
        200, json.dumps(body).encode("utf-8")
    )
    result, record = client.complete_json(
        messages=[{"role": "user", "content": "ping"}],
        schema=OK_SCHEMA,
        effort="low",
        max_output_tokens=128,
        deadline=_client_deadline(),
    )
    assert result is None and record.status == "error"
    assert record.returned_model is None  # never advertise a refused model
    assert record.attempts == 2


# ---------------------------------------------------------------------------
# Blocker 5: REAL transport timeout against a local unresponsive socket
# ---------------------------------------------------------------------------


def test_real_transport_timeout_converts_to_llm_timeout(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local server accepts the connection and NEVER answers.

    Deterministic and cross-platform: 127.0.0.1, ephemeral port, no proxy in
    this environment, no Internet, no external quota. The socket.timeout
    path must surface as LLMTimeout internally, and complete_json must
    return (None, record) per the frozen public contract.
    """

    import socket as _socket
    import threading
    import time as _time

    from src.llm import LLMTimeout

    server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    release = threading.Event()

    def _accept_and_hold() -> None:
        try:
            conn, _addr = server.accept()
            release.wait(5.0)  # accepted, then deliberately silent
            conn.close()
        except OSError:
            pass

    worker = threading.Thread(target=_accept_and_hold, daemon=True)
    worker.start()

    client = _client(monkeypatch, tmp_path)
    local_url = f"http://127.0.0.1:{port}/chat/completions"
    client._settings.LITELLM_CHAT_URL = local_url  # transport-level test only
    try:
        # internal conversion check: socket.timeout -> LLMTimeout
        with pytest.raises(LLMTimeout, match="timed out"):
            client._post_bytes(local_url, b"{}", timeout_s=0.5)
        # public contract check: (None, record). A transport timeout consumes
        # the remaining budget (docs/architecture.md §1.4: "chaque timeout est
        # borné par le temps restant"), so exactly one attempt was launched:
        # a second attempt would start with timeout_s≈0. record.attempts == 1
        # is the documented correct behavior here, NOT a dropped retry.
        result, record = client.complete_json(
            messages=[{"role": "user", "content": "ping"}],
            schema=OK_SCHEMA,
            effort="low",
            max_output_tokens=128,
            deadline=_time.monotonic() + 10.0,
        )
        assert result is None and record.status == "error"
        assert record.attempts == 1
        assert record.request_sha256 is not None
    finally:
        release.set()
        server.close()


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

"""Minimal real OpenAI-compatible LLM client.

``LunaClient.complete_json`` performs a real POST to the exact endpoint
configured in ``Settings.LITELLM_CHAT_URL`` with structured output
(``response_format=json_schema``, strict). There is no fallback: not to
another model, not to another provider, not to free-form JSON. Refusals,
abnormal ``finish_reason``, invalid JSON, schema violations and unexpected
response types are explicit errors — never replaced by a synthetic answer.

Security invariants:

- Authentication headers are built here, from ``Settings.LITELLM_API_KEY``,
  and are never part of ``messages``, never logged and never archived.
- Captured artifacts contain usage, returned model and hashes only; request
  headers are never persisted.
- Provider and model selection come only from the generic ``LITELLM_*``
  settings. ``LunaClient`` remains the frozen public class name, not a
  provider-selection mechanism.

Transport note: the stdlib ``urllib.request`` is used instead of httpx
because FILES ALLOWED for TICKET-02 does not include the dependency
manifests (pyproject.toml / requirements.lock). httpx will be introduced by
the ticket that may edit them; the client isolates the transport in
``_post_bytes`` so that swap stays local.

TICKET-04 addition — exact-bytes input audit (docs/contracts.md §2.6.1):
the payload is serialized ONCE, the audit (``input_audit`` fields) is
calculated from those exact bytes and those exact bytes are what the
transport sends. Per attempt actually emitted, the client archives
``<phase>_attempt_<n>.input_audit.json``; the full HTTP request body is
archived as ``<phase>_attempt_<n>.request.json`` ONLY when the caller
explicitly enables it (``persist_request_body=True``), which the harness
does exclusively for ``source_profile=fixture``. The default is
minimization: for ``public_corpus`` / ``private_authorized`` the same
serialization/audit path runs entirely in memory and no request body is
ever persisted.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import Settings
from .prompts import canonical_bytes
from .state import CallRecord

#: Mask anything secret-like before an error message can be displayed or
#: archived (same intent as scripts/check_gate.expurgate, kept local so the
#: client never imports from scripts).
_SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"authorization\s*:\s*Bearer\s+\S+",
        # Bare bearer-token form too (defense in depth): even without the
        # "Authorization:" prefix, a Bearer credential must never surface.
        r"bearer\s+[A-Za-z0-9_\-]{8,}",
        r'"(?:api[_-]?key|access[_-]?token|secret|token|password|authorization)"\s*:\s*"[^"]*"',
        r"\b(api[_-]?key|access[_-]?token|token|secret|password)\s*[=:]\s*\S+",
        r"sk-[A-Za-z0-9\-]{8,}",
        r"akml-[A-Za-z0-9_\-]{4,}",
    )
]


def expurgate(text: str) -> str:
    """Mask anything resembling a secret in messages meant for humans."""

    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


class LLMError(Exception):
    """Base class of every explicit client failure (message is secret-free)."""


class LLMTimeout(LLMError):
    """The deadline expired before a validated answer was obtained."""


class LLMRefused(LLMError):
    """The model refused or returned an explicit refusal content."""


class LLMInvalidResponse(LLMError):
    """Abnormal finish_reason, unexpected type, invalid JSON or schema violation."""


class LLMTransportError(LLMError):
    """HTTP / network failure against the configured endpoint."""


def _json_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical serialization of the request body (one serialization only)."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")


def validate_against_schema(
    value: object, schema: dict[str, Any], path: str = "$", root: dict[str, Any] | None = None
) -> list[str]:
    """Minimal JSON-Schema subset validator (no external dependency).

    Supports the constructs used by the frozen POC schemas: ``$ref`` into
    ``$defs``, ``type``, ``properties``, ``required``, ``items``,
    ``additionalProperties: false``, ``enum``, ``minimum``/``maximum`` and
    ``anyOf``. Full Assessment schema validation arrives with G2
    (docs/gates.md §5.1).
    """

    if root is None:
        root = schema

    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target: object = root
        for part in ref[2:].split("/"):
            if not isinstance(target, dict) or part not in target:
                return [f"{path}: unresolved $ref {ref!r}"]
            target = target[part]
        if not isinstance(target, dict):
            return [f"{path}: $ref {ref!r} does not resolve to a schema"]
        return validate_against_schema(value, target, path, root)

    errors: list[str] = []

    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and any_of:
        for variant in any_of:
            if not validate_against_schema(value, variant, path, root):
                return []
        return [f"{path}: does not match any variant of anyOf"]

    expected = schema.get("type")
    if expected is not None:
        type_ok = {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "boolean": lambda v: isinstance(v, bool),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "null": lambda v: v is None,
        }.get(expected)
        if type_ok is None:
            return [f"{path}: unsupported schema type {expected!r}"]
        if not type_ok(value):
            return [f"{path}: expected {expected}, got {type(value).__name__}"]

    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and value not in enum_values:
        errors.append(f"{path}: value {value!r} not in enum")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{path}: value {value} below minimum {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            errors.append(f"{path}: value {value} above maximum {maximum}")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key!r}")
        for key, subschema in properties.items():
            if key in value and isinstance(subschema, dict):
                errors.extend(validate_against_schema(value[key], subschema, f"{path}.{key}", root))
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required property {key!r}")
    elif isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                errors.extend(validate_against_schema(item, items, f"{path}[{index}]", root))
    return errors


class LunaClient:
    """Real OpenAI-compatible client; no mock mode exists by design."""

    def __init__(
        self,
        settings: Settings,
        phase: str = "internal",
        capture_dir: Path | None = None,
        clock: Any = time.monotonic,
        persist_request_body: bool = False,
    ) -> None:
        if phase not in ("internal", "final"):
            raise ValueError("phase must be 'internal' or 'final'")
        self._settings = settings
        self._phase = phase
        self._capture_dir = Path(capture_dir) if capture_dir is not None else None
        self._clock = clock
        # §2.6.1 minimization: the full request body is persisted ONLY when
        # the caller explicitly allows it (fixture source profile for G2
        # wiring proof). Default False: public_corpus/private_authorized
        # never leave a request body on disk.
        self._persist_request_body = persist_request_body

    # -- request construction ------------------------------------------------

    def build_payload(
        self,
        messages: list[dict[str, Any]],
        schema: dict[str, Any],
        effort: str,
        max_output_tokens: int,
    ) -> dict[str, Any]:
        """Payload per docs/architecture.md §1.4: no tools, no legacy params."""

        return {
            "model": self._settings.LITELLM_MODEL,
            "messages": messages,
            "reasoning_effort": effort,
            "max_completion_tokens": max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "response_v1",
                    "strict": True,
                    "schema": schema,
                },
            },
        }

    def build_headers(self) -> dict[str, str]:
        """Auth headers built here, outside messages; never logged/archived."""

        headers = {"Content-Type": "application/json"}
        key = self._settings.LITELLM_API_KEY
        if key is not None:
            headers["Authorization"] = f"Bearer {key.get_secret_value()}"
        return headers

    # -- transport -------------------------------------------------------------

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
            raise LLMTimeout(f"request timed out after {timeout_s:.3f}s") from error
        except urllib.error.URLError as error:
            reason = expurgate(str(error.reason))
            raise LLMTransportError(f"connection failed: {reason}") from error
        except OSError as error:
            # ConnectionResetError and other raw socket errors are raised
            # DIRECTLY by http.client during read (not wrapped in URLError):
            # without this catch-all they would escape complete_json and
            # break the frozen (None, CallRecord) public contract.
            raise LLMTransportError(f"network I/O failure: {expurgate(str(error))}") from error

    # -- response handling -----------------------------------------------------

    @staticmethod
    def _extract_result(
        body: bytes, schema: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None, dict[str, int | None], bool]:
        """Parse a successful HTTP body; every anomaly is an explicit error.

        Returns ``(result, returned_model, usage, fenced)`` — 4 items. The
        usage is already normalized to the CallRecord fields.
        """

        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LLMInvalidResponse(f"response is not valid JSON: {error}") from error
        if not isinstance(data, dict):
            raise LLMInvalidResponse(f"unexpected response type: {type(data).__name__}")

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMInvalidResponse("response has no choices")
        choice = choices[0]
        if not isinstance(choice, dict):
            raise LLMInvalidResponse(f"unexpected choice type: {type(choice).__name__}")

        finish_reason = choice.get("finish_reason")
        if finish_reason != "stop":
            raise LLMInvalidResponse(f"abnormal finish_reason: {finish_reason!r}")

        message = choice.get("message")
        if not isinstance(message, dict):
            raise LLMInvalidResponse(f"unexpected message type: {type(message).__name__}")

        refusal = message.get("refusal")
        if refusal:
            raise LLMRefused(expurgate(str(refusal))[:200])

        content = message.get("content")
        if not isinstance(content, str):
            raise LLMInvalidResponse(f"unexpected content type: {type(content).__name__}")
        result, fenced = LunaClient._parse_content(content)
        if not isinstance(result, dict):
            raise LLMInvalidResponse(f"unexpected content type: {type(result).__name__}")
        # ``fenced`` is returned for tracing (CallRecord/artifacts) but never
        # injected into the result object: the validated document must stay
        # exactly what the schema allows (additionalProperties: false).
        errors = validate_against_schema(result, schema)
        if errors:
            raise LLMInvalidResponse("schema violation: " + "; ".join(errors[:5]))

        returned_model = data.get("model") if isinstance(data.get("model"), str) else None
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        return result, returned_model, LunaClient._normalize_usage(usage), fenced

    @staticmethod
    def _parse_content(content: str) -> tuple[object, bool]:
        """Parse the message content: strict JSON first, fenced JSON second.

        Returns ``(parsed, fenced)``. A fenced block is accepted ONLY when the
        content is exactly one markdown code fence whose payload is the JSON
        object; anything else is an explicit error. The fence tolerance is a
        traced transport deviation, not a structured-output fallback.
        """

        try:
            return json.loads(content), False
        except json.JSONDecodeError:
            pass
        fence = re.fullmatch(
            r"```[a-zA-Z0-9]*\s*\n(?P<payload>.*)\n?```\s*",
            content,
            re.DOTALL,
        )
        if fence:
            try:
                return json.loads(fence.group("payload")), True
            except json.JSONDecodeError as error:
                raise LLMInvalidResponse(
                    f"fenced content is not valid JSON: {error}"
                ) from error
        raise LLMInvalidResponse(f"content is not valid JSON: {content[:80]!r}")

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
                prompt_details.get("cached_tokens") if isinstance(prompt_details, dict) else None
            ),
            "output_tokens": usage.get("completion_tokens"),
            "reasoning_tokens": (
                completion_details.get("reasoning_tokens")
                if isinstance(completion_details, dict)
                else None
            ),
        }

    # -- exact-bytes input audit (docs/contracts.md §2.6.1) ---------------------

    @staticmethod
    def compute_input_audit(body: bytes, phase: str) -> dict[str, Any]:
        """Audit fields computed from the EXACT bytes handed to transport.

        The serialized request body is parsed back (same bytes object that
        ``_post_bytes`` receives), the user envelope is extracted from it and
        the §2.6.1 fields are derived from that extraction — never from the
        pre-projection objects:

        - ``input_payload_sha256``: SHA-256 of the exact body bytes;
        - ``untrusted_email_sha256``: SHA-256 of ``C(UNTRUSTED_EMAIL)``
          extracted from the user message in this body (``None`` when the
          call carries no INTERNAL/FINAL envelope — e.g. the G0 smoke);
        - ``body_chars_sent`` / ``headers_chars_sent``: Unicode character
          counters of the useful content actually included;
        - ``evidence_count_sent`` / ``observable_count_sent``: registry
          entry counts actually included.
        """

        payload = json.loads(body.decode("utf-8"))
        messages = payload.get("messages") if isinstance(payload, dict) else None
        user_content: Any = None
        if isinstance(messages, list):
            for message in messages:
                if isinstance(message, dict) and message.get("role") == "user":
                    user_content = message.get("content")
        # Multimodal form: read the first text block of the content parts.
        if isinstance(user_content, list):
            first_text = next(
                (part.get("text") for part in user_content if isinstance(part, dict) and part.get("type") == "text"),
                None,
            )
            user_content = first_text

        envelope: dict[str, Any] | None = None
        if isinstance(user_content, str):
            try:
                parsed_content = json.loads(user_content)
            except json.JSONDecodeError:
                parsed_content = None
            if isinstance(parsed_content, dict) and "UNTRUSTED_EMAIL" in parsed_content:
                envelope = parsed_content

        if envelope is None:
            # No INTERNAL/FINAL envelope in this call (e.g. smoke probe): the
            # envelope-specific audit fields are truthfully absent/zero, and
            # the payload hash stays exact.
            return {
                "phase": phase,
                "input_payload_sha256": hashlib.sha256(body).hexdigest(),
                "untrusted_email_sha256": None,
                "body_chars_sent": 0,
                "headers_chars_sent": 0,
                "evidence_count_sent": 0,
                "observable_count_sent": 0,
            }

        untrusted = envelope["UNTRUSTED_EMAIL"]
        body_chars = sum(
            len(part.get("text") or "")
            for part in (
                *(untrusted.get("text_parts") or []),
                *(untrusted.get("html_parts") or []),
            )
            if isinstance(part, dict)
        )
        headers_chars = sum(
            len(header.get("name") or "") + len(header.get("decoded_value") or "")
            for header in (untrusted.get("headers") or [])
            if isinstance(header, dict)
        )
        evidence_registry = envelope.get("EVIDENCE_REGISTRY")
        observable_registry = envelope.get("OBSERVABLE_REGISTRY")
        return {
            "phase": phase,
            "input_payload_sha256": hashlib.sha256(body).hexdigest(),
            "untrusted_email_sha256": hashlib.sha256(
                canonical_bytes(untrusted)
            ).hexdigest(),
            "body_chars_sent": body_chars,
            "headers_chars_sent": headers_chars,
            "evidence_count_sent": (
                len(evidence_registry) if isinstance(evidence_registry, dict) else 0
            ),
            "observable_count_sent": (
                len(observable_registry) if isinstance(observable_registry, dict) else 0
            ),
        }

    def _capture_attempt_input(
        self, attempt: int, body: bytes, audit: dict[str, Any]
    ) -> None:
        """Archive the per-attempt audit (always) and the request body (only
        when explicitly allowed for the fixture source profile)."""

        if self._capture_dir is None:
            return
        (self._capture_dir / f"{self._phase}_attempt_{attempt}.input_audit.json").write_text(
            json.dumps(audit, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        if self._persist_request_body:
            # The EXACT bytes object handed to transport — one serialization,
            # one variable, no independent re-serialization for the archive.
            (self._capture_dir / f"{self._phase}_attempt_{attempt}.request.json").write_bytes(body)

    # -- public contract ---------------------------------------------------------

    def complete_json(
        self,
        messages: list[dict[str, Any]],
        schema: dict[str, Any],
        effort: str,
        max_output_tokens: int,
        deadline: float,
    ) -> tuple[dict[str, Any] | None, CallRecord]:
        """Real POST with structured output; returns (result | None, CallRecord).

        ``deadline`` is a monotonic timestamp. Every attempt is bounded by the
        remaining time; no attempt starts after the deadline. On any error the
        result is ``None`` and the record carries the explicit cause. There is
        no model/provider/structured-output fallback of any kind.
        """

        record = CallRecord(
            phase=self._phase,  # type: ignore[arg-type]
            status="error",
            requested_model=self._settings.LITELLM_MODEL,
            reasoning_effort=effort,
        )
        if self._capture_dir is not None:
            self._capture_dir.mkdir(parents=True, exist_ok=True)

        payload = self.build_payload(messages, schema, effort, max_output_tokens)
        body = _json_bytes(payload)
        url = self._settings.LITELLM_CHAT_URL
        max_attempts = self._settings.MAX_LLM_ATTEMPTS

        last_error: LLMError | None = None
        for attempt in range(1, max_attempts + 1):
            remaining = deadline - self._clock()
            if remaining <= 0:
                last_error = LLMTimeout(
                    f"deadline expired before attempt {attempt} (no request sent)"
                )
                break
            record.attempts = attempt
            record.request_sha256 = hashlib.sha256(body).hexdigest()
            # §2.6.1: audit computed from the EXACT body bytes about to be
            # handed to transport (same variable, no re-serialization), then
            # those exact bytes are sent.
            input_audit = self.compute_input_audit(body, self._phase)
            self._capture_attempt_input(attempt, body, input_audit)
            try:
                status, raw = self._post_bytes(url, body, timeout_s=remaining)
            except LLMError as error:
                last_error = error
                self._capture_error(attempt, error)
                continue  # transient or not: keep the first-class error, retry within budget
            # Hash of the EXACT provider bytes, computed BEFORE any parsing
            # (blocker 2): this is the only provider-response fingerprint
            # that is ever persisted; the raw body itself never is.
            response_sha256 = hashlib.sha256(raw).hexdigest()
            if status != 200:
                last_error = LLMTransportError(f"unexpected HTTP status {status}")
                self._capture_response_meta(attempt, response_sha256, len(raw), None, None, None)
                self._capture_error(attempt, last_error)
                continue
            try:
                result, returned_model, usage, fenced = self._extract_result(raw, schema)
            except LLMError as error:
                last_error = error
                if record.first_attempt_schema_valid is None and attempt == 1:
                    record.first_attempt_schema_valid = False
                self._capture_response_meta(attempt, response_sha256, len(raw), None, None, None)
                self._capture_error(attempt, error)
                continue
            if attempt == 1:
                record.first_attempt_schema_valid = True
            # No-model-fallback (blocker 3): a success is never declared when
            # the provider did not report the model actually used, or when it
            # silently substituted the requested model.
            if returned_model is None:
                last_error = LLMInvalidResponse(
                    "provider did not report the model actually used"
                )
                self._capture_response_meta(attempt, response_sha256, len(raw), None, usage, fenced)
                self._capture_error(attempt, last_error)
                continue
            if returned_model != record.requested_model:
                last_error = LLMInvalidResponse(
                    "model substitution refused: requested "
                    f"{record.requested_model!r}, returned {returned_model!r}"
                )
                self._capture_response_meta(
                    attempt, response_sha256, len(raw), returned_model, usage, fenced
                )
                self._capture_error(attempt, last_error)
                continue
            self._capture_response_meta(
                attempt, response_sha256, len(raw), returned_model, usage, fenced
            )
            record.status = "ok"
            record.returned_model = returned_model
            record.input_tokens = usage["input_tokens"]
            record.cached_input_tokens = usage["cached_input_tokens"]
            record.output_tokens = usage["output_tokens"]
            record.reasoning_tokens = usage["reasoning_tokens"]
            if fenced:
                # Traced transport deviation (see _parse_content): never
                # silent. The trace artifact under capture_dir and the
                # smoke receipt mirror it; nothing is injected into the
                # validated result object.
                self._capture_trace(attempt, "fence_extracted")
            record.response_refs = self._attempt_artifact_names()
            return result, record

        # Blocker 1: the frozen public contract returns (None, record) on any
        # failure with record.status="error"; the error classes stay internal
        # (used by _post_bytes / _extract_result) and NEVER escape this
        # method. The cause remains available through the error artifacts
        # referenced by response_refs.
        record.status = "error"
        record.response_refs = self._attempt_artifact_names()
        return None, record

    def _attempt_artifact_names(self) -> list[str]:
        """Names of every attempt artifact (metadata, errors, traces)."""

        if self._capture_dir is None:
            return []
        # ``*attempt_*`` also matches the §2.6.1 per-attempt audit files
        # (``<phase>_attempt_<n>.input_audit.json``) and, when the fixture
        # source profile explicitly allows it, the archived request bodies.
        return sorted(
            str(path.relative_to(self._capture_dir))
            for path in self._capture_dir.glob("*attempt_*")
        )

    # -- capture helpers (usage/hashes only; never request headers) -------------

    def _capture_trace(self, attempt: int, kind: str) -> None:
        if self._capture_dir is None:
            return
        (self._capture_dir / f"attempt_{attempt}_trace_{kind}.txt").write_text(
            f"{kind}: transport deviation traced (content extracted from a "
            "markdown code fence; JSON fully validated against the schema)",
            encoding="utf-8",
        )

    def _capture_response_meta(
        self,
        attempt: int,
        response_sha256: str,
        response_bytes: int,
        returned_model: str | None,
        usage: dict[str, int | None] | None,
        fenced: bool | None,
    ) -> None:
        """Blocker 2: metadata ONLY — the raw provider response body is never
        written to disk. Persisted fields: SHA-256 of the exact raw bytes
        (computed before parsing), byte size, returned model, usage and the
        markdown-fence trace flag when observed."""

        if self._capture_dir is None:
            return
        meta = {
            "response_sha256": response_sha256,
            "response_bytes": response_bytes,
            "returned_model": returned_model,
            "usage": usage,
            "fence_extracted": fenced,
        }
        (self._capture_dir / f"attempt_{attempt}_response_meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

    def _capture_error(self, attempt: int, error: LLMError) -> None:
        if self._capture_dir is None:
            return
        (self._capture_dir / f"attempt_{attempt}_error.txt").write_text(
            expurgate(f"{type(error).__name__}: {error}"), encoding="utf-8"
        )


__all__ = [
    "LLMError",
    "LLMInvalidResponse",
    "LLMRefused",
    "LLMTimeout",
    "LLMTransportError",
    "LunaClient",
    "expurgate",
    "validate_against_schema",
]

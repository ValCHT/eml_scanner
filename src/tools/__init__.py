"""Shared tool-adapter contracts (docs/contracts.md §2.7).

``ToolContext`` and ``ResponseMetadata`` are the typed boundaries shared by
every lookup adapter (virustotal, opencti, urlscan):

- ``ToolContext`` carries run identity, source profile, the monotonic
  deadline, the operator egress policy, the capture directory and the
  collection mode. It is a plain Python object owned by the harness: it is
  never serialized into the checkpointed state, never carries secrets and
  never reaches the LLM.
- ``ResponseMetadata`` describes one provider response (origin, HTTP
  status, service date, exact-bytes SHA-256, local reference). It never
  contains a request header or any key material. ``error_kind`` /
  ``error_detail`` carry CONTROLLED error objects (timeout, connection
  failure, malformed capture) so that the adapter-specific
  ``normalize_response`` can map them deterministically; they are never a
  fabricated provider observation.

``normalize_response(...)`` itself is adapter-specific and lives in each
adapter module. Status vocabulary and causes are fixed by docs/architecture.md
§1.6: ``ok`` / ``not_found`` / ``unavailable`` / ``skipped``; unavailable
carries its cause, skipped carries its reason.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ..config import EgressConfig, SourceProfile

#: Closed cause vocabulary for ``unavailable`` results (architecture §1.6).
UNAVAILABLE_CAUSES: tuple[str, ...] = (
    "not_configured",
    "access_not_authorized",
    "timeout",
    "rate_limited",
    "auth_error",
    "api_error",
    "malformed_response",
    "deadline",
)

#: Closed reason vocabulary for ``skipped`` results (architecture §1.6).
SKIPPED_REASONS: tuple[str, ...] = ("disabled", "not_applicable", "privacy_policy", "budget")

#: Controlled error-object kinds a transport may hand to a normalizer. They
#: describe the LOCAL transport failure, never a fabricated provider answer.
ERROR_KINDS: tuple[str, ...] = ("timeout", "connection_error", "malformed")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolContext(_Strict):
    """Per-run harness context of one lookup call (§2.7). Never a secret."""

    run_id: str
    source_profile: SourceProfile
    deadline: float  # monotonic timestamp; every request is bounded by it
    egress: EgressConfig
    capture_dir: Path
    mode: Literal["live", "recorded"]


class ResponseMetadata(_Strict):
    """Origin/HTTP status/date/empreinte/référence locale, sans clé (§2.7).

    ``error_kind`` is set ONLY for controlled transport error objects
    (timeout / connection_error / malformed). It is a local fact and must
    never be presented as a provider observation.
    """

    origin: str
    http_status: int | None = None
    response_date: str | None = None
    response_sha256: str | None = None
    response_ref: str | None = None
    error_kind: Literal["timeout", "connection_error", "malformed"] | None = None
    error_detail: str | None = None


def now_utc_iso() -> str:
    """UTC ISO 8601 timestamp (§2.1 time rules)."""

    return datetime.now(UTC).isoformat()


def det_id(prefix: str, *content: object) -> str:
    """Deterministic id: ``prefix`` + SHA-256 of the canonical representation
    (docs/contracts.md §2.4; same convention as src/parsing.py)."""

    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


_SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"authorization\s*:\s*Bearer\s+\S+",
        r"x-apikey\s*:\s*\S+",
        r"\b(api[_-]?key|access[_-]?token|token|secret|password|apikey)\s*[=:]\s*\S+",
        r"sk-[A-Za-z0-9\-]{8,}",
        r"akml-[A-Za-z0-9_\-]{4,}",
    )
]


def expurgate(text: str) -> str:
    """Mask anything secret-like before a message can be displayed/archived."""

    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


__all__ = [
    "ERROR_KINDS",
    "ResponseMetadata",
    "SKIPPED_REASONS",
    "ToolContext",
    "UNAVAILABLE_CAUSES",
    "det_id",
    "expurgate",
    "now_utc_iso",
]

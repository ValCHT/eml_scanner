"""Configuration (docs/contracts.md §2.7).

``Settings`` mirrors the canonical environment variable names and defaults.
All secrets are ``SecretStr | None`` and are excluded from the public dump
(``Settings.public_dump``). No secret value is ever printed or logged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Observable types fixed by docs/contracts.md §2.4 (schema ObservableType).
ObservableType = Literal[
    "url",
    "domain",
    "ipv4",
    "ipv6",
    "email",
    "sha256",
    "sha1",
    "md5",
    "message_id",
    "campaign_id",
]

#: Fixed taxonomy (docs/contracts.md §2.1).
Label = Literal["spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"]

#: Fixed provenance values (docs/contracts.md §2.1).
Provenance = Literal["INTERNE", "OSINT", "SANDBOX", "INFERENCE"]

#: Source profiles (docs/contracts.md §2.2).
SourceProfile = Literal["fixture", "public_corpus", "private_authorized"]

#: Secret-bearing fields; never exposed in the public dump.
_SECRET_FIELDS = ("LITELLM_API_KEY", "VT_API_KEY", "OPENCTI_API_KEY", "URLSCAN_API_KEY")


class Settings(BaseSettings):
    """Canonical settings; secrets are ``SecretStr | None`` (§2.7)."""

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=True,
    )

    # --- Luna / LLM proxy ---------------------------------------------------
    LITELLM_CHAT_URL: str = "https://management.llmproxy.ai.orange/chat/completions"
    LITELLM_MODEL: str = "openai/gpt-5.6-luna"
    LITELLM_API_KEY: SecretStr | None = None

    # --- Tools credentials / switches ---------------------------------------
    VT_API_KEY: SecretStr | None = None
    VT_ACCESS_AUTHORIZED: bool = False
    OPENCTI_URL: str = "https://demo.opencti.io"
    OPENCTI_API_KEY: SecretStr | None = None
    URLSCAN_API_KEY: SecretStr | None = None
    MODEL_SUPPORTS_VISION: bool = False
    RAG_ENABLED: bool = False
    QR_DECODE_ENABLED: bool = False
    LIVE_INTEGRATION: bool = False

    # --- Directories ----------------------------------------------------------
    RUNS_DIR: Path = Path("runs")
    CORPUS_DIR: Path = Path("corpus")
    CONFIG_DIR: Path = Path("configs")
    RAG_DIR: Path = Path("corpus/rag/chroma")

    # --- Budgets ----------------------------------------------------------------
    MAX_EMAIL_SECONDS: float = Field(default=240, gt=0)
    INTERNAL_PHASE_SECONDS: float = Field(default=60, gt=0)
    FINAL_PHASE_SECONDS: float = Field(default=90, gt=0)
    INTERNAL_MAX_OUTPUT_TOKENS: int = Field(default=8192, gt=0)
    FINAL_MAX_OUTPUT_TOKENS: int = Field(default=16384, gt=0)
    MAX_LLM_ATTEMPTS: int = Field(default=2, ge=1, le=2)

    # --- Live smoke references (public/approved artifacts only) ------------------
    LIVE_VT_KNOWN_SHA256: str | None = None
    LIVE_CTI_KNOWN_VALUE: str | None = None
    LIVE_CTI_KNOWN_TYPE: ObservableType | None = None
    LIVE_BENIGN_URL: str | None = None
    LIVE_REDIRECT_URL: str | None = None

    @field_validator("LITELLM_CHAT_URL", "OPENCTI_URL")
    @classmethod
    def _validate_https_url(cls, value: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("must be an HTTPS URL")
        return value

    @field_validator("LIVE_BENIGN_URL", "LIVE_REDIRECT_URL")
    @classmethod
    def _validate_optional_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from urllib.parse import urlparse

        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("must be an HTTP(S) URL")
        return value

    def public_dump(self) -> dict[str, object]:
        """Secret-free projection of the settings (never includes key values).

        Secret fields are reduced to ``None``: their *presence* is not a value.
        The dump can be hashed into ``config_sha256`` and archived safely.
        """

        data = self.model_dump(mode="json")
        public: dict[str, object] = {}
        for key, value in data.items():
            if key in _SECRET_FIELDS:
                public[key] = None
            else:
                public[key] = value
        return public

    def secret_presence(self) -> dict[str, bool]:
        """Report only *presence* of secrets (booleans), never their values."""

        dump = self.model_dump()
        return {key: dump[key] is not None for key in _SECRET_FIELDS}


def load_settings(env_file: Path | None = None) -> Settings:
    """Load settings; an absent key is accepted at bootstrap (§2.7).

    ``env_file`` may be ``None`` (environment only) or a path to a dotenv
    file. Secrets stay ``None`` when absent; no fallback value is invented.
    """

    return Settings(_env_file=env_file, _env_file_encoding="utf-8")


# ---------------------------------------------------------------------------
# YAML configuration models (docs/contracts.md §2.7, docs/decisions.md §4.1/§4.3)
# ---------------------------------------------------------------------------


class _YamlStrict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GateConfig(_YamlStrict):
    """configs/gate.yaml — BASELINE V0 thresholds, never optimized before G6."""

    version: int
    min_confidence: float = Field(ge=0, le=1)
    min_margin: float = Field(ge=0, le=1)
    enrich_http_urls: bool
    enrich_non_inline_attachments: bool
    enrich_on_material_coverage_gap: bool


class PolicyConfig(_YamlStrict):
    """configs/policy.yaml — fixed priorities; thresholds only changed on dev."""

    version: int
    auto_min_confidence: float = Field(ge=0, le=1)
    auto_min_margin: float = Field(ge=0, le=1)
    escalate_malicious_min_confidence: float = Field(ge=0, le=1)
    auto_labels: list[Label] = Field(default_factory=list)
    blocked_reason_codes: dict[str, Literal["AUTO", "REVIEW", "ESCALATE"]] = Field(
        default_factory=dict
    )


class VirustotalToolConfig(_YamlStrict):
    enabled: bool
    max_targets: int = Field(ge=0)
    phase_timeout_s: float = Field(gt=0)
    requests_per_minute: int = Field(ge=0)
    requests_per_day: int = Field(ge=0)


class OpenctiToolConfig(_YamlStrict):
    enabled: bool
    max_targets: int = Field(ge=0)
    first: int = Field(ge=1)
    phase_timeout_s: float = Field(gt=0)


class UrlscanToolConfig(_YamlStrict):
    enabled: bool
    max_urls: int = Field(ge=0)
    visibility_real: Literal["private", "unlisted"]
    visibility_fixture: Literal["private", "unlisted"]
    first_poll_s: float = Field(ge=0)
    poll_interval_s: float = Field(gt=0)
    phase_timeout_s: float = Field(gt=0)


class RagToolConfig(_YamlStrict):
    enabled: bool
    max_cases: int = Field(ge=1)
    k: int = Field(ge=1)
    max_distance: float = Field(ge=0, le=1)
    max_case_chars: int = Field(gt=0)
    embedding_model: str


class VisionToolConfig(_YamlStrict):
    enabled: bool
    max_images: int = Field(ge=0)
    max_image_bytes: int = Field(gt=0)
    max_total_bytes: int = Field(gt=0)
    max_pixels: int = Field(gt=0)


class EgressConfig(_YamlStrict):
    allow_real_urls: bool
    approved_services: list[str] = Field(default_factory=list)
    approved_exact_url_hosts: list[str] = Field(default_factory=list)
    trusted_authserv_ids: list[str] = Field(default_factory=list)
    shared_hosts: list[str] = Field(default_factory=list)
    trusted_cti_sources: list[str] = Field(default_factory=list)


class ParseLimitsConfig(_YamlStrict):
    max_eml_bytes: int = Field(gt=0)
    max_mime_parts: int = Field(gt=0)
    max_mime_depth: int = Field(gt=0)
    max_attachments: int = Field(gt=0)
    max_decoded_bytes_per_part: int = Field(gt=0)
    max_decoded_bytes_total: int = Field(gt=0)


class ToolsConfig(_YamlStrict):
    """configs/tools.yaml — exactly the seven sections of §2.7."""

    virustotal: VirustotalToolConfig
    opencti: OpenctiToolConfig
    urlscan: UrlscanToolConfig
    rag: RagToolConfig
    vision: VisionToolConfig
    egress: EgressConfig
    parse_limits: ParseLimitsConfig


def load_yaml_config(path: Path, model: type[_YamlStrict]) -> _YamlStrict:
    """Load and strictly validate a YAML configuration file."""

    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping at top level")
    return model.model_validate(raw)


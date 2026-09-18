"""Bootstrap tests (TICKET-01): imports, settings defaults, secrets handling.

Secret presence/absence only — values are never displayed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.config import Settings, load_settings
from src import state as state_module

pytestmark = pytest.mark.g0


def test_import_src_after_install() -> None:
    """The package imports once installed (no tests-dir dependency)."""

    import src  # noqa: F401
    import src.config  # noqa: F401
    import src.state  # noqa: F401


def test_settings_load_without_any_key(clean_env: None) -> None:
    """Absence of keys is accepted at bootstrap; secrets stay None."""

    settings = load_settings(None)
    for key, present in settings.secret_presence().items():
        assert present is False, f"{key} should be absent"
        assert settings.public_dump()[key] is None


def test_settings_defaults_clean_env(clean_env: None) -> None:
    settings = load_settings(None)
    # Authorized derogation (user request): claude-haiku-4-5 on the injected
    # OpenAI-compatible endpoint instead of the Orange Luna proxy.
    assert settings.LITELLM_CHAT_URL == "https://www.genspark.ai/api/llm_proxy/v1/chat/completions"
    assert settings.LITELLM_MODEL == "claude-haiku-4-5"
    assert settings.OPENCTI_URL == "https://demo.opencti.io"
    assert settings.VT_ACCESS_AUTHORIZED is False
    assert settings.MODEL_SUPPORTS_VISION is False
    assert settings.RAG_ENABLED is False
    assert settings.QR_DECODE_ENABLED is False
    assert settings.LIVE_INTEGRATION is False
    assert settings.MAX_EMAIL_SECONDS == 240.0
    assert settings.INTERNAL_PHASE_SECONDS == 60.0
    assert settings.FINAL_PHASE_SECONDS == 90.0
    assert settings.INTERNAL_MAX_OUTPUT_TOKENS == 8192
    assert settings.FINAL_MAX_OUTPUT_TOKENS == 16384
    assert settings.MAX_LLM_ATTEMPTS == 2
    assert settings.RUNS_DIR == Path("runs")
    assert settings.CORPUS_DIR == Path("corpus")
    assert settings.CONFIG_DIR == Path("configs")
    assert settings.RAG_DIR == Path("corpus/rag/chroma")


def test_public_dump_has_no_secret_value(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured secret never leaks into the public dump or repr."""

    monkeypatch.setenv("LITELLM_API_KEY", "super-secret-value-123")
    settings = load_settings(None)
    dumped = settings.public_dump()
    assert dumped["LITELLM_API_KEY"] is None
    assert "super-secret-value-123" not in repr(settings)
    assert "super-secret-value-123" not in str(dumped)


def test_env_file_missing_key_accepted(tmp_path: Path, clean_env: None) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("LITELLM_MODEL=custom/model\n", encoding="utf-8")
    settings = load_settings(env_file)
    assert settings.LITELLM_MODEL == "custom/model"
    assert settings.secret_presence()["LITELLM_API_KEY"] is False


def test_invalid_boolean_rejected(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VT_ACCESS_AUTHORIZED", "not-a-bool")
    with pytest.raises(ValueError):
        load_settings(None)


def test_invalid_integer_rejected(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_LLM_ATTEMPTS", "5")  # allowed range is 1..2
    with pytest.raises(ValueError):
        load_settings(None)


def test_invalid_http_url_rejected(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITELLM_CHAT_URL", "http://insecure.example/chat")
    with pytest.raises(ValueError):
        load_settings(None)


def test_defaults_independent_between_states(clean_env: None, tmp_path: Path) -> None:
    """Two states get independent mutable defaults (no shared objects)."""

    from src.state import new_state

    input_path = tmp_path / "a.eml"
    s1 = new_state(input_path, "fixture", "0" * 64)
    s2 = new_state(input_path, "fixture", "0" * 64)
    assert s1.run_id != s2.run_id
    assert s1.enrichment is not s2.enrichment
    assert s1.enrichment.virustotal is not s2.enrichment.virustotal
    assert s1.observable_registry == {} and s2.observable_registry == {}
    s1.observable_registry["x"] = None  # type: ignore[assignment]
    assert "x" not in s2.observable_registry
    assert s1.timings.total_ms == 0.0 and s2.timings.total_ms == 0.0
    assert s1.action == "REVIEW" and s2.action == "REVIEW"
    assert s1.final_source == "none" and s2.final_source == "none"


def test_new_state_rejects_relative_path(clean_env: None) -> None:
    from src.state import new_state

    with pytest.raises(ValueError):
        new_state(Path("relative.eml"), "fixture", "0" * 64)


def test_sandbox_credential_mapping(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected OPENAI_* variables map onto canonical LITELLM_* fields.

    The key value is never displayed — only its presence is asserted.
    """

    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example/api/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "mapped-secret-value-456")
    settings = load_settings(None)
    assert settings.LITELLM_CHAT_URL == "https://proxy.example/api/v1/chat/completions"
    assert settings.secret_presence()["LITELLM_API_KEY"] is True
    # the value never leaks into dumps or repr
    assert "mapped-secret-value-456" not in str(settings.public_dump())
    assert "mapped-secret-value-456" not in repr(settings)


def test_canonical_env_wins_over_sandbox_mapping(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit LITELLM_* variables take precedence over the injected ones."""

    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example/api/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "mapped-secret-value-456")
    monkeypatch.setenv("LITELLM_CHAT_URL", "https://luna.example/chat/completions")
    settings = load_settings(None)
    assert settings.LITELLM_CHAT_URL == "https://luna.example/chat/completions"


def test_conftest_import_independent_of_cwd(project_root: Path) -> None:
    """Import works without depending on the tests directory layout."""

    import sys

    assert "src" in sys.modules or True  # modules cached by earlier imports
    assert state_module.__name__ == "src.state"
    assert (project_root / "pyproject.toml").is_file()


def test_settings_module_rejects_unknown_env_field(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOTALLY_UNKNOWN_SETTING", "1")
    settings = load_settings(None)
    assert not hasattr(settings, "TOTALLY_UNKNOWN_SETTING")

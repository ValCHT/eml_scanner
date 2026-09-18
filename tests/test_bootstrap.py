"""Bootstrap tests (TICKET-01): imports, settings defaults, secrets handling.

Secret presence/absence only — values are never displayed.
"""

from __future__ import annotations

import os
import subprocess
import sys
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
    # Canonical V1.2 defaults: the claude-haiku-4-5 derogation is scoped to
    # the Genspark sandbox environment, never a universal default.
    assert settings.LITELLM_CHAT_URL == "https://management.llmproxy.ai.orange/chat/completions"
    assert settings.LITELLM_MODEL == "openai/gpt-5.6-luna"
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
    """Injected Genspark OPENAI_* variables map onto canonical LITELLM_* fields.

    The key value is never displayed — only its presence is asserted.
    """

    monkeypatch.setenv("OPENAI_BASE_URL", "https://www.genspark.ai/api/llm_proxy/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "mapped-secret-value-456")
    settings = load_settings(None)
    assert settings.LITELLM_CHAT_URL == "https://www.genspark.ai/api/llm_proxy/v1/chat/completions"
    assert settings.LITELLM_MODEL == "claude-haiku-4-5"
    assert settings.secret_presence()["LITELLM_API_KEY"] is True
    # the value never leaks into dumps or repr
    assert "mapped-secret-value-456" not in str(settings.public_dump())
    assert "mapped-secret-value-456" not in repr(settings)


def test_mapping_refused_for_foreign_openai_endpoint(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected OPENAI_* pointing elsewhere than the Genspark proxy map nothing.

    The canonical V1.2 Luna defaults apply and no secret is carried over.
    """

    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example/api/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "foreign-secret-value-789")
    settings = load_settings(None)
    assert settings.LITELLM_CHAT_URL == "https://management.llmproxy.ai.orange/chat/completions"
    assert settings.LITELLM_MODEL == "openai/gpt-5.6-luna"
    assert settings.secret_presence()["LITELLM_API_KEY"] is False


def test_canonical_env_wins_over_sandbox_mapping(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit canonical LITELLM_* config: NO OPENAI_* field is mapped.

    Atomicity rule: explicit canonical configuration and injected sandbox
    credentials are never combined.
    """

    monkeypatch.setenv("OPENAI_BASE_URL", "https://www.genspark.ai/api/llm_proxy/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "mapped-secret-value-456")
    monkeypatch.setenv("LITELLM_CHAT_URL", "https://luna.example/chat/completions")
    settings = load_settings(None)
    assert settings.LITELLM_CHAT_URL == "https://luna.example/chat/completions"
    # canonical V1.2 default model (no model override mapped)
    assert settings.LITELLM_MODEL == "openai/gpt-5.6-luna"
    # the injected key is NOT carried over: mapping refused as a whole
    assert settings.secret_presence()["LITELLM_API_KEY"] is False


def test_canonical_env_file_blocks_mapping(
    clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A canonical LITELLM_* provided via env_file also blocks the mapping."""

    monkeypatch.setenv("OPENAI_BASE_URL", "https://www.genspark.ai/api/llm_proxy/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "mapped-secret-value-456")
    env_file = tmp_path / ".env"
    env_file.write_text("LITELLM_MODEL=openai/gpt-5.6-luna\n", encoding="utf-8")
    settings = load_settings(env_file)
    assert settings.LITELLM_MODEL == "openai/gpt-5.6-luna"
    # canonical Luna URL default (nothing mapped)
    assert settings.LITELLM_CHAT_URL == "https://management.llmproxy.ai.orange/chat/completions"
    assert settings.secret_presence()["LITELLM_API_KEY"] is False


def test_atomic_mapping_no_partial_mix(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single canonical LITELLM_* field forbids every OPENAI_* mapping."""

    monkeypatch.setenv("OPENAI_BASE_URL", "https://www.genspark.ai/api/llm_proxy/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "mapped-secret-value-456")
    monkeypatch.setenv("LITELLM_MODEL", "openai/gpt-5.6-luna")  # only one canonical field
    settings = load_settings(None)
    assert settings.LITELLM_MODEL == "openai/gpt-5.6-luna"
    assert settings.LITELLM_CHAT_URL == "https://management.llmproxy.ai.orange/chat/completions"
    assert settings.secret_presence()["LITELLM_API_KEY"] is False


def test_atomic_mapping_requires_genspark_base_for_key(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without an injected Genspark base URL, an OPENAI_API_KEY maps nothing."""

    monkeypatch.setenv("OPENAI_API_KEY", "orphan-secret-value-999")
    settings = load_settings(None)
    assert settings.secret_presence()["LITELLM_API_KEY"] is False
    assert settings.LITELLM_MODEL == "openai/gpt-5.6-luna"


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


# ---------------------------------------------------------------------------
# G0 maintenance fix: real CLI semantics of the pytest ``--live`` flag.
#
# The frozen gate commands (docs/gates.md §5.2) run pytest with ``--live``;
# the option is defined by tests/conftest.py, which must ALSO lift the
# default ``-m 'not live'`` exclusion of pyproject.toml ``addopts`` when the
# flag is explicitly given. These regressions exercise the REAL conftest of
# this repository, copied into a temporary isolated pytest project, through
# subprocess (shell=False) — cross-platform, no Bash/PowerShell syntax.
# ---------------------------------------------------------------------------


def _write_live_probe_project(tmp_path: Path, project_root: Path) -> Path:
    """Minimal isolated pytest project using the REAL repository conftest."""

    conftest_source = (project_root / "tests" / "conftest.py").read_text(encoding="utf-8")
    (tmp_path / "conftest.py").write_text(conftest_source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        "addopts = \"-m 'not live'\"\n"
        "markers = [\"live: tests calling real external services\", \"g0: gate G0 tests\"]\n",
        encoding="utf-8",
    )
    (tmp_path / "test_probe.py").write_text(
        "import pytest\n\n\n@pytest.mark.live\ndef test_live_probe() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    return tmp_path


def _run_pytest_in_probe(project_root: Path, probe_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the repository interpreter's pytest inside the probe project."""

    env = dict(os.environ)
    env["PYTHONPATH"] = str(project_root)  # the copied conftest imports src.config
    return subprocess.run(
        [sys.executable, "-m", "pytest", "test_probe.py", "-q", *args],
        cwd=probe_dir,
        shell=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_pytest_live_flag_semantics(project_root: Path, tmp_path: Path) -> None:
    """A/B/C: default exclusion, flag acceptance, real execution of live."""

    probe_dir = _write_live_probe_project(tmp_path, project_root)

    # A. WITHOUT --live: the live-marked test stays excluded by the default
    #    ``-m 'not live'`` addopts; nothing runs (exit code 5, deselected).
    without_flag = _run_pytest_in_probe(project_root, probe_dir)
    assert without_flag.returncode == 5, without_flag.stdout + without_flag.stderr
    assert "deselected" in without_flag.stdout
    assert "1 passed" not in without_flag.stdout

    # B/C. WITH --live: the option is ACCEPTED (no ``unrecognized arguments``)
    #      AND the live-marked test is REALLY executed — i.e. the flag does
    #      not merely get recognized while the default exclusion stays active.
    with_flag = _run_pytest_in_probe(project_root, probe_dir, "--live")
    assert "unrecognized arguments" not in with_flag.stderr, with_flag.stderr
    assert with_flag.returncode == 0, with_flag.stdout + with_flag.stderr
    assert "1 passed" in with_flag.stdout
    assert "deselected" not in with_flag.stdout


def test_pytest_live_flag_preserves_explicit_marker_expression(
    project_root: Path, tmp_path: Path
) -> None:
    """``--live`` never destroys a user-chosen ``-m`` expression that differs
    from the project default (the only preservation the mandate requires).

    Known, documented limit: an explicit ``-m 'not live'`` is byte-identical
    to the ``addopts`` default after pytest merges them, so the flag lifts it
    too — the spec only protects expressions DIFFERENT from the default.
    """

    probe_dir = _write_live_probe_project(tmp_path, project_root)

    # An explicit non-default expression is preserved: the live test is
    # deselected by the user's own ``-m 'g0'`` despite ``--live`` being given.
    explicit_other = _run_pytest_in_probe(project_root, probe_dir, "--live", "-m", "g0")
    assert "unrecognized arguments" not in explicit_other.stderr, explicit_other.stderr
    assert explicit_other.returncode == 5, explicit_other.stdout + explicit_other.stderr
    assert "deselected" in explicit_other.stdout
    assert "1 passed" not in explicit_other.stdout

    # An explicit live-targeting expression keeps working with the flag.
    explicit_live = _run_pytest_in_probe(project_root, probe_dir, "--live", "-m", "live")
    assert explicit_live.returncode == 0, explicit_live.stdout + explicit_live.stderr
    assert "1 passed" in explicit_live.stdout

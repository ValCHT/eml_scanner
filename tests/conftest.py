"""Shared pytest fixtures for the G0 skeleton tests.

Also defines the ``--live`` CLI option required by the frozen gate commands
(docs/gates.md §5.2: ``pytest ... --live -q``). The ``live`` marker itself is
declared in ``pyproject.toml``; without ``--live`` its default exclusion
(``addopts = "-m 'not live'"``) keeps live tests deselected. With ``--live``
that DEFAULT exclusion is lifted for the run, while a user-chosen ``-m``
expression that differs from the project default is never touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.config import load_settings

#: Exact default marker expression of pyproject.toml ``addopts``. Only this
#: exact effective expression is neutralized by ``--live``; any other,
#: user-chosen ``-m`` expression is never destroyed.
DEFAULT_MARKER_EXPR = "not live"


def pytest_addoption(parser: pytest.Parser) -> None:
    """Declare the ``--live`` flag (docs/gates.md §5.2 live test contract)."""

    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Include tests marked 'live' (real external calls); by default they are excluded.",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Lift the DEFAULT ``-m 'not live'`` exclusion when ``--live`` is given.

    Runs before test selection. Without ``--live`` nothing changes: the
    ``addopts`` exclusion keeps live tests deselected. With ``--live`` the
    exclusion is removed (markexpr emptied) ONLY while the effective ``-m``
    expression is exactly the project default ``not live``; a different,
    explicitly chosen expression always keeps precedence over the flag.
    """

    if not config.getoption("--live"):
        return
    marker_expr = config.getoption("-m") or ""
    if marker_expr and marker_expr != DEFAULT_MARKER_EXPR:
        return  # user-chosen expression different from the default: keep it
    config.option.markexpr = ""


@pytest.fixture()
def project_root() -> Path:
    """Repository root, independent of the tests directory location."""

    return Path(__file__).resolve().parent.parent


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every canonical settings variable from the environment.

    Also removes the sandbox-injected OpenAI-compatible variables so the
    credential mapping in ``load_settings`` cannot leak into tests that
    assume a bootstrap without any key.
    """

    import os

    from src.config import Settings

    for name in Settings.model_fields:
        monkeypatch.delenv(name, raising=False)
    for name in ("OPENAI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    assert not any(
        name in os.environ for name in ("LITELLM_API_KEY", "VT_API_KEY", "OPENCTI_API_KEY", "URLSCAN_API_KEY")
    )


@pytest.fixture()
def settings_no_secrets(clean_env: None) -> object:
    """Settings loaded with no secret present anywhere."""

    return load_settings(None)


@pytest.fixture()
def configs_dir(project_root: Path) -> Path:
    return project_root / "configs"

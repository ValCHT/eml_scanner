"""Shared pytest fixtures for the G0 skeleton tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.config import load_settings


@pytest.fixture()
def project_root() -> Path:
    """Repository root, independent of the tests directory location."""

    return Path(__file__).resolve().parent.parent


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every canonical settings variable from the environment."""

    import os

    from src.config import Settings

    for name in Settings.model_fields:
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

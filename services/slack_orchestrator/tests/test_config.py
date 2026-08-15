"""Settings parsing tests — especially response_team_user_ids, which must not
crash startup on empty / CSV / JSON env values (regression for the
pydantic-settings pre-decode bug)."""

import importlib

import pytest


@pytest.fixture
def get_settings():
    # Import lazily so monkeypatched env is picked up per test.
    from services.slack_orchestrator import config as config_module

    importlib.reload(config_module)
    return config_module.get_settings


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", []),
        ("   ", []),
        ('["U01234567", "U89ABCDEF"]', ["U01234567", "U89ABCDEF"]),
        ("U01234567,U89ABCDEF", ["U01234567", "U89ABCDEF"]),
        ("U01234567, U89ABCDEF ", ["U01234567", "U89ABCDEF"]),
    ],
)
def test_response_team_user_ids_parsing(monkeypatch, get_settings, raw, expected):
    monkeypatch.setenv("CORELINE_RESPONSE_TEAM_USER_IDS", raw)
    monkeypatch.setenv("CORELINE_ENVIRONMENT", "dev")
    settings = get_settings()
    assert settings.response_team_user_ids == expected


def test_response_team_user_ids_unset_defaults_empty(monkeypatch, get_settings):
    monkeypatch.delenv("CORELINE_RESPONSE_TEAM_USER_IDS", raising=False)
    settings = get_settings()
    assert settings.response_team_user_ids == []


def test_invalid_json_array_raises(monkeypatch, get_settings):
    monkeypatch.setenv("CORELINE_RESPONSE_TEAM_USER_IDS", "[not valid json")
    with pytest.raises(Exception):
        get_settings()


def test_swagger_forbidden_in_prod(monkeypatch, get_settings):
    monkeypatch.setenv("CORELINE_ENVIRONMENT", "prod")
    monkeypatch.setenv("CORELINE_ENABLE_SWAGGER", "true")
    with pytest.raises(Exception):
        get_settings()

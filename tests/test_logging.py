from __future__ import annotations

from arcjet._logging import _env_log_level
import logging


def test_env_log_level_default_warning(monkeypatch):
    monkeypatch.delenv("ARCJET_LOG_LEVEL", raising=False)
    assert _env_log_level(logging.INFO) == logging.INFO


def test_env_log_level_names(monkeypatch):
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "debug")
    assert _env_log_level() == logging.DEBUG
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "WARNING")
    assert _env_log_level(logging.ERROR) == logging.WARNING


def test_env_log_level_numeric(monkeypatch):
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "10")
    assert _env_log_level() == 10
    # Non-numeric falls back
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "x10")
    assert _env_log_level(25) == 25

"""Unit tests for logging configuration.

Tests logging level configuration and environment variable handling.
"""

from __future__ import annotations

import logging

from arcjet._logging import _env_log_level


def test_env_log_level_default_warning(monkeypatch):
    """Test that _env_log_level returns default when no env var is set."""
    monkeypatch.delenv("ARCJET_LOG_LEVEL", raising=False)
    assert _env_log_level(logging.INFO) == logging.INFO


def test_env_log_level_names(monkeypatch):
    """Test that _env_log_level handles level names correctly."""
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "debug")
    assert _env_log_level() == logging.DEBUG
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "WARNING")
    assert _env_log_level(logging.ERROR) == logging.WARNING


def test_env_log_level_numeric(monkeypatch):
    """Test that _env_log_level handles numeric level values."""
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "10")
    assert _env_log_level() == 10
    # Non-numeric falls back to default
    monkeypatch.setenv("ARCJET_LOG_LEVEL", "x10")
    assert _env_log_level(25) == 25

"""Unit tests for Guard client defaults."""

from __future__ import annotations

import inspect

from arcjet.guard import launch_arcjet, launch_arcjet_sync
from arcjet.guard._client import _DEFAULT_TIMEOUT_MS


def test_guard_default_timeout_is_2000_ms() -> None:
    assert _DEFAULT_TIMEOUT_MS == 2000
    assert inspect.signature(launch_arcjet).parameters["timeout_ms"].default == 2000
    assert (
        inspect.signature(launch_arcjet_sync).parameters["timeout_ms"].default == 2000
    )

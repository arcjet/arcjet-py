"""Guard never falls back to ARCJET_KEY (JS Guard policy)."""

from __future__ import annotations

from typing import Any

import pytest


def test_empty_key_rejected_even_when_env_set(monkeypatch: Any):
    from arcjet._errors import ArcjetMisconfiguration
    from arcjet.guard import launch_arcjet, launch_arcjet_sync

    monkeypatch.setenv("ARCJET_KEY", "ajkey_from_env")
    with pytest.raises(ArcjetMisconfiguration, match="required"):
        launch_arcjet(key="")
    with pytest.raises(ArcjetMisconfiguration, match="required"):
        launch_arcjet_sync(key="")

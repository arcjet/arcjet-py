"""Guard constructors keep a LIVE default (JS Guard parity)."""

from __future__ import annotations

import inspect

from arcjet.guard import DetectPromptInjection, TokenBucket


def test_guard_mode_defaults_to_live_matching_js():
    assert inspect.signature(TokenBucket.__init__).parameters["mode"].default == "LIVE"
    assert (
        inspect.signature(DetectPromptInjection.__init__).parameters["mode"].default
        == "LIVE"
    )

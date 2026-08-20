"""protect_signup() composes sliding window + bot + email rules."""

from __future__ import annotations


def test_returns_three_rules(mock_protobuf_modules):
    from arcjet._rules import (
        BotDetection,
        EmailType,
        EmailValidation,
        Mode,
        SlidingWindow,
        protect_signup,
    )

    rules = protect_signup(
        rate_limit={"mode": Mode.LIVE, "max": 5, "interval": 600},
        bots={"mode": Mode.LIVE, "allow": []},
        email={
            "mode": Mode.LIVE,
            "deny": [EmailType.DISPOSABLE, EmailType.INVALID],
        },
    )
    assert len(rules) == 3
    assert isinstance(rules[0], SlidingWindow)
    assert isinstance(rules[1], BotDetection)
    assert isinstance(rules[2], EmailValidation)
    assert rules[0].max == 5
    assert rules[1].allow == ()
    assert rules[2].deny is not None


def test_exported_from_package(mock_protobuf_modules):
    from arcjet import protect_signup
    from arcjet._rules import Mode

    rules = protect_signup(
        rate_limit={"mode": Mode.LIVE, "max": 5, "interval": 60},
        bots={"mode": Mode.LIVE, "deny": ["CURL"]},
        email={"mode": Mode.LIVE, "deny": ["INVALID"]},
    )
    assert len(rules) == 3

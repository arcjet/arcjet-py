"""with_rule() appends rules and shares DecisionCache."""

from __future__ import annotations


def test_with_rule_appends_and_shares_cache(mock_protobuf_modules, dev_environment):
    from arcjet import arcjet_sync
    from arcjet._rules import Mode, detect_bot, shield

    base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
    clone = base.with_rule(detect_bot(mode=Mode.LIVE, allow=["CATEGORY:SEARCH_ENGINE"]))

    assert clone is not base
    assert len(base._rules) == 1
    assert len(clone._rules) == 2
    assert clone._cache is base._cache


def test_with_rule_recomputes_email_flag(mock_protobuf_modules, dev_environment):
    from arcjet import arcjet_sync
    from arcjet._rules import EmailType, Mode, shield, validate_email

    base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
    assert base._needs_email is False
    clone = base.with_rule(validate_email(mode=Mode.LIVE, deny=[EmailType.INVALID]))
    assert clone._needs_email is True
    assert base._needs_email is False


def test_with_rule_accepts_sequence(mock_protobuf_modules, dev_environment):
    from arcjet import arcjet_sync
    from arcjet._rules import Mode, detect_bot, shield, sliding_window

    base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
    clone = base.with_rule(
        (
            sliding_window(mode=Mode.LIVE, max=5, interval=60),
            detect_bot(mode=Mode.LIVE, allow=["CATEGORY:SEARCH_ENGINE"]),
        )
    )
    assert len(clone._rules) == 3
    assert clone._cache is base._cache


def test_async_with_rule_shares_cache(mock_protobuf_modules, dev_environment):
    from arcjet import arcjet
    from arcjet._rules import Mode, detect_bot, shield

    base = arcjet(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
    clone = base.with_rule(detect_bot(mode=Mode.LIVE, allow=["CATEGORY:SEARCH_ENGINE"]))
    assert clone is not base
    assert clone._cache is base._cache
    assert len(clone._rules) == 2

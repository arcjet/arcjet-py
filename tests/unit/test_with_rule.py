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


def test_with_rule_recomputes_message_and_token_bucket_flags(
    mock_protobuf_modules, dev_environment
):
    from arcjet import arcjet_sync
    from arcjet._rules import Mode, detect_prompt_injection, shield, token_bucket

    base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
    assert base._needs_message is False
    assert base._has_token_bucket is False

    with_pi = base.with_rule(detect_prompt_injection(mode=Mode.LIVE))
    assert with_pi._needs_message is True
    assert with_pi._has_token_bucket is False
    assert base._needs_message is False

    with_tb = base.with_rule(
        token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)
    )
    assert with_tb._has_token_bucket is True
    assert with_tb._needs_message is False
    assert base._has_token_bucket is False


def test_with_rule_preserves_identity_fields(mock_protobuf_modules, dev_environment):
    from arcjet import arcjet_sync
    from arcjet._rules import Mode, detect_bot, shield

    base = arcjet_sync(
        key="ajkey_test",
        rules=[shield(mode=Mode.LIVE)],
        characteristics=("ip.src",),
        proxies=("10.0.0.0/8",),
        fail_open=True,
        timeout_ms=1500,
        environment="development",
    )
    clone = base.with_rule(detect_bot(mode=Mode.LIVE, allow=["CATEGORY:SEARCH_ENGINE"]))

    assert clone._key is base._key
    assert clone._client is base._client
    assert clone._proxies == base._proxies
    assert clone._fail_open is base._fail_open
    assert clone._timeout_ms == base._timeout_ms
    assert clone._environment == base._environment
    assert clone._sdk_stack == base._sdk_stack
    assert clone._sdk_version == base._sdk_version


def test_with_rule_local_eval_still_sorts_sensitive_info_first(
    mock_protobuf_modules, dev_environment
):
    from arcjet import arcjet_sync
    from arcjet._client import _sort_rules_for_local
    from arcjet._rules import (
        BotDetection,
        Mode,
        SensitiveInfoDetection,
        detect_bot,
        detect_sensitive_info,
        shield,
    )

    base = arcjet_sync(
        key="ajkey_test",
        rules=[
            shield(mode=Mode.LIVE),
            detect_bot(mode=Mode.LIVE, deny=["CURL"]),
        ],
    )
    clone = base.with_rule(detect_sensitive_info(mode=Mode.LIVE, deny=["EMAIL"]))
    assert isinstance(clone._rules[-1], SensitiveInfoDetection)
    ordered = _sort_rules_for_local(clone._rules)
    assert isinstance(ordered[0], SensitiveInfoDetection)
    assert any(isinstance(r, BotDetection) for r in ordered[1:])

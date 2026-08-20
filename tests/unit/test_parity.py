"""Parity tests for JS-aligned SDK behavior.

Each class maps to one item in the core-SDK parity review (items 6 and 9
were out of scope). Tests use the protobuf stubs so they stay isolated.
"""

from __future__ import annotations

import inspect
import types
from typing import Any

import pytest

from arcjet._decision import (
    Decision,
    is_missing_user_agent,
    is_spoofed_bot,
    is_verified_bot,
    materialize_cached_decision,
)
from arcjet._decision import RuleResult as SDKRuleResult


# ---------------------------------------------------------------------------
# 1. Cache hits: remaining TTL, isolated copy, rate-limit reset rewrite
# ---------------------------------------------------------------------------


class TestCacheHitMaterialization:
    def test_get_returns_remaining_ttl(self, mock_protobuf_modules):
        from arcjet._cache import DecisionCache
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        cache = DecisionCache()
        stored = Decision(
            decide_pb2.Decision(id="orig", conclusion=decide_pb2.CONCLUSION_DENY, ttl=60)
        )
        cache.set("k", stored, ttl_seconds=2)
        hit = cache.get("k")
        assert hit is not None
        decision, remaining = hit
        assert decision is stored
        assert 1 <= remaining <= 2

    def test_materialize_does_not_mutate_cached_proto(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        proto = decide_pb2.Decision(
            id="orig", conclusion=decide_pb2.CONCLUSION_DENY, ttl=60
        )
        cached = Decision(proto)
        served = materialize_cached_decision(cached, remaining_ttl=12, request_id="lreq_x")

        assert served is not cached
        assert served.id == "lreq_x"
        assert served.ttl == 12
        assert cached.id == "orig"
        assert cached.ttl == 60
        served.to_proto().id = "mutated"
        assert cached.id == "orig"

    def test_materialize_rewrites_rate_limit_reset(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rl = StubRateLimitReason(
            max=10, remaining=0, reset_in_seconds=60, window_in_seconds=60
        )
        proto = decide_pb2.Decision(
            id="orig",
            conclusion=decide_pb2.CONCLUSION_DENY,
            ttl=60,
            reason=decide_pb2.Reason(rate_limit=rl),
        )
        cached = Decision(proto)
        served = materialize_cached_decision(cached, remaining_ttl=7, request_id="lreq_y")

        assert served.ttl == 7
        assert served.to_proto().reason.rate_limit.reset_in_seconds == 7
        assert cached.to_proto().reason.rate_limit.reset_in_seconds == 60

    def test_protect_cache_hit_is_isolated(
        self, mock_protobuf_modules, dev_environment, monkeypatch
    ):
        from arcjet import arcjet_sync
        from arcjet._rules import Mode, token_bucket
        from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClientSync

        def deny_with_ttl(_req):
            return mock_protobuf_modules["DecideResponse"](
                mock_protobuf_modules["Decision"](
                    id="deny1",
                    conclusion=mock_protobuf_modules["pb2"].CONCLUSION_DENY,
                    ttl=10,
                )
            )

        monkeypatch.setattr(
            DecideServiceClientSync, "decide_behavior", deny_with_ttl, raising=False
        )

        aj = arcjet_sync(
            key="ajkey_test",
            rules=[token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)],
        )
        d1 = aj.protect({"headers": [], "type": "http"})
        d2 = aj.protect({"headers": [], "type": "http"})

        assert d1.is_denied() and d2.is_denied()
        assert d1.id == "deny1"
        assert d2.id != d1.id
        assert d2.id.startswith("lreq_")
        assert d2.ttl <= 10
        d2.to_proto().id = "mutated-by-caller"
        assert d1.id == "deny1"

    def test_async_protect_cache_hit_is_isolated(
        self, mock_protobuf_modules, dev_environment, monkeypatch
    ):
        import asyncio

        from arcjet import arcjet
        from arcjet._rules import Mode, token_bucket
        from arcjet.proto.decide.v1alpha1.decide_connect import DecideServiceClient

        def deny_with_ttl(_req):
            return mock_protobuf_modules["DecideResponse"](
                mock_protobuf_modules["Decision"](
                    id="deny1",
                    conclusion=mock_protobuf_modules["pb2"].CONCLUSION_DENY,
                    ttl=10,
                )
            )

        monkeypatch.setattr(
            DecideServiceClient, "decide_behavior", deny_with_ttl, raising=False
        )

        aj = arcjet(
            key="ajkey_test",
            rules=[token_bucket(mode=Mode.LIVE, refill_rate=1, interval=1, capacity=1)],
        )

        async def _run() -> None:
            d1 = await aj.protect({"headers": [], "type": "http"})
            d2 = await aj.protect({"headers": [], "type": "http"})
            assert d1.is_denied() and d2.is_denied()
            assert d1.id == "deny1"
            assert d2.id != d1.id
            assert d2.id.startswith("lreq_")
            d2.to_proto().id = "mutated-by-caller"
            assert d1.id == "deny1"

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. Explicit mode
# ---------------------------------------------------------------------------


class TestExplicitMode:
    @pytest.mark.parametrize(
        "factory,kwargs",
        [
            ("shield", {}),
            ("detect_bot", {"allow": ["CURL"]}),
            ("token_bucket", {"refill_rate": 1, "interval": 1, "capacity": 1}),
            ("fixed_window", {"max": 1, "window": 1}),
            ("sliding_window", {"max": 1, "interval": 1}),
            ("validate_email", {"deny": ["INVALID"]}),
            ("detect_prompt_injection", {}),
            ("detect_sensitive_info", {"deny": ["EMAIL"]}),
            ("filter_request", {"deny": ["ip.src == 1"]}),
        ],
    )
    def test_http_factory_requires_mode(self, mock_protobuf_modules, factory, kwargs):
        import arcjet._rules as rules

        fn = getattr(rules, factory)
        with pytest.raises(TypeError, match="mode"):
            fn(**kwargs)

    def test_guard_mode_defaults_to_live_matching_js(self):
        from arcjet.guard import DetectPromptInjection, TokenBucket

        assert (
            inspect.signature(TokenBucket.__init__).parameters["mode"].default == "LIVE"
        )
        assert (
            inspect.signature(DetectPromptInjection.__init__)
            .parameters["mode"]
            .default
            == "LIVE"
        )


# ---------------------------------------------------------------------------
# 3. detect_bot / validate_email allow XOR deny
# ---------------------------------------------------------------------------


class TestAllowDenyExclusivity:
    def test_detect_bot_rejects_neither(self, mock_protobuf_modules):
        from arcjet._rules import Mode, detect_bot

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            detect_bot(mode=Mode.LIVE)

    def test_detect_bot_rejects_both(self, mock_protobuf_modules):
        from arcjet._rules import BotCategory, Mode, detect_bot

        with pytest.raises(ValueError, match="cannot be provided together"):
            detect_bot(mode=Mode.LIVE, allow=[BotCategory.GOOGLE], deny=["CURL"])

    def test_detect_bot_empty_allow_blocks_all_bots(self, mock_protobuf_modules):
        from arcjet._rules import Mode, detect_bot

        rule = detect_bot(mode=Mode.LIVE, allow=[])
        assert rule.allow == ()
        assert rule.deny is None

    def test_bot_detection_dataclass_rejects_neither(self, mock_protobuf_modules):
        from arcjet._rules import BotDetection, Mode

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            BotDetection(mode=Mode.LIVE)

    def test_validate_email_rejects_neither(self, mock_protobuf_modules):
        from arcjet._rules import Mode, validate_email

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            validate_email(mode=Mode.LIVE)

    def test_validate_email_rejects_both(self, mock_protobuf_modules):
        from arcjet._rules import EmailType, Mode, validate_email

        with pytest.raises(ValueError, match="cannot be provided together"):
            validate_email(
                mode=Mode.LIVE,
                allow=[EmailType.FREE],
                deny=[EmailType.DISPOSABLE],
            )

    def test_validate_email_empty_allow_is_valid(self, mock_protobuf_modules):
        from arcjet._rules import Mode, validate_email

        rule = validate_email(mode=Mode.LIVE, allow=[])
        assert rule.allow == ()
        assert rule.deny is None


# ---------------------------------------------------------------------------
# 4. Local rules evaluate in JS priority order
# ---------------------------------------------------------------------------


class TestLocalRulePriority:
    def test_sensitive_info_denies_before_later_bot(
        self, mock_protobuf_modules
    ):
                from arcjet._client import _run_local_rules, _sort_rules_for_local
        from arcjet._context import RequestContext
        from arcjet._rules import (
            BotDetection,
            EmailValidation,
            Filter,
            Mode,
            SensitiveInfoDetection,
            Shield,
            SlidingWindow,
            detect_bot,
            detect_sensitive_info,
            filter_request,
            shield,
            sliding_window,
            validate_email,
        )
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        bot = detect_bot(mode=Mode.LIVE, deny=["CURL"])
        filt = filter_request(mode=Mode.LIVE, deny=["ip.src == 1"])
        sensi = detect_sensitive_info(mode=Mode.LIVE, deny=["EMAIL"])
        email = validate_email(mode=Mode.LIVE, deny=["INVALID"])
        sh = shield(mode=Mode.LIVE)
        rl = sliding_window(mode=Mode.LIVE, max=5, interval=60)
        ordered = _sort_rules_for_local((bot, email, filt, rl, sh, sensi))
        assert [type(r) for r in ordered] == [
            SensitiveInfoDetection,
            Filter,
            Shield,
            SlidingWindow,
            BotDetection,
            EmailValidation,
        ]

        si_deny = decide_pb2.RuleResult(
            rule_id="si",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(error=decide_pb2.ErrorReason(message="pii")),
        )
        bot_deny = decide_pb2.RuleResult(
            rule_id="bot",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(error=decide_pb2.ErrorReason(message="bot")),
        )

        calls: list[str] = []

        def track_si(_ctx, _rule):
            calls.append("si")
            return si_deny

        def track_bot(_ctx, _rule):
            calls.append("bot")
            return bot_deny

        from unittest.mock import patch

        ctx = RequestContext(ip="1.2.3.4")
        with (
            patch("arcjet._client.evaluate_sensitive_info_locally", side_effect=track_si),
            patch("arcjet._client.evaluate_filter_locally", return_value=None),
            patch("arcjet._client.evaluate_bot_locally", side_effect=track_bot),
            patch("arcjet._client.evaluate_email_locally", return_value=None),
        ):
            decision = _run_local_rules(ctx, (bot, sensi))

        assert calls == ["si"]
        assert decision is not None
        assert decision.results[0].rule_id == "si"


# ---------------------------------------------------------------------------
# 5. Inspect helpers skip DRY_RUN
# ---------------------------------------------------------------------------


class TestInspectHelpers:
    def _bot_result(self, mock_protobuf_modules, *, spoofed, verified, state):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        bot_v2 = types.SimpleNamespace(spoofed=spoofed, verified=verified)
        rr = decide_pb2.RuleResult(
            rule_id="r1",
            state=state,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(bot_v2=bot_v2),
        )
        return SDKRuleResult(rr)

    def test_is_spoofed_bot_live(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = self._bot_result(
            mock_protobuf_modules,
            spoofed=True,
            verified=False,
            state=decide_pb2.RULE_STATE_RUN,
        )
        assert is_spoofed_bot(rr) is True

    def test_is_spoofed_bot_ignores_dry_run(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = self._bot_result(
            mock_protobuf_modules,
            spoofed=True,
            verified=False,
            state=decide_pb2.RULE_STATE_DRY_RUN,
        )
        assert is_spoofed_bot(rr) is False

    def test_is_verified_bot_live(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = self._bot_result(
            mock_protobuf_modules,
            spoofed=False,
            verified=True,
            state=decide_pb2.RULE_STATE_RUN,
        )
        assert is_verified_bot(rr) is True
        assert is_spoofed_bot(rr) is False

    def test_is_verified_bot_ignores_dry_run(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = self._bot_result(
            mock_protobuf_modules,
            spoofed=False,
            verified=True,
            state=decide_pb2.RULE_STATE_DRY_RUN,
        )
        assert is_verified_bot(rr) is False

    def test_is_missing_user_agent(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = decide_pb2.RuleResult(
            rule_id="r1",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_ERROR,
            reason=decide_pb2.Reason(
                error=decide_pb2.ErrorReason(message="missing User-Agent header")
            ),
        )
        assert is_missing_user_agent(SDKRuleResult(rr)) is True

    def test_is_missing_user_agent_ignores_dry_run(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = decide_pb2.RuleResult(
            rule_id="r1",
            state=decide_pb2.RULE_STATE_DRY_RUN,
            conclusion=decide_pb2.CONCLUSION_ERROR,
            reason=decide_pb2.Reason(
                error=decide_pb2.ErrorReason(message="missing User-Agent header")
            ),
        )
        assert is_missing_user_agent(SDKRuleResult(rr)) is False

    def test_helpers_false_for_non_bot_reason(self, mock_protobuf_modules):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rr = decide_pb2.RuleResult(
            rule_id="r1",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(
                error=decide_pb2.ErrorReason(message="something else")
            ),
        )
        wrapped = SDKRuleResult(rr)
        assert is_spoofed_bot(wrapped) is False
        assert is_verified_bot(wrapped) is False
        assert is_missing_user_agent(wrapped) is False


# ---------------------------------------------------------------------------
# 7. with_rule shares the cache
# ---------------------------------------------------------------------------


class TestWithRule:
    def test_with_rule_appends_and_shares_cache(
        self, mock_protobuf_modules, dev_environment
    ):
        from arcjet import arcjet_sync
        from arcjet._rules import Mode, detect_bot, shield

        base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
        clone = base.with_rule(
            detect_bot(mode=Mode.LIVE, allow=["CATEGORY:SEARCH_ENGINE"])
        )

        assert clone is not base
        assert len(base._rules) == 1
        assert len(clone._rules) == 2
        assert clone._cache is base._cache

    def test_with_rule_recomputes_email_flag(
        self, mock_protobuf_modules, dev_environment
    ):
        from arcjet import arcjet_sync
        from arcjet._rules import EmailType, Mode, shield, validate_email

        base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
        assert base._needs_email is False
        clone = base.with_rule(
            validate_email(mode=Mode.LIVE, deny=[EmailType.INVALID])
        )
        assert clone._needs_email is True
        assert base._needs_email is False

    def test_with_rule_accepts_protect_signup_tuple(
        self, mock_protobuf_modules, dev_environment
    ):
        from arcjet import arcjet_sync
        from arcjet._rules import EmailType, Mode, protect_signup, shield

        base = arcjet_sync(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
        clone = base.with_rule(
            protect_signup(
                rate_limit={"mode": Mode.LIVE, "max": 5, "interval": 60},
                bots={"mode": Mode.LIVE, "allow": []},
                email={"mode": Mode.LIVE, "deny": [EmailType.DISPOSABLE]},
            )
        )
        assert len(clone._rules) == 4
        assert clone._needs_email is True

    def test_async_with_rule_shares_cache(
        self, mock_protobuf_modules, dev_environment
    ):
        from arcjet import arcjet
        from arcjet._rules import Mode, detect_bot, shield

        base = arcjet(key="ajkey_test", rules=[shield(mode=Mode.LIVE)])
        clone = base.with_rule(
            detect_bot(mode=Mode.LIVE, allow=["CATEGORY:SEARCH_ENGINE"])
        )
        assert clone is not base
        assert clone._cache is base._cache
        assert len(clone._rules) == 2


# ---------------------------------------------------------------------------
# 8. protect_signup
# ---------------------------------------------------------------------------


class TestProtectSignup:
    def test_returns_three_rules(self, mock_protobuf_modules):
        from arcjet._rules import Mode, (
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

    def test_rejects_bot_without_allow_or_deny(self, mock_protobuf_modules):
        from arcjet._rules import Mode, protect_signup

        with pytest.raises(ValueError, match="either `allow` or `deny`"):
            protect_signup(
                rate_limit={"mode": Mode.LIVE, "max": 5, "interval": 60},
                bots={"mode": Mode.LIVE},
                email={"mode": Mode.LIVE, "deny": ["INVALID"]},
            )

    def test_requires_mode_on_nested_factories(self, mock_protobuf_modules):
        from arcjet._rules import Mode, protect_signup

        with pytest.raises(TypeError, match="mode"):
            protect_signup(
                rate_limit={"max": 5, "interval": 60},
                bots={"mode": Mode.LIVE, "allow": []},
                email={"mode": Mode.LIVE, "deny": ["INVALID"]},
            )


# ---------------------------------------------------------------------------
# 10. Rate-limit header helper
# ---------------------------------------------------------------------------


class TestRateLimitHeaders:
    def test_sets_ietf_headers(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet import set_rate_limit_headers
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        rl = StubRateLimitReason(
            max=100, remaining=3, reset_in_seconds=9, window_in_seconds=60
        )
        decision = Decision(
            decide_pb2.Decision(
                id="d1",
                conclusion=decide_pb2.CONCLUSION_ALLOW,
                reason=decide_pb2.Reason(rate_limit=rl),
            )
        )
        headers: dict[str, str] = {}
        set_rate_limit_headers(headers, decision)
        assert headers["RateLimit"] == "limit=100, remaining=3, reset=9"
        assert headers["RateLimit-Policy"] == "100;w=60"

    def test_uses_response_headers_attribute(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet import set_rate_limit_headers
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        class Response:
            def __init__(self) -> None:
                self.headers: dict[str, str] = {}

        rl = StubRateLimitReason(
            max=10, remaining=0, reset_in_seconds=4, window_in_seconds=10
        )
        decision = Decision(
            decide_pb2.Decision(
                id="d1",
                conclusion=decide_pb2.CONCLUSION_DENY,
                reason=decide_pb2.Reason(rate_limit=rl),
            )
        )
        response = Response()
        set_rate_limit_headers(response, decision)
        assert "RateLimit" in response.headers

    def test_noop_when_not_rate_limited(self, mock_protobuf_modules):
        from arcjet import set_rate_limit_headers
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        decision = Decision(
            decide_pb2.Decision(id="d1", conclusion=decide_pb2.CONCLUSION_ALLOW)
        )
        headers: dict[str, str] = {}
        set_rate_limit_headers(headers, decision)
        assert headers == {}

    def _decision_with_reasons(self, mock_protobuf_modules, *reasons):
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        results = [
            decide_pb2.RuleResult(
                rule_id=f"r{i}",
                state=decide_pb2.RULE_STATE_RUN,
                conclusion=decide_pb2.CONCLUSION_ALLOW,
                reason=decide_pb2.Reason(rate_limit=reason),
            )
            for i, reason in enumerate(reasons)
        ]
        return Decision(
            decide_pb2.Decision(
                id="d1",
                conclusion=decide_pb2.CONCLUSION_ALLOW,
                rule_results=results,
            )
        )

    def test_nearest_remaining_wins(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet import set_rate_limit_headers

        decision = self._decision_with_reasons(
            mock_protobuf_modules,
            StubRateLimitReason(
                max=100, remaining=5, reset_in_seconds=20, window_in_seconds=60
            ),
            StubRateLimitReason(
                max=10, remaining=1, reset_in_seconds=30, window_in_seconds=10
            ),
        )
        headers: dict[str, str] = {}
        set_rate_limit_headers(headers, decision)
        assert headers["RateLimit"] == "limit=10, remaining=1, reset=30"
        assert headers["RateLimit-Policy"] == "10;w=10, 100;w=60"

    def test_duplicate_max_aborts(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet import set_rate_limit_headers

        decision = self._decision_with_reasons(
            mock_protobuf_modules,
            StubRateLimitReason(
                max=10, remaining=5, reset_in_seconds=9, window_in_seconds=60
            ),
            StubRateLimitReason(
                max=10, remaining=1, reset_in_seconds=4, window_in_seconds=10
            ),
        )
        headers: dict[str, str] = {}
        set_rate_limit_headers(headers, decision)
        assert headers == {}

    def test_fetch_style_headers(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet import set_rate_limit_headers
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        class FetchHeaders:
            def __init__(self) -> None:
                self._data: dict[str, str] = {}

            def has(self, name: str) -> bool:
                return name in self._data

            def get(self, name: str) -> str | None:
                return self._data.get(name)

            def set(self, name: str, value: str) -> None:
                self._data[name] = value

        rl = StubRateLimitReason(
            max=10, remaining=2, reset_in_seconds=8, window_in_seconds=10
        )
        decision = Decision(
            decide_pb2.Decision(
                id="d1",
                conclusion=decide_pb2.CONCLUSION_ALLOW,
                reason=decide_pb2.Reason(rate_limit=rl),
            )
        )
        headers = FetchHeaders()
        set_rate_limit_headers(headers, decision)
        assert headers.get("RateLimit") == "limit=10, remaining=2, reset=8"
        assert headers.get("RateLimit-Policy") == "10;w=10"

    def test_set_header_style_response(self, mock_protobuf_modules):
        from tests.fixtures.protobuf_stubs import StubRateLimitReason

        from arcjet import set_rate_limit_headers
        from arcjet.proto.decide.v1alpha1 import decide_pb2

        class Outgoing:
            def __init__(self) -> None:
                self.headersSent = False
                self._data: dict[str, str] = {}

            def hasHeader(self, name: str) -> bool:
                return name in self._data

            def getHeader(self, name: str) -> str | None:
                return self._data.get(name)

            def setHeader(self, name: str, value: str) -> None:
                self._data[name] = value

        rl = StubRateLimitReason(
            max=5, remaining=0, reset_in_seconds=3, window_in_seconds=5
        )
        decision = Decision(
            decide_pb2.Decision(
                id="d1",
                conclusion=decide_pb2.CONCLUSION_DENY,
                reason=decide_pb2.Reason(rate_limit=rl),
            )
        )
        response = Outgoing()
        set_rate_limit_headers(response, decision)
        assert response.getHeader("RateLimit") == "limit=5, remaining=0, reset=3"


# ---------------------------------------------------------------------------
# 11. Prompt-injection threshold removed
# ---------------------------------------------------------------------------


class TestPromptInjectionThresholdRemoved:
    def test_factory_rejects_threshold(self, mock_protobuf_modules):
        from arcjet._rules import Mode, detect_prompt_injection

        with pytest.raises(TypeError, match="threshold"):
            detect_prompt_injection(mode=Mode.LIVE, threshold=0.8)  # type: ignore[call-arg]

    def test_proto_omits_custom_threshold(self, mock_protobuf_modules):
        from arcjet._rules import Mode, detect_prompt_injection

        rule = detect_prompt_injection(mode=Mode.LIVE)
        assert not hasattr(rule, "threshold") or getattr(rule, "threshold", None) is None
        pb = rule.to_proto()
        assert pb.prompt_injection_detection.mode == mock_protobuf_modules["pb2"].MODE_LIVE


# ---------------------------------------------------------------------------
# 12. Guard does not read ARCJET_KEY
# ---------------------------------------------------------------------------


class TestGuardKeyPolicy:
    def test_empty_key_rejected_even_when_env_set(self, monkeypatch: Any):
        from arcjet._errors import ArcjetMisconfiguration
        from arcjet.guard import launch_arcjet, launch_arcjet_sync

        monkeypatch.setenv("ARCJET_KEY", "ajkey_from_env")
        with pytest.raises(ArcjetMisconfiguration, match="required"):
            launch_arcjet(key="")
        with pytest.raises(ArcjetMisconfiguration, match="required"):
            launch_arcjet_sync(key="")

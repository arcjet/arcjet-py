"""Tests for the _local module (WASM-based local rule evaluation)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from arcjet_analyze import (
    AllowedBotConfig,
    AllowEmailValidationConfig,
    BotResult,
    DeniedBotConfig,
    DenyEmailValidationConfig,
    EmailValidationResult,
    Err,
    Ok,
)

from arcjet._enums import Mode
from arcjet._local import (
    _FAILED,
    _MISSING,
    _context_to_analyze_request,
    _get_component,
    evaluate_bot_locally,
    evaluate_email_locally,
)
from arcjet.client import _build_local_deny_report, _run_local_rules
from arcjet.context import RequestContext
from arcjet.decision import Decision
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.rules import BotDetection, EmailType, EmailValidation, Shield

# ---------------------------------------------------------------------------
# _context_to_analyze_request
# ---------------------------------------------------------------------------


class TestContextToAnalyzeRequest:
    def test_minimal_context(self):
        import json

        ctx = RequestContext()
        result = json.loads(_context_to_analyze_request(ctx))
        assert result == {}

    def test_full_context(self):
        import json

        ctx = RequestContext(
            ip="1.2.3.4",
            method="GET",
            host="example.com",
            path="/test",
            headers={"User-Agent": "curl/7.0", "Accept": "text/html"},
            cookies="session=abc",
            query="q=hello",
        )
        result = json.loads(_context_to_analyze_request(ctx))
        assert result["ip"] == "1.2.3.4"
        assert result["method"] == "GET"
        assert result["host"] == "example.com"
        assert result["path"] == "/test"
        assert result["headers"]["user-agent"] == "curl/7.0"
        assert result["cookies"] == "session=abc"
        assert result["query"] == "q=hello"

    def test_headers_lowercased(self):
        import json

        ctx = RequestContext(headers={"X-Custom-Header": "value"})
        result = json.loads(_context_to_analyze_request(ctx))
        assert "x-custom-header" in result["headers"]


# ---------------------------------------------------------------------------
# _get_component — graceful degradation
# ---------------------------------------------------------------------------


class TestGetComponent:
    def test_returns_none_when_wasm_not_loadable(self):
        import arcjet._local as mod

        # Reset the singleton to force re-initialization
        old = mod._component_state
        mod._component_state = mod._MISSING
        try:
            with patch(
                "arcjet._local.AnalyzeComponent",
                side_effect=RuntimeError("no wasm"),
            ):
                component = _get_component()
            assert component is None
        finally:
            mod._component_state = old

    def test_caches_result(self):
        import arcjet._local as mod

        old = mod._component_state
        mod._component_state = mod._MISSING
        try:
            with patch(
                "arcjet._local.AnalyzeComponent",
                side_effect=FileNotFoundError("no wasm"),
            ):
                c1 = _get_component()
                c2 = _get_component()
            assert c1 is None
            assert c2 is None
        finally:
            mod._component_state = old

    def test_retries_on_transient_error(self):
        """Transient errors (e.g. RuntimeError) should allow retry on next call."""
        import arcjet._local as mod

        old = mod._component_state
        mod._component_state = mod._MISSING
        try:
            mock_component = MagicMock()
            with patch(
                "arcjet._local.AnalyzeComponent",
                side_effect=[RuntimeError("transient"), mock_component],
            ):
                c1 = _get_component()
                assert c1 is None  # first call fails
                c2 = _get_component()
                assert c2 is mock_component  # second call succeeds
        finally:
            mod._component_state = old

    def test_permanent_error_latches(self):
        """Permanent errors (FileNotFoundError) should latch — no retry."""
        import arcjet._local as mod

        old = mod._component_state
        mod._component_state = mod._MISSING
        try:
            mock_component = MagicMock()
            with patch(
                "arcjet._local.AnalyzeComponent",
                side_effect=[FileNotFoundError("no file"), mock_component],
            ):
                c1 = _get_component()
                assert c1 is None
                c2 = _get_component()
                assert c2 is None  # still None — latched on permanent error
        finally:
            mod._component_state = old


# ---------------------------------------------------------------------------
# evaluate_bot_locally
# ---------------------------------------------------------------------------


class TestEvaluateBotLocally:
    def test_returns_none_when_component_unavailable(self):
        ctx = RequestContext(ip="1.2.3.4")
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )
        with patch("arcjet._local._get_component", return_value=None):
            result = evaluate_bot_locally(ctx, rule)
        assert result is None

    def test_returns_allow_result(self):
        mock_component = MagicMock()
        bot_result = BotResult(
            allowed=["CURL"], denied=[], verified=False, spoofed=False
        )
        mock_component.detect_bot.return_value = Ok(bot_result)

        ctx = RequestContext(
            ip="1.2.3.4", headers={"User-Agent": "curl/7.0"}, method="GET"
        )
        rule = BotDetection(
            mode=Mode.LIVE, allow=("CURL",), deny=(), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_bot_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW
        assert result.state == decide_pb2.RULE_STATE_RUN

    def test_returns_deny_result(self):
        mock_component = MagicMock()
        bot_result = BotResult(
            allowed=[], denied=["CURL"], verified=False, spoofed=False
        )
        mock_component.detect_bot.return_value = Ok(bot_result)

        ctx = RequestContext(
            ip="1.2.3.4", headers={"User-Agent": "curl/7.0"}, method="GET"
        )
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_bot_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_RUN

    def test_dry_run_mode(self):
        mock_component = MagicMock()
        bot_result = BotResult(
            allowed=[], denied=["CURL"], verified=False, spoofed=False
        )
        mock_component.detect_bot.return_value = Ok(bot_result)

        ctx = RequestContext(ip="1.2.3.4", method="GET")
        rule = BotDetection(
            mode=Mode.DRY_RUN, allow=(), deny=("CURL",), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_bot_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_DRY_RUN

    def test_returns_none_on_exception(self):
        mock_component = MagicMock()
        mock_component.detect_bot.side_effect = RuntimeError("wasm error")

        ctx = RequestContext(ip="1.2.3.4", method="GET")
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_bot_locally(ctx, rule)

        assert result is None

    def test_returns_none_on_err_result(self):
        mock_component = MagicMock()
        mock_component.detect_bot.return_value = Err("some error")

        ctx = RequestContext(ip="1.2.3.4", method="GET")
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_bot_locally(ctx, rule)

        assert result is None


# ---------------------------------------------------------------------------
# evaluate_email_locally
# ---------------------------------------------------------------------------


class TestEvaluateEmailLocally:
    def test_returns_none_when_component_unavailable(self):
        ctx = RequestContext(email="test@example.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )
        with patch("arcjet._local._get_component", return_value=None):
            result = evaluate_email_locally(ctx, rule)
        assert result is None

    def test_returns_none_when_no_email(self):
        ctx = RequestContext()
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )
        with patch("arcjet._local._get_component", return_value=MagicMock()):
            result = evaluate_email_locally(ctx, rule)
        assert result is None

    def test_returns_allow_for_valid_email(self):
        mock_component = MagicMock()
        ev_result = EmailValidationResult(validity="valid", blocked=[])
        mock_component.is_valid_email.return_value = Ok(ev_result)

        ctx = RequestContext(email="test@example.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_email_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW

    def test_returns_deny_for_invalid_email(self):
        mock_component = MagicMock()
        ev_result = EmailValidationResult(validity="invalid", blocked=[])
        mock_component.is_valid_email.return_value = Ok(ev_result)

        ctx = RequestContext(email="bad-email")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_email_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY

    def test_returns_deny_for_blocked_email(self):
        mock_component = MagicMock()
        ev_result = EmailValidationResult(validity="valid", blocked=["DISPOSABLE"])
        mock_component.is_valid_email.return_value = Ok(ev_result)

        ctx = RequestContext(email="test@disposable.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_email_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert decide_pb2.EMAIL_TYPE_DISPOSABLE in result.reason.email.email_types

    def test_no_duplicate_invalid_email_type(self):
        """EMAIL_TYPE_INVALID should not be duplicated when both blocked and validity flag it."""
        mock_component = MagicMock()
        # Both signals: "INVALID" in blocked list AND validity != "valid"
        ev_result = EmailValidationResult(validity="invalid", blocked=["INVALID"])
        mock_component.is_valid_email.return_value = Ok(ev_result)

        ctx = RequestContext(email="bad@example.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_email_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        # EMAIL_TYPE_INVALID should appear exactly once, not twice
        invalid_count = list(result.reason.email.email_types).count(
            decide_pb2.EMAIL_TYPE_INVALID
        )
        assert invalid_count == 1

    def test_returns_none_on_err_result(self):
        mock_component = MagicMock()
        mock_component.is_valid_email.return_value = Err("email error")

        ctx = RequestContext(email="test@example.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_email_locally(ctx, rule)

        assert result is None

    def test_allow_config_branch(self):
        """When rule.allow is set, AllowEmailValidationConfig is used."""
        mock_component = MagicMock()
        ev_result = EmailValidationResult(validity="valid", blocked=[])
        mock_component.is_valid_email.return_value = Ok(ev_result)

        ctx = RequestContext(email="test@example.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(),
            allow=(EmailType.DISPOSABLE,),
            require_top_level_domain=True,
            allow_domain_literal=False,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_email_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW
        # Verify AllowEmailValidationConfig was passed to the component
        call_args = mock_component.is_valid_email.call_args
        assert call_args[0][0] == "test@example.com"
        config = call_args[0][1]
        assert isinstance(config, AllowEmailValidationConfig)
        assert config.allow == ["DISPOSABLE"]

    def test_deny_config_passes_correct_args(self):
        """Verify DenyEmailValidationConfig is constructed correctly."""
        mock_component = MagicMock()
        ev_result = EmailValidationResult(validity="valid", blocked=["DISPOSABLE"])
        mock_component.is_valid_email.return_value = Ok(ev_result)

        ctx = RequestContext(email="test@disposable.com")
        rule = EmailValidation(
            mode=Mode.LIVE,
            deny=(EmailType.DISPOSABLE, EmailType.FREE),
            allow=(),
            require_top_level_domain=False,
            allow_domain_literal=True,
            characteristics=(),
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_email_locally(ctx, rule)

        call_args = mock_component.is_valid_email.call_args
        config = call_args[0][1]
        assert isinstance(config, DenyEmailValidationConfig)
        assert config.deny == ["DISPOSABLE", "FREE"]
        assert config.require_top_level_domain is False
        assert config.allow_domain_literal is True

    def test_bot_passes_correct_denied_config(self):
        """Verify DeniedBotConfig is constructed with correct entities."""
        mock_component = MagicMock()
        bot_result = BotResult(
            allowed=[], denied=["CURL"], verified=False, spoofed=False
        )
        mock_component.detect_bot.return_value = Ok(bot_result)

        ctx = RequestContext(
            ip="1.2.3.4", headers={"User-Agent": "curl/7.0"}, method="GET"
        )
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL", "GOOGLEBOT"), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_bot_locally(ctx, rule)

        call_args = mock_component.detect_bot.call_args
        config = call_args[0][1]
        assert isinstance(config, DeniedBotConfig)
        assert config.entities == ["CURL", "GOOGLEBOT"]
        assert config.skip_custom_detect is False

    def test_bot_passes_correct_allowed_config(self):
        """Verify AllowedBotConfig is constructed with correct entities."""
        mock_component = MagicMock()
        bot_result = BotResult(
            allowed=["CURL"], denied=[], verified=False, spoofed=False
        )
        mock_component.detect_bot.return_value = Ok(bot_result)

        ctx = RequestContext(
            ip="1.2.3.4", headers={"User-Agent": "curl/7.0"}, method="GET"
        )
        rule = BotDetection(
            mode=Mode.LIVE, allow=("CURL",), deny=(), characteristics=()
        )

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_bot_locally(ctx, rule)

        call_args = mock_component.detect_bot.call_args
        config = call_args[0][1]
        assert isinstance(config, AllowedBotConfig)
        assert config.entities == ["CURL"]


# ---------------------------------------------------------------------------
# _run_local_rules
# ---------------------------------------------------------------------------


class TestRunLocalRules:
    def test_returns_none_when_no_local_rules(self):
        ctx = RequestContext(ip="1.2.3.4")
        rules = (Shield(mode=Mode.LIVE),)
        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
        ):
            result = _run_local_rules(ctx, rules)
        assert result is None

    def test_returns_none_when_local_allows(self):
        allow_result = decide_pb2.RuleResult(
            rule_id="",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_ALLOW,
        )
        ctx = RequestContext(ip="1.2.3.4")
        rule = BotDetection(
            mode=Mode.LIVE, allow=("CURL",), deny=(), characteristics=()
        )
        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=allow_result),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
        ):
            result = _run_local_rules(ctx, (rule,))
        assert result is None

    def test_short_circuits_on_deny_live(self):
        deny_result = decide_pb2.RuleResult(
            rule_id="",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(bot_v2=decide_pb2.BotV2Reason(denied=["CURL"])),
        )
        ctx = RequestContext(ip="1.2.3.4")
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )
        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=deny_result),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
        ):
            decision = _run_local_rules(ctx, (rule,))
        assert decision is not None
        assert decision.conclusion == decide_pb2.CONCLUSION_DENY

    def test_no_short_circuit_on_deny_dry_run(self):
        deny_dry_run = decide_pb2.RuleResult(
            rule_id="",
            state=decide_pb2.RULE_STATE_DRY_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
        )
        ctx = RequestContext(ip="1.2.3.4")
        rule = BotDetection(
            mode=Mode.DRY_RUN, allow=(), deny=("CURL",), characteristics=()
        )
        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=deny_dry_run),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
        ):
            result = _run_local_rules(ctx, (rule,))
        assert result is None

    def test_returns_none_when_evaluator_returns_none(self):
        """When WASM component fails to load, evaluators return None."""
        ctx = RequestContext(ip="1.2.3.4")
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )
        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
        ):
            result = _run_local_rules(ctx, (rule,))
        assert result is None


# ---------------------------------------------------------------------------
# _build_local_deny_report
# ---------------------------------------------------------------------------


class TestBuildLocalDenyReport:
    def test_builds_report_with_decision(self):
        deny_proto = decide_pb2.Decision(
            id="lreq_test123",
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(bot_v2=decide_pb2.BotV2Reason(denied=["CURL"])),
        )
        local_decision = Decision(deny_proto)
        ctx = RequestContext(ip="1.2.3.4", method="GET")
        rule = BotDetection(
            mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()
        )

        rep = _build_local_deny_report(None, "0.4.1", ctx, local_decision, (rule,))

        assert isinstance(rep, decide_pb2.ReportRequest)
        assert rep.decision.id == "lreq_test123"
        assert rep.decision.conclusion == decide_pb2.CONCLUSION_DENY
        assert rep.sdk_version == "0.4.1"
        assert rep.details.ip == "1.2.3.4"
        assert len(rep.rules) == 1

    def test_includes_all_rules(self):
        deny_proto = decide_pb2.Decision(
            id="lreq_test",
            conclusion=decide_pb2.CONCLUSION_DENY,
        )
        local_decision = Decision(deny_proto)
        ctx = RequestContext(ip="1.2.3.4")
        rules = (
            BotDetection(mode=Mode.LIVE, allow=(), deny=("CURL",), characteristics=()),
            EmailValidation(
                mode=Mode.LIVE,
                deny=(),
                allow=(),
                require_top_level_domain=True,
                allow_domain_literal=False,
                characteristics=(),
            ),
        )

        rep = _build_local_deny_report(None, "0.4.1", ctx, local_decision, rules)
        assert len(rep.rules) == 2

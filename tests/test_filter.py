"""Tests for Filter rule and local evaluation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from arcjet._analyze import Err, FilterResult, Ok
from arcjet._enums import Mode
from arcjet._local import evaluate_filter_locally
from arcjet.client import _run_local_rules
from arcjet.context import RequestContext
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.rules import Filter, filter_request

# ---------------------------------------------------------------------------
# filter_request() factory — validation
# ---------------------------------------------------------------------------


class TestFilterRequestFactory:
    def test_creates_rule_with_deny(self):
        rule = filter_request(deny=['ip.src == "1.2.3.4"'])
        assert isinstance(rule, Filter)
        assert rule.mode == Mode.LIVE
        assert rule.deny == ('ip.src == "1.2.3.4"',)
        assert rule.allow == ()

    def test_creates_rule_with_allow(self):
        rule = filter_request(allow=['http.host == "example.com"'])
        assert isinstance(rule, Filter)
        assert rule.allow == ('http.host == "example.com"',)
        assert rule.deny == ()

    def test_default_mode_is_live(self):
        rule = filter_request(deny=["ip.src == 1"])
        assert rule.mode == Mode.LIVE

    def test_dry_run_mode(self):
        rule = filter_request(mode=Mode.DRY_RUN, deny=["ip.src == 1"])
        assert rule.mode == Mode.DRY_RUN

    def test_rejects_both_allow_and_deny(self):
        with pytest.raises(ValueError, match="not both"):
            filter_request(allow=["a"], deny=["b"])

    def test_rejects_empty_allow_and_deny(self):
        with pytest.raises(ValueError, match="one or more expressions"):
            filter_request()

    def test_rejects_empty_string_expression(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            filter_request(deny=[""])

    def test_multiple_expressions(self):
        rule = filter_request(deny=["ip.src == 1", 'http.host == "x"'])
        assert len(rule.deny) == 2


# ---------------------------------------------------------------------------
# Filter.to_proto()
# ---------------------------------------------------------------------------


class TestFilterToProto:
    def test_deny_to_proto(self):
        rule = filter_request(deny=['ip.src == "1.2.3.4"'])
        proto = rule.to_proto()
        assert proto.HasField("filter")
        assert list(proto.filter.deny) == ['ip.src == "1.2.3.4"']
        assert list(proto.filter.allow) == []

    def test_allow_to_proto(self):
        rule = filter_request(allow=['http.host == "example.com"'])
        proto = rule.to_proto()
        assert proto.HasField("filter")
        assert list(proto.filter.allow) == ['http.host == "example.com"']
        assert list(proto.filter.deny) == []


# ---------------------------------------------------------------------------
# evaluate_filter_locally — mocked component
# ---------------------------------------------------------------------------


class TestEvaluateFilterLocally:
    def test_returns_none_when_component_unavailable(self):
        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=["ip.src == 1"])
        with patch("arcjet._local._get_component", return_value=None):
            result = evaluate_filter_locally(ctx, rule)
        assert result is None

    def test_deny_match_returns_deny(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=False,
                matched_expressions=['ip.src == "1.2.3.4"'],
                undetermined_expressions=[],
            )
        )

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=['ip.src == "1.2.3.4"'])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_RUN
        assert list(result.reason.filter.matched_expressions) == ['ip.src == "1.2.3.4"']

    def test_deny_no_match_returns_allow(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=True, matched_expressions=[], undetermined_expressions=[]
            )
        )

        ctx = RequestContext(ip="5.6.7.8")
        rule = filter_request(deny=['ip.src == "1.2.3.4"'])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW

    def test_allow_match_returns_allow(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=True,
                matched_expressions=['ip.src == "1.2.3.4"'],
                undetermined_expressions=[],
            )
        )

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(allow=['ip.src == "1.2.3.4"'])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_ALLOW

    def test_allow_no_match_returns_deny(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=False, matched_expressions=[], undetermined_expressions=[]
            )
        )

        ctx = RequestContext(ip="5.6.7.8")
        rule = filter_request(allow=['ip.src == "1.2.3.4"'])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY

    def test_dry_run_mode(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=False, matched_expressions=["x"], undetermined_expressions=[]
            )
        )

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(mode=Mode.DRY_RUN, deny=["x"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is not None
        assert result.conclusion == decide_pb2.CONCLUSION_DENY
        assert result.state == decide_pb2.RULE_STATE_DRY_RUN

    def test_undetermined_expressions(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=True,
                matched_expressions=[],
                undetermined_expressions=["ip.src.country == US"],
            )
        )

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=["ip.src.country == US"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is not None
        assert list(result.reason.filter.undetermined_expressions) == [
            "ip.src.country == US"
        ]

    def test_passes_filter_local(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=True, matched_expressions=[], undetermined_expressions=[]
            )
        )

        ctx = RequestContext(ip="1.2.3.4", filter_local={"user_role": "admin"})
        rule = filter_request(allow=['local.user_role == "admin"'])

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_filter_locally(ctx, rule)

        call_args = mock_component.match_filters.call_args[0]
        # Second arg is local_fields JSON
        assert '"user_role"' in call_args[1]
        assert '"admin"' in call_args[1]

    def test_passes_allow_if_match_true_for_allow(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=True, matched_expressions=[], undetermined_expressions=[]
            )
        )

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(allow=["x"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_filter_locally(ctx, rule)

        # Fourth arg is allow_if_match
        assert mock_component.match_filters.call_args[0][3] is True

    def test_passes_allow_if_match_false_for_deny(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Ok(
            FilterResult(
                allowed=True, matched_expressions=[], undetermined_expressions=[]
            )
        )

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=["x"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_filter_locally(ctx, rule)

        assert mock_component.match_filters.call_args[0][3] is False

    def test_returns_none_on_err(self):
        mock_component = MagicMock()
        mock_component.match_filters.return_value = Err("parse error")

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=["bad expression"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is None

    def test_returns_none_on_exception(self):
        mock_component = MagicMock()
        mock_component.match_filters.side_effect = RuntimeError("wasm error")

        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=["x"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is None

    def test_returns_none_on_filter_local_serialization_error(self):
        mock_component = MagicMock()

        # Pass a non-JSON-serializable value in filter_local
        ctx = RequestContext(ip="1.2.3.4", filter_local={"key": object()})  # type: ignore[arg-type]
        rule = filter_request(deny=["x"])

        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_filter_locally(ctx, rule)

        assert result is None
        mock_component.match_filters.assert_not_called()


# ---------------------------------------------------------------------------
# _run_local_rules integration — filter dispatch
# ---------------------------------------------------------------------------


class TestRunLocalRulesFilter:
    def test_dispatches_filter_rule(self):
        deny_result = decide_pb2.RuleResult(
            rule_id="",
            state=decide_pb2.RULE_STATE_RUN,
            conclusion=decide_pb2.CONCLUSION_DENY,
            reason=decide_pb2.Reason(
                filter=decide_pb2.FilterReason(
                    matched_expressions=['ip.src == "1.2.3.4"']
                )
            ),
        )
        ctx = RequestContext(ip="1.2.3.4")
        rule = filter_request(deny=['ip.src == "1.2.3.4"'])

        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
            patch("arcjet.client.evaluate_sensitive_info_locally", return_value=None),
            patch("arcjet.client.evaluate_filter_locally", return_value=deny_result),
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
        rule = filter_request(mode=Mode.DRY_RUN, deny=["x"])

        with (
            patch("arcjet.client.evaluate_bot_locally", return_value=None),
            patch("arcjet.client.evaluate_email_locally", return_value=None),
            patch("arcjet.client.evaluate_sensitive_info_locally", return_value=None),
            patch("arcjet.client.evaluate_filter_locally", return_value=deny_dry_run),
        ):
            result = _run_local_rules(ctx, (rule,))

        assert result is None

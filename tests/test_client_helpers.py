"""Tests for shared helper functions in arcjet.client.

These tests exercise the extracted helper functions directly, without
monkeypatched protobuf stubs. Functions that are pure logic (no protobuf
dependency) are tested exhaustively; protobuf-dependent helpers are tested
with real protobuf types.
"""

from __future__ import annotations

import logging
import time

import pytest

from arcjet._errors import ArcjetMisconfiguration, ArcjetTransportError
from arcjet.cache import DecisionCache
from arcjet.client import (
    _auth_headers,
    _compute_client_kwargs,
    _default_timeout_ms,
    _new_local_request_id,
    _prepare_protect_context,
    _sdk_version,
    _validate_ip_config,
)
from arcjet.context import RequestContext


class TestNewLocalRequestId:
    """Tests for _new_local_request_id."""

    def test_returns_string_with_lreq_prefix(self):
        rid = _new_local_request_id()
        assert isinstance(rid, str)
        assert rid.startswith("lreq")

    def test_ids_are_unique(self):
        ids = {_new_local_request_id() for _ in range(50)}
        assert len(ids) == 50


class TestDefaultTimeoutMs:
    """Tests for _default_timeout_ms."""

    def test_production_default(self, monkeypatch):
        monkeypatch.delenv("ARCJET_ENV", raising=False)
        assert _default_timeout_ms() == 500

    def test_development_timeout(self, monkeypatch):
        monkeypatch.setenv("ARCJET_ENV", "development")
        assert _default_timeout_ms() == 1000

    def test_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("ARCJET_ENV", "Development")
        assert _default_timeout_ms() == 1000

    def test_unknown_env_uses_production(self, monkeypatch):
        monkeypatch.setenv("ARCJET_ENV", "staging")
        assert _default_timeout_ms() == 500


class TestAuthHeaders:
    """Tests for _auth_headers."""

    def test_key_adds_bearer(self):
        h = _auth_headers("sk_test_123")
        assert h == {"Authorization": "Bearer sk_test_123"}

    def test_none_key_no_auth(self):
        h = _auth_headers(None)
        assert h == {}

    def test_empty_key_no_auth(self):
        h = _auth_headers("")
        assert h == {}

    def test_existing_auth_not_overridden(self):
        h = _auth_headers("sk_test_123", {"Authorization": "custom"})
        assert h["Authorization"] == "custom"

    def test_extra_headers_included(self):
        h = _auth_headers("sk_test", {"X-Custom": "foo"})
        assert h["X-Custom"] == "foo"
        assert h["Authorization"] == "Bearer sk_test"

    def test_header_values_stringified(self):
        h = _auth_headers("key", {42: 99})  # type: ignore[dict-item]
        assert h["42"] == "99"


class TestSdkVersion:
    """Tests for _sdk_version."""

    def test_returns_string(self):
        v = _sdk_version()
        assert isinstance(v, str)

    def test_fallback_default(self, monkeypatch):
        # Force PackageNotFoundError by patching pkg_version
        import arcjet.client as client_mod

        monkeypatch.setattr(
            client_mod,
            "pkg_version",
            lambda _name: (_ for _ in ()).throw(
                __import__(
                    "importlib.metadata", fromlist=["PackageNotFoundError"]
                ).PackageNotFoundError
            ),
        )
        assert _sdk_version() == "0.0.0"

    def test_custom_default(self, monkeypatch):
        from importlib.metadata import PackageNotFoundError

        import arcjet.client as client_mod

        monkeypatch.setattr(
            client_mod,
            "pkg_version",
            lambda _: (_ for _ in ()).throw(PackageNotFoundError),
        )
        assert _sdk_version(default="1.2.3") == "1.2.3"


class TestValidateIpConfig:
    """Tests for _validate_ip_config."""

    def test_auto_detection_no_ip_src_passes(self):
        # Should not raise
        _validate_ip_config(
            disable_automatic_ip_detection=False,
            ip_src=None,
            proxies=(),
        )

    def test_manual_detection_with_ip_src_passes(self):
        _validate_ip_config(
            disable_automatic_ip_detection=True,
            ip_src="1.2.3.4",
            proxies=(),
        )

    def test_manual_detection_missing_ip_src_raises(self):
        with pytest.raises(ArcjetMisconfiguration, match="ip_src is required"):
            _validate_ip_config(
                disable_automatic_ip_detection=True,
                ip_src=None,
                proxies=(),
            )

    def test_manual_detection_with_proxies_raises(self):
        with pytest.raises(ArcjetMisconfiguration, match="proxies cannot be used"):
            _validate_ip_config(
                disable_automatic_ip_detection=True,
                ip_src="1.2.3.4",
                proxies=("10.0.0.0/8",),
            )

    def test_auto_detection_with_ip_src_raises(self):
        with pytest.raises(ArcjetMisconfiguration, match="ip_src cannot be set"):
            _validate_ip_config(
                disable_automatic_ip_detection=False,
                ip_src="1.2.3.4",
                proxies=(),
            )


def _call_prepare(
    request: RequestContext,
    *,
    proxies: tuple[str, ...] = (),
    ip_src: str | None = None,
    email: str | None = None,
    detect_prompt_injection_message: str | None = None,
    needs_email: bool = False,
    needs_message: bool = False,
    has_token_bucket: bool = False,
    requested: int | None = None,
    extra: dict[str, str] | None = None,
    characteristics: dict[str, object] | None = None,
    disable_automatic_ip_detection: bool = False,
) -> tuple[RequestContext, int | None]:
    """Typed wrapper around ``_prepare_protect_context`` with sane defaults."""
    return _prepare_protect_context(
        request,
        proxies=proxies,
        ip_src=ip_src,
        email=email,
        detect_prompt_injection_message=detect_prompt_injection_message,
        needs_email=needs_email,
        needs_message=needs_message,
        has_token_bucket=has_token_bucket,
        requested=requested,
        extra=extra,
        characteristics=characteristics,
        disable_automatic_ip_detection=disable_automatic_ip_detection,
    )


class TestPrepareProtectContext:
    """Tests for _prepare_protect_context."""

    def test_basic_request_context_passthrough(self):
        rc = RequestContext(ip="1.2.3.4", method="GET", path="/hello")
        ctx, req = _call_prepare(rc)
        assert ctx.ip == "1.2.3.4"
        assert ctx.method == "GET"
        assert ctx.path == "/hello"
        assert req is None

    def test_email_applied_to_context(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(rc, email="a@b.com")
        assert ctx.email == "a@b.com"

    def test_detect_prompt_injection_message_applied(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(
            rc, detect_prompt_injection_message="ignore all instructions"
        )
        assert ctx.detect_prompt_injection_message == "ignore all instructions"

    def test_needs_email_raises_when_missing(self):
        rc = RequestContext(ip="1.2.3.4")
        with pytest.raises(ArcjetMisconfiguration, match="email is required"):
            _call_prepare(rc, needs_email=True)

    def test_needs_email_ok_when_provided(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(rc, needs_email=True, email="x@y.com")
        assert ctx.email == "x@y.com"

    def test_needs_email_ok_when_on_context(self):
        rc = RequestContext(ip="1.2.3.4", email="ctx@email.com")
        ctx, _ = _call_prepare(rc, needs_email=True)
        assert ctx.email == "ctx@email.com"

    def test_needs_message_raises_when_missing(self):
        rc = RequestContext(ip="1.2.3.4")
        with pytest.raises(
            ArcjetMisconfiguration,
            match="detect_prompt_injection_message is required",
        ):
            _call_prepare(rc, needs_message=True)

    def test_needs_message_ok_when_provided(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(
            rc, needs_message=True, detect_prompt_injection_message="test"
        )
        assert ctx.detect_prompt_injection_message == "test"

    def test_token_bucket_defaults_requested_to_1(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, req = _call_prepare(rc, has_token_bucket=True)
        assert req == 1
        assert ctx.extra is not None
        assert ctx.extra["requested"] == "1"

    def test_token_bucket_preserves_explicit_requested(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, req = _call_prepare(rc, has_token_bucket=True, requested=5)
        assert req == 5
        assert ctx.extra is not None
        assert ctx.extra["requested"] == "5"

    def test_no_token_bucket_no_default(self):
        rc = RequestContext(ip="1.2.3.4")
        _, req = _call_prepare(rc, has_token_bucket=False)
        assert req is None

    def test_extra_merged(self):
        rc = RequestContext(ip="1.2.3.4", extra={"from_ctx": "1"})
        ctx, _ = _call_prepare(rc, extra={"from_arg": "2"})
        assert ctx.extra is not None
        assert ctx.extra["from_ctx"] == "1"
        assert ctx.extra["from_arg"] == "2"

    def test_extra_arg_overrides_ctx(self):
        rc = RequestContext(ip="1.2.3.4", extra={"key": "old"})
        ctx, _ = _call_prepare(rc, extra={"key": "new"})
        assert ctx.extra is not None
        assert ctx.extra["key"] == "new"

    def test_characteristics_flattened_as_extra(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(rc, characteristics={"user_id": "abc"})
        assert ctx.extra is not None
        assert ctx.extra["user_id"] == "abc"

    def test_characteristics_list_joined(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(rc, characteristics={"tags": ["a", "b", "c"]})
        assert ctx.extra is not None
        assert ctx.extra["tags"] == "a,b,c"

    def test_characteristics_tuple_joined(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(rc, characteristics={"ids": (1, 2)})
        assert ctx.extra is not None
        assert ctx.extra["ids"] == "1,2"

    def test_disable_automatic_ip_detection_extra_field(self):
        rc = RequestContext(ip="5.6.7.8")
        ctx, _ = _call_prepare(
            rc, disable_automatic_ip_detection=True, ip_src="5.6.7.8"
        )
        assert ctx.extra is not None
        assert ctx.extra["arcjet_disable_automatic_ip_detection"] == "true"

    def test_no_extra_when_nothing_added(self):
        rc = RequestContext(ip="1.2.3.4")
        ctx, _ = _call_prepare(rc)
        assert ctx.extra is None


class TestComputeClientKwargs:
    """Tests for _compute_client_kwargs."""

    def test_empty_key_raises(self):
        with pytest.raises(ArcjetMisconfiguration, match="key is required"):
            _compute_client_kwargs(
                key="",
                rules=[],
                stack=None,
                sdk_version="1.0.0",
                timeout_ms=500,
                fail_open=True,
                proxies=[],
                disable_automatic_ip_detection=False,
            )

    def test_basic_kwargs(self):
        kw = _compute_client_kwargs(
            key="test_key",
            rules=[],
            stack=None,
            sdk_version="2.0.0",
            timeout_ms=750,
            fail_open=False,
            proxies=["10.0.0.0/8"],
            disable_automatic_ip_detection=True,
        )
        assert kw["_key"] == "test_key"
        assert kw["_rules"] == ()
        assert kw["_sdk_stack"] is None
        assert kw["_sdk_version"] == "2.0.0"
        assert kw["_timeout_ms"] == 750
        assert kw["_fail_open"] is False
        assert kw["_proxies"] == ("10.0.0.0/8",)
        assert kw["_disable_automatic_ip_detection"] is True

    def test_rules_converted_to_tuple(self):
        from arcjet.rules import RuleSpec

        r = RuleSpec()
        kw = _compute_client_kwargs(
            key="k",
            rules=[r, r],
            stack=None,
            sdk_version="1.0",
            timeout_ms=100,
            fail_open=True,
            proxies=[],
            disable_automatic_ip_detection=False,
        )
        assert isinstance(kw["_rules"], tuple)
        assert len(kw["_rules"]) == 2

    def test_no_special_rules_all_flags_false(self):
        kw = _compute_client_kwargs(
            key="k",
            rules=[],
            stack=None,
            sdk_version="1.0",
            timeout_ms=100,
            fail_open=True,
            proxies=[],
            disable_automatic_ip_detection=False,
        )
        assert kw["_needs_email"] is False
        assert kw["_needs_message"] is False
        assert kw["_has_token_bucket"] is False

    def test_timeout_defaults_when_none(self, monkeypatch):
        monkeypatch.delenv("ARCJET_ENV", raising=False)
        kw = _compute_client_kwargs(
            key="k",
            rules=[],
            stack=None,
            sdk_version="1.0",
            timeout_ms=None,
            fail_open=True,
            proxies=[],
            disable_automatic_ip_detection=False,
        )
        assert kw["_timeout_ms"] == 500  # production default

    def test_sdk_version_defaults_when_none(self):
        kw = _compute_client_kwargs(
            key="k",
            rules=[],
            stack=None,
            sdk_version=None,
            timeout_ms=100,
            fail_open=True,
            proxies=[],
            disable_automatic_ip_detection=False,
        )
        # Should be a string (real version or fallback "0.0.0")
        assert isinstance(kw["_sdk_version"], str)

    def test_custom_stack_preserved(self):
        kw = _compute_client_kwargs(
            key="k",
            rules=[],
            stack="CUSTOM_STACK",
            sdk_version="1.0",
            timeout_ms=100,
            fail_open=True,
            proxies=[],
            disable_automatic_ip_detection=False,
        )
        assert kw["_sdk_stack"] == "CUSTOM_STACK"


from arcjet.client import (
    _build_cache_hit_report,
    _build_decide_request,
    _finalize_decision,
    _handle_invalid_response,
    _handle_transport_error,
    _log_cache_hit_report,
    _sdk_stack,
)
from arcjet.decision import Decision
from arcjet.proto.decide.v1alpha1 import decide_pb2


class TestSdkStack:
    """Tests for _sdk_stack."""

    def test_none_returns_python(self):
        assert _sdk_stack(None) == decide_pb2.SDK_STACK_PYTHON

    def test_custom_string_passthrough(self):
        assert _sdk_stack("MY_STACK") == "MY_STACK"


class TestBuildDecideRequest:
    """Tests for _build_decide_request."""

    def test_basic_request(self):
        ctx = RequestContext(ip="1.2.3.4", method="GET", path="/")
        req = _build_decide_request(None, "1.0.0", ctx, ())
        assert isinstance(req, decide_pb2.DecideRequest)
        assert req.sdk_version == "1.0.0"
        assert req.sdk_stack == decide_pb2.SDK_STACK_PYTHON
        assert req.details.ip == "1.2.3.4"

    def test_explicit_stack(self):
        ctx = RequestContext(ip="1.2.3.4")
        req = _build_decide_request("SDK_STACK_PYTHON", "2.0", ctx, ())
        assert req.sdk_stack == decide_pb2.SDK_STACK_PYTHON


class TestBuildCacheHitReport:
    """Tests for _build_cache_hit_report."""

    def _make_decision(self):
        d = decide_pb2.Decision(
            id="test_id",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(shield=decide_pb2.ShieldReason()),
            ttl=60,
        )
        return Decision(d)

    def test_returns_report_and_decision(self):
        ctx = RequestContext(ip="1.2.3.4")
        cached = self._make_decision()
        rep, dec = _build_cache_hit_report(None, "1.0", ctx, cached, ())
        assert isinstance(rep, decide_pb2.ReportRequest)
        assert dec.id.startswith("lreq")
        assert rep.sdk_version == "1.0"

    def test_report_id_differs_from_original(self):
        ctx = RequestContext(ip="1.2.3.4")
        cached = self._make_decision()
        _, dec = _build_cache_hit_report(None, "1.0", ctx, cached, ())
        assert dec.id != "test_id"


class TestHandleTransportError:
    """Tests for _handle_transport_error."""

    def test_fail_open_returns_error_decision(self):
        t0 = time.perf_counter()
        t_api = time.perf_counter()
        result = _handle_transport_error(
            ConnectionError("timeout"),
            fail_open=True,
            rules=(),
            t0=t0,
            t_api_start=t_api,
        )
        assert isinstance(result, Decision)
        assert result.conclusion == decide_pb2.CONCLUSION_ERROR

    def test_fail_closed_raises(self):
        t0 = time.perf_counter()
        t_api = time.perf_counter()
        with pytest.raises(ArcjetTransportError, match="timeout"):
            _handle_transport_error(
                ConnectionError("timeout"),
                fail_open=False,
                rules=(),
                t0=t0,
                t_api_start=t_api,
            )

    def test_fail_open_error_message_preserved(self):
        t0 = time.perf_counter()
        t_api = time.perf_counter()
        result = _handle_transport_error(
            RuntimeError("custom error msg"),
            fail_open=True,
            rules=(),
            t0=t0,
            t_api_start=t_api,
        )
        from arcjet.dataclasses import ErrorReason

        reason = result.reason_v2
        assert isinstance(reason, ErrorReason)
        assert "custom error msg" in reason.message


class TestHandleInvalidResponse:
    """Tests for _handle_invalid_response."""

    def test_fail_open_returns_error_decision(self):
        t0 = time.perf_counter()
        t_api = time.perf_counter()
        t_end = time.perf_counter()
        result = _handle_invalid_response(
            fail_open=True,
            rules=(),
            t0=t0,
            t_api_start=t_api,
            t_api_end=t_end,
        )
        assert isinstance(result, Decision)
        assert result.conclusion == decide_pb2.CONCLUSION_ERROR

    def test_fail_closed_raises(self):
        t0 = time.perf_counter()
        t_api = time.perf_counter()
        t_end = time.perf_counter()
        with pytest.raises(ArcjetTransportError, match="invalid response"):
            _handle_invalid_response(
                fail_open=False,
                rules=(),
                t0=t0,
                t_api_start=t_api,
                t_api_end=t_end,
            )


class TestFinalizeDecision:
    """Tests for _finalize_decision."""

    def _make_resp(self, conclusion=decide_pb2.CONCLUSION_ALLOW, ttl=0):
        d = decide_pb2.Decision(
            id="dec_123",
            conclusion=conclusion,
            reason=decide_pb2.Reason(shield=decide_pb2.ShieldReason()),
            ttl=ttl,
        )

        class FakeResp:
            def __init__(self, decision):
                self.decision = decision

            def HasField(self, name):
                return name == "decision"

        return FakeResp(d)

    def test_returns_decision(self):
        t = time.perf_counter()
        resp = self._make_resp()
        result = _finalize_decision(resp, DecisionCache(), None, (), t, t, t, t)
        assert isinstance(result, Decision)
        assert result.id == "dec_123"

    def test_caches_when_ttl_positive(self):
        t = time.perf_counter()
        cache = DecisionCache()
        resp = self._make_resp(ttl=30)
        result = _finalize_decision(resp, cache, "test_cache_key", (), t, t, t, t)
        assert cache.get("test_cache_key") is not None

    def test_no_cache_when_ttl_zero(self):
        t = time.perf_counter()
        cache = DecisionCache()
        resp = self._make_resp(ttl=0)
        _finalize_decision(resp, cache, "key", (), t, t, t, t)
        assert cache.get("key") is None

    def test_no_cache_when_key_is_none(self):
        t = time.perf_counter()
        cache = DecisionCache()
        resp = self._make_resp(ttl=30)
        result = _finalize_decision(resp, cache, None, (), t, t, t, t)
        assert isinstance(result, Decision)


class TestLogCacheHitReport:
    """Tests for _log_cache_hit_report."""

    def _make_decision(self):
        d = decide_pb2.Decision(
            id="log_test",
            conclusion=decide_pb2.CONCLUSION_ALLOW,
            reason=decide_pb2.Reason(shield=decide_pb2.ShieldReason()),
            ttl=10,
        )
        return Decision(d)

    def test_emits_debug_log(self, caplog):
        cached = self._make_decision()
        with caplog.at_level(logging.DEBUG, logger="arcjet"):
            _log_cache_hit_report("lreq_test", cached, (), time.perf_counter())
        assert any("lreq_test" in r.message for r in caplog.records)

    def test_no_log_above_debug(self, caplog):
        cached = self._make_decision()
        with caplog.at_level(logging.INFO, logger="arcjet"):
            _log_cache_hit_report("lreq_test", cached, (), time.perf_counter())
        assert not any("lreq_test" in r.message for r in caplog.records)

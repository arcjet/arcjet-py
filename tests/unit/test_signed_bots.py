"""Web Bot Auth request forwarding and signed-bot rule behavior."""

from __future__ import annotations

import asyncio
from typing import cast
from unittest.mock import Mock, patch

import pytest

from arcjet._cache import make_cache_key
from arcjet._client import (
    Arcjet,
    ArcjetSync,
    _run_local_rules,
    _should_defer_signed_bot_rules,
)
from arcjet._context import (
    RequestContext,
    coerce_request_context,
    request_details_from_context,
)
from arcjet._decision import Decision
from arcjet._enums import Mode
from arcjet._rules import BotCategory, detect_bot
from arcjet.proto.decide.v1alpha1 import decide_pb2
from arcjet.proto.decide.v1alpha1.decide_connect import (
    DecideServiceClient,
    DecideServiceClientSync,
)

_DIRECTORY = (
    "SIGNED_BOT:https://bot.example.com/.well-known/http-message-signatures-directory"
)


@pytest.mark.parametrize(
    "identity",
    [
        "GOOGLE_AGENT",
        "CHATGPT_AGENT",
        "DUCKASSIST_BOT",
        "BROWSERBASE",
        "MANUS_BOT",
        _DIRECTORY,
    ],
)
def test_signed_bot_identifiers_are_sent_to_cloud(identity: str) -> None:
    rule = detect_bot(mode=Mode.LIVE, allow=[identity])
    assert list(rule.to_proto().bot_v2.allow) == [identity]
    assert _should_defer_signed_bot_rules(
        RequestContext(headers={"Signature-Input": "sig1=..."}), (rule,)
    )


@pytest.mark.parametrize(
    "category",
    [BotCategory.AI, BotCategory.GOOGLE, BotCategory.SEARCH_ENGINE, BotCategory.TOOL],
)
def test_signed_bot_categories_are_deferred(category: BotCategory) -> None:
    rule = detect_bot(mode=Mode.LIVE, allow=[category])
    assert _should_defer_signed_bot_rules(
        RequestContext(headers={"signature-input": "sig1=..."}), (rule,)
    )


def test_unrelated_and_unsigned_bot_rules_still_evaluate_locally() -> None:
    signed = detect_bot(mode=Mode.LIVE, allow=["CHATGPT_AGENT"])
    unrelated = detect_bot(mode=Mode.LIVE, allow=[BotCategory.MONITOR])
    assert not _should_defer_signed_bot_rules(RequestContext(headers={}), (signed,))
    assert not _should_defer_signed_bot_rules(
        RequestContext(headers={"Signature-Input": "sig1=..."}), (unrelated,)
    )


@pytest.mark.parametrize(
    "identity",
    [
        "SIGNED_BOT",
        "SIGNED_BOT:bad-url",
        "SIGNED_BOT:http://bot.example.com/.well-known/http-message-signatures-directory",
        "SIGNED_BOT:https://bot.example.com/other",
        _DIRECTORY + "?key=1",
        _DIRECTORY + "#fragment",
        _DIRECTORY + "\n",
    ],
)
def test_invalid_signed_bot_directory_rejected(identity: str) -> None:
    with pytest.raises(ValueError, match="HTTPS Web Bot Auth directory URL"):
        detect_bot(mode=Mode.LIVE, allow=[identity])


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (b"/a/%2E%2e?x=1", "/a/%2E%2e"),
        (b"/a#fragment", None),
        (b"/a b", None),
        (b"/caf\xc3\xa9", None),
        ("/café", None),
        ("https://example.com/a", None),
    ],
)
def test_asgi_raw_path_is_preserved_only_when_origin_form(
    target: bytes | str, expected: str | None
) -> None:
    ctx = coerce_request_context(
        {
            "type": "http",
            "method": "GET",
            "path": "/normalized",
            "raw_path": target,
            "headers": [(b"host", b"example.com")],
        }
    )
    assert ctx.path == "/normalized"
    assert ctx.raw_path == expected
    details = request_details_from_context(ctx, include_raw_path=True)
    assert details.path == "/normalized"
    assert details.raw_path == (expected or "")


def test_raw_path_is_decide_only_and_round_trips_on_wire() -> None:
    ctx = RequestContext(path="/decoded", raw_path="/%2F?x=1")
    decide_details = request_details_from_context(ctx, include_raw_path=True)
    report_details = request_details_from_context(ctx)
    assert decide_pb2.RequestDetails.RAW_PATH_FIELD_NUMBER == 13
    assert (
        decide_pb2.RequestDetails.FromString(
            decide_details.SerializeToString()
        ).raw_path
        == "/%2F"
    )
    assert report_details.raw_path == ""


def test_wsgi_raw_request_targets_are_used_without_rebuilding_parsed_paths() -> None:
    class FlaskRequest:
        headers = {"Host": "example.com"}
        method = "GET"
        path = "/decoded"
        host = "example.com"
        remote_addr = "8.8.8.8"
        is_secure = True
        query_string = b"x=1"
        environ = {"RAW_URI": "/%2F?x=1"}

        def get_data(self) -> bytes:
            return b""

    class DjangoRequest:
        headers = {"Host": "example.com"}
        method = "GET"
        path = "/decoded"
        body = b""
        META = {
            "REMOTE_ADDR": "8.8.8.8",
            "HTTP_HOST": "example.com",
            "wsgi.url_scheme": "https",
            "REQUEST_URI": "/%2F?x=1",
        }

    assert coerce_request_context(FlaskRequest()).raw_path == "/%2F"
    assert coerce_request_context(DjangoRequest()).raw_path == "/%2F"
    FlaskRequest.environ = {}
    DjangoRequest.META.pop("REQUEST_URI")
    assert coerce_request_context(FlaskRequest()).raw_path is None
    assert coerce_request_context(DjangoRequest()).raw_path is None


def _local_bot_deny() -> decide_pb2.RuleResult:
    return decide_pb2.RuleResult(
        state=decide_pb2.RULE_STATE_RUN,
        conclusion=decide_pb2.CONCLUSION_DENY,
        reason=decide_pb2.Reason(
            bot_v2=decide_pb2.BotV2Reason(denied=["OPENAI_CRAWLER_USER"])
        ),
        ttl=60,
    )


class _AsyncCloud:
    def __init__(self) -> None:
        self.requests: list[decide_pb2.DecideRequest] = []

    async def decide(
        self, request: decide_pb2.DecideRequest, **_kwargs: object
    ) -> decide_pb2.DecideResponse:
        self.requests.append(request)
        return decide_pb2.DecideResponse(
            decision=decide_pb2.Decision(conclusion=decide_pb2.CONCLUSION_ALLOW)
        )

    async def report(self, *_args: object, **_kwargs: object) -> None:
        pass


class _SyncCloud:
    def __init__(self) -> None:
        self.requests: list[decide_pb2.DecideRequest] = []

    def decide(
        self, request: decide_pb2.DecideRequest, **_kwargs: object
    ) -> decide_pb2.DecideResponse:
        self.requests.append(request)
        return decide_pb2.DecideResponse(
            decision=decide_pb2.Decision(conclusion=decide_pb2.CONCLUSION_ALLOW)
        )

    def report(self, *_args: object, **_kwargs: object) -> None:
        pass


def _signed_context() -> RequestContext:
    return RequestContext(
        ip="8.8.8.8",
        method="GET",
        path="/decoded",
        raw_path="/%2F",
        headers={
            "User-Agent": "ChatGPT-User",
            "Signature-Input": "sig1=...",
            "Signature": "sig1=:...:",
            "Signature-Agent": '"https://chatgpt.com"',
        },
    )


def test_async_signed_request_bypasses_cached_and_local_bot_denies() -> None:
    cloud = _AsyncCloud()
    rule = detect_bot(mode=Mode.LIVE, allow=["CHATGPT_AGENT"])
    client = Arcjet(
        _key="ajkey_test",
        _rules=(rule,),
        _client=cast(DecideServiceClient, cloud),
        _sdk_stack=None,
        _sdk_version="test",
        _timeout_ms=None,
        _fail_open=False,
    )
    ctx = _signed_context()
    cache_key = make_cache_key(ctx, (rule,))
    assert cache_key is not None
    client._cache.set(
        cache_key,
        Decision(decide_pb2.Decision(conclusion=decide_pb2.CONCLUSION_DENY, ttl=60)),
        60,
    )

    local = Mock(return_value=_local_bot_deny())
    with patch.dict(_run_local_rules.__globals__, evaluate_bot_locally=local):
        result = asyncio.run(client.protect(ctx))

    assert result.is_allowed()
    assert len(cloud.requests) == 1
    assert cloud.requests[0].details.raw_path == "/%2F"
    assert cloud.requests[0].details.path == "/decoded"
    assert (
        cloud.requests[0].details.headers["signature-agent"] == '"https://chatgpt.com"'
    )
    local.assert_not_called()


def test_sync_signed_request_bypasses_local_deny_but_unsigned_still_denies() -> None:
    cloud = _SyncCloud()
    rule = detect_bot(mode=Mode.LIVE, allow=[_DIRECTORY])
    client = ArcjetSync(
        _key="ajkey_test",
        _rules=(rule,),
        _client=cast(DecideServiceClientSync, cloud),
        _sdk_stack=None,
        _sdk_version="test",
        _timeout_ms=None,
        _fail_open=False,
    )
    ctx = _signed_context()
    local = Mock(return_value=_local_bot_deny())
    with patch.dict(_run_local_rules.__globals__, evaluate_bot_locally=local):
        assert client.protect(ctx).is_allowed()
        local.assert_not_called()
        unsigned = RequestContext(
            ip=ctx.ip,
            method=ctx.method,
            path=ctx.path,
            headers={"User-Agent": "ChatGPT-User"},
        )
        assert not _should_defer_signed_bot_rules(unsigned, (rule,))
        unsigned_cache_key = make_cache_key(unsigned, (rule,))
        assert unsigned_cache_key is not None
        assert client._cache.get(unsigned_cache_key) is None
        assert client.protect(unsigned).is_denied()
        assert len(cloud.requests) == 1
        assert local.call_count == 1
        # The signed request must bypass the unsigned denial now cached by IP.
        assert client.protect(ctx).is_allowed()
        assert local.call_count == 1
    assert len(cloud.requests) == 2

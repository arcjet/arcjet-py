"""Strands Agents adapter unit tests that must run with the extra absent.

The extra is optional. These tests import ``arcjet.guard.strands_agents``
helpers that do not load the peer.
"""

from __future__ import annotations

import ast
import asyncio
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from guard_doubles import (
    StubGuardClient,
    make_allow_decision,
    make_deny_decision,
)

from arcjet._errors import ArcjetMisconfiguration
from arcjet.guard import arcjet_sequence
from arcjet.guard._policy_input import PolicyInputMap
from arcjet.guard._types import RuleResultError, RuleResultTokenBucket
from arcjet.guard.strands_agents import _import as import_module
from arcjet.guard.strands_agents import (
    guard_hooks,
    guard_tool,
    strands_agent_context,
)
from arcjet.guard.strands_agents._context import StrandsAgentContext
from arcjet.guard.strands_agents._denial import (
    UNAVAILABLE_RETRY_AFTER_SECONDS,
    cancel_tool_value,
    denial_result,
    dumps_denial,
    retry_after_seconds,
    unavailable_result,
)
from arcjet.guard.strands_agents._hooks import (
    BeforeToolCallVerdict,
    _after_outcome,
    _HookConfig,
    apply_cancel_tool,
    capture_after_tool_call,
    evaluate_before_tool_call,
)
from arcjet.guard.strands_agents._import import (
    _release,
    load_decorated_function_tool,
    strands_agents_present,
)
from arcjet.guard.strands_agents._tool import (
    _GUARD_BRAND,
    HandlerVerdict,
    _arguments_from_handler,
    _brand,
    _ToolConfig,
    _wrap_stream,
    denial_tool_result,
    evaluate_handler,
    handler_denial_result,
)

STRANDS_SRC = (
    Path(__file__).resolve().parents[3] / "src" / "arcjet" / "guard" / "strands_agents"
)


def _tool_config(**kwargs: Any) -> _ToolConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": "echo.invoked",
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "on_guard_error": "deny",
        "tool_name": "echo",
    }
    defaults.update(kwargs)
    return _ToolConfig(**defaults)


def _hook_config(**kwargs: Any) -> _HookConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": None,
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "on_guard_error": "deny",
    }
    defaults.update(kwargs)
    return _HookConfig(**defaults)


def _event(**kwargs: object) -> SimpleNamespace:
    defaults: dict[str, object] = {
        "selected_tool": SimpleNamespace(tool_name="echo"),
        "tool_use": {"name": "echo", "input": {"value": "hello"}, "toolUseId": "tu_1"},
        "invocation_state": {},
        "cancel_tool": False,
        "agent": SimpleNamespace(
            id=property(lambda _self: (_ for _ in ()).throw(AssertionError("agent.id")))
        ),
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestSourceIsolation:
    def test_package_does_not_import_sibling_adapters(self) -> None:
        for path in STRANDS_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "langchain" not in node.module
                    assert "crewai" not in node.module
                    assert "openai_agents" not in node.module
                    assert "claude_agent_sdk" not in node.module
                    assert "claude_managed_agents" not in node.module
                    assert "google_adk" not in node.module
                    assert node.module != "arcjet.guard.langchain"
                    assert node.module != "arcjet.guard.crewai"
                    assert node.module != "arcjet.guard.openai_agents"
                    assert node.module != "arcjet.guard.claude_agent_sdk"
                    assert node.module != "arcjet.guard.claude_managed_agents"
                    assert node.module != "arcjet.guard.google_adk"
                    assert node.module != "strands"
                    assert not node.module.startswith("strands.")
                    assert node.module != "strands_agents"
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "langchain" not in alias.name
                        assert "crewai" not in alias.name
                        assert "openai_agents" not in alias.name
                        assert "claude_agent_sdk" not in alias.name
                        assert "claude_managed_agents" not in alias.name
                        assert "google_adk" not in alias.name
                        assert alias.name != "strands"
                        assert not alias.name.startswith("strands.")
                        assert alias.name != "strands_agents"

    def test_core_guard_imports_with_peer_unimportable(self) -> None:
        """The real invariant, in a process where the peer cannot import."""
        program = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "strands" or name.startswith("strands."):
            raise ImportError("strands is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())

import arcjet.guard
assert callable(arcjet.guard.guard)
assert "strands" not in sys.modules

import arcjet.guard.strands_agents as adapter
assert callable(adapter.guard_tool)
assert callable(adapter.guard_hooks)
assert callable(adapter.strands_agent_context)
assert adapter.__all__ == ["guard_tool", "guard_hooks", "strands_agent_context"]
assert not hasattr(adapter, "guard_inbound")
assert not hasattr(adapter, "guard_approval")
try:
    adapter.guard_tool(guard=object(), tool=object(), action="x.done")
except ImportError as exc:
    assert "arcjet[strands-agents]" in str(exc), exc
else:
    raise AssertionError("expected an ImportError naming what to install")
try:
    adapter.guard_hooks(guard=object())
except ImportError as exc:
    assert "arcjet[strands-agents]" in str(exc), exc
else:
    raise AssertionError("expected an ImportError naming what to install")
print("ok")
"""
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"

    def test_does_not_register_before_tools_event(self) -> None:
        text = (STRANDS_SRC / "_hooks.py").read_text()
        assert "BeforeToolCallEvent" in text
        assert "AfterToolCallEvent" in text
        assert "BeforeToolsEvent.cancel" in text
        assert "hooks.BeforeToolsEvent" not in text
        assert "add_callback(hooks.BeforeToolsEvent" not in text


class TestStrandsAgentContext:
    def test_prefers_correlation_id_then_session_then_request(
        self, reset_sequence_context
    ) -> None:
        ctx = strands_agent_context(
            {
                "correlationId": "corr",
                "sessionId": "sess",
                "requestId": "req",
            }
        )
        assert ctx.correlation_id == "corr"

        ctx = strands_agent_context({"sessionId": "sess", "requestId": "req"})
        assert ctx.correlation_id == "sess"

        ctx = strands_agent_context({"requestId": "req"})
        assert ctx.correlation_id == "req"

    def test_reads_nested_invocation_state(self, reset_sequence_context) -> None:
        ctx = strands_agent_context(
            SimpleNamespace(invocation_state={"session_id": "from-state"})
        )
        assert ctx.correlation_id == "from-state"

    def test_accepts_snake_case_aliases(self, reset_sequence_context) -> None:
        ctx = strands_agent_context({"session_id": "sess", "request_id": "req"})
        assert ctx.correlation_id == "sess"

    def test_invalid_correlation_id_does_not_hide_session_id_alias(
        self, reset_sequence_context
    ) -> None:
        ctx = strands_agent_context(
            {"correlationId": "not\nvalid", "session_id": "sess-from-alias"}
        )
        assert ctx.correlation_id == "sess-from-alias"
        assert ctx.metadata is not None
        assert ctx.metadata["strands.session"] == "sess-from-alias"

    def test_invalid_session_id_is_not_recorded_in_metadata(
        self, reset_sequence_context
    ) -> None:
        ctx = strands_agent_context({"session_id": "not\nvalid"})
        assert ctx.correlation_id is None
        assert ctx.metadata is None

    def test_never_reads_trace_id(self, reset_sequence_context) -> None:
        ctx = strands_agent_context({"trace_id": "tr_minted", "traceId": "tr2"})
        assert ctx.correlation_id is None

    def test_never_reads_agent_id(self, reset_sequence_context) -> None:
        ctx = strands_agent_context({"agent_id": "agent-minted", "agentId": "a2"})
        assert ctx.correlation_id is None

    def test_never_mints_when_nothing_is_present(self, reset_sequence_context) -> None:
        ctx = strands_agent_context({})
        assert ctx.correlation_id is None
        assert isinstance(ctx, StrandsAgentContext)

    def test_falls_back_to_ambient_sequence(self, reset_sequence_context) -> None:
        with arcjet_sequence(correlation_id="from-sequence"):
            ctx = strands_agent_context({})
        assert ctx.correlation_id == "from-sequence"

    def test_skips_invalid_then_uses_next(self, reset_sequence_context) -> None:
        ctx = strands_agent_context(
            {"correlation_id": "not\nvalid", "session_id": "sess"}
        )
        assert ctx.correlation_id == "sess"

    def test_explicit_kwargs_are_last_resort(self, reset_sequence_context) -> None:
        ctx = strands_agent_context(
            {"sessionId": "from-state"},
            correlation_id="from-kw",
        )
        assert ctx.correlation_id == "from-state"
        ctx = strands_agent_context({}, session_id="from-kw")
        assert ctx.correlation_id == "from-kw"
        ctx = strands_agent_context({}, request_id="from-req")
        assert ctx.correlation_id == "from-req"

    def test_does_not_construct_a_session(self, reset_sequence_context) -> None:
        session = SimpleNamespace(
            get_session_id=lambda: (_ for _ in ()).throw(
                AssertionError("must not call get_session_id")
            )
        )
        ctx = strands_agent_context(session)
        assert ctx.correlation_id is None

    def test_does_not_read_agent_id_attribute(self, reset_sequence_context) -> None:
        class ForbiddenAgent:
            @property
            def id(self) -> str:
                raise AssertionError("must not read agent.id")

            @property
            def agent_id(self) -> str:
                raise AssertionError("must not read agent.agent_id")

        ctx = strands_agent_context(SimpleNamespace(agent=ForbiddenAgent()))
        assert ctx.correlation_id is None

    def test_records_tool_name_from_tool_use(self, reset_sequence_context) -> None:
        ctx = strands_agent_context(
            SimpleNamespace(
                invocation_state={"sessionId": "sess"},
                tool_use={"name": "echo", "input": {}},
            )
        )
        assert ctx.metadata is not None
        assert ctx.metadata["strands.session"] == "sess"
        assert ctx.metadata["strands.tool"] == "echo"


class TestDenialPayload:
    def test_rate_limit_is_retryable_and_may_include_retry_after(self) -> None:
        decision = make_deny_decision(
            reason="RATE_LIMIT",
            results=(
                RuleResultTokenBucket(
                    conclusion="DENY",
                    reset_at_unix_seconds=2_000_000_000,
                ),
            ),
        )
        payload = denial_result(decision)
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
        assert payload["retryable"] is True
        assert "retryAfterSeconds" in payload
        assert "Do not retry" not in payload["message"]

    def test_non_rate_limit_is_not_retryable(self) -> None:
        decision = make_deny_decision(reason="PROMPT_INJECTION")
        payload = denial_result(decision)
        assert payload["retryable"] is False
        assert "retryAfterSeconds" not in payload
        assert "Do not retry" in payload["message"]

    def test_unavailable_is_retryable_with_fixed_backoff(self) -> None:
        payload = unavailable_result()
        assert payload == {
            "arcjetDenied": True,
            "reason": "ERROR",
            "message": "Arcjet security check could not be completed; please retry later.",
            "retryable": True,
            "retryAfterSeconds": UNAVAILABLE_RETRY_AFTER_SECONDS,
        }

    def test_dumps_is_json_the_model_can_read(self) -> None:
        raw = dumps_denial(unavailable_result())
        parsed = json.loads(raw)
        assert parsed["arcjetDenied"] is True

    def test_cancel_tool_value_is_the_json_envelope(self) -> None:
        raw = cancel_tool_value(unavailable_result())
        assert json.loads(raw)["arcjetDenied"] is True

    def test_retry_after_ignores_allow_results_with_reset_at(self) -> None:
        decision = make_deny_decision(
            reason="RATE_LIMIT",
            results=(
                RuleResultTokenBucket(
                    conclusion="ALLOW",
                    reset_at_unix_seconds=9_999_999_999,
                ),
                RuleResultTokenBucket(
                    conclusion="DENY",
                    reset_at_unix_seconds=2_000_000_000,
                ),
            ),
        )
        retry_after = retry_after_seconds(decision)
        assert retry_after is not None
        payload = denial_result(decision)
        assert payload.get("retryAfterSeconds") == retry_after


class TestEvaluateHandler:
    """arcjet-py has no pytest-asyncio; drive coroutines with ``asyncio.run``."""

    def test_deny_returns_plain_payload_not_a_throw(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_handler({"value": "hello"}, _tool_config(guard=client))
        )
        assert verdict.deny is True
        payload = handler_denial_result(verdict)
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
        assert "status" not in payload
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_allow_does_not_deny(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(
            evaluate_handler({"value": "hello"}, _tool_config(guard=client))
        )
        assert verdict.deny is False
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_unavailable_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(evaluate_handler({}, _tool_config(guard=client)))
        assert verdict.deny is True
        payload = handler_denial_result(verdict)
        assert payload["reason"] == "ERROR"
        assert payload["retryable"] is True
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_unavailable_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_handler({}, _tool_config(guard=client, on_guard_error="allow"))
        )
        assert verdict.deny is False

    def test_failed_open_fail_closed(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        assert decision.has_failed_open()
        client = StubGuardClient(decision=decision)
        verdict = asyncio.run(evaluate_handler({}, _tool_config(guard=client)))
        assert verdict.deny is True
        assert handler_denial_result(verdict)["reason"] == "ERROR"

    def test_policy_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> PolicyInputMap:
            raise RuntimeError("resolver exploded")

        verdict = asyncio.run(
            evaluate_handler({}, _tool_config(guard=client, inputs=boom))
        )
        assert verdict.deny is True
        assert len(client.guards) == 1

    def test_rules_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> list[Any]:
            raise RuntimeError("no rules")

        verdict = asyncio.run(
            evaluate_handler({}, _tool_config(guard=client, rules=boom))
        )
        assert verdict.deny is True
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_uses_policy_correlation_id_never_mints(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        asyncio.run(
            evaluate_handler({}, _tool_config(guard=client, correlation_id="run-9"))
        )
        assert client.guards[0]["correlation_id"] == "run-9"

    def test_never_mints_without_a_caller_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(evaluate_handler({}, _tool_config(guard=client)))
        assert client.guards[0]["correlation_id"] is None

    def test_tool_arguments_are_not_correlation_ids(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_handler(
                {
                    "session_id": "model-controlled",
                    "correlationId": "also-model",
                    "requestId": "req-model",
                },
                _tool_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] is None

    def test_invocation_state_is_the_correlation_source(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_handler(
                {"session_id": "model-controlled"},
                _tool_config(guard=client),
                invocation_state={"sessionId": "from-invoke"},
                tool_use={"name": "echo", "input": {"session_id": "model-controlled"}},
            )
        )
        assert client.guards[0]["correlation_id"] == "from-invoke"
        assert client.guards[0]["metadata"]["strands.session"] == "from-invoke"
        assert client.guards[0]["metadata"]["strands.tool"] == "echo"

    def test_resolver_sees_handler_arguments(self, reset_sequence_context) -> None:
        seen: list[Mapping[str, Any]] = []

        def actor(arguments: Mapping[str, Any]) -> str:
            seen.append(dict(arguments))
            return str(arguments["user_id"])

        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(
            evaluate_handler(
                {"user_id": "u_1", "body": "hello"},
                _tool_config(guard=client, actor=actor),
            )
        )
        assert verdict.deny is False
        assert seen == [{"user_id": "u_1", "body": "hello"}]
        assert client.guards[0]["actor"] == "u_1"


class TestWrapStream:
    def test_deny_yields_error_status_json_and_skips_original(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        ran: list[str] = []

        async def original(
            tool_use: Any, invocation_state: Any = None, **_kw: Any
        ) -> Any:
            ran.append("ran")
            yield {"status": "success", "content": [{"text": "hello"}]}

        wrapped = _wrap_stream(
            _tool_config(guard=client), tool=object(), original=original
        )
        tool_use = {"name": "echo", "input": {"value": "hello"}, "toolUseId": "tu_1"}

        async def collect() -> list[Any]:
            return [item async for item in wrapped(tool_use, {"sessionId": "sess"})]

        events = asyncio.run(collect())
        assert ran == []
        result = events[0]
        assert result["status"] == "error"
        assert result["toolUseId"] == "tu_1"
        payload = json.loads(result["content"][0]["text"])
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
        assert client.guards[0]["correlation_id"] == "sess"

    def test_allow_runs_original(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        ran: list[str] = []

        async def original(
            tool_use: Any, invocation_state: Any = None, **_kw: Any
        ) -> Any:
            ran.append(str(tool_use["input"]["value"]))
            yield {"status": "success", "content": [{"text": "hello"}]}

        wrapped = _wrap_stream(
            _tool_config(guard=client), tool=object(), original=original
        )

        async def collect() -> list[Any]:
            return [
                item
                async for item in wrapped(
                    {"name": "echo", "input": {"value": "hello"}, "toolUseId": "tu_1"}
                )
            ]

        assert asyncio.run(collect())[0]["status"] == "success"
        assert ran == ["hello"]

    def test_deny_uses_tool_wrap_tool_result_when_present(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())

        class _Tool:
            def _wrap_tool_result(self, tool_use_id: str, result: Any) -> Any:
                return {"wrapped": True, "id": tool_use_id, "result": result}

        wrapped = _wrap_stream(_tool_config(guard=client), tool=_Tool(), original=None)

        async def collect() -> list[Any]:
            return [
                item
                async for item in wrapped(
                    {"name": "echo", "input": {}, "toolUseId": "tu_9"}
                )
            ]

        event = asyncio.run(collect())[0]
        assert event["wrapped"] is True
        assert event["id"] == "tu_9"
        assert event["result"]["status"] == "error"
        json.loads(event["result"]["content"][0]["text"])

    def test_denial_tool_result_is_status_content_json(self) -> None:
        result = denial_tool_result(
            handler_denial_result(HandlerVerdict(deny=True, payload=None))
        )
        assert result["status"] == "error"
        assert json.loads(result["content"][0]["text"])["reason"] == "ERROR"


class TestArgumentsFromHandler:
    def test_accepts_a_mapping(self) -> None:
        assert _arguments_from_handler({"value": "x"}) == {"value": "x"}

    def test_non_mapping_is_empty_not_an_exception(self) -> None:
        assert _arguments_from_handler("{not-json") == {}
        assert _arguments_from_handler(None) == {}


class TestEvaluateBeforeToolCall:
    def test_deny_sets_cancel_tool_to_json_string(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        event = _event()
        verdict = asyncio.run(
            evaluate_before_tool_call(event, _hook_config(guard=client))
        )
        assert verdict.cancel is True
        assert verdict.message is not None
        payload = json.loads(verdict.message)
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
        apply_cancel_tool(event, verdict)
        assert event.cancel_tool == verdict.message
        assert event.cancel_tool is not True
        assert client.captures[0]["metadata"]["outcome"] == "denied"
        assert client.captures[0]["metadata"]["strands.phase"] == "before"

    def test_allow_does_not_cancel(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        event = _event()
        verdict = asyncio.run(
            evaluate_before_tool_call(event, _hook_config(guard=client))
        )
        assert verdict.cancel is False
        apply_cancel_tool(event, verdict)
        assert event.cancel_tool is False

    def test_unavailable_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_before_tool_call(_event(), _hook_config(guard=client))
        )
        assert verdict.cancel is True
        assert json.loads(verdict.message or "")["reason"] == "ERROR"

    def test_unavailable_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_before_tool_call(
                _event(), _hook_config(guard=client, on_guard_error="allow")
            )
        )
        assert verdict.cancel is False

    def test_wrapped_tool_is_excluded_from_hook_path(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        branded = SimpleNamespace(tool_name="echo")
        object.__setattr__(branded, _GUARD_BRAND, True)
        verdict = asyncio.run(
            evaluate_before_tool_call(
                _event(selected_tool=branded), _hook_config(guard=client)
            )
        )
        assert verdict.cancel is False
        assert client.guards == []

    def test_unbranded_tool_is_still_gated(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_before_tool_call(_event(), _hook_config(guard=client))
        )
        assert verdict.cancel is True
        assert len(client.guards) == 1

    def test_rules_see_tool_name_and_input(self, reset_sequence_context) -> None:
        seen: list[Mapping[str, Any]] = []

        def rules(arguments: Mapping[str, Any]) -> list[Any]:
            seen.append(dict(arguments))
            return []

        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_before_tool_call(_event(), _hook_config(guard=client, rules=rules))
        )
        assert seen == [{"value": "hello", "tool_name": "echo"}]

    def test_correlation_from_invocation_state(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        asyncio.run(
            evaluate_before_tool_call(
                _event(invocation_state={"correlationId": "corr-9"}),
                _hook_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] == "corr-9"

    def test_never_mints_without_a_caller_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(evaluate_before_tool_call(_event(), _hook_config(guard=client)))
        assert client.guards[0]["correlation_id"] is None

    def test_never_reads_trace_id_from_invocation_state(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_before_tool_call(
                _event(invocation_state={"trace_id": "tr_minted"}),
                _hook_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] is None

    def test_default_action_is_tool_name_invoked(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(evaluate_before_tool_call(_event(), _hook_config(guard=client)))
        assert client.guards[0]["label"] == "echo.invoked"


class TestCaptureAfterToolCall:
    def test_is_capture_only_and_does_not_re_evaluate(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        branded = SimpleNamespace(tool_name="echo")
        object.__setattr__(branded, _GUARD_BRAND, True)
        capture_after_tool_call(
            _event(selected_tool=branded), _hook_config(guard=client)
        )
        assert client.guards == []
        assert len(client.captures) == 1
        assert client.captures[0]["metadata"]["strands.phase"] == "after"
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_cancel_message_is_denied_not_success(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        capture_after_tool_call(
            _event(cancel_message=dumps_denial(denial_result(make_deny_decision()))),
            _hook_config(guard=client),
        )
        assert client.guards == []
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_error_cancel_message_is_unavailable(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        capture_after_tool_call(
            _event(cancel_message=dumps_denial(unavailable_result())),
            _hook_config(guard=client),
        )
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_exception_is_error(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        capture_after_tool_call(
            _event(exception=RuntimeError("tool crashed")),
            _hook_config(guard=client),
        )
        assert client.captures[0]["metadata"]["outcome"] == "error"

    def test_never_raises(self, reset_sequence_context) -> None:
        def boom(_arguments: Mapping[str, Any]) -> dict[str, str]:
            raise RuntimeError("metadata exploded")

        capture_after_tool_call(_event(), _hook_config(metadata=boom))


class TestAfterOutcome:
    def test_success_when_tool_ran(self) -> None:
        assert _after_outcome(_event()) == "success"

    def test_plain_cancel_string_is_denied(self) -> None:
        assert _after_outcome(_event(cancel_message="cancelled")) == "denied"


class TestApplyCancelTool:
    def test_true_or_str_skips_the_handler(self) -> None:
        event = _event()
        apply_cancel_tool(event, BeforeToolCallVerdict(cancel=True, message="no"))
        assert event.cancel_tool == "no"
        event = _event()
        apply_cancel_tool(event, BeforeToolCallVerdict(cancel=True))
        assert event.cancel_tool is True
        event = _event()
        apply_cancel_tool(event, BeforeToolCallVerdict(cancel=False))
        assert event.cancel_tool is False


class TestGuardToolValidation:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_tool(
                guard=StubGuardClient(),
                tool=object(),
                action="x.done",
                on_guard_error="maybe",  # type: ignore[arg-type]
            )

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            guard_tool(
                guard=StubGuardClient(),
                tool=object(),
                action="x.done",
                correlation_id="not\nvalid",
            )


class TestGuardHooksValidation:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_hooks(guard=StubGuardClient(), on_guard_error="maybe")  # type: ignore[arg-type]

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            guard_hooks(guard=StubGuardClient(), correlation_id="not\nvalid")


class TestMissingPeer:
    def test_guard_tool_names_what_to_install(self) -> None:
        if strands_agents_present():
            pytest.skip("strands-agents is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[strands-agents\]"):
            guard_tool(guard=StubGuardClient(), tool=object(), action="x.done")

    def test_guard_hooks_names_what_to_install(self) -> None:
        if strands_agents_present():
            pytest.skip("strands-agents is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[strands-agents\]"):
            guard_hooks(guard=StubGuardClient())

    def test_load_decorated_function_tool_names_what_to_install(self) -> None:
        if strands_agents_present():
            pytest.skip("strands-agents is installed in this environment")
        with pytest.raises(ImportError, match="needs Strands Agents"):
            load_decorated_function_tool()


class TestVersionFloor:
    def test_release_parsing(self) -> None:
        assert _release("1.11.0") == (1, 11, 0)
        assert _release("1.54.0") == (1, 54, 0)
        assert _release("1.54.0rc1") == (1, 54, 0)
        assert _release("2.0.0") == (2, 0, 0)
        assert _release("weird") == ()
        assert _release("1.11") == (1, 11)
        assert _release("1.11.post1") == (1, 11)
        assert _release("1.10.0") < import_module.MINIMUM_STRANDS_AGENTS
        assert _release("1.11.0") >= import_module.MINIMUM_STRANDS_AGENTS

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "1.10.0")
        with pytest.raises(
            ArcjetMisconfiguration, match="needs strands-agents >= 1.11.0"
        ):
            import_module._require_strands_agents()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("1.11.0", "1.54.0", "1.54.0rc1"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_strands_agents()

    def test_absent_peer_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_strands_agents()


class TestFailClosedHelperVsFailOpenProtect:
    def test_helper_denies_the_same_failed_open_protect_would_allow(
        self, reset_sequence_context
    ) -> None:
        """``protect()`` / core ``guard()`` fail open; these helpers do not."""
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        assert decision.conclusion == "ALLOW"
        assert decision.has_failed_open()
        client = StubGuardClient(decision=decision)
        verdict = asyncio.run(evaluate_handler({}, _tool_config(guard=client)))
        assert verdict.deny is True
        assert handler_denial_result(verdict)["reason"] == "ERROR"


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import strands_agents as adapter

    assert adapter.__all__ == ["guard_tool", "guard_hooks", "strands_agent_context"]
    assert not hasattr(adapter, "guard_inbound")
    assert not hasattr(adapter, "guard_approval")


def test_brand_constant_is_stable() -> None:
    assert _GUARD_BRAND == "_arcjet_guarded"


def test_brand_slots_without_the_attribute_fail_loudly() -> None:
    class Slotted:
        __slots__ = ()

    with pytest.raises(TypeError, match=_GUARD_BRAND):
        _brand(Slotted())


def test_extra_does_not_pull_chromadb() -> None:
    text = (Path(__file__).resolve().parents[3] / "pyproject.toml").read_text()
    assert 'strands-agents = ["strands-agents>=1.11.0,<2"]' in text
    assert "chromadb" not in text.split("strands-agents = ")[1].split("\n", 1)[0]

"""Google ADK adapter unit tests that must run with google-adk absent.

The extra is optional. These tests import ``arcjet.guard.google_adk``
helpers that do not load the peer.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
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
from arcjet.guard import arcjet_sequence, server_input
from arcjet.guard._policy_input import PolicyInputMap
from arcjet.guard._types import RuleResultError, RuleResultTokenBucket
from arcjet.guard.google_adk import _import as import_module
from arcjet.guard.google_adk import _plugin as plugin_module
from arcjet.guard.google_adk import (
    google_adk_context,
    guard_plugin,
    guard_tool,
)
from arcjet.guard.google_adk._callback import (
    BeforeToolVerdict,
    CallbackConfig,
    callback_result,
    default_action,
    evaluate_before_tool,
    tool_call,
)
from arcjet.guard.google_adk._context import GoogleAdkContext
from arcjet.guard.google_adk._denial import (
    UNAVAILABLE_RETRY_AFTER_SECONDS,
    denial_result,
    payload_from_block,
    retry_after_seconds,
    skip_dict,
    unavailable_result,
)
from arcjet.guard.google_adk._import import (
    _comparable_release,
    _release,
    google_adk_present,
    load_base_plugin,
)
from arcjet.guard.google_adk._plugin import _PLUGIN_NAME

GOOGLE_ADK_SRC = (
    Path(__file__).resolve().parents[3] / "src" / "arcjet" / "guard" / "google_adk"
)


def _tool(name: str = "echo") -> SimpleNamespace:
    return SimpleNamespace(name=name)


def _config(**kwargs: Any) -> CallbackConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": "echo.invoked",
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "on_guard_error": "deny",
        "exclude": frozenset(),
    }
    defaults.update(kwargs)
    return CallbackConfig(**defaults)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


class TestSourceIsolation:
    def test_package_does_not_import_sibling_adapters(self) -> None:
        for path in GOOGLE_ADK_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "langchain" not in node.module
                    assert "crewai" not in node.module
                    assert "openai_agents" not in node.module
                    assert "claude_agent_sdk" not in node.module
                    assert "claude_managed_agents" not in node.module
                    assert "strands_agents" not in node.module
                    assert node.module != "arcjet.guard.langchain"
                    assert node.module != "arcjet.guard.crewai"
                    assert node.module != "arcjet.guard.openai_agents"
                    assert node.module != "arcjet.guard.claude_agent_sdk"
                    assert node.module != "arcjet.guard.claude_managed_agents"
                    assert node.module != "arcjet.guard.strands_agents"
                    assert node.module != "google.adk"
                    assert not node.module.startswith("google.adk.")
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "langchain" not in alias.name
                        assert "crewai" not in alias.name
                        assert "openai_agents" not in alias.name
                        assert "claude_agent_sdk" not in alias.name
                        assert "claude_managed_agents" not in alias.name
                        assert "strands_agents" not in alias.name
                        assert alias.name != "google.adk"
                        assert not alias.name.startswith("google.adk.")

    def test_core_guard_imports_with_peer_unimportable(self) -> None:
        """The real invariant, in a process where ``google.adk`` cannot import."""
        program = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "google.adk" or name.startswith("google.adk."):
            raise ImportError("google.adk is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())

import arcjet.guard
assert callable(arcjet.guard.guard)
assert "google.adk" not in sys.modules

import arcjet.guard.google_adk as adapter
assert callable(adapter.guard_tool)
assert callable(adapter.guard_plugin)
assert callable(adapter.google_adk_context)
assert adapter.__all__ == ["guard_tool", "guard_plugin", "google_adk_context"]
assert not hasattr(adapter, "guard_inbound")
assert not hasattr(adapter, "guard_approval")
callback = adapter.guard_tool(guard=object(), action="echo.invoked")
assert callable(callback)
try:
    adapter.guard_plugin(guard=object())
except ImportError as exc:
    assert "arcjet[google-adk]" in str(exc), exc
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


class TestGoogleAdkContext:
    def test_prefers_correlation_id_then_session_then_conversation(
        self, reset_sequence_context
    ) -> None:
        ctx = google_adk_context(
            {
                "correlationId": "corr",
                "sessionId": "sess",
                "conversationId": "conv",
            }
        )
        assert ctx.correlation_id == "corr"

        ctx = google_adk_context({"sessionId": "sess", "conversationId": "conv"})
        assert ctx.correlation_id == "sess"

        ctx = google_adk_context({"conversationId": "conv"})
        assert ctx.correlation_id == "conv"

    def test_reads_application_owned_state(self, reset_sequence_context) -> None:
        ctx = google_adk_context(SimpleNamespace(state={"session_id": "from-state"}))
        assert ctx.correlation_id == "from-state"

    def test_accepts_snake_case_aliases(self, reset_sequence_context) -> None:
        ctx = google_adk_context({"session_id": "sess", "conversation_id": "conv"})
        assert ctx.correlation_id == "sess"

    def test_invalid_correlation_id_does_not_hide_session_id_alias(
        self, reset_sequence_context
    ) -> None:
        ctx = google_adk_context(
            {"correlationId": "not\nvalid", "session_id": "sess-from-alias"}
        )
        assert ctx.correlation_id == "sess-from-alias"
        assert ctx.metadata is not None
        assert ctx.metadata["google-adk.session"] == "sess-from-alias"

    def test_invalid_session_id_is_not_recorded_in_metadata(
        self, reset_sequence_context
    ) -> None:
        ctx = google_adk_context({"session_id": "not\nvalid"})
        assert ctx.correlation_id is None
        assert ctx.metadata is None

    def test_all_rejected_ids_are_named_in_the_warning(
        self, reset_sequence_context, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            ctx = google_adk_context(
                {"correlationId": "not\nvalid", "sessionId": "also\nbad"}
            )
        assert ctx.correlation_id is None
        assert "correlationId" in caplog.text
        assert "sessionId" in caplog.text

    def test_never_reads_trace_id(self, reset_sequence_context) -> None:
        ctx = google_adk_context({"trace_id": "tr_minted", "traceId": "tr2"})
        assert ctx.correlation_id is None

    def test_never_reads_invocation_id(self, reset_sequence_context) -> None:
        ctx = google_adk_context(
            {"invocation_id": "inv-minted", "invocationId": "inv2"}
        )
        assert ctx.correlation_id is None

    def test_never_reads_tool_context_session_id(self, reset_sequence_context) -> None:
        session = SimpleNamespace(id="adk-generated-session")
        tool_context = SimpleNamespace(
            session=session,
            session_id="adk-generated-session",
            sessionId="adk-generated-session",
            invocation_id="inv-minted",
        )
        ctx = google_adk_context(tool_context)
        assert ctx.correlation_id is None
        assert ctx.metadata is None

    def test_never_walks_into_session_id(self, reset_sequence_context) -> None:
        session = SimpleNamespace(id="adk-generated-session")
        ctx = google_adk_context(SimpleNamespace(session=session))
        assert ctx.correlation_id is None

    def test_never_mints_when_nothing_is_present(self, reset_sequence_context) -> None:
        ctx = google_adk_context({})
        assert ctx.correlation_id is None
        assert isinstance(ctx, GoogleAdkContext)

    def test_falls_back_to_ambient_sequence(self, reset_sequence_context) -> None:
        with arcjet_sequence(correlation_id="from-sequence"):
            ctx = google_adk_context({})
        assert ctx.correlation_id == "from-sequence"

    def test_explicit_kwargs_are_last_resort(self, reset_sequence_context) -> None:
        ctx = google_adk_context(
            {"session_id": "from-ctx"},
            correlation_id="from-kw",
        )
        assert ctx.correlation_id == "from-ctx"
        ctx = google_adk_context({}, session_id="from-kw")
        assert ctx.correlation_id == "from-kw"

    def test_does_not_construct_a_session(self, reset_sequence_context) -> None:
        session = SimpleNamespace(
            id=property(
                lambda _self: (_ for _ in ()).throw(
                    AssertionError("must not read session.id")
                )
            )
        )
        ctx = google_adk_context(session)
        assert ctx.correlation_id is None

    def test_reads_adk_state_object(self, reset_sequence_context) -> None:
        ctx = google_adk_context(_AdkState({"sessionId": "from-adk-state"}))
        assert ctx.correlation_id == "from-adk-state"
        assert ctx.metadata is not None
        assert ctx.metadata["google-adk.session"] == "from-adk-state"

    def test_reads_adk_state_on_tool_context(self, reset_sequence_context) -> None:
        """Real ToolContext.state is ADK State, not a Mapping.

        session.id / toolContext.sessionId stay unread; the caller-owned
        id lives on state.
        """
        session = SimpleNamespace(id="adk-generated-session")
        tool_context = SimpleNamespace(
            session=session,
            session_id="adk-generated-session",
            sessionId="adk-generated-session",
            invocation_id="inv-minted",
            state=_AdkState({"sessionId": "from-state"}),
        )
        ctx = google_adk_context(tool_context)
        assert ctx.correlation_id == "from-state"
        assert ctx.metadata is not None
        assert ctx.metadata["google-adk.session"] == "from-state"


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
        assert skip_dict(payload)

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

    def test_skip_dict_is_never_empty(self) -> None:
        result = skip_dict(unavailable_result())
        assert result
        assert result["arcjetDenied"] is True

    def test_callback_result_allow_is_none_not_empty_dict(self) -> None:
        assert callback_result(BeforeToolVerdict(deny=False)) is None

    def test_callback_result_deny_is_truthy_skip_dict(self) -> None:
        result = callback_result(
            BeforeToolVerdict(deny=True, payload=unavailable_result())
        )
        assert result is not None
        assert result != {}
        assert result["arcjetDenied"] is True

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


class TestEvaluateBeforeTool:
    """arcjet-py has no pytest-asyncio; drive coroutines with ``asyncio.run``."""

    def test_allow_returns_none(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client),
            )
        )
        assert verdict.deny is False
        assert callback_result(verdict) is None
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_deny_is_skip_dict_not_an_exception(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client),
            )
        )
        assert verdict.deny is True
        result = callback_result(verdict)
        assert result is not None
        assert result["arcjetDenied"] is True
        assert result["reason"] == "RATE_LIMIT"
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_unavailable_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client),
            )
        )
        assert verdict.deny is True
        result = callback_result(verdict)
        assert result is not None
        assert result["reason"] == "ERROR"
        assert result["retryable"] is True
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_unavailable_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client, on_guard_error="allow"),
            )
        )
        assert verdict.deny is False
        assert callback_result(verdict) is None

    def test_failed_open_fail_closed(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client),
            )
        )
        assert verdict.deny is True
        result = callback_result(verdict)
        assert result is not None
        assert result["reason"] == "ERROR"

    def test_actor_and_inputs_are_forwarded(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        inputs = {"recipient": server_input.string("a@example.com")}
        _run(
            evaluate_before_tool(
                tool=_tool("send_email"),
                args={"to": "a@example.com"},
                tool_context={},
                config=_config(guard=client, actor="user-1", inputs=inputs),
            )
        )
        assert client.guards[0]["actor"] == "user-1"
        assert client.guards[0]["inputs"] == inputs

    def test_omitted_actor_and_inputs_are_none(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client),
            )
        )
        assert client.guards[0]["actor"] is None
        assert client.guards[0]["inputs"] is None

    def test_resolver_sees_tool_name_and_args(self, reset_sequence_context) -> None:
        seen: list[Mapping[str, Any]] = []

        def actor(arguments: Mapping[str, Any]) -> str:
            seen.append(dict(arguments))
            return "user-1"

        client = StubGuardClient(decision=make_allow_decision())
        _run(
            evaluate_before_tool(
                tool=_tool("send_email"),
                args={"to": "a@example.com", "body": "hello"},
                tool_context={},
                config=_config(guard=client, actor=actor),
            )
        )
        assert seen == [
            {"to": "a@example.com", "body": "hello", "tool_name": "send_email"}
        ]
        assert client.guards[0]["actor"] == "user-1"

    def test_resolver_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> PolicyInputMap:
            raise RuntimeError("resolver exploded")

        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client, inputs=boom),
            )
        )
        assert verdict.deny is True
        assert len(client.guards) == 1
        result = callback_result(verdict)
        assert result is not None
        assert result["arcjetDenied"] is True

    def test_actor_resolver_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> str:
            raise RuntimeError("no actor")

        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client, actor=boom),
            )
        )
        assert verdict.deny is True
        assert len(client.guards) == 1

    def test_rules_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> list[Any]:
            raise RuntimeError("no rules")

        verdict = _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={},
                config=_config(guard=client, rules=boom),
            )
        )
        assert verdict.deny is True
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_correlation_from_state_never_mints(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context=SimpleNamespace(state={"session_id": "sess-9"}),
                config=_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] == "sess-9"

    def test_never_reads_session_id_from_tool_context(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        session = SimpleNamespace(id="adk-generated-session")
        _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context=SimpleNamespace(
                    session=session,
                    session_id="adk-generated-session",
                    invocation_id="inv-minted",
                ),
                config=_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] is None

    def test_correlation_from_adk_state_object(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        session = SimpleNamespace(id="adk-generated-session")
        _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context=SimpleNamespace(
                    session=session,
                    session_id="adk-generated-session",
                    invocation_id="inv-minted",
                    state=_AdkState({"sessionId": "sess-from-state"}),
                ),
                config=_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] == "sess-from-state"

    def test_never_reads_trace_id_from_context(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        _run(
            evaluate_before_tool(
                tool=_tool(),
                args={"value": "hello"},
                tool_context={"trace_id": "tr_minted"},
                config=_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] is None

    def test_ambient_sequence_is_used_when_context_has_none(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        with arcjet_sequence(correlation_id="from-sequence"):
            _run(
                evaluate_before_tool(
                    tool=_tool(),
                    args={"value": "hello"},
                    tool_context={},
                    config=_config(guard=client),
                )
            )
        assert client.guards[0]["correlation_id"] == "from-sequence"

    def test_exclude_skips_guard(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = _run(
            evaluate_before_tool(
                tool=_tool("send_email"),
                args={"to": "a@example.com"},
                tool_context={},
                config=_config(guard=client, exclude=frozenset({"send_email"})),
            )
        )
        assert verdict.deny is False
        assert client.guards == []

    def test_default_action_uses_tool_name(self) -> None:
        assert default_action({"tool_name": "send_email"}) == "send_email.invoked"
        assert default_action({}) == "tool.invoked"

    def test_tool_name_wins_over_argument(self) -> None:
        call = tool_call(_tool("send_email"), {"tool_name": "forged"})
        assert call["tool_name"] == "send_email"


class TestGuardToolCallback:
    def test_parameter_names_match_adk_agent_callback(self) -> None:
        callback = guard_tool(guard=StubGuardClient(), action="echo.invoked")
        assert tuple(inspect.signature(callback).parameters) == (
            "tool",
            "args",
            "tool_context",
        )

    def test_allow_returns_none(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        callback = guard_tool(guard=client, action="echo.invoked")
        result = _run(callback(tool=_tool(), args={"value": "hello"}, tool_context={}))
        assert result is None

    def test_deny_returns_skip_dict(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        callback = guard_tool(guard=client, action="echo.invoked")
        result = _run(callback(tool=_tool(), args={"value": "hello"}, tool_context={}))
        assert result is not None
        assert result != {}
        assert result["arcjetDenied"] is True

    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_tool(
                guard=StubGuardClient(),
                action="x.done",
                on_guard_error="maybe",  # type: ignore[arg-type]
            )

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            guard_tool(
                guard=StubGuardClient(),
                action="x.done",
                correlation_id="not\nvalid",
            )

    def test_missing_action_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="action"):
            guard_tool(guard=StubGuardClient(), action=None)


class _AdkState:
    """ADK ``sessions.state.State`` is dict-like but not a Mapping."""

    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in self._values

    def __getitem__(self, key: str) -> Any:
        return self._values[key]


class _DummyBasePlugin:
    def __init__(self, name: str) -> None:
        self.name = name


class TestGuardPlugin:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_plugin(
                guard=StubGuardClient(),
                on_guard_error="maybe",  # type: ignore[arg-type]
            )

    def test_invalid_exclude_is_refused(self) -> None:
        with pytest.raises(TypeError, match="exclude"):
            guard_plugin(guard=StubGuardClient(), exclude=[""])

    def test_allow_and_deny_via_dummy_base(
        self, monkeypatch: pytest.MonkeyPatch, reset_sequence_context
    ) -> None:
        monkeypatch.setattr(plugin_module, "load_base_plugin", lambda: _DummyBasePlugin)
        allow_client = StubGuardClient(decision=make_allow_decision())
        plugin = guard_plugin(guard=allow_client, action="echo.invoked")
        assert plugin.name == _PLUGIN_NAME
        result = _run(
            plugin.before_tool_callback(
                tool=_tool(),
                tool_args={"value": "hello"},
                tool_context={},
            )
        )
        assert result is None

        deny_client = StubGuardClient(decision=make_deny_decision())
        plugin = guard_plugin(guard=deny_client, action="echo.invoked")
        result = _run(
            plugin.before_tool_callback(
                tool=_tool(),
                tool_args={"value": "hello"},
                tool_context={},
            )
        )
        assert result is not None
        assert result != {}
        assert result["arcjetDenied"] is True

    def test_repeated_calls_reuse_the_plugin_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(plugin_module, "load_base_plugin", lambda: _DummyBasePlugin)
        first = guard_plugin(guard=StubGuardClient(), action="echo.invoked")
        second = guard_plugin(guard=StubGuardClient(), action="echo.invoked")
        assert type(first) is type(second)
        assert first is not second

    def test_exclude_skips_named_tool(
        self, monkeypatch: pytest.MonkeyPatch, reset_sequence_context
    ) -> None:
        monkeypatch.setattr(plugin_module, "load_base_plugin", lambda: _DummyBasePlugin)
        client = StubGuardClient(decision=make_deny_decision())
        plugin = guard_plugin(
            guard=client, action="echo.invoked", exclude=["send_email"]
        )
        result = _run(
            plugin.before_tool_callback(
                tool=_tool("send_email"),
                tool_args={"to": "a@example.com"},
                tool_context={},
            )
        )
        assert result is None
        assert client.guards == []


class TestMissingPeer:
    def test_guard_plugin_names_what_to_install(self) -> None:
        if google_adk_present():
            pytest.skip("google-adk is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[google-adk\]"):
            guard_plugin(guard=StubGuardClient())

    def test_load_base_plugin_names_what_to_install(self) -> None:
        if google_adk_present():
            pytest.skip("google-adk is installed in this environment")
        with pytest.raises(ImportError, match="needs Google ADK"):
            load_base_plugin()


class TestVersionFloor:
    def test_release_parsing(self) -> None:
        assert _release("2.0.0") == (2, 0, 0)
        assert _release("2.1.0") == (2, 1, 0)
        assert _release("2.0.0rc1") == (2, 0, 0)
        assert _release("1.19.0") == (1, 19, 0)
        assert _release("2.0") == (2, 0)
        assert _release("weird") == ()
        assert _comparable_release((2, 0)) == (2, 0, 0)
        assert _comparable_release((2, 0, 0)) == (2, 0, 0)
        assert _comparable_release(()) == ()

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "1.19.0")
        with pytest.raises(ArcjetMisconfiguration, match="needs google-adk >= 2.0.0"):
            import_module._require_google_adk()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("2.0.0", "2.1.0", "2.0.1", "2.0"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_google_adk()

    def test_absent_peer_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_google_adk()


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import google_adk as adapter

    assert adapter.__all__ == ["guard_tool", "guard_plugin", "google_adk_context"]


def test_nothing_outside_google_adk_imports_the_peer() -> None:
    src = Path(__file__).resolve().parents[3] / "src" / "arcjet"
    for path in src.rglob("*.py"):
        if "guard/google_adk" in path.as_posix():
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module != "google.adk"
                assert not node.module.startswith("google.adk.")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "google.adk"
                    assert not alias.name.startswith("google.adk.")


def test_payload_from_block_without_decision_is_unavailable() -> None:
    payload = payload_from_block(None)
    assert payload["reason"] == "ERROR"
    assert payload["arcjetDenied"] is True

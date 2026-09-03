"""Claude Managed Agents adapter unit tests that must run with anthropic absent.

The extra is optional. These tests import ``arcjet.guard.claude_managed_agents``
helpers that do not load the peer. This is not the Claude Agent SDK extra.
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
from arcjet.guard._errors import ArcjetDeniedError, ArcjetUnavailableError
from arcjet.guard._types import RuleResultError, RuleResultTokenBucket
from arcjet.guard.claude_managed_agents import _denial as denial_module
from arcjet.guard.claude_managed_agents import _import as import_module
from arcjet.guard.claude_managed_agents import _tool as tool_module
from arcjet.guard.claude_managed_agents import (
    claude_managed_agents_context,
    guard_custom_tool,
    guard_events,
)
from arcjet.guard.claude_managed_agents._common import (
    _GUARD_BRAND,
    PHASE_METADATA_KEY,
    TOOL_METADATA_KEY,
)
from arcjet.guard.claude_managed_agents._context import (
    SESSION_METADATA_KEY,
    ClaudeManagedAgentsContext,
)
from arcjet.guard.claude_managed_agents._denial import (
    UNAVAILABLE_RETRY_AFTER_SECONDS,
    WorkerToolDenied,
    custom_tool_result_event,
    denial_result,
    dumps_denial,
    payload_from_block,
    raise_worker_denial,
    retry_after_seconds,
    unavailable_result,
)
from arcjet.guard.claude_managed_agents._events import (
    _EventsConfig,
    evaluate_user_message,
    inbound_events,
    message_arguments,
)
from arcjet.guard.claude_managed_agents._import import (
    _release,
    anthropic_present,
    load_anthropic,
)
from arcjet.guard.claude_managed_agents._tool import (
    _arguments_from_event,
    _invoke_run,
    _ToolConfig,
    denial_event,
    evaluate_custom_tool,
)

MANAGED_SRC = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "arcjet"
    / "guard"
    / "claude_managed_agents"
)


def _events_config(**kwargs: Any) -> _EventsConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": "message.received",
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "session_id": None,
        "on_guard_error": "deny",
    }
    defaults.update(kwargs)
    return _EventsConfig(**defaults)


def _tool_config(**kwargs: Any) -> _ToolConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": "email.sent",
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "session_id": None,
        "on_guard_error": "deny",
        "tool_name": "send_email",
    }
    defaults.update(kwargs)
    return _ToolConfig(**defaults)


def _user_message(text: str = "hello") -> dict[str, Any]:
    return {
        "type": "user.message",
        "content": [{"type": "text", "text": text}],
    }


def _custom_tool_use(
    *,
    event_id: str = "sevt_tool_1",
    name: str = "send_email",
    input_data: Mapping[str, Any] | None = None,
    session_thread_id: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "type": "agent.custom_tool_use",
        "id": event_id,
        "name": name,
        "input": dict(input_data or {"to": "a@example.com", "body": "hi"}),
    }
    if session_thread_id is not None:
        event["session_thread_id"] = session_thread_id
    return event


class RecordingSend:
    """Stand-in for ``client.beta.sessions.events.send``."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, dict[str, Any]]] = []

    def __call__(self, session_id: Any, *, events: Any = None, **kwargs: Any) -> str:
        self.calls.append((session_id, {"events": events, **kwargs}))
        return "sent"


class AsyncRecordingSend:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, dict[str, Any]]] = []

    async def __call__(
        self, session_id: Any, *, events: Any = None, **kwargs: Any
    ) -> str:
        self.calls.append((session_id, {"events": events, **kwargs}))
        return "sent"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _worker_denial_type() -> type[BaseException]:
    return import_module.load_tool_error() or WorkerToolDenied


def _denial_content(exc: BaseException) -> str:
    content = getattr(exc, "content", None)
    if isinstance(content, str):
        return content
    return str(exc)


class TestSourceIsolation:
    def test_package_does_not_import_sibling_adapters(self) -> None:
        for path in MANAGED_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "langchain" not in node.module
                    assert "crewai" not in node.module
                    assert "openai_agents" not in node.module
                    assert "claude_agent_sdk" not in node.module
                    assert "google_adk" not in node.module
                    assert node.module != "arcjet.guard.langchain"
                    assert node.module != "arcjet.guard.crewai"
                    assert node.module != "arcjet.guard.openai_agents"
                    assert node.module != "arcjet.guard.claude_agent_sdk"
                    assert node.module != "arcjet.guard.google_adk"
                    assert node.module != "claude_agent_sdk"
                    assert not node.module.startswith("claude_agent_sdk.")
                    assert node.module != "anthropic"
                    assert not node.module.startswith("anthropic.")
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "langchain" not in alias.name
                        assert "crewai" not in alias.name
                        assert "openai_agents" not in alias.name
                        assert "claude_agent_sdk" not in alias.name
                        assert "google_adk" not in alias.name
                        assert alias.name != "claude_agent_sdk"
                        assert alias.name != "anthropic"
                        assert not alias.name.startswith("anthropic.")

    def test_core_guard_imports_with_peer_unimportable(self) -> None:
        program = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        blocked = (
            "anthropic",
            "claude_agent_sdk",
        )
        if name in blocked or name.startswith("anthropic.") or name.startswith("claude_agent_sdk."):
            raise ImportError(name + " is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())

import arcjet.guard
assert callable(arcjet.guard.guard)
assert "anthropic" not in sys.modules
assert "claude_agent_sdk" not in sys.modules

import arcjet.guard.claude_managed_agents as adapter
assert callable(adapter.guard_custom_tool)
assert callable(adapter.guard_events)
assert callable(adapter.claude_managed_agents_context)
assert adapter.__all__ == [
    "guard_custom_tool",
    "guard_events",
    "claude_managed_agents_context",
]
assert not hasattr(adapter, "guard_tool")
assert not hasattr(adapter, "guard_hooks")
assert not hasattr(adapter, "guard_inbound")
print("ok")
"""
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"


class TestClaudeManagedAgentsContext:
    def test_prefers_correlation_id_then_session_id(
        self, reset_sequence_context
    ) -> None:
        ctx = claude_managed_agents_context(
            {"correlation_id": "corr", "session_id": "sess"}
        )
        assert ctx.correlation_id == "corr"

        ctx = claude_managed_agents_context({"session_id": "sess"})
        assert ctx.correlation_id == "sess"

    def test_accepts_camel_case_aliases(self, reset_sequence_context) -> None:
        ctx = claude_managed_agents_context({"sessionId": "sess"})
        assert ctx.correlation_id == "sess"

    def test_never_reads_anthropic_session_or_event_id(
        self, reset_sequence_context
    ) -> None:
        ctx = claude_managed_agents_context(
            {"id": "ses_anthropic", "event_id": "sevt_1", "eventId": "sevt_2"}
        )
        assert ctx.correlation_id is None
        assert ctx.metadata is None

    def test_never_reads_id_off_an_anthropic_shaped_object(
        self, reset_sequence_context
    ) -> None:
        session = SimpleNamespace(id="ses_01XYZ", status="idle")
        ctx = claude_managed_agents_context(session)
        assert ctx.correlation_id is None

    def test_never_reads_trace_id(self, reset_sequence_context) -> None:
        ctx = claude_managed_agents_context({"trace_id": "tr_minted", "traceId": "tr2"})
        assert ctx.correlation_id is None

    def test_never_mints_when_nothing_is_present(self, reset_sequence_context) -> None:
        ctx = claude_managed_agents_context({})
        assert ctx.correlation_id is None
        assert isinstance(ctx, ClaudeManagedAgentsContext)

    def test_falls_back_to_ambient_sequence(self, reset_sequence_context) -> None:
        with arcjet_sequence(correlation_id="from-sequence"):
            ctx = claude_managed_agents_context({})
        assert ctx.correlation_id == "from-sequence"

    def test_skips_invalid_then_uses_next(self, reset_sequence_context) -> None:
        ctx = claude_managed_agents_context(
            {"correlation_id": "not\nvalid", "session_id": "sess"}
        )
        assert ctx.correlation_id == "sess"

    def test_explicit_kwargs_are_last_resort(self, reset_sequence_context) -> None:
        ctx = claude_managed_agents_context(
            {"session_id": "from-ctx"},
            correlation_id="from-kw",
        )
        assert ctx.correlation_id == "from-ctx"
        ctx = claude_managed_agents_context({}, session_id="from-kw")
        assert ctx.correlation_id == "from-kw"

    def test_caller_session_is_metadata_not_an_anthropic_id(
        self, reset_sequence_context
    ) -> None:
        ctx = claude_managed_agents_context({"session_id": "app-owned"})
        assert ctx.metadata is not None
        assert ctx.metadata["claude-managed-agents.session"] == "app-owned"


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

    def test_unavailable_is_retryable_with_fixed_backoff(self) -> None:
        payload = unavailable_result()
        assert payload == {
            "arcjetDenied": True,
            "reason": "ERROR",
            "message": "Arcjet security check could not be completed; please retry later.",
            "retryable": True,
            "retryAfterSeconds": UNAVAILABLE_RETRY_AFTER_SECONDS,
        }

    def test_custom_tool_result_uses_real_events_schema(self) -> None:
        event = custom_tool_result_event(
            custom_tool_use_id="sevt_abc",
            payload=unavailable_result(),
            session_thread_id="thr_1",
        )
        assert event["type"] == "user.custom_tool_result"
        assert event["custom_tool_use_id"] == "sevt_abc"
        assert event["is_error"] is True
        assert event["session_thread_id"] == "thr_1"
        assert event["content"][0]["type"] == "text"
        parsed = json.loads(event["content"][0]["text"])
        assert parsed["arcjetDenied"] is True

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
        assert retry_after_seconds(decision) is not None
        payload = denial_result(decision)
        assert "retryAfterSeconds" in payload


class TestInboundGate:
    def test_user_message_is_selected_from_events_and_initial_events(self) -> None:
        events = [
            {"type": "user.interrupt"},
            _user_message("one"),
            {"type": "user.custom_tool_result", "custom_tool_use_id": "x"},
        ]
        initial = [_user_message("two")]
        found = inbound_events(events, initial)
        assert [message_arguments(e)["prompt"] for e in found] == ["one", "two"]

    def test_deny_does_not_call_send(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        with pytest.raises(ArcjetDeniedError):
            _run(wrapped("ses_anthropic", events=[_user_message("inject")]))
        assert send.calls == []
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_allow_calls_send(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        result = _run(wrapped("ses_anthropic", events=[_user_message("hello")]))
        assert result == "sent"
        assert len(send.calls) == 1
        assert send.calls[0][0] == "ses_anthropic"

    def test_initial_events_are_gated_before_create_shaped_send(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        with pytest.raises(ArcjetDeniedError):
            _run(wrapped(initial_events=[_user_message("seed")]))
        assert send.calls == []

    def test_non_message_events_pass_through(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        _run(
            wrapped(
                "ses_1",
                events=[
                    {
                        "type": "user.custom_tool_result",
                        "custom_tool_use_id": "sevt_1",
                        "content": [{"type": "text", "text": "ok"}],
                    }
                ],
            )
        )
        assert len(send.calls) == 1
        assert client.guards == []

    def test_unavailable_fail_closed_does_not_send(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        with pytest.raises(ArcjetUnavailableError):
            _run(wrapped("ses_1", events=[_user_message("hello")]))
        assert send.calls == []

    def test_unavailable_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        send = RecordingSend()
        wrapped = guard_events(
            guard=client,
            send=send,
            action="message.received",
            on_guard_error="allow",
        )
        _run(wrapped("ses_1", events=[_user_message("hello")]))
        assert len(send.calls) == 1

    def test_failed_open_fail_closed(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        with pytest.raises(ArcjetUnavailableError):
            _run(wrapped("ses_1", events=[_user_message("hello")]))
        assert send.calls == []

    def test_never_uses_anthropic_session_id_as_correlation(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        _run(wrapped("ses_01ANTHROPIC", events=[_user_message("hello")]))
        assert client.guards[0]["correlation_id"] is None

    def test_async_send_is_awaited(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        send = AsyncRecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        result = asyncio.run(wrapped("ses_1", events=[_user_message("hello")]))
        assert result == "sent"
        assert len(send.calls) == 1

    def test_evaluate_reads_prompt_text(self, reset_sequence_context) -> None:
        seen: list[Mapping[str, Any]] = []

        def actor(arguments: Mapping[str, Any]) -> str:
            seen.append(dict(arguments))
            return "user-1"

        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(
            evaluate_user_message(
                _user_message("please help"),
                _events_config(guard=client, actor=actor),
            )
        )
        assert verdict.deny is False
        assert seen[0]["prompt"] == "please help"
        assert client.guards[0]["actor"] == "user-1"


class TestCustomToolGate:
    def test_deny_does_not_execute_and_sends_real_result(
        self, reset_sequence_context
    ) -> None:
        executed: list[Any] = []

        def run(event: Any) -> str:
            executed.append(event)
            return "sent-email"

        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        handle = guard_custom_tool(guard=client, run=run, action="email.sent")
        event = _custom_tool_use()
        result = asyncio.run(handle(event, send=send, anthropic_session_id="ses_1"))
        assert result is None
        assert executed == []
        assert len(send.calls) == 1
        sent = send.calls[0][1]["events"][0]
        assert sent["type"] == "user.custom_tool_result"
        assert sent["custom_tool_use_id"] == "sevt_tool_1"
        assert sent["is_error"] is True
        payload = json.loads(sent["content"][0]["text"])
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"

    def test_allow_executes_and_does_not_send(self, reset_sequence_context) -> None:
        executed: list[Any] = []

        def run(event: Any) -> str:
            executed.append(_arguments_from_event(event))
            return "ok"

        client = StubGuardClient(decision=make_allow_decision())
        send = RecordingSend()
        handle = guard_custom_tool(guard=client, run=run, action="email.sent")
        result = asyncio.run(
            handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1")
        )
        assert result == "ok"
        assert executed == [{"to": "a@example.com", "body": "hi"}]
        assert send.calls == []

    def test_fail_closed_sends_unavailable_and_does_not_run(
        self, reset_sequence_context
    ) -> None:
        executed: list[Any] = []

        def run(event: Any) -> str:
            executed.append(event)
            return "ok"

        client = StubGuardClient(exception=RuntimeError("down"))
        send = RecordingSend()
        handle = guard_custom_tool(guard=client, run=run, action="email.sent")
        asyncio.run(handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1"))
        assert executed == []
        sent = send.calls[0][1]["events"][0]
        assert sent["type"] == "user.custom_tool_result"
        payload = json.loads(sent["content"][0]["text"])
        assert payload["reason"] == "ERROR"
        assert payload["retryable"] is True

    def test_echoes_session_thread_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        handle = guard_custom_tool(
            guard=client, run=lambda _e: "x", action="email.sent"
        )
        asyncio.run(
            handle(
                _custom_tool_use(session_thread_id="thr_9"),
                send=send,
                anthropic_session_id="ses_1",
            )
        )
        assert send.calls[0][1]["events"][0]["session_thread_id"] == "thr_9"

    def test_never_mints_correlation(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_custom_tool(_custom_tool_use(), _tool_config(guard=client))
        )
        assert verdict.deny is True
        assert client.guards[0]["correlation_id"] is None

    def test_caller_owned_session_is_used(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        handle = guard_custom_tool(
            guard=client,
            run=lambda _e: "x",
            action="email.sent",
            session_id="app-owned",
        )
        asyncio.run(handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1"))
        assert client.guards[0]["correlation_id"] == "app-owned"

    def test_never_reads_anthropic_event_id_as_correlation(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_custom_tool(
                _custom_tool_use(event_id="sevt_minted"),
                _tool_config(guard=client),
            )
        )
        assert client.guards[0]["correlation_id"] is None

    def test_worker_tool_call_deny_does_not_execute(
        self, reset_sequence_context
    ) -> None:
        executed: list[Any] = []

        class _Tool:
            name = "lookup"

            def call(self, input: object) -> str:
                executed.append(dict(input))  # type: ignore[arg-type]
                return "ran"

        client = StubGuardClient(decision=make_deny_decision())
        guarded = guard_custom_tool(
            guard=client, tool=_Tool(), action="order.looked-up"
        )
        assert getattr(guarded, _GUARD_BRAND) is True
        with pytest.raises(_worker_denial_type()) as raised:
            guarded.call({"order_id": "1"})
        assert executed == []
        parsed = json.loads(_denial_content(raised.value))
        assert parsed["arcjetDenied"] is True

    def test_worker_tool_without_call_is_refused(self) -> None:
        class _JsShaped:
            name = "lookup"

            def run(self, arguments: Mapping[str, Any]) -> str:
                return "ran"

        with pytest.raises(TypeError, match="callable call"):
            guard_custom_tool(
                guard=StubGuardClient(),
                tool=_JsShaped(),
                action="order.looked-up",
            )

    def test_worker_tool_already_branded_is_skipped(
        self, reset_sequence_context
    ) -> None:
        class _Tool:
            name = "lookup"
            call = staticmethod(lambda arguments: "ok")

        tool = _Tool()
        object.__setattr__(tool, _GUARD_BRAND, True)
        client = StubGuardClient(decision=make_deny_decision())
        guarded = guard_custom_tool(guard=client, tool=tool, action="order.looked-up")
        assert guarded is tool

    def test_denial_event_matches_evaluate(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        event = _custom_tool_use()
        verdict = asyncio.run(evaluate_custom_tool(event, _tool_config(guard=client)))
        body = denial_event(event, verdict)
        assert body["type"] == "user.custom_tool_result"
        assert body["custom_tool_use_id"] == "sevt_tool_1"
        assert body["is_error"] is True


class TestGuardValidation:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_custom_tool(
                guard=StubGuardClient(),
                run=lambda _e: None,
                action="x.done",
                on_guard_error="maybe",  # type: ignore[arg-type]
            )
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_events(
                guard=StubGuardClient(),
                send=lambda *_a, **_k: None,
                action="x.done",
                on_guard_error="maybe",  # type: ignore[arg-type]
            )

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            guard_custom_tool(
                guard=StubGuardClient(),
                run=lambda _e: None,
                action="x.done",
                correlation_id="not\nvalid",
            )

    def test_run_or_tool_is_required(self) -> None:
        with pytest.raises(TypeError, match="run= or tool="):
            guard_custom_tool(guard=StubGuardClient(), action="x.done")

    def test_send_must_be_callable(self) -> None:
        with pytest.raises(TypeError, match="send callable"):
            guard_events(
                guard=StubGuardClient(),
                send=object(),
                action="x.done",
            )

    def test_empty_action_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="non-empty action"):
            guard_events(
                guard=StubGuardClient(),
                send=lambda *_a, **_k: None,
                action="",
            )
        with pytest.raises(ArcjetMisconfiguration, match="non-empty action"):
            guard_custom_tool(
                guard=StubGuardClient(),
                run=lambda _e: None,
                action="",
            )

    def test_object_shaped_user_message_is_gated(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        event = SimpleNamespace(
            type="user.message",
            content=[SimpleNamespace(type="text", text="hello")],
        )
        with pytest.raises(ArcjetDeniedError):
            _run(wrapped("ses_1", events=[event]))
        assert send.calls == []


class TestMissingPeer:
    def test_load_anthropic_names_what_to_install(self) -> None:
        if anthropic_present():
            pytest.skip("anthropic is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[claude-managed-agents\]"):
            load_anthropic()

    def test_wrap_does_not_require_the_peer(self) -> None:
        if anthropic_present():
            pytest.skip("anthropic is installed in this environment")
        send = RecordingSend()
        handle = guard_custom_tool(
            guard=StubGuardClient(decision=make_allow_decision()),
            run=lambda _e: "ok",
            action="x.done",
        )
        result = asyncio.run(
            handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1")
        )
        assert result == "ok"


class TestVersionFloor:
    def test_release_parsing(self) -> None:
        assert _release("0.92.0") == (0, 92, 0)
        assert _release("0.92.0rc1") == (0, 92, 0)
        assert _release("0.92.0.post1") == (0, 92, 0)
        assert _release("0.92") == (0, 92)
        assert _release("0.92.post1") == (0, 92)
        assert _release("1.3.0") == (1, 3, 0)
        assert _release("weird") == ()

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "0.91.0")
        with pytest.raises(ArcjetMisconfiguration, match="needs anthropic >= 0.92.0"):
            import_module._require_anthropic()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("0.92.0", "0.92.0.post1", "0.97.0", "1.3.0"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_anthropic()

    def test_absent_peer_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_anthropic()

    def test_short_post_release_of_the_floor_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "0.92.post1")
        with pytest.raises(ArcjetMisconfiguration, match="needs anthropic >= 0.92.0"):
            import_module._require_anthropic()


class TestReviewFixes:
    def test_sync_send_from_running_loop(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        send = RecordingSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")

        async def inner() -> str:
            return await wrapped("ses_1", events=[_user_message("hello")])

        assert _run(inner()) == "sent"
        assert len(send.calls) == 1

    def test_second_events_wrap_is_skipped(self, reset_sequence_context) -> None:
        send = RecordingSend()
        first = guard_events(
            guard=StubGuardClient(decision=make_allow_decision()),
            send=send,
            action="message.received",
        )
        second = guard_events(
            guard=StubGuardClient(decision=make_deny_decision()),
            send=first,
            action="message.received",
        )
        assert second is first
        _run(second("ses_1", events=[_user_message("hello")]))
        assert len(send.calls) == 1

    def test_reserved_metadata_is_not_overwritten(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        wrapped = guard_events(
            guard=client,
            send=RecordingSend(),
            action="message.received",
            session_id="app-owned",
            metadata={
                PHASE_METADATA_KEY: "forged",
                SESSION_METADATA_KEY: "forged",
            },
        )
        _run(wrapped("ses_1", events=[_user_message("hello")]))
        meta = client.guards[0]["metadata"]
        assert meta[PHASE_METADATA_KEY] == "inbound"
        assert meta[SESSION_METADATA_KEY] == "app-owned"

    def test_worker_tool_allow_runs_body(self, reset_sequence_context) -> None:
        executed: list[Any] = []

        class _Tool:
            name = "lookup"

            def call(self, input: object) -> str:
                executed.append(dict(input))  # type: ignore[arg-type]
                return "ran"

        client = StubGuardClient(decision=make_allow_decision())
        guarded = guard_custom_tool(
            guard=client, tool=_Tool(), action="order.looked-up"
        )
        assert guarded.call({"order_id": "1"}) == "ran"
        assert executed == [{"order_id": "1"}]

    def test_worker_tool_allow_on_guard_error(self, reset_sequence_context) -> None:
        executed: list[Any] = []

        class _Tool:
            name = "lookup"

            def call(self, input: object) -> str:
                executed.append(1)
                return "ran"

        client = StubGuardClient(exception=RuntimeError("down"))
        guarded = guard_custom_tool(
            guard=client,
            tool=_Tool(),
            action="order.looked-up",
            on_guard_error="allow",
        )
        assert guarded.call({"order_id": "1"}) == "ran"
        assert executed == [1]

    def test_hosted_allow_on_guard_error(self, reset_sequence_context) -> None:
        executed: list[Any] = []

        def run(event: Any) -> str:
            executed.append(event)
            return "ok"

        client = StubGuardClient(exception=RuntimeError("down"))
        send = RecordingSend()
        handle = guard_custom_tool(
            guard=client,
            run=run,
            action="email.sent",
            on_guard_error="allow",
        )
        assert (
            _run(handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1"))
            == "ok"
        )
        assert executed
        assert send.calls == []

    def test_invoke_run_uses_signature_not_typeerror(
        self, reset_sequence_context
    ) -> None:
        seen: list[Any] = []

        def by_event(event: Any) -> str:
            seen.append(("event", _arguments_from_event(event)))
            return "e"

        def by_input(input: Mapping[str, Any]) -> str:
            seen.append(("input", dict(input)))
            return "i"

        def by_name_input(name: str, input: Mapping[str, Any]) -> str:
            seen.append(("name_input", name, dict(input)))
            return "n"

        event = _custom_tool_use()
        assert _invoke_run(by_event, event) == "e"
        assert _invoke_run(by_input, event) == "i"
        assert _invoke_run(by_name_input, event) == "n"
        assert seen[0][0] == "event"
        assert seen[1] == ("input", {"to": "a@example.com", "body": "hi"})
        assert seen[2] == (
            "name_input",
            "send_email",
            {"to": "a@example.com", "body": "hi"},
        )

    def test_typeerror_in_run_body_is_not_retried(self, reset_sequence_context) -> None:
        calls: list[int] = []

        def run(event: Any) -> str:
            calls.append(1)
            raise TypeError("real failure")

        handle = guard_custom_tool(
            guard=StubGuardClient(decision=make_allow_decision()),
            run=run,
            action="email.sent",
        )
        with pytest.raises(TypeError, match="real failure"):
            _run(
                handle(
                    _custom_tool_use(),
                    send=RecordingSend(),
                    anthropic_session_id="ses_1",
                )
            )
        assert calls == [1]

    def test_pydantic_shaped_custom_tool_use(self, reset_sequence_context) -> None:
        executed: list[Any] = []

        def run(event: Any) -> str:
            executed.append(_arguments_from_event(event))
            return "ok"

        client = StubGuardClient(decision=make_allow_decision())
        handle = guard_custom_tool(guard=client, run=run, action="email.sent")
        event = SimpleNamespace(
            type="agent.custom_tool_use",
            id="sevt_obj",
            name="send_email",
            input={"to": "a@example.com"},
            session_thread_id=None,
        )
        assert (
            _run(handle(event, send=RecordingSend(), anthropic_session_id="ses_1"))
            == "ok"
        )
        assert executed == [{"to": "a@example.com"}]
        assert client.guards[0]["inputs"] is None
        assert client.guards[0]["metadata"][TOOL_METADATA_KEY] == "send_email"

    def test_denial_send_retries_then_succeeds(
        self, reset_sequence_context, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tool_module, "DENIAL_SEND_BACKOFF_SECONDS", (0, 0))

        class FlakySend:
            def __init__(self) -> None:
                self.n = 0

            def __call__(
                self, session_id: Any, *, events: Any = None, **kwargs: Any
            ) -> str:
                self.n += 1
                if self.n < 3:
                    raise ConnectionError("blip")
                return "sent"

        send = FlakySend()
        handle = guard_custom_tool(
            guard=StubGuardClient(decision=make_deny_decision()),
            run=lambda _e: "x",
            action="email.sent",
        )
        _run(handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1"))
        assert send.n == 3

    def test_denial_send_does_not_retry_programmer_errors(
        self, reset_sequence_context, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tool_module, "DENIAL_SEND_BACKOFF_SECONDS", (0, 0))

        class BadSend:
            def __init__(self) -> None:
                self.n = 0

            def __call__(
                self, session_id: Any, *, events: Any = None, **kwargs: Any
            ) -> str:
                self.n += 1
                raise TypeError("send() missing events")

        send = BadSend()
        handle = guard_custom_tool(
            guard=StubGuardClient(decision=make_deny_decision()),
            run=lambda _e: "x",
            action="email.sent",
        )
        with pytest.raises(TypeError, match="missing events"):
            _run(handle(_custom_tool_use(), send=send, anthropic_session_id="ses_1"))
        assert send.n == 1

    def test_positional_second_arg_is_not_treated_as_events(
        self, reset_sequence_context
    ) -> None:
        class LooseSend:
            def __init__(self) -> None:
                self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

            def __call__(self, *args: Any, **kwargs: Any) -> str:
                self.calls.append((args, kwargs))
                return "sent"

        client = StubGuardClient(decision=make_deny_decision())
        send = LooseSend()
        wrapped = guard_events(guard=client, send=send, action="message.received")
        assert _run(wrapped("ses_1", [_user_message("inject")])) == "sent"
        assert client.guards == []
        assert len(send.calls) == 1

    def test_denial_send_retries_then_raises(
        self, reset_sequence_context, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tool_module, "DENIAL_SEND_BACKOFF_SECONDS", (0, 0))

        class DeadSend:
            def __call__(
                self, session_id: Any, *, events: Any = None, **kwargs: Any
            ) -> str:
                raise ConnectionError("down")

        handle = guard_custom_tool(
            guard=StubGuardClient(decision=make_deny_decision()),
            run=lambda _e: "x",
            action="email.sent",
        )
        with pytest.raises(ConnectionError, match="down"):
            _run(
                handle(
                    _custom_tool_use(), send=DeadSend(), anthropic_session_id="ses_1"
                )
            )

    def test_worker_denial_prefers_tool_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeToolError(Exception):
            def __init__(self, content: str) -> None:
                super().__init__(content)
                self.content = content

        monkeypatch.setattr(denial_module, "load_tool_error", lambda: FakeToolError)
        with pytest.raises(FakeToolError) as raised:
            raise_worker_denial(unavailable_result())
        assert json.loads(raised.value.content)["arcjetDenied"] is True

    def test_web_search_wrap_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        class _Search:
            name = "web_search"

            def call(self, input: object) -> str:
                return "x"

        with caplog.at_level("WARNING", logger="arcjet"):
            guard_custom_tool(
                guard=StubGuardClient(),
                tool=_Search(),
                action="search.ran",
            )
        assert any("web_search" in rec.message for rec in caplog.records)

    def test_run_and_tool_together_are_refused(self) -> None:
        class _Tool:
            def call(self, input: object) -> str:
                return "x"

        with pytest.raises(TypeError, match="not both"):
            guard_custom_tool(
                guard=StubGuardClient(),
                run=lambda _e: None,
                tool=_Tool(),
                action="x.done",
            )

    def test_async_worker_call_is_awaited(self, reset_sequence_context) -> None:
        executed: list[Any] = []

        class _Tool:
            name = "lookup"

            async def call(self, input: object) -> str:
                executed.append(dict(input))  # type: ignore[arg-type]
                return "ran"

        guarded = guard_custom_tool(
            guard=StubGuardClient(decision=make_allow_decision()),
            tool=_Tool(),
            action="order.looked-up",
        )
        assert _run(guarded.call({"order_id": "2"})) == "ran"
        assert executed == [{"order_id": "2"}]


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import claude_managed_agents as adapter

    assert adapter.__all__ == [
        "guard_custom_tool",
        "guard_events",
        "claude_managed_agents_context",
    ]
    assert not hasattr(adapter, "guard_tool")
    assert not hasattr(adapter, "guard_hooks")
    assert not hasattr(adapter, "guard_inbound")


def test_brand_constant_is_stable() -> None:
    assert _GUARD_BRAND == "_arcjet_guarded"


def test_payload_from_block_uses_deny_or_unavailable() -> None:
    deny = payload_from_block(make_deny_decision())
    assert deny["reason"] == "RATE_LIMIT"
    assert payload_from_block(None)["reason"] == "ERROR"
    assert dumps_denial(deny).startswith("{")

"""Claude Agent SDK adapter unit tests that must run with the extra absent.

The extra is optional. These tests import ``arcjet.guard.claude_agent_sdk``
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
from arcjet.guard.claude_agent_sdk import _import as import_module
from arcjet.guard.claude_agent_sdk import (
    claude_agent_context,
    guard_hooks,
    guard_tool,
)
from arcjet.guard.claude_agent_sdk._context import ClaudeAgentContext
from arcjet.guard.claude_agent_sdk._denial import (
    UNAVAILABLE_RETRY_AFTER_SECONDS,
    denial_result,
    denial_tool_result,
    dumps_denial,
    retry_after_seconds,
    unavailable_result,
)
from arcjet.guard.claude_agent_sdk._hooks import (
    PreToolUseVerdict,
    UserPromptSubmitVerdict,
    _HookConfig,
    _InboundConfig,
    evaluate_pre_tool_use,
    evaluate_user_prompt_submit,
    pre_tool_use_output,
    user_prompt_submit_output,
)
from arcjet.guard.claude_agent_sdk._import import (
    _release,
    claude_agent_sdk_present,
    load_sdk_mcp_tool,
)
from arcjet.guard.claude_agent_sdk._names import (
    exclude_name,
    excluded_names,
    mcp_tool_name,
)
from arcjet.guard.claude_agent_sdk._tool import (
    _GUARD_BRAND,
    _arguments_from_handler,
    _ToolConfig,
    evaluate_handler,
    handler_denial_result,
)

CLAUDE_AGENT_SDK_SRC = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "arcjet"
    / "guard"
    / "claude_agent_sdk"
)

SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


def _tool_config(**kwargs: Any) -> _ToolConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": "echo.invoked",
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "session_id": None,
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
        "session_id": None,
        "on_guard_error": "deny",
        "exclude": frozenset(),
    }
    defaults.update(kwargs)
    return _HookConfig(**defaults)


def _inbound_config(**kwargs: Any) -> _InboundConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": "message.received",
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "session_id": None,
        "on_guard_error": "deny",
    }
    defaults.update(kwargs)
    return _InboundConfig(**defaults)


def _pre_input(**kwargs: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "session_id": SESSION_ID,
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": "tu_1",
        "transcript_path": "/tmp/t",
        "cwd": "/tmp",
    }
    defaults.update(kwargs)
    return defaults


def _prompt_input(**kwargs: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "hook_event_name": "UserPromptSubmit",
        "session_id": SESSION_ID,
        "prompt": "hello",
        "transcript_path": "/tmp/t",
        "cwd": "/tmp",
    }
    defaults.update(kwargs)
    return defaults


class TestSourceIsolation:
    def test_package_does_not_import_sibling_adapters(self) -> None:
        for path in CLAUDE_AGENT_SDK_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "langchain" not in node.module
                    assert "crewai" not in node.module
                    assert "openai_agents" not in node.module
                    assert node.module != "arcjet.guard.langchain"
                    assert node.module != "arcjet.guard.crewai"
                    assert node.module != "arcjet.guard.openai_agents"
                    assert node.module != "claude_agent_sdk"
                    assert not node.module.startswith("claude_agent_sdk.")
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "langchain" not in alias.name
                        assert "crewai" not in alias.name
                        assert "openai_agents" not in alias.name
                        assert alias.name != "claude_agent_sdk"
                        assert not alias.name.startswith("claude_agent_sdk.")

    def test_core_guard_imports_with_peer_unimportable(self) -> None:
        """The real invariant, in a process where the peer cannot import."""
        program = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "claude_agent_sdk" or name.startswith("claude_agent_sdk."):
            raise ImportError("claude_agent_sdk is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())

import arcjet.guard
assert callable(arcjet.guard.guard)
assert "claude_agent_sdk" not in sys.modules

import arcjet.guard.claude_agent_sdk as adapter
assert callable(adapter.guard_tool)
assert callable(adapter.guard_hooks)
assert callable(adapter.claude_agent_context)
assert adapter.__all__ == ["guard_tool", "guard_hooks", "claude_agent_context"]
assert not hasattr(adapter, "guard_inbound")
assert not hasattr(adapter, "guard_can_use_tool")
try:
    adapter.guard_tool(guard=object(), tool=object(), action="x.done")
except ImportError as exc:
    assert "arcjet[claude-agent-sdk]" in str(exc), exc
else:
    raise AssertionError("expected an ImportError naming what to install")
try:
    adapter.guard_hooks(guard=object(), action="x.done")
except ImportError as exc:
    assert "arcjet[claude-agent-sdk]" in str(exc), exc
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


class TestClaudeAgentContext:
    def test_prefers_hook_session_id(self, reset_sequence_context) -> None:
        ctx = claude_agent_context(
            {"session_id": SESSION_ID},
            session_id="11111111-1111-4111-8111-111111111111",
        )
        assert ctx.correlation_id == SESSION_ID

    def test_falls_back_to_caller_owned_session_id(
        self, reset_sequence_context
    ) -> None:
        ctx = claude_agent_context({}, session_id=SESSION_ID)
        assert ctx.correlation_id == SESSION_ID

    def test_never_mints_when_nothing_is_present(self, reset_sequence_context) -> None:
        ctx = claude_agent_context({})
        assert ctx.correlation_id is None
        assert isinstance(ctx, ClaudeAgentContext)

    def test_never_reads_trace_id(self, reset_sequence_context) -> None:
        ctx = claude_agent_context({"trace_id": "tr_minted", "traceId": "tr2"})
        assert ctx.correlation_id is None

    def test_non_uuid_session_id_is_skipped(self, reset_sequence_context) -> None:
        ctx = claude_agent_context({"session_id": "not-a-uuid"})
        assert ctx.correlation_id is None
        assert ctx.metadata is None

    def test_invalid_session_id_is_skipped(self, reset_sequence_context) -> None:
        ctx = claude_agent_context({"session_id": "not\nvalid"})
        assert ctx.correlation_id is None

    def test_falls_back_to_ambient_sequence(self, reset_sequence_context) -> None:
        with arcjet_sequence(correlation_id="from-sequence"):
            ctx = claude_agent_context({})
        assert ctx.correlation_id == "from-sequence"

    def test_agent_id_is_metadata_only(self, reset_sequence_context) -> None:
        ctx = claude_agent_context(
            {"session_id": SESSION_ID, "agent_id": "agent-9", "tool_name": "Bash"}
        )
        assert ctx.correlation_id == SESSION_ID
        assert ctx.metadata is not None
        assert ctx.metadata["claude.session"] == SESSION_ID
        assert ctx.metadata["claude.agent"] == "agent-9"
        assert ctx.metadata["claude.tool"] == "Bash"

    def test_does_not_construct_a_session(self, reset_sequence_context) -> None:
        session = SimpleNamespace(
            getSessionId=lambda: (_ for _ in ()).throw(
                AssertionError("must not call getSessionId")
            )
        )
        ctx = claude_agent_context(session)
        assert ctx.correlation_id is None


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

    def test_non_rate_limit_is_not_retryable(self) -> None:
        decision = make_deny_decision(reason="PROMPT_INJECTION")
        payload = denial_result(decision)
        assert payload["retryable"] is False
        assert "retryAfterSeconds" not in payload

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

    def test_denial_tool_result_has_no_structured_content(self) -> None:
        result = denial_tool_result(unavailable_result())
        assert result["is_error"] is True
        assert "structuredContent" not in result
        assert "structured_content" not in result
        text = result["content"][0]["text"]
        assert json.loads(text)["arcjetDenied"] is True

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

    def test_deny_envelope_is_content_plus_is_error_not_a_throw(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_handler({"value": "hello"}, _tool_config(guard=client))
        )
        assert verdict.deny is True
        result = handler_denial_result(verdict)
        assert result["is_error"] is True
        assert "structuredContent" not in result
        payload = json.loads(result["content"][0]["text"])
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
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
        result = handler_denial_result(verdict)
        payload = json.loads(result["content"][0]["text"])
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
        payload = json.loads(handler_denial_result(verdict)["content"][0]["text"])
        assert payload["reason"] == "ERROR"

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

    def test_uses_policy_session_id_never_mints(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        asyncio.run(
            evaluate_handler({}, _tool_config(guard=client, session_id=SESSION_ID))
        )
        assert client.guards[0]["correlation_id"] == SESSION_ID

    def test_never_mints_without_a_caller_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(evaluate_handler({}, _tool_config(guard=client)))
        assert client.guards[0]["correlation_id"] is None

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


class TestArgumentsFromHandler:
    def test_accepts_a_mapping(self) -> None:
        assert _arguments_from_handler({"value": "x"}) == {"value": "x"}

    def test_non_mapping_is_empty_not_an_exception(self) -> None:
        assert _arguments_from_handler("{not-json") == {}
        assert _arguments_from_handler(None) == {}


class TestEvaluatePreToolUse:
    def test_deny_is_permission_decision_deny(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_pre_tool_use(_pre_input(), _hook_config(guard=client))
        )
        assert verdict.deny is True
        output = pre_tool_use_output(verdict)
        specific = output["hookSpecificOutput"]
        assert specific["hookEventName"] == "PreToolUse"
        assert specific["permissionDecision"] == "deny"
        assert specific["permissionDecision"] != "ask"
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_allow_is_empty_output(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(
            evaluate_pre_tool_use(_pre_input(), _hook_config(guard=client))
        )
        assert verdict.deny is False
        assert pre_tool_use_output(verdict) == {}

    def test_unavailable_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_pre_tool_use(_pre_input(), _hook_config(guard=client))
        )
        assert verdict.deny is True
        assert (
            pre_tool_use_output(verdict)["hookSpecificOutput"]["permissionDecision"]
            == "deny"
        )

    def test_wrapped_tool_is_excluded_from_pre_tool_use(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        excluded = excluded_names([{"server": "support", "name": "lookup_order"}])
        verdict = asyncio.run(
            evaluate_pre_tool_use(
                _pre_input(tool_name="mcp__support__lookup_order"),
                _hook_config(guard=client, exclude=excluded),
            )
        )
        assert verdict.deny is False
        assert client.guards == []

    def test_bare_authored_name_is_not_an_exclude_match(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        excluded = excluded_names([{"server": "support", "name": "lookup_order"}])
        verdict = asyncio.run(
            evaluate_pre_tool_use(
                _pre_input(tool_name="lookup_order"),
                _hook_config(guard=client, exclude=excluded),
            )
        )
        assert verdict.deny is True
        assert len(client.guards) == 1

    def test_other_server_same_name_is_still_gated(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        excluded = excluded_names([{"server": "support", "name": "lookup_order"}])
        verdict = asyncio.run(
            evaluate_pre_tool_use(
                _pre_input(tool_name="mcp__other__lookup_order"),
                _hook_config(guard=client, exclude=excluded),
            )
        )
        assert verdict.deny is True

    def test_correlation_from_hook_session_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        asyncio.run(evaluate_pre_tool_use(_pre_input(), _hook_config(guard=client)))
        assert client.guards[0]["correlation_id"] == SESSION_ID

    def test_never_mints_without_a_caller_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_pre_tool_use(
                _pre_input(session_id="not-a-uuid"), _hook_config(guard=client)
            )
        )
        assert client.guards[0]["correlation_id"] is None


class TestEvaluateUserPromptSubmit:
    def test_deny_is_decision_block(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_user_prompt_submit(_prompt_input(), _inbound_config(guard=client))
        )
        assert verdict.block is True
        output = user_prompt_submit_output(verdict)
        assert output["decision"] == "block"
        assert "reason" in output
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_allow_is_empty_output(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(
            evaluate_user_prompt_submit(_prompt_input(), _inbound_config(guard=client))
        )
        assert verdict.block is False
        assert user_prompt_submit_output(verdict) == {}

    def test_unavailable_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_user_prompt_submit(_prompt_input(), _inbound_config(guard=client))
        )
        assert verdict.block is True
        assert user_prompt_submit_output(verdict)["decision"] == "block"

    def test_unavailable_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_user_prompt_submit(
                _prompt_input(),
                _inbound_config(guard=client, on_guard_error="allow"),
            )
        )
        assert verdict.block is False

    def test_rules_see_prompt(self, reset_sequence_context) -> None:
        seen: list[Mapping[str, Any]] = []

        def rules(arguments: Mapping[str, Any]) -> list[Any]:
            seen.append(dict(arguments))
            return []

        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_user_prompt_submit(
                _prompt_input(prompt="inject me"),
                _inbound_config(guard=client, rules=rules),
            )
        )
        assert seen == [{"prompt": "inject me"}]


class TestExcludeNames:
    def test_qualifies_server_and_name(self) -> None:
        assert mcp_tool_name("support", "lookup_order") == "mcp__support__lookup_order"
        assert (
            exclude_name({"server": "support", "name": "lookup_order"})
            == "mcp__support__lookup_order"
        )

    def test_bare_string_is_exact(self) -> None:
        assert exclude_name("Bash") == "Bash"

    def test_mapping_requires_server_and_name(self) -> None:
        with pytest.raises(ValueError, match="server"):
            exclude_name({"name": "lookup_order"})
        with pytest.raises(ValueError, match="name"):
            exclude_name({"server": "support"})


class TestGuardToolValidation:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_tool(
                guard=StubGuardClient(),
                tool=object(),
                action="x.done",
                on_guard_error="maybe",  # type: ignore[arg-type]
            )

    def test_invalid_session_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            guard_tool(
                guard=StubGuardClient(),
                tool=object(),
                action="x.done",
                session_id="not\nvalid",
            )


class TestGuardHooksValidation:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_hooks(on_guard_error="maybe")  # type: ignore[arg-type]

    def test_neither_tool_nor_inbound_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="inbound"):
            guard_hooks()

    def test_inbound_without_action_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="action"):
            guard_hooks(inbound={"rules": ()})


class TestMissingPeer:
    def test_guard_tool_names_what_to_install(self) -> None:
        if claude_agent_sdk_present():
            pytest.skip("claude-agent-sdk is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[claude-agent-sdk\]"):
            guard_tool(guard=StubGuardClient(), tool=object(), action="x.done")

    def test_guard_hooks_names_what_to_install(self) -> None:
        if claude_agent_sdk_present():
            pytest.skip("claude-agent-sdk is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[claude-agent-sdk\]"):
            guard_hooks(guard=StubGuardClient(), action="x.done")

    def test_load_sdk_mcp_tool_names_what_to_install(self) -> None:
        if claude_agent_sdk_present():
            pytest.skip("claude-agent-sdk is installed in this environment")
        with pytest.raises(ImportError, match="needs the Claude Agent SDK"):
            load_sdk_mcp_tool()


class TestVersionFloor:
    def test_release_parsing(self) -> None:
        assert _release("0.2.127") == (0, 2, 127)
        assert _release("0.2.148") == (0, 2, 148)
        assert _release("0.2.148rc1") == (0, 2, 148)
        assert _release("1.0.0") == (1, 0, 0)
        assert _release("weird") == ()

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "0.2.83")
        with pytest.raises(
            ArcjetMisconfiguration, match="needs claude-agent-sdk >= 0.2.127"
        ):
            import_module._require_claude_agent_sdk()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("0.2.127", "0.2.148", "0.3.0"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_claude_agent_sdk()

    def test_absent_peer_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_claude_agent_sdk()


class TestFailClosedHelperVsFailOpenProtect:
    def test_helper_denies_the_same_failed_open_protect_would_allow(
        self, reset_sequence_context
    ) -> None:
        """``protect()`` / core ``guard()`` fail open; these helpers do not.

        A decision with an error result is the shape ``protect()`` returns
        when evaluation did not finish: ``has_failed_open()`` is True and
        the conclusion is still ALLOW. The helper treats that as a deny.
        """
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        assert decision.conclusion == "ALLOW"
        assert decision.has_failed_open()
        client = StubGuardClient(decision=decision)
        verdict = asyncio.run(evaluate_handler({}, _tool_config(guard=client)))
        assert verdict.deny is True
        result = handler_denial_result(verdict)
        assert result["is_error"] is True
        assert "structuredContent" not in result


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import claude_agent_sdk as adapter

    assert adapter.__all__ == ["guard_tool", "guard_hooks", "claude_agent_context"]
    assert not hasattr(adapter, "guard_inbound")
    assert not hasattr(adapter, "guard_can_use_tool")


def test_brand_constant_is_stable() -> None:
    assert _GUARD_BRAND == "_arcjet_guarded"


def test_pre_tool_use_ask_is_never_emitted() -> None:
    output = pre_tool_use_output(PreToolUseVerdict(deny=True, reason="no"))
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    output = pre_tool_use_output(PreToolUseVerdict(deny=False))
    assert "permissionDecision" not in output.get("hookSpecificOutput", {})


def test_user_prompt_submit_block_shape() -> None:
    output = user_prompt_submit_output(UserPromptSubmitVerdict(block=True, reason="no"))
    assert output == {"decision": "block", "reason": "no"}

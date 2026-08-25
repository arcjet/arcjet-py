"""OpenAI Agents adapter unit tests that must run with openai-agents absent.

The extra is optional. These tests import ``arcjet.guard.openai_agents``
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
from arcjet.guard.openai_agents import _import as import_module
from arcjet.guard.openai_agents import guard_tool, openai_agents_context
from arcjet.guard.openai_agents._context import OpenAIAgentsContext
from arcjet.guard.openai_agents._denial import (
    UNAVAILABLE_RETRY_AFTER_SECONDS,
    denial_result,
    dumps_denial,
    unavailable_result,
)
from arcjet.guard.openai_agents._import import (
    _release,
    load_function_tool,
    openai_agents_present,
)
from arcjet.guard.openai_agents._tool import (
    _GUARD_BRAND,
    _arguments_from_tool_context,
    _ToolConfig,
    evaluate_tool_input,
)

OPENAI_AGENTS_SRC = (
    Path(__file__).resolve().parents[3] / "src" / "arcjet" / "guard" / "openai_agents"
)


def _ctx(**kwargs: object) -> SimpleNamespace:
    defaults: dict[str, object] = {
        "tool_name": "echo",
        "tool_arguments": '{"value": "hello"}',
        "context": {},
    }
    defaults.update(kwargs)
    return SimpleNamespace(context=SimpleNamespace(**defaults))


def _config(**kwargs: Any) -> _ToolConfig:
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


class TestSourceIsolation:
    def test_package_does_not_import_langchain_or_crewai(self) -> None:
        for path in OPENAI_AGENTS_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "langchain" not in node.module
                    assert "crewai" not in node.module
                    assert node.module != "arcjet.guard.langchain"
                    assert node.module != "arcjet.guard.crewai"
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "langchain" not in alias.name
                        assert "crewai" not in alias.name

    def test_core_guard_imports_with_agents_unimportable(self) -> None:
        """The real invariant, in a process where ``agents`` cannot import."""
        program = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "agents" or name.startswith("agents."):
            raise ImportError("agents is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())

import arcjet.guard
assert callable(arcjet.guard.guard)
assert "agents" not in sys.modules

import arcjet.guard.openai_agents as adapter
assert callable(adapter.guard_tool)
assert callable(adapter.openai_agents_context)
try:
    adapter.guard_tool(guard=object(), tool=object(), action="x.done")
except ImportError as exc:
    assert "arcjet[openai-agents]" in str(exc), exc
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


class TestOpenaiAgentsContext:
    def test_prefers_correlation_id_then_session_then_conversation_then_group(
        self, reset_sequence_context
    ) -> None:
        ctx = openai_agents_context(
            {
                "correlation_id": "corr",
                "session_id": "sess",
                "conversation_id": "conv",
                "group_id": "grp",
            }
        )
        assert ctx.correlation_id == "corr"

        ctx = openai_agents_context(
            {"session_id": "sess", "conversation_id": "conv", "group_id": "grp"}
        )
        assert ctx.correlation_id == "sess"

        ctx = openai_agents_context({"conversation_id": "conv", "group_id": "grp"})
        assert ctx.correlation_id == "conv"

        ctx = openai_agents_context({"group_id": "grp"})
        assert ctx.correlation_id == "grp"

    def test_reads_nested_run_context(self, reset_sequence_context) -> None:
        ctx = openai_agents_context(SimpleNamespace(context={"session_id": "from-app"}))
        assert ctx.correlation_id == "from-app"

    def test_accepts_camel_case_aliases(self, reset_sequence_context) -> None:
        ctx = openai_agents_context({"sessionId": "sess", "conversationId": "conv"})
        assert ctx.correlation_id == "sess"

    def test_never_reads_trace_id(self, reset_sequence_context) -> None:
        ctx = openai_agents_context({"trace_id": "tr_minted", "traceId": "tr2"})
        assert ctx.correlation_id is None

    def test_never_mints_when_nothing_is_present(self, reset_sequence_context) -> None:
        ctx = openai_agents_context({})
        assert ctx.correlation_id is None
        assert isinstance(ctx, OpenAIAgentsContext)

    def test_falls_back_to_ambient_sequence(self, reset_sequence_context) -> None:
        with arcjet_sequence(correlation_id="from-sequence"):
            ctx = openai_agents_context({})
        assert ctx.correlation_id == "from-sequence"

    def test_skips_invalid_then_uses_next(self, reset_sequence_context) -> None:
        ctx = openai_agents_context(
            {"correlation_id": "not\nvalid", "session_id": "sess"}
        )
        assert ctx.correlation_id == "sess"

    def test_skips_invalid_and_does_not_mint(self, reset_sequence_context) -> None:
        ctx = openai_agents_context({"correlation_id": "not\nvalid"})
        assert ctx.correlation_id is None

    def test_explicit_kwargs_are_last_resort(self, reset_sequence_context) -> None:
        ctx = openai_agents_context(
            {"session_id": "from-ctx"},
            correlation_id="from-kw",
        )
        assert ctx.correlation_id == "from-ctx"
        ctx = openai_agents_context({}, session_id="from-kw")
        assert ctx.correlation_id == "from-kw"

    def test_does_not_construct_a_session(self, reset_sequence_context) -> None:
        """A session object is not a source of ids; constructing one would mint."""
        session = SimpleNamespace(
            getSessionId=lambda: (_ for _ in ()).throw(
                AssertionError("must not call getSessionId")
            )
        )
        ctx = openai_agents_context(session)
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


class TestEvaluateToolInput:
    """arcjet-py has no pytest-asyncio; drive coroutines with ``asyncio.run``."""

    def test_deny_is_reject_content_not_an_exception(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(evaluate_tool_input(_ctx(), _config(guard=client)))
        assert verdict.behavior == "reject_content"
        assert verdict.message is not None
        payload = json.loads(verdict.message)
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
        assert client.captures[0]["metadata"]["outcome"] == "denied"

    def test_allow_does_not_reject(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(evaluate_tool_input(_ctx(), _config(guard=client)))
        assert verdict.behavior == "allow"
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_unavailable_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(evaluate_tool_input(_ctx(), _config(guard=client)))
        assert verdict.behavior == "reject_content"
        payload = json.loads(verdict.message or "")
        assert payload["reason"] == "ERROR"
        assert payload["retryable"] is True
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_unavailable_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        verdict = asyncio.run(
            evaluate_tool_input(_ctx(), _config(guard=client, on_guard_error="allow"))
        )
        assert verdict.behavior == "allow"

    def test_failed_open_fail_closed(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        verdict = asyncio.run(evaluate_tool_input(_ctx(), _config(guard=client)))
        assert verdict.behavior == "reject_content"
        payload = json.loads(verdict.message or "")
        assert payload["reason"] == "ERROR"

    def test_policy_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> PolicyInputMap:
            raise RuntimeError("resolver exploded")

        verdict = asyncio.run(
            evaluate_tool_input(_ctx(), _config(guard=client, inputs=boom))
        )
        assert verdict.behavior == "reject_content"
        assert len(client.guards) == 1

    def test_rules_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any]) -> list[Any]:
            raise RuntimeError("no rules")

        verdict = asyncio.run(
            evaluate_tool_input(_ctx(), _config(guard=client, rules=boom))
        )
        assert verdict.behavior == "reject_content"
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_correlation_from_context_never_mints(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        data = _ctx(context={"session_id": "sess-9"})
        asyncio.run(evaluate_tool_input(data, _config(guard=client)))
        assert client.guards[0]["correlation_id"] == "sess-9"

    def test_ambient_sequence_is_used_when_context_has_none(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        with arcjet_sequence(correlation_id="from-sequence"):
            asyncio.run(evaluate_tool_input(_ctx(), _config(guard=client)))
        assert client.guards[0]["correlation_id"] == "from-sequence"

    def test_never_mints_without_a_caller_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(evaluate_tool_input(_ctx(), _config(guard=client)))
        assert client.guards[0]["correlation_id"] is None

    def test_never_reads_trace_id_from_context(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        data = _ctx(context={"trace_id": "tr_minted"})
        asyncio.run(evaluate_tool_input(data, _config(guard=client)))
        assert client.guards[0]["correlation_id"] is None

    def test_resolver_sees_parsed_arguments(self, reset_sequence_context) -> None:
        seen: list[Mapping[str, Any]] = []

        def actor(arguments: Mapping[str, Any]) -> str:
            seen.append(dict(arguments))
            return str(arguments["user_id"])

        client = StubGuardClient(decision=make_allow_decision())
        data = _ctx(tool_arguments='{"user_id": "u_1", "body": "hello"}')
        verdict = asyncio.run(
            evaluate_tool_input(data, _config(guard=client, actor=actor))
        )
        assert verdict.behavior == "allow"
        assert seen == [{"user_id": "u_1", "body": "hello"}]
        assert client.guards[0]["actor"] == "u_1"


class TestArgumentsFromToolContext:
    def test_parses_json_string(self) -> None:
        assert _arguments_from_tool_context(
            SimpleNamespace(tool_arguments='{"value": "x"}')
        ) == {"value": "x"}

    def test_accepts_a_mapping(self) -> None:
        assert _arguments_from_tool_context(
            SimpleNamespace(tool_arguments={"value": "x"})
        ) == {"value": "x"}

    def test_malformed_json_is_empty_not_an_exception(self) -> None:
        assert (
            _arguments_from_tool_context(SimpleNamespace(tool_arguments="{not-json"))
            == {}
        )


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


class TestMissingPeer:
    def test_guard_tool_names_what_to_install(self) -> None:
        if openai_agents_present():
            pytest.skip("openai-agents is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[openai-agents\]"):
            guard_tool(guard=StubGuardClient(), tool=object(), action="x.done")

    def test_load_function_tool_names_what_to_install(self) -> None:
        if openai_agents_present():
            pytest.skip("openai-agents is installed in this environment")
        with pytest.raises(ImportError, match="needs OpenAI Agents"):
            load_function_tool()


class TestVersionFloor:
    def test_release_parsing(self) -> None:
        assert _release("0.19.0") == (0, 19, 0)
        assert _release("0.22.0") == (0, 22, 0)
        assert _release("0.22.0rc1") == (0, 22, 0)
        assert _release("1.0.0") == (1, 0, 0)
        assert _release("weird") == ()

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "0.18.9")
        with pytest.raises(
            ArcjetMisconfiguration, match="needs openai-agents >= 0.19.0"
        ):
            import_module._require_openai_agents()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("0.19.0", "0.22.0", "0.23.1"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_openai_agents()

    def test_absent_peer_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_openai_agents()


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import openai_agents as adapter

    assert adapter.__all__ == ["guard_tool", "openai_agents_context"]


def test_brand_constant_is_stable() -> None:
    assert _GUARD_BRAND == "_arcjet_guarded"

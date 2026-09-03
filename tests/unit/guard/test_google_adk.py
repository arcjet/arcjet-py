"""Google ADK adapter unit tests that must run with google-adk absent.

The extra is optional. These tests import ``arcjet.guard.google_adk``
helpers that do not load the peer.
"""

from __future__ import annotations

import ast
import asyncio
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
from arcjet.guard._types import RuleResultError
from arcjet.guard.google_adk import _import as import_module
from arcjet.guard.google_adk import (
    google_adk_context,
    guard_plugin,
    guard_tool,
)
from arcjet.guard.google_adk._callback import (
    _GUARD_BRAND,
    BeforeToolVerdict,
    _CallbackConfig,
    evaluate_before_tool,
    run_before_tool_callback,
    verdict_result,
)
from arcjet.guard.google_adk._context import GoogleAdkContext
from arcjet.guard.google_adk._denial import (
    UNAVAILABLE_RETRY_AFTER_SECONDS,
    denial_result,
    deny_dict,
    payload_from_block,
    retry_after_seconds,
    unavailable_result,
)
from arcjet.guard.google_adk._import import (
    _release,
    google_adk_present,
    load_base_plugin,
    load_google_adk,
)

GOOGLE_ADK_SRC = (
    Path(__file__).resolve().parents[3] / "src" / "arcjet" / "guard" / "google_adk"
)


def _config(**kwargs: Any) -> _CallbackConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": None,
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "session_id": None,
        "on_guard_error": "deny",
    }
    defaults.update(kwargs)
    return _CallbackConfig(**defaults)


def _tool(*, name: str = "echo", guarded: bool = False) -> SimpleNamespace:
    tool = SimpleNamespace(name=name)
    if guarded:
        object.__setattr__(tool, _GUARD_BRAND, True)
    return tool


def _dispatch(
    callback: Any,
    tool: Any,
    args: Mapping[str, Any],
    tool_context: Any,
    tool_fn: Any,
) -> Any:
    """Simulate ADK: a returned dict skips *tool_fn*; ``None`` runs it."""
    result = asyncio.run(callback(tool, args, tool_context))
    if result is not None:
        return result
    return tool_fn(**dict(args))


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
        """The real invariant, in a process where the peer cannot import."""
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
print("ok")
"""
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"

    def test_does_not_call_hitl_or_security_plugin(self) -> None:
        text = "".join(path.read_text() for path in GOOGLE_ADK_SRC.glob("*.py"))
        assert "request_confirmation(" not in text
        assert "require_confirmation(" not in text
        assert "SecurityPlugin()" not in text
        assert "before_tool_callback" in text


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

    def test_reads_nested_context_wrap(self, reset_sequence_context) -> None:
        ctx = google_adk_context({"context": {"session_id": "from-app"}})
        assert ctx.correlation_id == "from-app"

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

    def test_never_reads_trace_id(self, reset_sequence_context) -> None:
        ctx = google_adk_context({"trace_id": "tr_minted", "traceId": "tr2"})
        assert ctx.correlation_id is None

    def test_never_reads_invocation_id(self, reset_sequence_context) -> None:
        ctx = google_adk_context(
            {
                "invocationId": "inv-auto",
                "sessionId": "sess-auto",
                "functionCallId": "call-auto",
            }
        )
        assert ctx.correlation_id is None
        assert ctx.metadata is None

    def test_never_reads_tool_context_session_id_on_adk_envelope(
        self, reset_sequence_context
    ) -> None:
        ctx = google_adk_context(
            SimpleNamespace(
                invocationId="inv-auto",
                sessionId="sess-auto",
                session_id="sess-auto",
            )
        )
        assert ctx.correlation_id is None

    def test_never_mints_when_nothing_is_present(self, reset_sequence_context) -> None:
        ctx = google_adk_context({})
        assert ctx.correlation_id is None
        assert isinstance(ctx, GoogleAdkContext)

    def test_falls_back_to_ambient_sequence(self, reset_sequence_context) -> None:
        with arcjet_sequence(correlation_id="from-sequence"):
            ctx = google_adk_context({})
        assert ctx.correlation_id == "from-sequence"

    def test_helper_session_id_wins_over_durable_state(
        self, reset_sequence_context
    ) -> None:
        ctx = google_adk_context(
            SimpleNamespace(
                invocationId="inv-auto",
                sessionId="sess-auto",
                state={"sessionId": "sess-stale"},
            ),
            session_id="policy-sess",
        )
        assert ctx.correlation_id == "policy-sess"

    def test_durable_state_used_when_helper_has_no_id(
        self, reset_sequence_context
    ) -> None:
        ctx = google_adk_context(
            SimpleNamespace(
                invocationId="inv-auto",
                sessionId="sess-auto",
                state={"sessionId": "sess-state"},
            )
        )
        assert ctx.correlation_id == "sess-state"

    def test_state_to_record(self, reset_sequence_context) -> None:
        state = SimpleNamespace(toRecord=lambda: {"sessionId": "from-record"})
        ctx = google_adk_context(SimpleNamespace(invocationId="inv-auto", state=state))
        assert ctx.correlation_id == "from-record"

    def test_kwargs_session_id(self, reset_sequence_context) -> None:
        ctx = google_adk_context({}, session_id="from-kw")
        assert ctx.correlation_id == "from-kw"
        assert ctx.metadata is not None
        assert ctx.metadata["google-adk.session"] == "from-kw"


class TestDenialEnvelope:
    def test_deny_dict_is_never_empty(self) -> None:
        payload = deny_dict(unavailable_result())
        assert payload
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "ERROR"
        assert payload["retryable"] is True
        assert payload["retryAfterSeconds"] == UNAVAILABLE_RETRY_AFTER_SECONDS

    def test_rate_limit_sets_retry_after(self) -> None:
        decision = make_deny_decision()
        payload = denial_result(decision)
        assert payload["arcjetDenied"] is True
        assert payload["reason"] == "RATE_LIMIT"
        assert payload["retryable"] is True

    def test_payload_from_block_uses_unavailable_when_not_deny(self) -> None:
        assert payload_from_block(None)["reason"] == "ERROR"
        assert payload_from_block(make_allow_decision())["reason"] == "ERROR"

    def test_verdict_allow_is_none_not_empty_dict(self) -> None:
        assert verdict_result(BeforeToolVerdict(deny=False)) is None

    def test_verdict_deny_is_non_empty_dict(self) -> None:
        result = verdict_result(
            BeforeToolVerdict(deny=True, payload=unavailable_result())
        )
        assert result is not None
        assert result != {}
        assert result["arcjetDenied"] is True


class TestEvaluateBeforeTool:
    def test_allow_returns_none_so_the_tool_can_run(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        verdict = asyncio.run(
            evaluate_before_tool(_tool(), {"value": "hello"}, {}, _config(guard=client))
        )
        assert verdict.deny is False
        assert verdict_result(verdict) is None
        assert client.guards[0]["label"] == "tool.invoked"
        assert client.guards[0]["correlation_id"] is None

    def test_deny_returns_skip_dict(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        verdict = asyncio.run(
            evaluate_before_tool(_tool(), {"value": "hello"}, {}, _config(guard=client))
        )
        result = verdict_result(verdict)
        assert result is not None
        assert result != {}
        assert result["arcjetDenied"] is True
        assert result["reason"] == "RATE_LIMIT"

    def test_fail_closed_unavailable_is_error_dict_never_none(
        self, reset_sequence_context
    ) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        assert decision.has_failed_open()
        client = StubGuardClient(decision=decision)
        result = asyncio.run(
            run_before_tool_callback(_tool(), {}, {}, _config(guard=client))
        )
        assert result is not None
        assert result != {}
        assert result["reason"] == "ERROR"

    def test_on_guard_error_allow_returns_none(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        result = asyncio.run(
            run_before_tool_callback(
                _tool(), {}, {}, _config(guard=client, on_guard_error="allow")
            )
        )
        assert result is None

    def test_thrown_guard_fail_closes_without_raising(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(exception=RuntimeError("transport down"))
        result = asyncio.run(
            run_before_tool_callback(_tool(), {}, {}, _config(guard=client))
        )
        assert result is not None
        assert result["reason"] == "ERROR"

    def test_policy_factory_throw_fail_closes(self, reset_sequence_context) -> None:
        def boom(_call: Mapping[str, Any]) -> tuple[Any, ...]:
            raise RuntimeError("rules exploded")

        client = StubGuardClient(decision=make_allow_decision())
        result = asyncio.run(
            run_before_tool_callback(_tool(), {}, {}, _config(guard=client, rules=boom))
        )
        assert result is not None
        assert result["reason"] == "ERROR"

    def test_branded_tool_is_skipped(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        result = asyncio.run(
            run_before_tool_callback(
                _tool(guarded=True), {"value": "x"}, {}, _config(guard=client)
            )
        )
        assert result is None
        assert client.guards == []

    def test_non_tool_context_is_passed_through(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        result = asyncio.run(
            run_before_tool_callback(None, {}, {}, _config(guard=client))
        )
        assert result is None
        assert client.guards == []

    def test_action_callback_names_the_guard_call(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_before_tool(
                _tool(name="mcp_search"),
                {"q": "hello"},
                {},
                _config(
                    guard=client,
                    action=lambda call: f"{call['tool_name']}.invoked",
                ),
            )
        )
        assert client.guards[0]["label"] == "mcp_search.invoked"

    def test_rules_see_tool_args_not_function_call_id(
        self, reset_sequence_context
    ) -> None:
        scanned: dict[str, Any] = {}
        client = StubGuardClient(decision=make_allow_decision())

        def rules(call: Mapping[str, Any]) -> tuple[Any, ...]:
            scanned.update(call)
            return ()

        asyncio.run(
            evaluate_before_tool(
                _tool(name="lookup"),
                {"note": "hello"},
                SimpleNamespace(invocationId="inv-auto", functionCallId="call-auto"),
                _config(guard=client, rules=rules),
            )
        )
        assert scanned["tool_name"] == "lookup"
        assert scanned["input"] == {"note": "hello"}
        assert scanned["note"] == "hello"
        assert "functionCallId" not in scanned

    def test_session_id_callback_receives_tool_name_and_input(
        self, reset_sequence_context
    ) -> None:
        seen: dict[str, Any] = {}
        client = StubGuardClient(decision=make_allow_decision())

        def session_id(call: Mapping[str, Any]) -> str:
            seen.update(call)
            return "sess-from-callback"

        asyncio.run(
            evaluate_before_tool(
                _tool(name="mcp_search"),
                {"q": "hello"},
                SimpleNamespace(invocationId="inv-auto"),
                _config(guard=client, session_id=session_id),
            )
        )
        assert seen["tool_name"] == "mcp_search"
        assert seen["input"] == {"q": "hello"}
        assert client.guards[0]["correlation_id"] == "sess-from-callback"

    def test_policy_session_id_never_uses_invocation_or_auto_session(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        asyncio.run(
            evaluate_before_tool(
                _tool(),
                {},
                SimpleNamespace(
                    invocationId="inv-auto",
                    sessionId="sess-auto",
                    functionCallId="call-auto",
                ),
                _config(guard=client, session_id="policy-sess"),
            )
        )
        assert client.guards[0]["correlation_id"] == "policy-sess"


class TestGuardToolCallback:
    def test_allow_runs_tool_function(self, reset_sequence_context) -> None:
        calls: list[str] = []

        def echo(*, value: str) -> dict[str, str]:
            calls.append(value)
            return {"value": value}

        client = StubGuardClient(decision=make_allow_decision())
        callback = guard_tool(guard=client, action="echo.invoked")
        result = _dispatch(callback, _tool(), {"value": "hello"}, {}, echo)
        assert calls == ["hello"]
        assert result == {"value": "hello"}

    def test_deny_skips_tool_function_and_returns_dict(
        self, reset_sequence_context
    ) -> None:
        calls: list[str] = []

        def echo(*, value: str) -> dict[str, str]:
            calls.append(value)
            return {"value": value}

        client = StubGuardClient(decision=make_deny_decision())
        callback = guard_tool(guard=client, action="echo.invoked")
        result = _dispatch(callback, _tool(), {"value": "hello"}, {}, echo)
        assert calls == []
        assert isinstance(result, dict)
        assert result != {}
        assert result["arcjetDenied"] is True
        assert result["reason"] == "RATE_LIMIT"

    def test_fail_closed_skips_tool_function(self, reset_sequence_context) -> None:
        calls: list[str] = []

        def echo(*, value: str) -> dict[str, str]:
            calls.append(value)
            return {"value": value}

        client = StubGuardClient(exception=RuntimeError("down"))
        callback = guard_tool(guard=client, action="echo.invoked")
        result = _dispatch(callback, _tool(), {"value": "hello"}, {}, echo)
        assert calls == []
        assert result is not None
        assert result["reason"] == "ERROR"

    def test_allow_result_is_none_not_empty_dict(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        callback = guard_tool(guard=client)
        result = asyncio.run(callback(_tool(), {"value": "x"}, {}))
        assert result is None
        assert result != {}

    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_tool(
                guard=StubGuardClient(),
                on_guard_error="maybe",  # type: ignore[arg-type]
            )

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            guard_tool(guard=StubGuardClient(), correlation_id="not\nvalid")


class TestGuardPlugin:
    def test_allow_returns_none(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        plugin = guard_plugin(guard=client, action="tool.invoked")
        assert isinstance(plugin.name, str)
        assert plugin.name.startswith("arcjet-guard-")
        result = asyncio.run(
            plugin.before_tool_callback(
                tool=_tool(), tool_args={"value": "hello"}, tool_context={}
            )
        )
        assert result is None

    def test_deny_returns_skip_dict(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        plugin = guard_plugin(guard=client)
        result = asyncio.run(
            plugin.before_tool_callback(
                tool=_tool(), tool_args={"note": "x"}, tool_context={}
            )
        )
        assert result is not None
        assert result != {}
        assert result["arcjetDenied"] is True

    def test_each_call_gets_a_unique_name(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        a = guard_plugin(guard=client)
        b = guard_plugin(guard=client)
        assert a.name != b.name

    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_plugin(on_guard_error="maybe")  # type: ignore[arg-type]


class TestMissingPeer:
    def test_load_google_adk_names_what_to_install(self) -> None:
        if google_adk_present():
            pytest.skip("google-adk is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[google-adk\]"):
            load_google_adk()

    def test_load_base_plugin_names_what_to_install(self) -> None:
        if google_adk_present():
            pytest.skip("google-adk is installed in this environment")
        with pytest.raises(ImportError, match=r"arcjet\[google-adk\]"):
            load_base_plugin()


class TestVersionFloor:
    def test_release_parsing(self) -> None:
        assert _release("2.0.0") == (2, 0, 0)
        assert _release("2.1.0") == (2, 1, 0)
        assert _release("2.0.0rc1") == (2, 0, 0)
        assert _release("weird") == ()
        assert _release("2.0") == (2, 0)
        assert _release("2.0.post1") == (2, 0)
        assert _release("1.16.0") < import_module.MINIMUM_GOOGLE_ADK
        assert _release("2.0.0") >= import_module.MINIMUM_GOOGLE_ADK

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "1.16.0")
        with pytest.raises(ArcjetMisconfiguration, match="needs google-adk >= 2.0.0"):
            import_module._require_google_adk()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("2.0.0", "2.1.0", "2.0.0rc1"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_google_adk()

    def test_absent_peer_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_google_adk()


class TestFailClosedHelperVsFailOpenProtect:
    def test_helper_denies_the_same_failed_open_protect_would_allow(
        self, reset_sequence_context
    ) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        assert decision.conclusion == "ALLOW"
        assert decision.has_failed_open()
        client = StubGuardClient(decision=decision)
        result = asyncio.run(
            run_before_tool_callback(_tool(), {}, {}, _config(guard=client))
        )
        assert result is not None
        assert result["reason"] == "ERROR"


def test_public_exports_are_only_the_locked_names() -> None:
    from arcjet.guard import google_adk as adapter

    assert adapter.__all__ == ["guard_tool", "guard_plugin", "google_adk_context"]
    assert not hasattr(adapter, "guard_inbound")
    assert not hasattr(adapter, "guard_approval")


def test_brand_constant_is_stable() -> None:
    assert _GUARD_BRAND == "_arcjet_guarded"


def test_extra_does_not_pull_chromadb() -> None:
    text = (Path(__file__).resolve().parents[3] / "pyproject.toml").read_text()
    assert 'google-adk = ["google-adk>=2.0.0,<3"]' in text
    assert "chromadb" not in text.split("google-adk = ")[1].split("\n", 1)[0]


def test_retry_after_seconds_without_reset_is_none() -> None:
    decision = make_deny_decision()
    assert retry_after_seconds(decision) is None

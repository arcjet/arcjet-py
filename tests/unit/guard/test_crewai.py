"""CrewAI adapter unit tests that must run with crewai absent.

The extra is not in the default dev group (CrewAI requires Python <3.14).
These tests import ``arcjet.guard.crewai`` helpers that do not load the peer.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from guard_doubles import (
    AsyncOnlyStubGuardClient,
    StubGuardClient,
    make_allow_decision,
    make_deny_decision,
)

from arcjet._errors import ArcjetMisconfiguration
from arcjet.guard import ArcjetDeniedError, ArcjetUnavailableError, arcjet_sequence
from arcjet.guard._policy_input import PolicyInputMap
from arcjet.guard._types import RuleResultError
from arcjet.guard.crewai._hooks import (
    ToolPolicy,
    _hook_config,
    evaluate_pre_tool_call,
    register_arcjet_hooks,
)
from arcjet.guard.crewai._import import crewai_present, load_crewai_hooks
from arcjet.guard.crewai._names import (
    _sanitize,
    free_text_arguments,
    sanitize_tool_name,
)
from arcjet.guard.crewai._tool import guard_tool

CREWAI_SRC = Path(__file__).resolve().parents[3] / "src" / "arcjet" / "guard" / "crewai"


def _ctx(**kwargs: object) -> SimpleNamespace:
    defaults: dict[str, object] = {
        "tool_name": "echo",
        "tool_input": {"value": "hello"},
        "tool": None,
        "agent": SimpleNamespace(role="researcher", name="r1", id="agent-uuid"),
        "task": SimpleNamespace(name="research", id="task-uuid"),
        "crew": SimpleNamespace(name="desk", id="crew-uuid"),
        "tool_result": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestSanitizeToolName:
    """The fallback copy of CrewAI's algorithm, exercised without the extra."""

    def test_matches_crewai_examples(self) -> None:
        assert _sanitize("Send Email") == "send_email"
        assert _sanitize("send_email") == "send_email"
        assert _sanitize("sendEmail") == "send_email"
        assert _sanitize("HTTPRequest") == "http_request"

    def test_truncates_with_hash_suffix(self) -> None:
        sanitized = _sanitize("a" * 80)
        assert len(sanitized) <= 64
        assert sanitized.startswith("a")

    def test_public_helper_agrees_with_the_fallback(self) -> None:
        """Whether or not it delegated, both spellings answer the same."""
        for name in ("Send Email", "sendEmail", "HTTPRequest", "already_sane"):
            assert sanitize_tool_name(name) == _sanitize(name)


class TestFreeTextArguments:
    """An opt-in helper. Nothing applies it to a resolver's arguments."""

    def test_drops_opaque_ids(self) -> None:
        filtered = free_text_arguments(
            {
                "query": "delete everything",
                "tool_call_id": "call_abc",
                "trace_id": "tr_1",
                "id": "opaque",
                "session_id": "sess",
                "user_id": "u_1",
            }
        )
        assert filtered == {"query": "delete everything"}

    def test_walks_nested_mappings(self) -> None:
        filtered = free_text_arguments(
            {"payload": {"body": "hi", "run_id": "r1"}, "count": 2}
        )
        assert filtered == {"payload": {"body": "hi"}, "count": 2}

    def test_non_mapping_is_empty(self) -> None:
        assert free_text_arguments("plain") == {}
        assert free_text_arguments(None) == {}


class TestSourceIsolation:
    def test_crewai_package_does_not_import_langchain(self) -> None:
        for path in CREWAI_SRC.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "langchain" not in node.module
                    assert node.module != "arcjet.guard.langchain"
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "langchain" not in alias.name

    def test_core_guard_imports_without_crewai(self) -> None:
        import arcjet.guard as guard

        assert hasattr(guard, "guard")
        assert hasattr(guard, "ArcjetUnavailableError")


class TestEvaluatePreToolCall:
    def test_deny_aborts_and_does_not_use_crew_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        ctx = _ctx()
        abort = evaluate_pre_tool_call(
            ctx, _hook_config(guard=client, correlation_id="session-99")
        )
        assert abort is not None
        assert "echo.invoked" in abort.reason
        assert client.guards[0]["correlation_id"] == "session-99"
        assert client.guards[0]["correlation_id"] != "crew-uuid"
        assert client.guards[0]["label"] == "echo.invoked"
        assert client.captures[0]["metadata"]["outcome"] == "denied"
        assert client.captures[0]["metadata"]["crew"] == "desk"
        assert client.captures[0]["metadata"]["task"] == "research"
        assert client.captures[0]["metadata"]["agent"] == "researcher"

    def test_allow_does_not_abort_and_captures_the_decision(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        abort = evaluate_pre_tool_call(_ctx(), _hook_config(guard=client))
        assert abort is None
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_each_call_is_captured_on_its_own_action(
        self, reset_sequence_context
    ) -> None:
        """A tool that runs a nested crew must not lose the outer event."""
        client = StubGuardClient(decision=make_allow_decision())
        config = _hook_config(guard=client)
        evaluate_pre_tool_call(_ctx(tool_name="outer"), config)
        evaluate_pre_tool_call(_ctx(tool_name="inner"), config)
        assert [capture["action"] for capture in client.captures] == [
            "outer.invoked",
            "inner.invoked",
        ]

    def test_guard_error_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        abort = evaluate_pre_tool_call(_ctx(), _hook_config(guard=client))
        assert abort is not None
        assert "could not be evaluated" in abort.reason
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_guard_error_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        abort = evaluate_pre_tool_call(
            _ctx(), _hook_config(guard=client, on_guard_error="allow")
        )
        assert abort is None

    def test_failed_open_fail_closed(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        abort = evaluate_pre_tool_call(_ctx(), _hook_config(guard=client))
        assert abort is not None
        assert "could not be evaluated" in abort.reason

    def test_policy_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any], _ctx: Any) -> PolicyInputMap:
            raise RuntimeError("resolver exploded")

        abort = evaluate_pre_tool_call(_ctx(), _hook_config(guard=client, inputs=boom))
        assert abort is not None
        assert "could not be evaluated" in abort.reason
        # Guard still saw the call — resolver failure is degraded, not skipped.
        assert len(client.guards) == 1

    def test_action_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_ctx: object) -> str:
            raise RuntimeError("no action")

        abort = evaluate_pre_tool_call(_ctx(), _hook_config(guard=client, action=boom))
        assert abort is not None
        assert "could not be evaluated" in abort.reason

    def test_ambient_sequence_is_used(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        with arcjet_sequence(correlation_id="from-sequence"):
            evaluate_pre_tool_call(_ctx(), _hook_config(guard=client))
        assert client.guards[0]["correlation_id"] == "from-sequence"

    def test_never_mints_from_crew_or_task_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        evaluate_pre_tool_call(_ctx(), _hook_config(guard=client))
        assert client.guards[0]["correlation_id"] is None

    def test_policies_and_tools_are_sanitized(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        abort = evaluate_pre_tool_call(
            _ctx(tool_name="send_email"),
            _hook_config(
                guard=client,
                policies={"Send Email": ToolPolicy(action="email.sent")},
                tools=["Send Email"],
            ),
        )
        assert abort is not None
        assert client.guards[0]["label"] == "email.sent"

    def test_tools_filter_skips_other_names(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        abort = evaluate_pre_tool_call(
            _ctx(tool_name="search"),
            _hook_config(guard=client, tools=["Send Email"]),
        )
        assert abort is None
        assert client.guards == []

    def test_resolver_sees_the_tools_own_arguments(
        self, reset_sequence_context
    ) -> None:
        """Including an id-shaped argument the policy itself needs."""
        seen: list[Mapping[str, Any]] = []

        def actor(arguments: Mapping[str, Any], _ctx: Any) -> str:
            seen.append(dict(arguments))
            return str(arguments["user_id"])

        client = StubGuardClient(decision=make_allow_decision())
        abort = evaluate_pre_tool_call(
            _ctx(tool_input={"user_id": "u_1", "body": "hello"}),
            _hook_config(guard=client, actor=actor),
        )
        assert abort is None
        assert seen == [{"user_id": "u_1", "body": "hello"}]
        assert client.guards[0]["actor"] == "u_1"


class TestRegistrarValidation:
    """Wiring mistakes are refused where they are made, not per call.

    A hook cannot report one: CrewAI swallows everything except
    ``HookAborted``, so under ``on_guard_error="allow"`` a bad client would
    silently allow every tool call.
    """

    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            register_arcjet_hooks(on_guard_error="maybe")  # type: ignore[arg-type]

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            register_arcjet_hooks(correlation_id="not\nvalid")

    def test_async_client_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="blocking guard"):
            register_arcjet_hooks(
                guard=AsyncOnlyStubGuardClient(decision=make_allow_decision())
            )

    def test_guard_tool_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            guard_tool(
                guard=StubGuardClient(),
                tool=object(),
                action="x.done",
                on_guard_error="maybe",  # type: ignore[arg-type]
            )


class TestMissingExtra:
    def test_register_names_the_extra_when_crewai_absent(self) -> None:
        if crewai_present():
            pytest.skip("crewai is installed in this environment")
        with pytest.raises(ImportError, match="arcjet\\[crewai\\]"):
            register_arcjet_hooks()

    def test_guard_tool_names_the_extra_when_crewai_absent(self) -> None:
        if crewai_present():
            pytest.skip("crewai is installed in this environment")
        with pytest.raises(ImportError, match="arcjet\\[crewai\\]"):
            guard_tool(guard=StubGuardClient(), tool=object(), action="x.done")

    def test_load_hooks_names_the_extra_when_crewai_absent(self) -> None:
        if crewai_present():
            pytest.skip("crewai is installed in this environment")
        with pytest.raises(ImportError, match="arcjet\\[crewai\\]"):
            load_crewai_hooks()


def test_public_errors_remain_for_guard_tool_path() -> None:
    """The wrap path is the only one that raises these; they still exist."""
    assert issubclass(ArcjetDeniedError, Exception)
    assert issubclass(ArcjetUnavailableError, Exception)

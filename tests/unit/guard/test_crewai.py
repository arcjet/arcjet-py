"""CrewAI adapter unit tests that must run with crewai absent.

The extra is not in the default dev group (CrewAI requires Python <3.14).
These tests import ``arcjet.guard.crewai`` helpers that do not load the peer.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from guard_doubles import (
    AsyncOnlyStubGuardClient,
    StubGuardClient,
    make_allow_decision,
    make_deny_decision,
)

from arcjet._errors import ArcjetMisconfiguration
from arcjet.guard import ArcjetDeniedError, ArcjetUnavailableError, arcjet_sequence
from arcjet.guard._types import RuleResultError
from arcjet.guard.crewai._hooks import (
    ToolPolicy,
    _HookConfig,
    _pending,
    capture_post_tool_call,
    evaluate_pre_tool_call,
    register_arcjet_hooks,
)
from arcjet.guard.crewai._import import crewai_present, load_crewai_hooks
from arcjet.guard.crewai._names import free_text_arguments, sanitize_tool_name
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


def _config(**kwargs: object) -> _HookConfig:
    values: dict[str, object] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": None,
        "actor": None,
        "inputs": None,
        "rules": (),
        "metadata": None,
        "correlation_id": None,
        "on_guard_error": "deny",
        "policies": {},
        "tools": None,
    }
    values.update(kwargs)
    return _HookConfig(**values)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _clear_pending():
    token = _pending.set(None)
    try:
        yield
    finally:
        _pending.reset(token)


class TestSanitizeToolName:
    def test_matches_crewai_examples(self) -> None:
        assert sanitize_tool_name("Send Email") == "send_email"
        assert sanitize_tool_name("send_email") == "send_email"
        assert sanitize_tool_name("sendEmail") == "send_email"
        assert sanitize_tool_name("HTTPRequest") == "http_request"

    def test_truncates_with_hash_suffix(self) -> None:
        long = "a" * 80
        sanitized = sanitize_tool_name(long)
        assert len(sanitized) <= 64
        assert sanitized.startswith("a")


class TestFreeTextArguments:
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

    def test_non_dict_is_empty(self) -> None:
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
            ctx, _config(guard=client, correlation_id="session-99")
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

    def test_allow_does_not_abort(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        abort = evaluate_pre_tool_call(_ctx(), _config(guard=client))
        assert abort is None
        assert client.captures == []
        pending = _pending.get()
        assert pending is not None
        assert pending.blocked is False

    def test_guard_error_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        abort = evaluate_pre_tool_call(_ctx(), _config(guard=client))
        assert abort is not None
        assert "could not be evaluated" in abort.reason
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_guard_error_allow_proceeds(self, reset_sequence_context) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        abort = evaluate_pre_tool_call(
            _ctx(), _config(guard=client, on_guard_error="allow")
        )
        assert abort is None

    def test_failed_open_fail_closed(self, reset_sequence_context) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        abort = evaluate_pre_tool_call(_ctx(), _config(guard=client))
        assert abort is not None
        assert "could not be evaluated" in abort.reason

    def test_policy_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: object, _ctx: object) -> object:
            raise RuntimeError("resolver exploded")

        abort = evaluate_pre_tool_call(_ctx(), _config(guard=client, inputs=boom))
        assert abort is not None
        assert "could not be evaluated" in abort.reason
        # Guard still saw the call — resolver failure is degraded, not skipped.
        assert len(client.guards) == 1

    def test_action_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_ctx: object) -> str:
            raise RuntimeError("no action")

        abort = evaluate_pre_tool_call(_ctx(), _config(guard=client, action=boom))
        assert abort is not None
        assert "could not be evaluated" in abort.reason

    def test_async_client_fail_closed(self, reset_sequence_context) -> None:
        client = AsyncOnlyStubGuardClient(decision=make_allow_decision())
        abort = evaluate_pre_tool_call(_ctx(), _config(guard=client))
        assert abort is not None
        assert "could not be evaluated" in abort.reason

    def test_ambient_sequence_is_used(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        with arcjet_sequence(correlation_id="from-sequence"):
            evaluate_pre_tool_call(_ctx(), _config(guard=client))
        assert client.guards[0]["correlation_id"] == "from-sequence"

    def test_never_mints_from_crew_or_task_id(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        evaluate_pre_tool_call(_ctx(), _config(guard=client))
        assert client.guards[0]["correlation_id"] is None

    def test_policies_and_tools_are_sanitized(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        abort = evaluate_pre_tool_call(
            _ctx(tool_name="send_email"),
            _config(
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
            _config(guard=client, tools=["Send Email"]),
        )
        assert abort is None
        assert client.guards == []

    def test_scans_free_text_not_opaque_ids(self, reset_sequence_context) -> None:
        seen: list[object] = []

        def inputs(arguments: object, _ctx: object) -> object:
            seen.append(arguments)
            return None

        client = StubGuardClient(decision=make_allow_decision())
        evaluate_pre_tool_call(
            _ctx(tool_input={"query": "hello", "tool_call_id": "call_1", "id": "x"}),
            _config(guard=client, inputs=inputs),
        )
        assert seen == [{"query": "hello"}]


class TestPostCapture:
    def test_allowed_call_emits_success(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        evaluate_pre_tool_call(_ctx(), _config(guard=client))
        capture_post_tool_call(_ctx(tool_result="ok"))
        assert client.captures[0]["metadata"]["outcome"] == "success"

    def test_blocked_call_does_not_emit_success(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        evaluate_pre_tool_call(_ctx(), _config(guard=client))
        before = list(client.captures)
        capture_post_tool_call(
            _ctx(tool_result="Tool execution blocked by hook. Tool: echo")
        )
        assert client.captures == before
        assert _pending.get() is None

    def test_does_not_rewrite_result(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        evaluate_pre_tool_call(_ctx(), _config(guard=client))
        ctx = _ctx(tool_result="original")
        assert capture_post_tool_call(ctx) is None
        assert ctx.tool_result == "original"


class TestRegistrarValidation:
    def test_invalid_on_guard_error_is_refused(self) -> None:
        with pytest.raises(ArcjetMisconfiguration, match="on_guard_error"):
            register_arcjet_hooks(on_guard_error="maybe")  # type: ignore[arg-type]

    def test_invalid_correlation_id_is_refused(self) -> None:
        with pytest.raises(ValueError, match="printable ASCII"):
            register_arcjet_hooks(correlation_id="not\nvalid")

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

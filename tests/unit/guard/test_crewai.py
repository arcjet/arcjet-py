"""CrewAI adapter unit tests that must run with crewai absent.

The extra is not in the default dev group (CrewAI requires Python <3.14).
These tests import ``arcjet.guard.crewai`` helpers that do not load the peer.
"""

from __future__ import annotations

import ast
import asyncio
import subprocess
import sys
import warnings
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from guard_doubles import (
    NOT_BOUND_RULES,
    AsyncOnlyStubGuardClient,
    StubGuardClient,
    make_allow_decision,
    make_deny_decision,
)

from arcjet._errors import ArcjetMisconfiguration
from arcjet.guard import ArcjetDeniedError, ArcjetUnavailableError, arcjet_sequence
from arcjet.guard._policy_input import PolicyInputMap
from arcjet.guard._types import RuleResultError
from arcjet.guard.crewai import _import as import_module
from arcjet.guard.crewai import _tool as tool_module
from arcjet.guard.crewai._hooks import (
    ToolPolicy,
    _hook_config,
    evaluate_pre_tool_call,
    register_arcjet_hooks,
)
from arcjet.guard.crewai._import import _release, crewai_present, load_crewai_hooks
from arcjet.guard.crewai._names import (
    _sanitize,
    free_text_arguments,
    sanitize_tool_name,
)
from arcjet.guard.crewai._tool import _UNREADABLE, _arguments_from_call, guard_tool

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

    def test_core_guard_imports_with_crewai_unimportable(self) -> None:
        """The real invariant, in a process where ``crewai`` cannot import.

        Asserted in a subprocess rather than here, because this module has
        already imported both packages: a check in-process would pass even if
        core Guard grew a hard dependency on CrewAI.
        """
        program = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "crewai" or name.startswith("crewai."):
            raise ImportError("crewai is blocked for this test")
        return None

sys.meta_path.insert(0, _Blocked())

import arcjet.guard
assert callable(arcjet.guard.guard)
assert arcjet.guard.ArcjetUnavailableError is not None
assert "crewai" not in sys.modules

# The adapter itself imports too, and names the extra when it is reached.
import arcjet.guard.crewai as adapter
try:
    adapter.register_arcjet_hooks()
except ImportError as exc:
    assert "crewai>=1.15.3,<2" in str(exc), exc
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

    def test_rules_factory_throw_fail_closed(self, reset_sequence_context) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any], _hook_ctx: Any) -> list[Any]:
            raise RuntimeError("no rules")

        verdict = evaluate_pre_tool_call(_ctx(), _hook_config(guard=client, rules=boom))
        assert verdict is not None
        # Guard still sees the call, without local rules, so remote policy runs.
        assert [guard["rules"] for guard in client.guards] == [()]
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"
        assert client.captures[0]["decision_id"] == "gdec_test_allow"

    def test_rules_factory_throw_allow_proceeds_and_records_degraded(
        self, reset_sequence_context
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_arguments: Mapping[str, Any], _hook_ctx: Any) -> list[Any]:
            raise RuntimeError("no rules")

        verdict = evaluate_pre_tool_call(
            _ctx(), _hook_config(guard=client, rules=boom, on_guard_error="allow")
        )
        assert verdict is None
        assert [guard["rules"] for guard in client.guards] == [()]
        assert client.captures[0]["metadata"]["outcome"] == "degraded"
        assert client.captures[0]["decision_id"] == "gdec_test_allow"

    @pytest.mark.parametrize(
        "returned", NOT_BOUND_RULES.values(), ids=NOT_BOUND_RULES.keys()
    )
    def test_rules_factory_returning_no_bound_rules_fail_closed(
        self, reset_sequence_context, returned: Callable[[], Any]
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            verdict = evaluate_pre_tool_call(
                _ctx(), _hook_config(guard=client, rules=lambda _a, _c: returned())
            )
        assert verdict is not None
        assert [guard["rules"] for guard in client.guards] == [()]
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"

    def test_failed_open_allow_proceeds_and_records_degraded(
        self, reset_sequence_context
    ) -> None:
        decision = make_allow_decision(
            results=(RuleResultError(code="TIMEOUT", message="deadline"),)
        )
        client = StubGuardClient(decision=decision)
        abort = evaluate_pre_tool_call(
            _ctx(), _hook_config(guard=client, on_guard_error="allow")
        )
        assert abort is None
        assert client.captures[0]["metadata"]["outcome"] == "degraded"

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


class TestArgumentsFromCall:
    """How a direct call's arguments are named for a resolver."""

    def test_keyword_mapping_and_single_positional_calls_are_named(self) -> None:
        assert _arguments_from_call((), {"value": "x"}) == {"value": "x"}
        assert _arguments_from_call(({"value": "x"},), {}) == {"value": "x"}
        assert _arguments_from_call(("bare",), {}) == {"input": "bare"}
        assert _arguments_from_call((), {}) == {}

    def test_multi_positional_call_is_unreadable_not_empty(self) -> None:
        """An empty mapping would report a clean evaluation of nothing."""
        assert _arguments_from_call(("a", "b"), {}) is _UNREADABLE


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


class TestMissingPeer:
    """CrewAI is not an Arcjet dependency, so the error has to name it."""

    def test_register_names_what_to_install(self) -> None:
        if crewai_present():
            pytest.skip("crewai is installed in this environment")
        with pytest.raises(ImportError, match=r'pip install "crewai>=1\.15\.3,<2"'):
            register_arcjet_hooks()

    def test_guard_tool_names_what_to_install(self) -> None:
        if crewai_present():
            pytest.skip("crewai is installed in this environment")
        with pytest.raises(ImportError, match=r'pip install "crewai>=1\.15\.3,<2"'):
            guard_tool(guard=StubGuardClient(), tool=object(), action="x.done")

    def test_load_hooks_names_what_to_install(self) -> None:
        if crewai_present():
            pytest.skip("crewai is installed in this environment")
        with pytest.raises(ImportError, match="needs CrewAI"):
            load_crewai_hooks()


class TestVersionFloor:
    """A CrewAI too old to deny is refused where it can still be reported."""

    def test_release_parsing(self) -> None:
        assert _release("1.15.3") == (1, 15, 3)
        assert _release("1.15.16") == (1, 15, 16)
        assert _release("2.0.0b1") == (2, 0, 0)
        assert _release("1.15") == (1, 15)
        assert _release("weird") == ()

    def test_below_the_floor_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(import_module, "_installed_version", lambda: "1.15.2")
        with pytest.raises(ArcjetMisconfiguration, match="needs crewai >= 1.15.3"):
            import_module._require_crewai()

    def test_at_or_above_the_floor_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for installed in ("1.15.3", "1.15.16", "1.16.0"):
            monkeypatch.setattr(
                import_module, "_installed_version", lambda v=installed: v
            )
            import_module._require_crewai()

    def test_absent_crewai_is_left_to_the_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ImportError names what to install; this check stays quiet."""
        monkeypatch.setattr(import_module, "_installed_version", lambda: None)
        import_module._require_crewai()


class _FakeBaseTool:
    """Stands in for CrewAI's ``BaseTool`` so the wrap runs without CrewAI.

    ``guard_tool`` asks CrewAI only for the class to check against; every
    entrypoint it installs is read off the tool itself, so a class with the
    same entrypoints exercises the same checkpoint.
    """

    def __init__(self) -> None:
        self.calls: list[Mapping[str, Any]] = []

    def model_copy(self) -> "_FakeBaseTool":
        copy = type(self)()
        copy.calls = self.calls
        return copy

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        return await self._arun(*args, **kwargs)

    def _run(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return "ran"

    async def _arun(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return "ran"


class TestGuardToolRules:
    """``rules=`` may be a callable of the call's arguments."""

    @pytest.fixture(autouse=True)
    def _fake_crewai(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(tool_module, "load_crewai_base_tool", lambda: _FakeBaseTool)

    def test_rules_are_bound_from_each_calls_arguments(self) -> None:
        from arcjet.guard import LocalDetectSensitiveInfo, TokenBucket

        bucket = TokenBucket(refill_rate=10, interval_seconds=60, max_tokens=100)
        sensitive = LocalDetectSensitiveInfo(deny=["EMAIL"])
        seen: list[Mapping[str, Any]] = []

        def rules(arguments: Mapping[str, Any]) -> list[Any]:
            seen.append(arguments)
            return [
                bucket(key=str(arguments["user"]), requested=int(arguments["count"])),
                sensitive(str(arguments["body"])),
            ]

        client = StubGuardClient(decision=make_allow_decision())
        tool = _FakeBaseTool()
        guarded = guard_tool(guard=client, tool=tool, action="m.sent", rules=rules)

        assert guarded.run(user="u1", count=3, body="hi") == "ran"
        assert guarded.run(user="u2", count=7, body="a@b.co") == "ran"

        assert seen == [
            {"user": "u1", "count": 3, "body": "hi"},
            {"user": "u2", "count": 7, "body": "a@b.co"},
        ]
        sent = [guard["rules"] for guard in client.guards]
        assert [(r[0].key, r[0].requested) for r in sent] == [("u1", 3), ("u2", 7)]
        assert [r[1].text for r in sent] == ["hi", "a@b.co"]
        assert len(tool.calls) == 2

    def test_rules_resolver_runs_on_the_async_entrypoint(self) -> None:
        """Called synchronously there too, as *actor* and *inputs* are."""
        from arcjet.guard import TokenBucket

        bucket = TokenBucket(refill_rate=10, interval_seconds=60, max_tokens=100)
        client = StubGuardClient(decision=make_allow_decision())
        guarded = guard_tool(
            guard=client,
            tool=_FakeBaseTool(),
            action="m.sent",
            rules=lambda arguments: [
                bucket(key="u", requested=int(arguments["count"]))
            ],
        )

        assert asyncio.run(guarded.arun(count=5)) == "ran"
        assert client.guards[0]["rules"][0].requested == 5

    def test_an_async_rules_resolver_fails_closed(self) -> None:
        """*actor* and *inputs* are never awaited here, so rules are not either."""

        async def rules(arguments: Mapping[str, Any]) -> list[Any]:
            return []

        client = StubGuardClient(decision=make_allow_decision())
        tool = _FakeBaseTool()
        guarded = guard_tool(
            guard=client, tool=tool, action="m.sent", rules=cast(Any, rules)
        )

        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with pytest.raises(ArcjetUnavailableError) as raised:
                asyncio.run(guarded.arun(count=1))
        assert isinstance(raised.value.__cause__, TypeError)
        assert tool.calls == []

    def test_a_list_of_rules_is_sent_unchanged(self) -> None:
        from arcjet.guard import TokenBucket

        rules = [TokenBucket(refill_rate=1, interval_seconds=60, max_tokens=5)(key="k")]
        client = StubGuardClient(decision=make_allow_decision())
        guarded = guard_tool(
            guard=client, tool=_FakeBaseTool(), action="m.sent", rules=rules
        )
        guarded.run(count=1)

        assert client.guards[0]["rules"] is rules

    def test_a_raising_rules_resolver_fails_closed_and_still_records(self) -> None:
        def rules(arguments: Mapping[str, Any]) -> list[Any]:
            raise KeyError("count")

        client = StubGuardClient(decision=make_allow_decision())
        tool = _FakeBaseTool()
        guarded = guard_tool(guard=client, tool=tool, action="m.sent", rules=rules)

        with pytest.raises(ArcjetUnavailableError) as raised:
            guarded.run(user="u")
        assert isinstance(raised.value.__cause__, KeyError)
        assert tool.calls == []
        assert [guard["rules"] for guard in client.guards] == [()]
        assert client.captures[-1]["metadata"]["outcome"] == "unavailable"

    def test_a_raising_rules_resolver_runs_the_tool_under_allow(self) -> None:
        def rules(arguments: Mapping[str, Any]) -> list[Any]:
            raise KeyError("count")

        client = StubGuardClient(decision=make_allow_decision())
        tool = _FakeBaseTool()
        guarded = guard_tool(
            guard=client,
            tool=tool,
            action="m.sent",
            rules=rules,
            on_guard_error="allow",
        )

        assert guarded.run(user="u") == "ran"
        assert [guard["rules"] for guard in client.guards] == [()]
        assert client.captures[-1]["metadata"]["outcome"] == "degraded"

    @pytest.mark.parametrize(
        "returned",
        [None, "not rules", 42, [object()], ["a string"], "unbound"],
        ids=["none", "string", "int", "object", "string-element", "unbound-rule"],
    )
    def test_a_rules_resolver_returning_no_bound_rules_fails_closed(
        self, returned: Any
    ) -> None:
        from arcjet.guard import TokenBucket

        if returned == "unbound":
            returned = [TokenBucket(refill_rate=1, interval_seconds=60, max_tokens=5)]
        client = StubGuardClient(decision=make_allow_decision())
        tool = _FakeBaseTool()
        guarded = guard_tool(
            guard=client,
            tool=tool,
            action="m.sent",
            rules=lambda _arguments: cast(Any, returned),
        )

        with pytest.raises(ArcjetUnavailableError) as raised:
            guarded.run(count=1)
        assert isinstance(raised.value.__cause__, TypeError)
        assert tool.calls == []
        assert [guard["rules"] for guard in client.guards] == [()]

    def test_unreadable_arguments_fail_closed_for_a_rules_resolver(self) -> None:
        """Several positional values cannot be named for the resolver."""
        client = StubGuardClient(decision=make_allow_decision())
        guarded = guard_tool(
            guard=client,
            tool=_FakeBaseTool(),
            action="m.sent",
            rules=lambda _arguments: [],
        )

        with pytest.raises(ArcjetUnavailableError):
            guarded._run("a", "b")
        assert len(client.guards) == 1


def test_public_errors_remain_for_guard_tool_path() -> None:
    """The wrap path is the only one that raises these; they still exist."""
    assert issubclass(ArcjetDeniedError, Exception)
    assert issubclass(ArcjetUnavailableError, Exception)

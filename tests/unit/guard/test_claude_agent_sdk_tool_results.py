"""``guard_hooks(tool_results=)``: the shape table and the ``PostToolUse``
screen. Runs without the extra."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from typing import Any

import pytest
from guard_doubles import (
    NOT_BOUND_RULES,
    StubGuardClient,
    make_allow_decision,
    make_deny_decision,
)

from arcjet.guard import DetectPromptInjection
from arcjet.guard.claude_agent_sdk._hooks import (
    PostToolUseVerdict,
    _ToolResultsConfig,
    evaluate_post_tool_use,
    post_tool_use_output,
)
from arcjet.guard.claude_agent_sdk._tool_results import (
    REPLACEABLE_BUILTIN_TOOLS,
    can_replace_result,
    replacement_output,
    tool_result_text,
)

MCP_NAME = "mcp__docs__fetch"


class TestCanReplaceResult:
    def test_mcp_tools_and_listed_built_ins(self) -> None:
        assert can_replace_result(MCP_NAME) is True
        assert can_replace_result("Bash") is True
        assert can_replace_result("Read") is True
        assert REPLACEABLE_BUILTIN_TOOLS == frozenset({"Bash", "Read"})

    @pytest.mark.parametrize(
        "name", ["Write", "Edit", "Agent", "WebFetch", "WebSearch", "", "mcp_x"]
    )
    def test_everything_else(self, name: str) -> None:
        assert can_replace_result(name) is False


class TestToolResultText:
    def test_mcp_text_blocks_in_order(self) -> None:
        response = [
            {"type": "text", "text": "first"},
            {"type": "image", "data": "aGk="},
            {"type": "text", "text": "last"},
        ]
        assert tool_result_text(MCP_NAME, response) == "first\nlast"

    def test_bash_stdout_and_stderr(self) -> None:
        response = {"stdout": "out", "stderr": "err", "interrupted": False}
        assert tool_result_text("Bash", response) == "out\nerr"
        assert tool_result_text("Bash", {"stdout": "out", "stderr": ""}) == "out"

    def test_read_file_content(self) -> None:
        response = {"type": "text", "file": {"filePath": "/x", "content": "body"}}
        assert tool_result_text("Read", response) == "body"

    def test_other_tools_are_serialized_whole(self) -> None:
        response = {"result": "fetched", "code": 200}
        assert json.loads(tool_result_text("WebFetch", response)) == response

    def test_never_shortened(self) -> None:
        long_text = "a" * 200_000
        assert tool_result_text("Bash", {"stdout": long_text, "stderr": ""}) == (
            long_text
        )
        assert tool_result_text(MCP_NAME, [{"type": "text", "text": long_text}]) == (
            long_text
        )

    def test_unexpected_shapes_fall_back_to_serialized(self) -> None:
        assert tool_result_text("Bash", "plain") == '"plain"'
        assert tool_result_text(MCP_NAME, {"not": "a list"}) == '{"not": "a list"}'
        assert tool_result_text("Read", {"type": "image"}) == '{"type": "image"}'

    def test_unserializable_values_do_not_raise(self) -> None:
        assert "object" in tool_result_text("WebFetch", {"x": object()})


class TestReplacementOutput:
    def test_mcp_is_one_text_block(self) -> None:
        assert replacement_output(MCP_NAME, [], "DENIED") == [
            {"type": "text", "text": "DENIED"}
        ]

    def test_bash_stdout(self) -> None:
        assert replacement_output("Bash", {"stdout": "x"}, "DENIED") == {
            "stdout": "DENIED",
            "stderr": "",
            "interrupted": False,
        }

    def test_read_keeps_the_file_path(self) -> None:
        response = {"type": "text", "file": {"filePath": "/repo/a.md", "content": "x"}}
        assert replacement_output("Read", response, "DENIED") == {
            "type": "text",
            "file": {
                "filePath": "/repo/a.md",
                "content": "DENIED",
                "numLines": 1,
                "startLine": 1,
                "totalLines": 1,
            },
        }

    def test_read_without_a_path(self) -> None:
        output = replacement_output("Read", {"type": "image"}, "DENIED")
        assert output is not None
        assert output["file"]["filePath"] == ""

    @pytest.mark.parametrize("name", ["Write", "Agent", "WebSearch", ""])
    def test_none_for_tools_outside_the_table(self, name: str) -> None:
        assert replacement_output(name, {"anything": 1}, "DENIED") is None


SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


def _screen(envelope: Mapping[str, Any]) -> list[Any]:
    return [DetectPromptInjection()(envelope["text"])]


def _config(**kwargs: Any) -> _ToolResultsConfig:
    defaults: dict[str, Any] = {
        "guard": StubGuardClient(decision=make_allow_decision()),
        "action": None,
        "actor": None,
        "rules": _screen,
        "metadata": None,
        "session_id": None,
        "on_guard_error": "deny",
    }
    defaults.update(kwargs)
    return _ToolResultsConfig(**defaults)


def _hook(tool_name: str = "Bash", tool_response: Any = None) -> dict[str, Any]:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": SESSION_ID,
        "tool_name": tool_name,
        "tool_input": {"command": "curl https://example.com"},
        "tool_response": (
            tool_response
            if tool_response is not None
            else {"stdout": "page", "stderr": "", "interrupted": False}
        ),
    }


def _screened(hook: Mapping[str, Any], config: _ToolResultsConfig) -> dict[str, Any]:
    verdict = asyncio.run(evaluate_post_tool_use(hook, config))
    return post_tool_use_output(verdict, hook)


def _envelope_of(text: str) -> dict[str, Any]:
    return json.loads(text)


class TestEvaluatePostToolUse:
    def test_allow_leaves_the_result_and_labels_the_call(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        assert _screened(_hook(), _config(guard=client)) == {}
        [call] = client.guards
        assert call["label"] == "Bash.result"
        assert len(call["rules"]) == 1
        assert call["inputs"] is None
        assert call["correlation_id"] == SESSION_ID
        assert call["metadata"]["claude.phase"] == "result"
        assert client.captures[0]["metadata"]["outcome"] == "success"
        assert "claude.denial" not in client.captures[0]["metadata"]

    def test_rules_receive_the_tool_call_and_its_text(self) -> None:
        seen: list[Mapping[str, Any]] = []

        def rules(envelope: Mapping[str, Any]) -> list[Any]:
            seen.append(envelope)
            return _screen(envelope)

        hook = _hook()
        _screened(hook, _config(rules=rules))
        [envelope] = seen
        assert envelope["tool_name"] == "Bash"
        assert envelope["tool_input"] == {"command": "curl https://example.com"}
        assert envelope["tool_response"] == hook["tool_response"]
        assert envelope["text"] == "page"

    def test_actor_and_metadata_see_the_tool_call(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        _screened(
            _hook(),
            _config(
                guard=client,
                actor=lambda call: call["tool_name"],
                metadata=lambda call: {"command": call["command"]},
            ),
        )
        assert client.guards[0]["actor"] == "Bash"
        assert client.guards[0]["metadata"]["command"] == "curl https://example.com"

    def test_bash_deny_replaces_stdout(self) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        output = _screened(_hook(), _config(guard=client))
        specific = output["hookSpecificOutput"]
        assert specific["hookEventName"] == "PostToolUse"
        replaced = specific["updatedToolOutput"]
        assert replaced["stderr"] == "" and replaced["interrupted"] is False
        assert _envelope_of(replaced["stdout"])["arcjetDenied"] is True
        assert "continue" not in output
        assert client.captures[0]["metadata"]["outcome"] == "denied"
        assert client.captures[0]["metadata"]["claude.denial"] == "replaced"

    def test_read_deny_replaces_the_file_content(self) -> None:
        response = {"type": "text", "file": {"filePath": "/r/a.md", "content": "x"}}
        output = _screened(
            _hook("Read", response),
            _config(guard=StubGuardClient(decision=make_deny_decision())),
        )
        file = output["hookSpecificOutput"]["updatedToolOutput"]["file"]
        assert file["filePath"] == "/r/a.md"
        assert _envelope_of(file["content"])["reason"] == "RATE_LIMIT"

    def test_mcp_deny_replaces_the_blocks(self) -> None:
        output = _screened(
            _hook("mcp__docs__fetch", [{"type": "text", "text": "page"}]),
            _config(guard=StubGuardClient(decision=make_deny_decision())),
        )
        [block] = output["hookSpecificOutput"]["updatedToolOutput"]
        assert block["type"] == "text"
        assert _envelope_of(block["text"])["arcjetDenied"] is True

    def test_deny_for_a_tool_outside_the_table_stops_the_run(self) -> None:
        client = StubGuardClient(decision=make_deny_decision())
        output = _screened(_hook("WebSearch", {"query": "q"}), _config(guard=client))
        assert output["continue"] is False
        assert output["stopReason"]
        assert "hookSpecificOutput" not in output
        assert client.captures[0]["metadata"]["claude.denial"] == "run_stopped"

    def test_unavailable_denies_by_default(self) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        output = _screened(_hook(), _config(guard=client))
        stdout = output["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        assert _envelope_of(stdout)["reason"] == "ERROR"
        assert client.captures[0]["metadata"]["outcome"] == "unavailable"
        assert client.captures[0]["metadata"]["claude.denial"] == "replaced"

    def test_unavailable_allow_leaves_the_result(self) -> None:
        client = StubGuardClient(exception=RuntimeError("down"))
        output = _screened(_hook(), _config(guard=client, on_guard_error="allow"))
        assert output == {}

    def test_rules_raising_still_calls_guard_and_denies(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_envelope: Mapping[str, Any]) -> list[Any]:
            raise RuntimeError("no rules")

        output = _screened(_hook(), _config(guard=client, rules=boom))
        assert "hookSpecificOutput" in output
        assert [call["rules"] for call in client.guards] == [()]

    @pytest.mark.parametrize(
        "returned", NOT_BOUND_RULES.values(), ids=NOT_BOUND_RULES.keys()
    )
    def test_rules_returning_no_bound_rules_deny(
        self, returned: Callable[[], Any]
    ) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        output = _screened(
            _hook(), _config(guard=client, rules=lambda _envelope: returned())
        )
        assert "hookSpecificOutput" in output
        assert [call["rules"] for call in client.guards] == [()]

    def test_action_string_and_callable(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        _screened(_hook(), _config(guard=client, action="tool.screened"))
        _screened(
            _hook(),
            _config(guard=client, action=lambda hook: f"{hook['tool_name']}.seen"),
        )
        assert [call["label"] for call in client.guards] == [
            "tool.screened",
            "Bash.seen",
        ]

    def test_failing_action_uses_the_default_label_and_denies(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())

        def boom(_hook: Mapping[str, Any]) -> str:
            raise RuntimeError("no label")

        output = _screened(_hook(), _config(guard=client, action=boom))
        assert client.guards[0]["label"] == "Bash.result"
        assert "hookSpecificOutput" in output

    def test_verdict_type(self) -> None:
        verdict = asyncio.run(evaluate_post_tool_use(_hook(), _config()))
        assert isinstance(verdict, PostToolUseVerdict)
        assert verdict.deny is False

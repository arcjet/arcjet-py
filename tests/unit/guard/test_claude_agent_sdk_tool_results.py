"""Shape table for replacing a denied tool result. Runs without the extra."""

from __future__ import annotations

import json

import pytest

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

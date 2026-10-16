"""How a denied tool result is kept from the model on ``PostToolUse``.

The CLI accepts ``updatedToolOutput`` for an MCP tool in any shape. For a
built-in tool it validates the replacement against that tool's output
schema, and a mismatch sends the **original** result to the model without
telling the SDK. The schemas are not published, so only tools whose shape
an integration test drives through the bundled CLI are listed here; every
other tool is stopped instead (see ``post_tool_use_output``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Optional

#: Built-in tools whose denied result is replaced. Every ``mcp__`` tool is
#: replaced too.
REPLACEABLE_BUILTIN_TOOLS: frozenset[str] = frozenset({"Bash", "Read"})

_MCP_PREFIX = "mcp__"


def can_replace_result(tool_name: str) -> bool:
    """Whether a denied result from *tool_name* is replaced rather than
    stopping the run."""
    return tool_name.startswith(_MCP_PREFIX) or tool_name in REPLACEABLE_BUILTIN_TOOLS


def _serialized(tool_response: Any) -> str:
    return json.dumps(tool_response, ensure_ascii=False, default=str)


def _mcp_text(tool_response: Any) -> Optional[str]:
    if not isinstance(tool_response, list):
        return None
    return "\n".join(
        block["text"]
        for block in tool_response
        if isinstance(block, Mapping)
        and block.get("type") == "text"
        and isinstance(block.get("text"), str)
    )


def _bash_text(tool_response: Any) -> Optional[str]:
    if not isinstance(tool_response, Mapping):
        return None
    parts: list[str] = []
    for field in ("stdout", "stderr"):
        value = tool_response.get(field)
        if isinstance(value, str) and value:
            parts.append(value)
    return "\n".join(parts)


def _read_text(tool_response: Any) -> Optional[str]:
    if not isinstance(tool_response, Mapping) or tool_response.get("type") != "text":
        return None
    file = tool_response.get("file")
    if not isinstance(file, Mapping) or not isinstance(file.get("content"), str):
        return None
    return file["content"]


def tool_result_text(tool_name: str, tool_response: Any) -> str:
    """The text a screen reads from a tool's result. Never shortened.

    MCP text blocks in order, Bash's ``stdout`` and ``stderr``, Read's file
    content, and for anything else the whole result serialized as JSON.
    """
    text: Optional[str] = None
    if tool_name.startswith(_MCP_PREFIX):
        text = _mcp_text(tool_response)
    elif tool_name == "Bash":
        text = _bash_text(tool_response)
    elif tool_name == "Read":
        text = _read_text(tool_response)
    return text if text is not None else _serialized(tool_response)


def replacement_output(tool_name: str, tool_response: Any, text: str) -> Optional[Any]:
    """An ``updatedToolOutput`` carrying *text*, or ``None`` when the CLI
    would not accept one for *tool_name*."""
    if tool_name.startswith(_MCP_PREFIX):
        return [{"type": "text", "text": text}]
    if tool_name == "Bash":
        return {"stdout": text, "stderr": "", "interrupted": False}
    if tool_name == "Read":
        file = tool_response.get("file") if isinstance(tool_response, Mapping) else None
        path = file.get("filePath") if isinstance(file, Mapping) else None
        return {
            "type": "text",
            "file": {
                "filePath": path if isinstance(path, str) else "",
                "content": text,
                "numLines": 1,
                "startLine": 1,
                "totalLines": 1,
            },
        }
    return None

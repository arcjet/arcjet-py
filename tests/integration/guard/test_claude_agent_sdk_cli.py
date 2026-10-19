"""``guard_hooks(tool_results=)`` through the CLI bundled with the Agent SDK.

The CLI talks to a scripted, local Messages API: the first request that
offers tools gets one ``tool_use``, and the request that carries its
``tool_result`` is recorded. That record is what the model would read, so
these tests check the replacement shapes against the CLI's own validation,
which silently sends the original result when a shape does not match.

Skips when the ``claude-agent-sdk`` extra is absent. No network access and
no API key are used.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

import pytest
from guard_doubles import StubGuardClient, make_allow_decision, make_deny_decision

pytest.importorskip(
    "claude_agent_sdk", reason="arcjet[claude-agent-sdk] extra is not installed"
)

from claude_agent_sdk import (  # noqa: E402
    ClaudeAgentOptions,
    ResultMessage,
    create_sdk_mcp_server,
    query,
    tool,
)

from arcjet.guard import DetectPromptInjection  # noqa: E402
from arcjet.guard.claude_agent_sdk import guard_hooks  # noqa: E402


class _Script:
    """What the scripted API answers, and what it recorded."""

    def __init__(self, tool_name: str, tool_input: Mapping[str, Any]) -> None:
        self.tool_name = tool_name
        self.tool_input = dict(tool_input)
        self.tool_sent = False
        self.tool_results: Optional[list[dict[str, Any]]] = None
        self.lock = threading.Lock()


def _sse(events: list[tuple[str, dict[str, Any]]]) -> bytes:
    return "".join(
        f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events
    ).encode()


def _message(blocks: list[dict[str, Any]], stop_reason: str) -> bytes:
    events: list[tuple[str, dict[str, Any]]] = [
        (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_scripted",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-scripted",
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            },
        )
    ]
    for index, block in enumerate(blocks):
        if block["type"] == "text":
            start = {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": block["text"]}
        else:
            start = {
                "type": "tool_use",
                "id": block["id"],
                "name": block["name"],
                "input": {},
            }
            delta = {
                "type": "input_json_delta",
                "partial_json": json.dumps(block["input"]),
            }
        events += [
            (
                "content_block_start",
                {"type": "content_block_start", "index": index, "content_block": start},
            ),
            (
                "content_block_delta",
                {"type": "content_block_delta", "index": index, "delta": delta},
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": index}),
        ]
    events += [
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                "usage": {"output_tokens": 1},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]
    return _sse(events)


def _handler(script: _Script) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            if not self.path.startswith("/v1/messages") or "count_tokens" in self.path:
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"input_tokens": 1}')
                return
            offered = [
                t.get("name") for t in body.get("tools", []) if isinstance(t, dict)
            ]
            results = [
                block
                for message in body.get("messages", [])
                if isinstance(message.get("content"), list)
                for block in message["content"]
                if isinstance(block, dict) and block.get("type") == "tool_result"
            ]
            with script.lock:
                if results:
                    script.tool_results = results
                    payload = _message([{"type": "text", "text": "done"}], "end_turn")
                elif script.tool_name in offered and not script.tool_sent:
                    script.tool_sent = True
                    payload = _message(
                        [
                            {
                                "type": "tool_use",
                                "id": "toolu_scripted",
                                "name": script.tool_name,
                                "input": script.tool_input,
                            }
                        ],
                        "tool_use",
                    )
                else:
                    payload = _message([{"type": "text", "text": "ok"}], "end_turn")
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            self.wfile.write(payload)

    return Handler


@tool("fetch", "Fetch a page", {"url": str})
async def fetch(args: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": f"page body for {args['url']}"}]}


@pytest.fixture
def workdir(tmp_path: Path) -> Iterator[Path]:
    (tmp_path / "notes.txt").write_text("line one\nfetched text\n")
    yield tmp_path


def _run(
    script: _Script, workdir: Path, guard: StubGuardClient
) -> tuple[_Script, Optional[ResultMessage]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(script))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    hooks = guard_hooks(
        guard=guard,
        tool_results={
            "rules": lambda result: [DetectPromptInjection()(result["text"])]
        },
    )
    options = ClaudeAgentOptions(
        cwd=str(workdir),
        permission_mode="bypassPermissions",
        max_turns=4,
        setting_sources=[],
        mcp_servers={"docs": create_sdk_mcp_server("docs", tools=[fetch])},
        hooks=hooks,
        env={
            "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
            "ANTHROPIC_API_KEY": "sk-ant-scripted",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
        },
    )

    async def collect() -> Optional[ResultMessage]:
        final = None
        async for message in query(prompt="use the tool", options=options):
            if isinstance(message, ResultMessage):
                final = message
        return final

    try:
        final = asyncio.run(collect())
    finally:
        server.shutdown()
        server.server_close()
    return script, final


def _content_text(result: dict[str, Any]) -> str:
    content = result["content"]
    if isinstance(content, str):
        return content
    return "".join(block.get("text", "") for block in content)


def _denied(result: dict[str, Any]) -> dict[str, Any]:
    text = _content_text(result)
    # Read numbers each line ("1\t...") before the model sees it.
    _, _, rest = text.partition("\t") if text[:1].isdigit() else ("", "", text)
    return json.loads(rest)


def test_bash_result_is_replaced(workdir: Path) -> None:
    script, _ = _run(
        _Script("Bash", {"command": "echo fetched-text"}),
        workdir,
        StubGuardClient(decision=make_deny_decision()),
    )
    assert script.tool_results is not None
    [result] = script.tool_results
    assert "fetched-text" not in _content_text(result)
    assert _denied(result)["arcjetDenied"] is True


def test_read_result_is_replaced(workdir: Path) -> None:
    script, _ = _run(
        _Script("Read", {"file_path": str(workdir / "notes.txt")}),
        workdir,
        StubGuardClient(decision=make_deny_decision()),
    )
    assert script.tool_results is not None
    [result] = script.tool_results
    assert "fetched text" not in _content_text(result)
    assert _denied(result)["arcjetDenied"] is True


def test_mcp_result_is_replaced(workdir: Path) -> None:
    script, _ = _run(
        _Script("mcp__docs__fetch", {"url": "https://example.com"}),
        workdir,
        StubGuardClient(decision=make_deny_decision()),
    )
    assert script.tool_results is not None
    [result] = script.tool_results
    assert "page body" not in _content_text(result)
    assert _denied(result)["arcjetDenied"] is True


def test_a_tool_outside_the_table_stops_the_run(workdir: Path) -> None:
    client = StubGuardClient(decision=make_deny_decision())
    script, final = _run(
        _Script("Write", {"file_path": str(workdir / "new.txt"), "content": "x"}),
        workdir,
        client,
    )
    assert script.tool_sent is True
    assert script.tool_results is None
    assert final is not None
    assert client.captures[-1]["metadata"]["claude.denial"] == "run_stopped"


def test_allow_sends_the_original_result(workdir: Path) -> None:
    script, _ = _run(
        _Script("Bash", {"command": "echo fetched-text"}),
        workdir,
        StubGuardClient(decision=make_allow_decision()),
    )
    assert script.tool_results is not None
    [result] = script.tool_results
    assert "fetched-text" in _content_text(result)

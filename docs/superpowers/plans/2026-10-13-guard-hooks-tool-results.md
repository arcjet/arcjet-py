# guard_hooks(tool_results=) Implementation Plan

> Transient: lives on this branch and is deleted in the PR's last commit.

**Goal:** `guard_hooks(tool_results=...)` screens every tool's result in `PostToolUse` and, on DENY, keeps it from the model: a replacement through `updatedToolOutput` for tools whose output shape is known, and `continue: false` for the rest.

**Spec:** ADR arcjet/arcjet#9790 (`docs/adrs/2026-10-13-claude-agent-sdk-adapters-screen-tool-results.md`), ENG-1536. The CLI behaviour it relies on was observed with the spike in the session scratchpad (`eng-1536-spike/`), which Task 4 turns into a test.

## Global constraints

- A denied result never reaches the model in the turn it was screened.
- The denial text is the existing envelope (`dumps_denial(payload_from_block(...))`); no new shape.
- `on_guard_error` defaults to `"deny"`; an unevaluated policy is a DENY.
- `PostToolUse` capture (`claude.phase: after`) keeps working unchanged when `tool_results` is not set.
- Nothing outside `src/arcjet/guard/claude_agent_sdk/` imports `claude_agent_sdk`.
- The screened text is never shortened.

## Facts from the spike (bundled CLI 2.1.286, `claude-agent-sdk` 0.2.163)

| Tool | `tool_response` | Replacement the model receives |
|---|---|---|
| `mcp__*` | list of content blocks | anything; `[{"type": "text", "text": ...}]` arrives as blocks |
| Bash | `{stdout, stderr, interrupted, isImage, noOutputExpected}` | `{"stdout": ..., "stderr": "", "interrupted": False}` |
| Read | `{"type": "text", "file": {filePath, content, numLines, startLine, totalLines}}` | same shape, `content` replaced |
| other built-ins | varies | wrong shape → original sent, silently |

`continue: false` stops the run before the next model request; the session keeps the original result; the result message is `success`.

## Tasks

### Task 1: shape table — `src/arcjet/guard/claude_agent_sdk/_tool_results.py`

- `REPLACEABLE_BUILTIN_TOOLS: frozenset[str] = frozenset({"Bash", "Read"})`.
- `can_replace_result(tool_name: str) -> bool`: `mcp__` prefix or in the set.
- `tool_result_text(tool_name: str, tool_response: Any) -> str`: MCP text blocks joined in order; Bash `stdout` and `stderr` joined; Read `file.content`; anything else `json.dumps(tool_response, ensure_ascii=False, default=str)`. Never shortened.
- `replacement_output(tool_name: str, tool_response: Any, text: str) -> Optional[Any]`: the shapes above; `None` when the tool is not replaceable. Read keeps the original `filePath` when it is a string.
- Unit tests for each branch, including a 200,000-character value kept whole and a non-mapping response.

### Task 2: evaluation — `_hooks.py`

- `_ToolResultsConfig`: `guard`, `action` (str or callable of the hook input; default `"{tool_name}.result"`), `actor`, `rules` (callable, required), `metadata`, `session_id`, `on_guard_error`.
- `PostToolUseVerdict(deny: bool, payload: Optional[ArcjetDenialResult])`.
- `evaluate_post_tool_use(source, config)`: rules callable receives `{"tool_name", "tool_input", "tool_response", "text"}`; actor and metadata see `_tool_call(hook)`; no policy inputs; metadata `claude.phase: result`, plus `claude.denial: replaced | run_stopped` on a deny so the capture records which happened. Same failure handling as `evaluate_user_prompt_submit`.
- `post_tool_use_output(verdict, source)`: `{}` on allow; `hookSpecificOutput.updatedToolOutput` when replaceable; `{"continue": False, "stopReason": <message>}` otherwise.
- Unit tests: allow, deny replaced (Bash, Read, MCP), deny stopped (Write), unevaluated deny and allow, rules raising / returning no bound rules, label default and callable, metadata.

### Task 3: wiring — `guard_hooks(tool_results=...)`

- New keyword `tool_results: Optional[Mapping[str, Any]]`, validated like `inbound` (mapping; `rules` callable; `on_guard_error`; `session_id` override; optional `guard`, `action`, `actor`, `metadata`).
- One `PostToolUse` matcher: capture when tool hooks are requested, then the screen when `tool_results` is set. A screen on its own registers `PostToolUse` only.
- The "needs a tool policy and/or inbound" error also accepts `tool_results`.
- Export `REPLACEABLE_BUILTIN_TOOLS` and `can_replace_result` from `arcjet.guard.claude_agent_sdk`.
- Tests: registration combinations, misconfiguration errors.

### Task 4: CLI integration test — `tests/integration/guard/test_claude_agent_sdk_cli.py`

- Port the spike: a local scripted Messages API (`tests/integration/guard/_fake_messages_api.py`) and `query()` against the bundled CLI with `ANTHROPIC_BASE_URL`.
- Cases: Bash, Read and an SDK MCP tool denied → the recorded `tool_result` holds the envelope; Write denied → no `tool_result` request is made; allow → original result.
- Skips when `claude_agent_sdk` is absent.

### Task 5: CI job — `.github/workflows/ci.yml`

- A job that runs both Claude Agent SDK integration files with `uv run --extra claude-agent-sdk`, following the existing jobs' setup steps and pins, and an aggregate result check if the repo's pattern needs one. CI change: needs human review.

### Task 6: docs

- README "Screen tool results on `PostToolUse`" subsection: the option, the table, that other tools stop the run, that a stopped session must not be resumed, that another hook's rewrite can replace the denial, and the timeout caveat. Update the module docstrings that call `PostToolUse` capture-only.

### Task 7: delete this plan

Last commit of the PR.

## Gate per task

`just format`, `just check`, `just test`; Task 4 also `uv run --extra claude-agent-sdk pytest tests/integration/guard/ -k claude --no-cov`.

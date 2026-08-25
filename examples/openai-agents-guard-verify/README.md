# OpenAI Agents guard verification harness

Runs **without** `ARCJET_KEY`, `OPENAI_API_KEY`, or network access. A stub model
and in-memory guard client exercise the same paths a production app uses with
`launch_arcjet` and a real model provider.

## What it checks

| Scenario | Guard control |
| --- | --- |
| `allow` | Tool invoke runs; capture outcome `success` |
| `deny` | `reject_content` JSON denial; tool body never runs |
| `unavailable` | Guard error → fail-closed `ERROR` envelope |
| `inbound-deny` | Core `guard()` inbound screen refuses the run |
| `inbound-failed-open` | `has_failed_open()` refuses the run |
| `brand-skip` | Second `guard_tool` on same copy does not double-call Guard |
| `correlation` | `session_id` on run context joins the Sequence |

## Run

```bash
cd examples/openai-agents-guard-verify
uv sync
uv run python main.py
```

Run one scenario:

```bash
uv run python main.py deny correlation
```

Production wiring matches the README section **OpenAI Agents function tools**:
`openai_agents_context` for inbound screening, `guard_tool` on authored
`FunctionTool`s, caller-owned `session_id` on `Runner.run(..., context=...)`.

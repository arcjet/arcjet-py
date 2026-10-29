# Contributing

## Development environment

We recommend using the provided [Dev
Container](https://code.visualstudio.com/docs/devcontainers/containers). It
gives you a consistent toolchain and avoids “works on my machine” issues.

Routine tasks are wrapped as [`just`](https://just.systems) recipes. Run
`just --list` to see them all.

The Dev Container installs `just` for you. Outside it, install `just` alongside
`uv`:

```sh
uv tool install rust-just
```

Then install the project dependencies:

```sh
just install
```

## Static analysis

Run every check CI runs — ruff lint, ruff format check, `ty`, `pyright`, and
the Griffe API breaking-change check:

```sh
just check
```

Sort imports and format the code with ruff (this mutates files):

```sh
just format
```

The individual steps are available too: `just lint` (ruff), `just typecheck`
(`ty`, then `pyright`), and `just api-check` (Griffe, see [Breaking
changes](#breaking-changes) below).

## Tests

Run the full test suite locally:

```sh
just test
```

Extra arguments are forwarded to pytest. Pass `--no-cov` when running a subset,
since the 80% coverage gate is measured across the whole suite:

```sh
just test tests/unit -k cache --no-cov
```

- Set `ARCJET_LOG_LEVEL=debug` to see detailed debug logs during development.

### Test Organization

All tests (unit and integration) run together in a single test suite:

- **Unit tests** (in `tests/unit/`): Use pytest fixtures to mock protobuf
  dependencies without permanent module stubbing
- **Integration tests** (in `tests/fastapi/`, `tests/flask/`, etc.): Test with
  real framework integrations
- **Fixtures** (in `tests/fixtures/`): Shared test fixtures and protobuf stubs

The fixture-based approach prevents cross-contamination between tests while
allowing them to run in a single pytest invocation.

### CrewAI tests

CrewAI is not an Arcjet dependency, an extra, or a dependency group, so it is
not in `uv.lock`. It hard-depends on `chromadb~=1.1.0`, and chromadb
1.0.0–1.5.9 all carry an unpatched critical RCE (CVE-2026-45829); locking it
would put that in every contributor's environment and in the published
metadata. Keep it out.

`tests/integration/guard/test_crewai.py` therefore skips unless you install
CrewAI yourself, alongside the locked environment rather than into it:

```sh
uv sync
uv pip install "crewai>=1.15.3,<2"
# `--no-sync`, or uv restores the lock and removes crewai again
uv run --no-sync pytest tests/integration/guard/test_crewai.py --no-cov
```

`tests/unit/guard/test_crewai.py` imports no CrewAI and always runs, including
on the 3.14 cell that CrewAI does not support. `just test` on a plain `uv sync`
skips the integration file, which is what CI does.

### OpenAI Agents tests

`arcjet[openai-agents]` is a real extra (`openai-agents>=0.19.0,<1`) but is in no
dependency group, so the lockfile does not pull its transitive tree into every
`uv sync`. Install it alongside the locked environment when you want integration
coverage:

```sh
uv sync
uv pip install "openai-agents>=0.19.0,<1"
# `--no-sync`, or uv restores the lock and removes openai-agents again
uv run --no-sync pytest tests/integration/guard/test_openai_agents.py tests/integration/guard/test_openai_agents_runner.py --no-cov
```

`tests/unit/guard/test_openai_agents.py` imports no `agents` and always runs,
including when the extra is absent. `just test` on a plain `uv sync` skips the
integration files, which is what CI does.

### Claude Agent SDK tests

`arcjet[claude-agent-sdk]` is a real extra (`claude-agent-sdk>=0.2.127,<1`) but
is in no dependency group, so a plain `uv sync` leaves it out. The lockfile
pins it, so run the integration files with the extra from the lock:

```sh
uv run --extra claude-agent-sdk pytest --no-cov \
  tests/integration/guard/test_claude_agent_sdk.py \
  tests/integration/guard/test_claude_agent_sdk_cli.py
```

`test_claude_agent_sdk_cli.py` drives the CLI bundled with the SDK against a
scripted, local Messages API, with no network access and no key, and checks
what the model would receive. A CLI release that changes a built-in tool's
output shape fails it.

`tests/unit/guard/test_claude_agent_sdk.py` and
`test_claude_agent_sdk_tool_results.py` import no `claude_agent_sdk` and always
run, including when the extra is absent. `just test` on a plain `uv sync` skips
the integration files; CI runs them in the `Run tests (claude-agent-sdk)` job.

### Claude Managed Agents tests

`arcjet[claude-managed-agents]` is a real extra (`anthropic>=0.92.0,<2`) but is
in no dependency group, so the lockfile does not pull its transitive tree
into every `uv sync`. The unit suite imports no `anthropic` and always runs,
including when the extra is absent. This extra is not the Claude Agent SDK
adapter — do not run those tests in place of these.

```sh
uv sync
uv run pytest tests/unit/guard/test_claude_managed_agents.py --no-cov
```

### Strands Agents tests

`arcjet[strands-agents]` is a real extra (`strands-agents>=1.11.0,<2`) but
is in no dependency group, so the lockfile does not pull its transitive tree
into every `uv sync`. Install it alongside the locked environment when you want
integration coverage:

```sh
uv sync
uv pip install "strands-agents>=1.11.0,<2"
# `--no-sync`, or uv restores the lock and removes strands-agents again
uv run --no-sync pytest tests/integration/guard/test_strands_agents.py --no-cov
```

`tests/unit/guard/test_strands_agents.py` imports no `strands` and always runs,
including when the extra is absent. `just test` on a plain `uv sync` skips the
integration file, which is what CI does.

### Google ADK tests

`arcjet[google-adk]` is a real extra (`google-adk>=2.0.0,<3`) but is in no
dependency group, so the lockfile does not pull its transitive tree into every
`uv sync`. Install it alongside the locked environment when you want
integration coverage:

```sh
uv sync
uv pip install "google-adk>=2.0.0,<3"
# `--no-sync`, or uv restores the lock and removes google-adk again
uv run --no-sync pytest tests/integration/guard/test_google_adk.py --no-cov
```

`tests/unit/guard/test_google_adk.py` imports no `google.adk` and always runs,
including when the extra is absent. `just test` on a plain `uv sync` skips the
integration file, which is what CI does.
## Benchmarks

WASM performance benchmarks live in `tests/benchmarks/` and measure the per-call
cost of local rule evaluation. They use `pytest-benchmark` and are not collected
during normal test runs (benchmark files use `bench_*.py` naming).

```sh
# Run all benchmarks
just bench

# Or directly with options
uv run pytest tests/benchmarks/ --benchmark-only --benchmark-warmup=on --no-cov -v
```

Always pass `--no-cov` — coverage instrumentation distorts timing.

## Regenerating WASM bindings

The `arcjet._analyze` subpackage's typed Python bindings are generated by
`witgen` from the WASM binary. This requires
[`wasm-tools`](https://github.com/bytecodealliance/wasm-tools) on PATH
(included in the devcontainer, or install with `cargo install wasm-tools`).

After placing an updated WASM binary at
`src/arcjet/_analyze/wasm/arcjet_analyze_js_req.component.wasm`:

```sh
# Regenerate the bindings and format them
just codegen

# Verify
just test
```

Configuration is in `witgen.toml`. Hand-maintained files in the `_analyze`
subpackage are `_import_defaults.py`, `_overrides.py`, and `_singleton.py`.

## Breaking changes

Check if there are any breaking changes in the public API using Griffe:

```sh
# Check against origin/main (default). Run `git fetch origin main` first if
# your copy of the branch is stale.
just api-check
# Check against another ref, e.g. your local `main` branch
just api-check main
# Check against the most recent tag
uv run griffe check arcjet -s src \
  -e tools/griffe_extensions.py:IgnoreProtobufDescriptors
```

Pull requests that introduce breaking changes must be labeled with the
`breaking` label. This will allow the PR to be merged even if Griffe detects
breaking changes.

## Releasing

This repository publishes **two** distributions from one uv workspace: `arcjet`
and the `arcjet-sensitive-info-rampart` backend in `sensitive-info-rampart/`.
The backend imports private core modules, so both are released together at the
same version and pin each other exactly (`==`).

Releases are prepared by [Release Please](https://github.com/googleapis/release-please)
(`.github/workflows/release-please.yml`), configured in
`.github/release-please-config.json` and `.github/.release-please-manifest.json`.

1. On every push to `main`, Release Please opens or updates a pull request
   titled `chore: Release <version>`. The version is derived from the
   [Conventional Commits](https://www.conventionalcommits.org/) merged since
   the last release (`fix:` → patch, `feat:` → minor, `!` or
   `BREAKING CHANGE:` → major), and the pull request updates `CHANGELOG.md`
   and every place the version lives, in lockstep:

   - `version` in `pyproject.toml` and `sensitive-info-rampart/pyproject.toml`
   - both `==` pins, via their `# x-release-please-version` markers
   - the two editable workspace entries in `uv.lock`

   CI runs `uv lock --check`, so a stale `uv.lock` fails the pull request.
   To choose a version yourself, merge a commit whose body contains
   `Release-As: <version>`.

2. The release pull request is opened with the default `GITHUB_TOKEN`, which
   does not start CI, including when Release Please updates it. Close and
   reopen it to run the required checks, then review and merge it like any
   other pull request.

3. Release Please creates the `v<version>` tag and the GitHub release. This
   does not publish anything.

4. Publish by hand: in **Actions → Release → Run workflow**, choose the
   `v<version>` tag, or run `gh workflow run release.yml --ref v<version>`.

5. The preflight job checks the tag, versions, and pins. Another member of the
   Python SDK Publishers team then approves the publish job in the `pypi`
   environment; "prevent self-review" stops whoever dispatched the run from
   approving it. Once approved, both distributions are published to PyPI.

Release Please only produces stable `X.Y.Z` versions. A prerelease
(`0.10.0b1`) is still bumped and tagged by hand: run
`uv version --bump minor --bump beta` for both packages
(`--package arcjet-sensitive-info-rampart` for the backend), update both `==`
pins and `uv.lock`, push an annotated `v<version>` tag, then dispatch the
release workflow on it as in step 4. Do not merge a prerelease version into
`main`: Release Please expects `main` to carry the last stable release.

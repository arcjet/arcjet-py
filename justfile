# Arcjet Python SDK command runner.
# Run `just --list` to see available recipes, or `just <recipe>` to run one.

# show available recipes (default when no recipe is given)
[private]
default:
    @just --list

# base ref for public API breaking-change detection
api_base_ref := "origin/main"

# styled header: bold cyan ✦, bold white label
h := BOLD + CYAN + "✦" + WHITE + " "
n := NORMAL

# ─── Setup ──────────────────────────────────────────────────────────────────────

# install dependencies from uv.lock into .venv
install:
    @echo '{{ h }}install: uv sync{{ n }}'
    @uv sync

# ─── Pre-commit gate ────────────────────────────────────────────────────────────

# format, run every check, then the full test suite — run this before committing
pre-commit: format check test

# all lint, type, and API breaking-change checks
check: lint typecheck api-check

# ─── Lint, format, types ────────────────────────────────────────────────────────

# ruff lint + format check
lint:
    @echo '{{ h }}lint: ruff{{ n }}'
    @uv run ruff check
    @uv run ruff format --check

# sort imports and format code (mutates files)
format:
    @echo '{{ h }}format: ruff{{ n }}'
    @uv run ruff check --select I --fix
    @uv run ruff format

# type check with ty and pyright — both must pass
typecheck:
    @echo '{{ h }}typecheck: ty{{ n }}'
    @uv run ty check
    @echo '{{ h }}typecheck: pyright{{ n }}'
    @uv run pyright

# audit published runtime and optional dependencies from the current lockfile
[doc('audit locked published dependencies (all extras, excluding dev tools)')]
audit:
    @echo '{{ h }}audit: uv{{ n }}'
    @uv audit --locked --no-dev

# detect breaking changes in the public API against a base ref. Run
# `git fetch origin main` first if origin/main is stale. Intentional breaking
# changes need the `breaking` label on the PR.
[doc('detect public API breaking changes against a base ref (default origin/main)')]
api-check base_ref=api_base_ref:
    @echo '{{ h }}api: griffe check against {{ base_ref }}{{ n }}'
    @uv run griffe check arcjet -s src -e tools/griffe_extensions.py:IgnoreProtobufDescriptors --against {{ quote(base_ref) }}

# ─── Tests ──────────────────────────────────────────────────────────────────────

# all tests (unit, framework integration, WASM bindings) with coverage. Extra
# args are forwarded to pytest; pass --no-cov when running a subset, since the
# coverage gate is measured across the whole suite, e.g.
# `just test tests/unit -k rate_limit --no-cov`
[doc('all tests with coverage; extra args are forwarded to pytest')]
test *args:
    @echo '{{ h }}test: pytest{{ n }}'
    @uv run pytest {{ args }}

# WASM performance benchmarks. Coverage is off because it distorts timing.
[doc('WASM performance benchmarks (coverage off — it distorts timing)')]
bench *args:
    @echo '{{ h }}bench: pytest-benchmark{{ n }}'
    @uv run pytest tests/benchmarks/ --benchmark-only --no-cov -o "addopts=" -o "python_files=bench_*.py" {{ args }}

# ─── Codegen ────────────────────────────────────────────────────────────────────

# regenerate the arcjet._analyze WASM bindings, then format them. Requires
# `wasm-tools` on PATH and an updated .component.wasm in
# src/arcjet/_analyze/wasm/. Run `just test` afterwards to verify.
[doc('regenerate the arcjet._analyze WASM bindings with witgen')]
codegen: && format
    @echo '{{ h }}codegen: witgen{{ n }}'
    @uv run python -m tools.witgen

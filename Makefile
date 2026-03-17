.PHONY: check lint typecheck apicheck format test bench

# ---------------------------------------------------------------------------
# Lint + type-check (single command: `make check`)
# ---------------------------------------------------------------------------

check: lint typecheck apicheck  ## Run all lint, type, and API checks

lint:  ## Ruff lint + format check (F401, import sorting, formatting)
	uv run ruff check
	uv run ruff format --check

typecheck:  ## ty + pyright
	uv run ty check
	uv run pyright

apicheck:  ## griffe breaking-change detection
	uv run griffe check arcjet -s src --against origin/main

# ---------------------------------------------------------------------------
# Formatting (mutates files)
# ---------------------------------------------------------------------------

format:  ## Auto-fix imports and format code
	uv run ruff check --select I --fix
	uv run ruff format

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test:  ## All tests (unit + integration + analyze, with coverage)
	uv run pytest

bench:  ## Run benchmarks
	uv run pytest tests/benchmarks/ --benchmark-only --no-cov

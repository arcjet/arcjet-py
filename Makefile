.PHONY: check lint typecheck apicheck format test test-analyze test-all

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

test:  ## SDK tests (unit + integration, with coverage)
	uv run pytest

test-analyze:  ## arcjet-analyze WASM binding tests (no coverage)
	uv run pytest arcjet-analyze/tests/ --no-cov

test-all: test test-analyze  ## Both test suites

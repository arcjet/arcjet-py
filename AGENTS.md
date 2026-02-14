# AGENTS.md - Coding Agent Onboarding Guide

This document provides essential information for coding agents working on the
arcjet-py repository for the first time.

## Repository Overview

**Project**: Arcjet Python SDK  
**Purpose**: Security SDK for Python applications providing bot detection, rate
limiting, email validation, Shield WAF, and attack protection for Flask,
FastAPI, and other Python web frameworks.  
**Language**: Python 3.10+  
**Package Manager**: uv (modern Python package manager)  

## Quick Start

### Environment Setup

1. **Python Version**: 3.10+ (see `.python-version`)
2. **Install uv** (if not already installed):
   ```bash
   pip install uv
   ```
3. **Install dependencies**:
   ```bash
   uv sync
   ```
   This creates a virtual environment in `.venv` and installs all dependencies
   from `uv.lock`

### Development Workflow

The repository uses **uv** for all package management and script execution.
Always prefix commands with `uv run`:

```bash
# Run tests
uv run pytest

# Run linting
uv run ruff check .

# Format code
uv run ruff format .

# Type checking
uv run ty check
uv run pyright
```

## Build, Test, and Lint Commands

### Testing

Run all tests with a single command:

```bash
uv run pytest
```

This runs both unit tests (in `tests/unit/`) and integration tests (in
`tests/fastapi/`, `tests/flask/`, etc.) together.

**Test Organization**: Tests use pytest fixtures for protobuf mocking, allowing
all tests to run together without cross-contamination. The `tests/unit/`
directory contains unit tests with mocked dependencies, while
`tests/fastapi/`, `tests/flask/`, etc. contain integration tests.

Configuration note: `pyproject.toml` has `addopts = ["-q", "--cov=src/arcjet",
"--cov-report=term-missing"]` for test coverage reporting with an 80% minimum
threshold.

### Linting and Formatting

The project uses multiple tools for code quality:

```bash
# Import sorting and formatting with ruff
uv run ruff check --select I --fix  # Sort imports
uv run ruff format                  # Format code

# Linting
uv run ruff check                   # Check for lint errors

# Type checking (two tools)
uv run ty check                     # Ty type checker (outputs to console)
uv run pyright                      # Pyright type checker
```

**Note**: Some files are excluded from linting/type checking (see
`pyproject.toml` for exclusions, including `examples/` and generated protobuf
code in `src/arcjet/proto/`).

### API Breaking Change Detection

Before merging PRs, check for API breaking changes:

```bash
# Check against main branch
uv run griffe check arcjet -s src --against origin/main

# Check against most recent tag (default)
uv run griffe check arcjet -s src
```

PRs with breaking changes must be labeled with `breaking` label to be merged.

**IMPORTANT**: Always run this check before committing changes. Breaking changes
must be avoided unless absolutely necessary. Whenever there is a breaking
change, existing code must not break - we must maintain backward compatibility
and provide clear migration paths. This can be docs, deprecation warnings, and
keeping the existing API surface intact with internal changes.

## Code Organization

### Source Structure

```
src/arcjet/
├── __init__.py          # Public API exports
├── client.py            # Main Arcjet client (async and sync)
├── decision.py          # Decision and result types
├── rules.py             # Rule definitions (bot detection, rate limiting, etc.)
├── context.py           # Request context utilities (framework-agnostic)
├── cache.py             # Decision caching
├── dataclasses.py       # Reason types and data structures
├── _enums.py            # Enums (Mode, etc.)
├── _errors.py           # Exception types
├── _logging.py          # Logging configuration
├── _convert.py          # Protobuf conversion utilities
└── proto/               # Generated protobuf code (DO NOT EDIT)
    └── decide/v1alpha1/
```

### Test Structure

```
tests/
├── conftest.py          # Shared fixtures for all tests
├── helpers.py           # Test utility functions
├── fixtures/            # Pytest fixtures and test data
│   ├── protobuf_stubs.py  # Protobuf mocking fixtures
│   └── __init__.py
├── unit/                # Unit tests with mocked dependencies
│   ├── conftest.py      # Makes protobuf mocking autouse for unit tests
│   ├── test_client_async.py
│   ├── test_client_sync.py
│   └── test_*.py        # Other unit tests
├── fastapi/             # FastAPI integration tests
│   ├── test_fastapi.py
│   └── test_reason_v2.py
├── flask/               # Flask integration tests
│   └── test_flask.py
└── test_convert.py      # Conversion utility tests
```

## Coding Conventions

### Python Style

1. **Future imports**: Always use `from __future__ import annotations` at the
   top of files for forward compatibility
   
2. **Type hints**: Fully type-annotated codebase
   - Use modern type syntax (e.g., `list[str]` not `List[str]`)
   - Use `from typing import` for protocols, type aliases, etc.

3. **Dataclasses**: Prefer `@dataclass(frozen=True, slots=True)` for immutable
   data structures

4. **Enums**: Use `str, Enum` pattern for string enums:
   ```python
   class Mode(str, Enum):
       DRY_RUN = "DRY_RUN"
       LIVE = "LIVE"
   ```

5. **Docstrings**: Module-level docstrings for public modules; class/function
   docstrings for public API

6. **Private modules**: Prefix with underscore (e.g., `_enums.py`,
   `_logging.py`) for internal-only modules

### Framework Support

The SDK is **framework-agnostic** with explicit support for:

- **ASGI** (Starlette, FastAPI) - async client
- **Flask/Werkzeug** - sync client
- **Django** - via `RequestContext`

The `context.py` module provides `coerce_request_context()` to convert framework
requests to a common `RequestContext` type.

### Environment Variables

The SDK supports these environment variables:

- `ARCJET_KEY` - API key (passed to `arcjet()` or `arcjet_sync()`; often stored in environment for security)
- `ARCJET_ENV` - Set to `"development"` for development mode (enables defaults
  like `127.0.0.1` for missing IPs)
- `ARCJET_LOG_LEVEL` - Log level (`debug`, `info`, `warning`, `error`)
- `ARCJET_BASE_URL` - Override Decide API endpoint (defaults to
  `https://decide.arcjet.com` or Fly.io internal URL)
- `FLY_APP_NAME` - Automatically detected; uses internal Fly.io Arcjet API URL
  when set

## Common Errors and Workarounds

### 1. uv Command Not Found

**Error**: `bash: uv: command not found`

**Solution**: Install uv first:
```bash
pip install uv
```

### 2. Breaking Change CI Failure

**Error**: Griffe check fails on PR due to API breaking changes.

**Cause**: Public API changes detected that would break existing users.

**Solutions**:
- Revert the breaking change if unintentional
- If intentional, add `breaking` label to the PR to allow it to pass CI. Always
  strive to avoid breaking changes and maintain backward compatibility for
  existing APIs. Provide clear migration paths if breaking changes are
  necessary.

### 3. Type Check Failures

**Error**: Pyright or ty reports type errors.

**Cause**: Missing type annotations or incorrect types.

**Solution**: 
- Fix type annotations to match actual usage
- Use `# type: ignore[error-code]` sparingly and only when necessary (currently
  only 6 instances in the codebase)

## Key Design Patterns

### 1. Dual Client Pattern

The SDK provides both async and sync clients for different frameworks:
- `arcjet()` / `Arcjet` - Async client for FastAPI, async frameworks
- `arcjet_sync()` / `ArcjetSync` - Sync client for Flask, Django

### 2. Framework-Agnostic Context

`RequestContext` provides a normalized request representation that works across
frameworks. The `coerce_request_context()` function handles conversion from
framework-specific request objects.

### 3. Decision-Based API

The `.protect()` method returns a `Decision` object with:
- `decision.is_denied()` - Simple allow/deny check
- `decision.reason_v2` - Detailed reason for the decision
- `decision.ip` - IP analysis helpers (`.is_vpn()`, `.is_hosting()`, etc.)
- `decision.results` - Per-rule results

### 4. Protobuf Code Generation

The `src/arcjet/proto/` directory contains **generated code**. Do not edit these
files directly. They are generated from protobuf definitions maintained
elsewhere.

## Testing Best Practices

### When to Use Unit Tests

Use `tests/unit/` for:
- Testing internal SDK logic without network calls
- Testing error handling and edge cases
- Fast unit tests that don't require the Decide API

Unit tests use pytest fixtures (`mock_protobuf_modules`) to mock protobuf
dependencies, providing automatic cleanup and preventing cross-contamination.

### When to Use Integration Tests

Use `tests/fastapi/`, `tests/flask/`, etc. for:
- Integration testing with real protobuf dependencies
- Framework-specific behavior
- End-to-end testing (may require API key or mock server)

### Writing New Tests

**For unit tests**:
```python
# tests/unit/test_feature.py
import pytest
from arcjet import arcjet_sync

def test_something():
    # Protobuf modules are automatically mocked via autouse fixture
    aj = arcjet_sync(key="test_key", rules=[...])
    # Test logic
```

**For integration tests**:
```python
# tests/fastapi/test_feature.py
import pytest
from arcjet import arcjet

async def test_something():
    aj = arcjet(key="test_key", rules=[...])
    # Test logic
```

**Using test helpers**:
```python
# Import helpers from conftest or fixtures
from conftest import make_allow_decision, make_deny_decision

def test_with_decision():
    decision = make_allow_decision()
    assert decision.is_allowed()
```

## Summary Checklist for New Changes

Before submitting a PR:
- [ ] Run `uv run ruff check --select I --fix` to sort imports
- [ ] Run `uv run ruff format` to format code
- [ ] Run `uv run ruff check` to check for lint errors
- [ ] Run `uv run ty check` and `uv run pyright` for type checking
- [ ] Run `uv run pytest` for all tests (unit and integration)
- [ ] Run `uv run griffe check arcjet -s src --against origin/main` to check for
  breaking changes
- [ ] Add `breaking` label if introducing intentional API breaking changes
- [ ] Update documentation, including docstrings and AGENTS.md if necessary
- [ ] Ensure all new code is fully type-annotated and follows coding conventions
- [ ] Add new tests to aim for 80%+ coverage (current threshold)

# Arcjet Python SDK Testing Guide

This document describes the testing strategy and patterns used in the Arcjet Python SDK, following best practices inspired by [datasette-enrichments](https://github.com/datasette/datasette-enrichments).

## Test Organization

The test suite is organized into three main categories:

```
tests/
├── conftest.py           # Shared fixtures for all tests
├── helpers.py            # Shared test utilities
├── mocked/               # Unit tests with mocked dependencies
│   ├── conftest.py       # Mock protocol buffers and stubs
│   ├── test_cache.py
│   ├── test_client_async.py
│   ├── test_client_sync.py
│   ├── test_context.py
│   ├── test_decision.py
│   ├── test_enums.py
│   ├── test_logging.py
│   └── test_rules.py
├── fastapi/              # FastAPI integration tests
│   ├── conftest.py       # FastAPI fixtures
│   ├── test_fastapi.py
│   └── test_reason_v2.py
├── flask/                # Flask integration tests
│   ├── conftest.py       # Flask fixtures
│   └── test_flask.py
└── test_convert.py       # Standalone conversion tests
```

## Test Categories

### 1. Mocked Unit Tests (`tests/mocked/`)

These tests verify core SDK logic without external dependencies:

- **Purpose**: Test SDK internals in isolation
- **Dependencies**: All external dependencies (protobuf, network) are stubbed
- **Speed**: Very fast (no network, no real protobuf)

**Key Characteristics:**
- Custom `conftest.py` provides complete protobuf stubs and helper functions
- Test behavior injection via class-level attributes:
  ```python
  DecideServiceClient.decide_behavior = custom_function
  ```
- Automatic environment reset between tests
- Default to `ARCJET_ENV=development` for permissive behavior

### 2. Framework Integration Tests

#### FastAPI Tests (`tests/fastapi/`)
- **Purpose**: Verify FastAPI framework integration
- **Tools**: `fastapi.testclient.TestClient`
- **Fixtures**: Shared app and client fixtures in `conftest.py`

#### Flask Tests (`tests/flask/`)
- **Purpose**: Verify Flask framework integration  
- **Tools**: Flask's built-in test client
- **Fixtures**: Shared app and client fixtures in `conftest.py`

**Common Patterns:**
- Use invalid base URL (`https://invalid.test`) to prevent real API calls
- Test HTTP request parsing and context extraction
- Verify decision handling in framework-specific ways

### 3. Standalone Tests

Tests that don't fit into the above categories, such as protocol buffer conversion utilities.

## Testing Patterns

### Async Test Pattern

All async tests use `pytest-asyncio` with the `@pytest.mark.asyncio` decorator:

```python
@pytest.mark.asyncio
async def test_something():
    """Clear docstring explaining what is tested."""
    result = await some_async_function()
    assert result.is_success()
```

**Don't:**
```python
def test_something():
    import asyncio
    result = asyncio.run(some_async_function())  # ❌ Don't do this
```

### Fixture Usage

Use fixtures for common test setups:

```python
def test_with_fastapi_client(fastapi_client):
    """Fixture provides configured test client."""
    response = fastapi_client.get("/protected")
    assert response.status_code == 200
```

Available shared fixtures (from `tests/conftest.py`):
- `simple_http_context`: Basic HTTP context dict
- `arcjet_instance`: Standard arcjet client
- `arcjet_with_fail_open`: Arcjet configured to fail open
- `arcjet_with_fail_closed`: Arcjet configured to fail closed

### Helper Functions

**For non-mocked tests**, use helper functions from `tests/helpers.py`:

```python
from tests.helpers import make_allow_decision, capture_request_field

# Create test decisions
decision = make_allow_decision(ttl=60)

# Capture request fields for assertions
capture_fn, captured = capture_request_field("details")
DecideServiceClient.decide_behavior = capture_fn
# ... run test ...
assert captured["ip"] == "1.2.3.4"
```

**For mocked tests**, use helper functions from `tests/mocked/conftest.py`:

```python
from .conftest import make_allow_decision, capture_request_field

# Same API, but uses mocked stubs
decision = make_allow_decision(ttl=60)
```

Available helpers:
- `make_allow_decision(ttl, id)`: Create ALLOW decision
- `make_deny_decision(ttl, id)`: Create DENY decision  
- `make_error_decision(message, id)`: Create ERROR decision
- `make_decide_response(decision)`: Wrap decision in response
- `capture_request_field(field_name)`: Capture and assert request fields
- `make_basic_http_context(headers, client)`: Create HTTP context

### Test Naming and Documentation

Every test should have:

1. **Clear name** describing what is tested:
   ```python
   def test_fail_open_false_raises():  # ✅ Clear
   def test_caching():  # ❌ Too vague
   ```

2. **Docstring** explaining the test's purpose:
   ```python
   def test_fail_open_false_raises():
       """Test that fail_open=False raises ArcjetTransportError on network failures."""
   ```

3. **Focused scope**: Test one behavior per test function

### Behavior Injection Pattern (Mocked Tests)

Mocked tests inject custom behavior into client stubs:

```python
def test_custom_decision():
    """Test that custom decisions are handled correctly."""
    
    def custom_decide(req):
        # Custom logic here
        return make_decide_response(make_deny_decision())
    
    # Inject behavior
    DecideServiceClient.decide_behavior = custom_decide
    
    # Run test
    decision = await arcjet.protect(context)
    assert decision.is_denied()
```

The `conftest.py` automatically resets behavior between tests via the `_reset_stub_clients_env` fixture.

## Running Tests

### Run all tests:
```bash
pytest
```
or
```bash
pytest tests/
```

### Run specific test files:
```bash
pytest tests/fastapi/test_fastapi.py
pytest tests/mocked/test_cache.py
```

### Run with verbose output:
```bash
pytest -v
```

### Run specific test:
```bash
pytest tests/mocked/test_client_async.py::test_fail_open_false_raises
```

## Best Practices

### DO:
✅ Use `@pytest.mark.asyncio` for async tests  
✅ Add docstrings to all test functions  
✅ Use shared fixtures from `conftest.py`  
✅ Use helper functions from `tests/helpers.py`  
✅ Keep tests focused and isolated  
✅ Use descriptive test names  
✅ Group related tests in the same file  

### DON'T:
❌ Use `asyncio.run()` manually in tests  
❌ Create duplicate helper functions  
❌ Mix mocked and integration test concerns  
❌ Test multiple behaviors in one test  
❌ Skip test documentation  
❌ Modify SDK code just to make testing easier (unless it's internal-only)  

## Adding New Tests

### For a new feature in core SDK:

1. Add test to appropriate file in `tests/mocked/`
2. Use existing helpers or add new ones to `tests/helpers.py`
3. Add docstring explaining the feature being tested
4. Follow async patterns if testing async code

### For a new framework integration:

1. Add conftest.py with fixtures if new framework
2. Create test file with framework-specific tests
3. Use shared patterns from existing framework tests
4. Test both success and error cases

### For a new helper function:

1. Add to `tests/helpers.py` with clear docstring
2. Include examples in the docstring
3. Make it generic enough for reuse
4. Add type hints

## Testing Philosophy

Our testing approach prioritizes:

1. **Clarity**: Tests should be easy to read and understand
2. **Isolation**: Tests should be independent and focused
3. **Maintainability**: Reduce duplication through shared utilities
4. **Speed**: Mocked tests are fast; integration tests verify real behavior
5. **Completeness**: Cover both success and failure paths

## Continuous Improvement

This testing strategy follows patterns from successful open-source projects like datasette-enrichments. As the SDK evolves, we should:

- Keep tests updated with code changes
- Add new patterns to this guide when discovered
- Refactor tests when duplication appears
- Maintain clear documentation
- Share knowledge through code reviews

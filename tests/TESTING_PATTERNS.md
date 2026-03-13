# Testing Patterns for arcjet-py

This document describes the testing patterns adopted from
[datasette-enrichments](https://github.com/datasette/datasette-enrichments) and
best practices for test organization.

## Key Patterns from datasette-enrichments

### 1. **Autouse Fixtures for Test Isolation**

Instead of permanently modifying `sys.modules`, use pytest's `autouse=True`
fixtures:

```python
@pytest.fixture(autouse=True)
def load_test_plugin():
    # Setup: register mock implementations
    pm.register(TestPlugin(), name="undo_TestPlugin")
    try:
        yield
    finally:
        # Teardown: always cleanup
        pm.unregister(name="undo_TestPlugin")
```

**Benefits:**
- Automatic setup/teardown per test
- No cross-contamination between tests
- All tests can run in same session

### 2. **Shared Fixture Scope**

Use fixture scope to control lifecycle:

```python
@pytest_asyncio.fixture  # or @pytest.fixture
async def datasette(tmpdir):
    """Shared test fixture with session-level data"""
    # Setup expensive resources once
    db = setup_database(tmpdir)
    app = create_app(db)
    await app.startup()
    return app
```

### 3. **Parametrized Tests**

Group similar test cases:

```python
@pytest.mark.parametrize("scenario", ["env", "user-input"])
@pytest.mark.parametrize("table", ("t", "rowid_table", "foo/bar"))
async def test_feature(datasette, scenario, table):
    # Test runs for all combinations
    pass
```

### 4. **Test Helpers in conftest.py**

Put reusable test helpers in conftest.py:

```python
# tests/conftest.py
def make_test_decision(conclusion="ALLOW", ttl=0):
    """Helper to create test decisions"""
    return Decision(conclusion=conclusion, ttl=ttl)
```

### 5. **Monkeypatch for Environment Variables**

Use pytest's monkeypatch fixture (not permanent env changes):

```python
def test_with_env(monkeypatch):
    monkeypatch.setenv("ARCJET_ENV", "development")
    # Test code
    # Environment automatically restored after test
```

## Current Issues in arcjet-py Tests

### Problem: sys.modules Stubbing

**Current approach** (tests/mocked/conftest.py):
```python
# PROBLEMATIC: Permanent module installation
mod_pb2 = types.ModuleType("arcjet.proto.decide.v1alpha1.decide_pb2")
sys.modules.setdefault("arcjet.proto.decide.v1alpha1.decide_pb2", mod_pb2)
```

**Issues:**
- Stubs persist for entire test session
- Cannot run mocked + standard tests together
- Hard to debug cross-contamination

### Solution: Fixture-Based Mocking

**Better approach:**
```python
@pytest.fixture(autouse=True, scope="function")
def mock_protobuf(monkeypatch):
    """Mock protobuf modules for this test only"""
    # Create stubs
    stub_module = create_stub_module()
    
    # Install temporarily
    monkeypatch.setitem(sys.modules, "module.name", stub_module)
    
    # Automatic cleanup when test ends
    yield
```

## Proposed Test Organization

```
tests/
├── conftest.py              # Shared fixtures and helpers
├── helpers.py               # Reusable test utilities
├── fixtures/                # Test data fixtures
│   ├── __init__.py
│   ├── decisions.py         # Decision factory functions
│   └── requests.py          # Request factory functions
├── unit/                    # Unit tests (mocked dependencies)
│   ├── test_client.py
│   ├── test_cache.py
│   ├── test_decision.py
│   └── ...
├── integration/             # Integration tests
│   ├── fastapi/
│   │   ├── test_fastapi.py
│   │   └── test_reason_v2.py
│   ├── flask/
│   │   └── test_flask.py
│   └── test_convert.py
└── TESTING_PATTERNS.md      # This file
```

## Best Practices

### Test Naming
- Use descriptive names: `test_email_validation_with_invalid_format`
- Not: `test_email_1`

### Test Structure
```python
async def test_feature_with_specific_condition():
    """Test that feature X behaves correctly when Y happens.
    
    This tests the specific case where...
    """
    # Arrange
    app = setup_app()
    
    # Act
    result = await app.process()
    
    # Assert
    assert result.is_valid()
```

### Fixture Usage
- Keep fixtures simple and focused
- Use `scope="function"` for isolation (default)
- Use `scope="session"` only for expensive, read-only resources
- Always cleanup in fixtures (use `yield` with try/finally)

### Parameterization
- Group related test cases
- Use meaningful parameter names
- Add ids for readability: `@pytest.mark.parametrize("x", [1, 2], ids=["small",
  "large"])`

## WASM Component Testing (`arcjet-analyze/tests/`)

The `arcjet-analyze` package has its own test suite for WASM bindings. These
tests exercise the wasmtime-py component model and are separate from the main
SDK tests.

### Shared Fixtures for Expensive Resources

WASM component creation is expensive (~50ms). Use fixtures to share the
component across tests:

```python
# arcjet-analyze/tests/conftest.py
@pytest.fixture()
def wasm_path() -> str:
    """Path to the full composite WASM component."""
    assert os.path.exists(WASM_PATH), f"WASM not found: {WASM_PATH}"
    return WASM_PATH

@pytest.fixture()
def component(wasm_path: str) -> AnalyzeComponent:
    """Default AnalyzeComponent with no custom callbacks."""
    return AnalyzeComponent(wasm_path)
```

### Shared Request Payloads

Define reusable request JSON constants in `conftest.py`:

```python
# arcjet-analyze/tests/conftest.py
BOT_REQUEST = json.dumps({
    "ip": "1.2.3.4",
    "method": "GET",
    "host": "example.com",
    "path": "/",
    "headers": {"user-agent": "curl/8.0"},
})

# In test files, import and optionally alias:
from conftest import BOT_REQUEST as CURL_REQUEST
```

### Test Class Organization

Group related tests into classes for readability:

```python
class TestDetectBot:
    def test_allowed_bot_config(self, component: AnalyzeComponent) -> None:
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(CURL_REQUEST, config)
        assert isinstance(result, Ok)
        assert isinstance(result.value, BotResult)

    def test_fail_without_user_agent(self, component: AnalyzeComponent) -> None:
        """Missing user-agent header returns Err."""
        request = json.dumps({"ip": "127.0.0.1"})
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        result = component.detect_bot(request, config)
        assert isinstance(result, Err)
        assert "user-agent" in result.value.lower()
```

### Result Type Assertions

WASM exports return `Ok`/`Err` result types. Use `isinstance` to check which
variant was returned, then access `.value` for the payload:

```python
result = component.detect_bot(request, config)
assert isinstance(result, Ok)          # or Err for error cases
assert isinstance(result.value, BotResult)
assert result.value.denied == ["CURL"]
```

### Thread Safety Testing

Use `ThreadPoolExecutor` to verify concurrent WASM access is safe:

```python
def test_concurrent_calls(self, component: AnalyzeComponent) -> None:
    """Concurrent calls don't crash or corrupt state."""
    num_calls = 32
    errors: list[Exception] = []

    def _call(i: int):
        config = AllowedBotConfig(entities=[], skip_custom_detect=False)
        return component.detect_bot(CURL_REQUEST, config)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_call, i) for i in range(num_calls)]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                errors.append(exc)

    assert errors == [], f"Concurrent calls raised: {errors}"
```

### Custom Callback Testing

When testing user-provided import callbacks, annotate return types with the
full union type (lists are invariant in Python typing):

```python
def test_custom_detect_called(self, wasm_path: str) -> None:
    all_tokens: list[list[str]] = []

    # Use the full SensitiveInfoEntity union, not a narrower subtype
    def my_detect(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
        all_tokens.append(tokens)
        return [None] * len(tokens)

    ac = AnalyzeComponent(
        wasm_path,
        callbacks=ImportCallbacks(sensitive_info_detect=my_detect),
    )
    config = SensitiveInfoConfig(...)
    ac.detect_sensitive_info("a b c", config)
    assert len(all_tokens) > 0
```

### Running arcjet-analyze Tests

```bash
# Via Makefile (recommended)
make test-analyze

# Or directly with coverage
uv run pytest arcjet-analyze/tests/ -o "addopts=-q --cov-report=term-missing" --cov=arcjet_analyze
```

Coverage is measured only for hand-maintained code (`_overrides.py`,
`_import_defaults.py`). The five witgen-generated files (`__init__.py`,
`_types.py`, `_convert.py`, `_component.py`, `_imports.py`) are excluded via
`[tool.coverage.run] omit` in `pyproject.toml`. The same 80% minimum threshold
applies.

## References

- [datasette-enrichments
  tests](https://github.com/datasette/datasette-enrichments/tree/main/tests)
- [pytest fixtures
  documentation](https://docs.pytest.org/en/stable/fixture.html)
- [pytest
  monkeypatch](https://docs.pytest.org/en/stable/how-to/monkeypatch.html)

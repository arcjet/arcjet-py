# Testing Patterns for arcjet-py

This document describes the testing patterns adopted from datasette-enrichments and best practices for test organization.

## Key Patterns from datasette-enrichments

### 1. **Autouse Fixtures for Test Isolation**

Instead of permanently modifying `sys.modules`, use pytest's `autouse=True` fixtures:

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

## Migration Strategy

### Step 1: Create Shared Infrastructure
1. Create `tests/conftest.py` with common fixtures
2. Create `tests/helpers.py` with utility functions
3. Create `tests/fixtures/` for test data factories

### Step 2: Convert Mocked Tests
1. Extract stub creation logic into fixtures
2. Use `autouse=True` fixtures with `scope="function"`
3. Replace `DecideServiceClient.decide_behavior = ...` with fixture parameters
4. Move helper functions to shared location

### Step 3: Reorganize Tests
1. Rename `tests/mocked/` to `tests/unit/`
2. Move integration tests under `tests/integration/`
3. Update imports

### Step 4: Enable Unified Suite
1. Remove `--ignore=tests/mocked` from pyproject.toml
2. Update CI workflows
3. Update AGENTS.md documentation

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
- Add ids for readability: `@pytest.mark.parametrize("x", [1, 2], ids=["small", "large"])`

## References

- [datasette-enrichments tests](https://github.com/datasette/datasette-enrichments/tree/main/tests)
- [pytest fixtures documentation](https://docs.pytest.org/en/stable/fixture.html)
- [pytest monkeypatch](https://docs.pytest.org/en/stable/how-to/monkeypatch.html)

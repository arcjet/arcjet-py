import pytest

pytest.importorskip(
    "fastapi",
    reason="FastAPI not installed; skipping FastAPI tests.",
)

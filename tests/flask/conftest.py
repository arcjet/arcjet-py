import pytest

pytest.importorskip(
    "flask",
    reason="Flask not installed; skipping Flask tests.",
)

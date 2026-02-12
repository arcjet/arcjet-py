"""Pytest fixtures for FastAPI integration tests."""

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

pytest.importorskip(
    "fastapi",
    reason="FastAPI not installed; skipping FastAPI tests.",
)

from arcjet import arcjet as arcjet_fastapi


@pytest.fixture
def fastapi_app() -> FastAPI:
    """Create a FastAPI application with arcjet protection for testing.
    
    Returns:
        A configured FastAPI application with a /protected route
    """
    app = FastAPI()

    arcjet = arcjet_fastapi(
        # Intentional invalid URL for testing - ensures we don't make real API calls
        base_url="https://invalid.test",
        key="ajkey_dummy",
        rules=[],
    )

    @app.get("/protected")
    async def protected_route(request: Request):
        decision = await arcjet.protect(request)

        if decision.is_error():
            return PlainTextResponse(
                f'Internal Server Error: "{decision.reason}"', status_code=500
            )
        if decision.is_allowed():
            return PlainTextResponse("Ok", status_code=200)
        if decision.is_denied():
            return PlainTextResponse("Forbidden", status_code=403)

        # This should never happen
        return PlainTextResponse("Unknown decision state", status_code=500)

    return app


@pytest.fixture
def fastapi_client(fastapi_app: FastAPI) -> TestClient:
    """Create a test client for the FastAPI application.
    
    Args:
        fastapi_app: The FastAPI application fixture
        
    Returns:
        A TestClient instance for making test requests
    """
    return TestClient(fastapi_app)


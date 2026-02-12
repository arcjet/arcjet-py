"""Integration tests for FastAPI framework support."""

import pytest


def test_basic_get(fastapi_client):
    """Test that a basic GET request to a protected route succeeds."""
    response = fastapi_client.get("/protected")
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_search_parameter(fastapi_client):
    """Test that query parameters are handled correctly."""
    response = fastapi_client.get("/protected?alpha=bravo")
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_hash(fastapi_client):
    """Test that URL fragments are handled correctly."""
    response = fastapi_client.get("/protected#alpha-bravo")
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_headers(fastapi_client):
    """Test that custom headers are passed through correctly."""
    headers = {
        "X-Custom-Header": "CustomValue",
        "User-Agent": "ArcjetTestClient/1.0",
    }
    response = fastapi_client.get("/protected", headers=headers)
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_cookies(fastapi_app):
    """Test that cookies are handled correctly."""
    from fastapi.testclient import TestClient

    cookies = {
        "session_id": "abc123",
        "user_pref": "dark_mode",
    }
    client = TestClient(fastapi_app, cookies=cookies)
    response = client.get("/protected")
    assert response.status_code == 200, f"Unexpected status: {response.text}"

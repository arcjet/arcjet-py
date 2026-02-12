"""Integration tests for Flask framework support."""

import pytest


def test_basic_get(flask_client):
    """Test that a basic GET request to a protected route succeeds."""
    response = flask_client.get("/protected")
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_search_parameter(flask_client):
    """Test that query parameters are handled correctly."""
    response = flask_client.get("/protected?alpha=bravo")
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_hash(flask_client):
    """Test that URL fragments are handled correctly."""
    response = flask_client.get("/protected#alpha-bravo")
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_headers(flask_client):
    """Test that custom headers are passed through correctly."""
    headers = {
        "X-Custom-Header": "CustomValue",
        "User-Agent": "ArcjetTestClient/1.0",
    }
    response = flask_client.get("/protected", headers=headers)
    assert response.status_code == 200, f"Unexpected status: {response.text}"


def test_basic_get_with_cookies(flask_client):
    """Test that cookies are handled correctly."""
    flask_client.set_cookie("alpha", "bravo")
    flask_client.set_cookie("charlie", "delta")

    response = flask_client.get("/protected")
    assert response.status_code == 200, f"Unexpected status: {response.text}"

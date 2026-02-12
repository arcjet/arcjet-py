"""Pytest fixtures for Flask integration tests."""

import pytest

pytest.importorskip(
    "flask",
    reason="Flask not installed; skipping Flask tests.",
)

from flask import Flask, request

from arcjet import arcjet_sync as arcjet_flask


@pytest.fixture
def flask_app() -> Flask:
    """Create a Flask application with arcjet protection for testing.
    
    Returns:
        A configured Flask application with a /protected route
    """
    app = Flask(__name__)

    arcjet = arcjet_flask(
        # Intentional invalid URL for testing - ensures we don't make real API calls
        base_url="https://invalid.test",
        key="ajkey_dummy",
        rules=[],
    )

    @app.route("/protected", methods=["GET"])
    def protected_route():
        decision = arcjet.protect(request)

        if decision.is_error():
            return f'Internal Server Error: "{decision.reason}"', 500
        if decision.is_allowed():
            return "Ok", 200
        if decision.is_denied():
            return "Forbidden", 403

        # This should never happen
        return "Unknown decision state", 500

    return app


@pytest.fixture
def flask_client(flask_app: Flask):
    """Create a test client for the Flask application.
    
    Args:
        flask_app: The Flask application fixture
        
    Returns:
        A Flask test client for making test requests
    """
    return flask_app.test_client()


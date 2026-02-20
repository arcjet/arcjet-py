import pytest
from flask import Flask, request

from arcjet import arcjet_sync as arcjet_flask


def create_app() -> Flask:
    app = Flask(__name__)

    arcjet = arcjet_flask(
        base_url="https://invalid.test",  # Intentional invalid URL for testing
        key="ajkey_dummy",
        rules=[],
    )

    @app.route("/protected", methods=["GET"])
    def protected_route():
        decision = arcjet.protect(request)

        if decision.is_error():
            return f'Internal Server Error: "${decision.reason}', 500
        if decision.is_allowed():
            return "Ok", 200
        if decision.is_denied():
            return "Forbidden", 403

        pytest.fail("Unexpected decision state.")

    return app


def test_basic_get():
    app = create_app()
    client = app.test_client()

    response = client.get("/protected")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_search_parameter():
    app = create_app()
    client = app.test_client()

    response = client.get("/protected?alpha=bravo")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_hash():
    app = create_app()
    client = app.test_client()

    response = client.get("/protected#alpha-bravo")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_headers():
    app = create_app()
    client = app.test_client()

    headers = {
        "X-Custom-Header": "CustomValue",
        "User-Agent": "ArcjetTestClient/1.0",
    }

    response = client.get("/protected", headers=headers)

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_cookies():
    app = create_app()

    client = app.test_client()
    client.set_cookie("alpha", "bravo")
    client.set_cookie("charlie", "delta")

    response = client.get("/protected")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"

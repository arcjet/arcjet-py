import pytest
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

from arcjet import arcjet as arcjet_fastapi


def create_app() -> FastAPI:
    app = FastAPI()

    arcjet = arcjet_fastapi(
        base_url="https://invalid.test",  # Intentional invalid URL for testing
        key="ajkey_dummy",
        rules=[],
    )

    @app.get("/protected")
    async def protected_route(request: Request):
        decision = await arcjet.protect(request)

        if decision.is_error():
            return PlainTextResponse(
                f'Internal Server Error: "${decision.reason}', status_code=500
            )
        if decision.is_allowed():
            return PlainTextResponse("Ok", status_code=200)
        if decision.is_denied():
            return PlainTextResponse("Forbidden", status_code=403)

        pytest.fail("Unexpected decision state.")

    return app


def test_basic_get():
    app = create_app()
    client = TestClient(app)

    response = client.get("/protected")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_search_parameter():
    app = create_app()
    client = TestClient(app)

    response = client.get("/protected?alpha=bravo")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_hash():
    app = create_app()
    client = TestClient(app)

    response = client.get("/protected#alpha-bravo")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_headers():
    app = create_app()
    client = TestClient(app)

    headers = {
        "X-Custom-Header": "CustomValue",
        "User-Agent": "ArcjetTestClient/1.0",
    }

    response = client.get("/protected", headers=headers)

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"


def test_basic_get_with_cookies():
    app = create_app()

    cookies = {
        "session_id": "abc123",
        "user_pref": "dark_mode",
    }

    client = TestClient(app, cookies=cookies)

    response = client.get("/protected")

    # With fail_open=True (default) and an invalid URL, we get an ERROR decision
    assert response.status_code == 500, f"Unexpected status: {response.text}"

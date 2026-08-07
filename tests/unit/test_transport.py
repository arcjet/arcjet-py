"""Tests for shared transport construction.

**What these prove, and what they do not.** None of these establish that TLS
works — that needs a real request to a real host, which a unit test should not
make. They are regression guards for the specific mistake that shipped: the flag
being absent from a transport, and transports being built outside the one helper
that sets it.

The bug: pyqwest 0.7.0 added ``tls_include_system_certs`` defaulting to
``False``, so a transport trusts no root certificates, and all four Arcjet client
factories built transports without it. Every HTTPS request failed with
``invalid peer certificate: UnknownIssuer``. Because the SDK fails open, that
surfaced as an ALLOW decision with ``reason=ERROR`` rather than an obvious
network fault.

Why the suite missed it: ``uv.lock`` pinned pyqwest 0.6.2, where the parameter
did not exist and the system store was always used. Only a fresh install
resolved 0.7.0 and broke — a dependency-resolution failure, which no in-repo
test run can see. Catching that class of problem needs a scheduled job that
installs the published package and makes a real request.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pyqwest
import pytest

import arcjet._client as request_client
import arcjet.guard._client as guard_client
from arcjet._transport import build_async_transport, build_sync_transport

BUILDERS = [build_sync_transport, build_async_transport]


def _spy_kwargs(monkeypatch: pytest.MonkeyPatch, build: Any, **kwargs: Any) -> dict:
    """Record the keyword arguments *build* passes to pyqwest."""
    seen: dict[str, Any] = {}

    def spy(**passed: Any) -> str:
        seen.update(passed)
        return "transport"

    monkeypatch.setattr(pyqwest, "SyncHTTPTransport", spy)
    monkeypatch.setattr(pyqwest, "HTTPTransport", spy)
    build(**kwargs)
    return seen


class TestInstalledPyqwest:
    """Guards against the installed pyqwest changing this API under us."""

    @pytest.mark.parametrize("build", BUILDERS)
    def test_the_installed_pyqwest_accepts_the_flag(self, build: Any) -> None:
        """A rename or removal must fail here, loudly and without network.

        This is the one test that touches real pyqwest. The flag is passed
        unconditionally rather than probed for, so if a future version drops or
        renames it, construction raises TypeError instead of silently falling
        back to trusting nothing.
        """
        transport = build()

        assert transport is not None

    def test_the_flag_still_defaults_to_false_upstream(self) -> None:
        """Documents *why* the flag is passed at all.

        If a future pyqwest defaults this back to True, this test fails and the
        explicit flag becomes redundant rather than load-bearing — worth knowing
        deliberately instead of discovering it later.
        """
        import inspect

        parameter = inspect.signature(pyqwest.SyncHTTPTransport).parameters.get(
            "tls_include_system_certs"
        )

        assert parameter is not None, "pyqwest dropped tls_include_system_certs"
        assert parameter.default is False, (
            "pyqwest changed the default; re-evaluate whether the explicit flag "
            f"is still needed (default is now {parameter.default!r})"
        )


class TestHelperPassesTheFlag:
    @pytest.mark.parametrize("build", BUILDERS)
    def test_passes_tls_include_system_certs_true(
        self, build: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = _spy_kwargs(monkeypatch, build)

        assert seen.get("tls_include_system_certs") is True

    @pytest.mark.parametrize("build", BUILDERS)
    def test_passes_http2(self, build: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _spy_kwargs(monkeypatch, build)

        assert seen.get("http_version") == pyqwest.HTTPVersion.HTTP2

    @pytest.mark.parametrize("build", BUILDERS)
    def test_an_override_cannot_silently_drop_tls_trust(
        self, build: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = _spy_kwargs(monkeypatch, build, connect_timeout=3.0)

        assert seen.get("connect_timeout") == 3.0
        assert seen.get("tls_include_system_certs") is True

    @pytest.mark.parametrize("build", BUILDERS)
    def test_an_override_can_still_replace_a_default_on_purpose(
        self, build: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = _spy_kwargs(monkeypatch, build, http_version=pyqwest.HTTPVersion.HTTP1)

        assert seen.get("http_version") == pyqwest.HTTPVersion.HTTP1


class TestNothingBypassesTheHelper:
    """The original bug was four independent constructions drifting apart.

    This is the most valuable test here: it fails if a new call site appears,
    which is how the flag went missing in the first place.
    """

    def test_client_modules_import_the_helper(self) -> None:
        for module in (request_client, guard_client):
            assert hasattr(module, "build_async_transport")
            assert hasattr(module, "build_sync_transport")

    def test_no_module_constructs_a_transport_directly(self) -> None:
        root = Path(request_client.__file__).parent
        offenders = []
        for path in root.rglob("*.py"):
            if path.name == "_transport.py" or "proto" in path.parts:
                continue
            text = path.read_text()
            for needle in ("pyqwest.HTTPTransport(", "pyqwest.SyncHTTPTransport("):
                if needle in text:
                    offenders.append(f"{path.relative_to(root)}: {needle}")

        assert offenders == [], (
            "build transports via arcjet._transport so TLS settings cannot "
            f"drift: {offenders}"
        )

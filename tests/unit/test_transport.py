"""Tests for shared transport construction.

**What these prove, and what they do not.** Most of these are regression
guards for the mistake that shipped in 0.9.0: constructing a custom
HTTP/2-only pyqwest transport, which trusts no root certificates.

The TLS handshake itself is covered by a local HTTPS server with a
throwaway CA — that reproduces ``UnknownIssuer`` without a network call.
Live requests to ``decide.arcjet.com`` are out of scope here; catching a
broken *published* package needs a scheduled install-and-request job.
"""

from __future__ import annotations

import http.server
import ssl
import subprocess
import threading
from collections.abc import Iterator
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

        The override path passes the flag unconditionally rather than probing
        for it, so if a future version drops or renames it, construction
        raises TypeError instead of silently falling back to trusting nothing.
        """
        transport = build(connect_timeout=3.0)

        assert transport is not None

    def test_the_flag_still_defaults_to_false_upstream(self) -> None:
        """Documents *why* a custom transport must set the flag.

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

    def test_bare_http_transport_is_not_the_default(self) -> None:
        """``HTTPTransport()`` is not the default Client() transport.

        pyqwest's docs are easy to misread here: constructing a transport with
        no arguments does **not** produce the shared default, and it does not
        trust any CAs. That distinction is the whole bug.
        """
        assert pyqwest.HTTPTransport() is not pyqwest.get_default_transport()
        assert pyqwest.SyncHTTPTransport() is not pyqwest.get_default_sync_transport()


class TestHelperUsesTheDefaultTransport:
    """Issue #201: we do not need a custom HTTP/2 transport."""

    @pytest.mark.parametrize("build", BUILDERS)
    def test_no_overrides_returns_the_default_singleton(self, build: Any) -> None:
        transport = build()

        if build is build_async_transport:
            assert transport is pyqwest.get_default_transport()
        else:
            assert transport is pyqwest.get_default_sync_transport()

    @pytest.mark.parametrize("build", BUILDERS)
    def test_no_overrides_does_not_construct_a_custom_transport(
        self, build: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(**kwargs: Any) -> str:
            raise AssertionError(
                f"no-arg helper must use the default transport, not construct one: {kwargs}"
            )

        monkeypatch.setattr(pyqwest, "SyncHTTPTransport", boom)
        monkeypatch.setattr(pyqwest, "HTTPTransport", boom)

        assert build() is not None


class TestOverridePathKeepsSystemCerts:
    @pytest.mark.parametrize("build", BUILDERS)
    def test_passes_tls_include_system_certs_true(
        self, build: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = _spy_kwargs(monkeypatch, build, connect_timeout=3.0)

        assert seen.get("tls_include_system_certs") is True

    @pytest.mark.parametrize("build", BUILDERS)
    def test_does_not_force_http2(
        self, build: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = _spy_kwargs(monkeypatch, build, connect_timeout=3.0)

        assert "http_version" not in seen

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
        assert seen.get("tls_include_system_certs") is True


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


class _LocalHTTPS:
    """A one-shot HTTPS server serving 200 on GET, with a throwaway CA."""

    def __init__(self, url: str, ca_pem: bytes) -> None:
        self.url = url
        self.ca_pem = ca_pem


def _run_openssl(*args: str) -> None:
    subprocess.run(
        ["openssl", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _make_ca_and_server_cert(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Return ``(ca_pem, server_pem, server_key)``.

    rustls rejects a CA certificate presented as the server leaf
    (``CaUsedAsEndEntity``), so the server cert must be a separate
    end-entity signed by the throwaway CA.
    """
    ca_key = tmp_path / "ca.key"
    ca_pem = tmp_path / "ca.pem"
    server_key = tmp_path / "server.key"
    server_csr = tmp_path / "server.csr"
    server_pem = tmp_path / "server.pem"
    server_ext = tmp_path / "server.ext"

    _run_openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_pem),
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=arcjet-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    )
    _run_openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(server_key),
        "-out",
        str(server_csr),
        "-nodes",
        "-subj",
        "/CN=localhost",
    )
    server_ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    _run_openssl(
        "x509",
        "-req",
        "-in",
        str(server_csr),
        "-CA",
        str(ca_pem),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(server_pem),
        "-days",
        "1",
        "-extfile",
        str(server_ext),
    )
    return ca_pem, server_pem, server_key


@pytest.fixture
def local_https(tmp_path: Path) -> Iterator[_LocalHTTPS]:
    """Local HTTPS server whose CA is *not* in the system store."""
    ca_path, cert_path, key_path = _make_ca_and_server_cert(tmp_path)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # PROTOCOL_TLS_SERVER can still offer TLS 1.0/1.1 unless pinned; CodeQL
    # flags that even for this localhost fixture.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield _LocalHTTPS(
            url=f"https://127.0.0.1:{httpd.server_port}/",
            ca_pem=ca_path.read_bytes(),
        )
    finally:
        httpd.shutdown()
        thread.join(timeout=2.0)


def _assert_unknown_issuer(exc: BaseException) -> None:
    message = str(exc)
    assert "UnknownIssuer" in message, message


class TestIssue201Reproduction:
    """Reproduce the 0.9.0 TLS failure against a local HTTPS server.

    These are the constructions from
    https://github.com/arcjet/arcjet-py/issues/201. The server's certificate
    is not in the system store, which is the same situation a custom
    transport with an empty root store sees for *every* host — including
    ``decide.arcjet.com``.
    """

    def test_bare_transport_fails_unknown_issuer(
        self, local_https: _LocalHTTPS
    ) -> None:
        client = pyqwest.SyncClient(pyqwest.SyncHTTPTransport())

        with pytest.raises(ConnectionError) as exc_info:
            client.get(local_https.url)

        _assert_unknown_issuer(exc_info.value)

    def test_http2_only_transport_fails_unknown_issuer(
        self, local_https: _LocalHTTPS
    ) -> None:
        """The exact 0.9.0 construction: force HTTP/2, forget the CA store."""
        client = pyqwest.SyncClient(
            pyqwest.SyncHTTPTransport(http_version=pyqwest.HTTPVersion.HTTP2)
        )

        with pytest.raises(ConnectionError) as exc_info:
            client.get(local_https.url)

        _assert_unknown_issuer(exc_info.value)

    def test_http2_plus_system_certs_still_needs_the_server_ca(
        self, local_https: _LocalHTTPS
    ) -> None:
        """System certs alone cannot validate a throwaway local CA.

        This is the #173 construction. It fixes public hosts; it is not a
        reason to keep forcing HTTP/2.
        """
        client = pyqwest.SyncClient(
            pyqwest.SyncHTTPTransport(
                http_version=pyqwest.HTTPVersion.HTTP2,
                tls_include_system_certs=True,
            )
        )

        with pytest.raises(ConnectionError) as exc_info:
            client.get(local_https.url)

        _assert_unknown_issuer(exc_info.value)

    def test_helper_with_server_ca_succeeds(self, local_https: _LocalHTTPS) -> None:
        client = pyqwest.SyncClient(
            build_sync_transport(tls_ca_cert=local_https.ca_pem)
        )

        response = client.get(local_https.url)

        assert response.status == 200

    def test_custom_transport_with_server_ca_succeeds(
        self, local_https: _LocalHTTPS
    ) -> None:
        client = pyqwest.SyncClient(
            pyqwest.SyncHTTPTransport(tls_ca_cert=local_https.ca_pem)
        )

        response = client.get(local_https.url)

        assert response.status == 200

"""Regression tests for HTTP_PROXY / HTTPS_PROXY / NO_PROXY support.

The Arcjet Python SDK talks to the Decide API over HTTPS using ``pyqwest``
(a binding around Rust's ``reqwest``). ``reqwest`` automatically honors the
standard ``HTTP_PROXY`` / ``HTTPS_PROXY`` / ``NO_PROXY`` environment variables
(both upper- and lower-case) unless proxying is explicitly disabled. These tests
pin that behavior so a future change to how we construct the transport (e.g.
accidentally disabling system proxies) is caught.

The tests make no connection to a real server: when the proxy is used, the
request goes to a local throwaway TCP listener that records the first bytes it
receives. For HTTPS targets ``reqwest`` issues an HTTP ``CONNECT`` tunnel
request to the proxy, so the listener observes ``CONNECT <host>:443`` when (and
only when) the proxy is used. The negative cases (proxy bypassed) instead
attempt a *direct* request to ``decide.arcjet.test``; that host uses a reserved
TLD (RFC 6761) so it never resolves to a real address — the only outbound
activity is a DNS lookup that is expected to fail.
"""

from __future__ import annotations

import socket
import threading
from contextlib import closing

import pyqwest
import pytest

# A reserved TLD (RFC 6761) that never resolves, so a *direct* (non-proxied)
# request fails fast at DNS resolution and our fake proxy is the only way the
# request could ever produce a CONNECT line.
TARGET_HOST = "decide.arcjet.test"
TARGET_URL = f"https://{TARGET_HOST}/"


class _FakeProxy:
    """A one-shot TCP listener that captures the first request line it sees."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self._sock.settimeout(5.0)
        self.port: int = self._sock.getsockname()[1]
        self.first_line: str | None = None
        # Set once the serve thread finishes (after capturing a line or timing
        # out). Lets the positive test synchronize before reading first_line
        # instead of racing the background thread.
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            self._capture()
        finally:
            self._done.set()

    def _capture(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except (OSError, socket.timeout):
            return
        with closing(conn):
            conn.settimeout(2.0)
            try:
                data = conn.recv(1024)
            except (OSError, socket.timeout):
                return
            if data:
                self.first_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")

    def wait_for_connection(self, timeout: float = 5.0) -> bool:
        """Block until the serve thread has handled a connection (or timed out).

        Returns True if the thread finished within ``timeout``.
        """
        return self._done.wait(timeout)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            # Best-effort cleanup: the listener socket may already be closed
            # (e.g. after a successful accept), which is fine to ignore.
            pass
        self._thread.join(timeout=1.0)


def _make_transport() -> pyqwest.SyncHTTPTransport:
    # Use the same HTTP/2 setting the SDK's transport uses (see arcjet_sync()
    # and the guard client), so we exercise the same proxy/CONNECT-tunnel code
    # path the real client uses. connect_timeout is a test-only addition to keep
    # the bypass cases fast; the SDK does not set it.
    return pyqwest.SyncHTTPTransport(
        http_version=pyqwest.HTTPVersion.HTTP2,
        connect_timeout=3.0,
    )


def _attempt_request() -> None:
    # Construct the client outside the try block: a transport/client setup
    # failure is a real test error and must not be swallowed, otherwise the
    # negative tests (asserting the proxy was *not* contacted) could pass
    # without ever exercising the proxy behavior.
    client = pyqwest.SyncClient(_make_transport())
    # Only the request itself is expected to fail (the fake proxy closes the
    # tunnel, or DNS fails for a direct request to the reserved .test host).
    # We assert on what the proxy observed, not on the request outcome, so any
    # request-path error here is intentionally ignored.
    try:
        client.get(TARGET_URL)
    except Exception:
        pass


@pytest.fixture
def clean_proxy_env(monkeypatch: pytest.MonkeyPatch):
    for var in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


@pytest.fixture
def fake_proxy():
    proxy = _FakeProxy()
    try:
        yield proxy
    finally:
        proxy.close()


@pytest.mark.parametrize("var", ["HTTPS_PROXY", "https_proxy"])
def test_https_proxy_is_used(clean_proxy_env, fake_proxy, var: str) -> None:
    """An HTTPS request tunnels through HTTPS_PROXY (upper- and lower-case)."""
    clean_proxy_env.setenv(var, fake_proxy.url)
    _attempt_request()
    # Synchronize with the listener thread before reading first_line, otherwise
    # the assertion can race the background recv().
    assert fake_proxy.wait_for_connection(), "proxy was not contacted"
    assert fake_proxy.first_line is not None, "proxy was not contacted"
    assert fake_proxy.first_line.startswith(f"CONNECT {TARGET_HOST}:443")


def test_http_proxy_does_not_capture_https(clean_proxy_env, fake_proxy) -> None:
    """HTTP_PROXY must not hijack HTTPS traffic (that's HTTPS_PROXY's job)."""
    clean_proxy_env.setenv("HTTP_PROXY", fake_proxy.url)
    _attempt_request()
    assert fake_proxy.first_line is None


def test_no_proxy_bypasses_proxy(clean_proxy_env, fake_proxy) -> None:
    """NO_PROXY matching the target host bypasses HTTPS_PROXY entirely."""
    clean_proxy_env.setenv("HTTPS_PROXY", fake_proxy.url)
    clean_proxy_env.setenv("NO_PROXY", TARGET_HOST)
    _attempt_request()
    assert fake_proxy.first_line is None


def test_no_proxy_wildcard_bypasses_proxy(clean_proxy_env, fake_proxy) -> None:
    """NO_PROXY=* disables proxying for all hosts."""
    clean_proxy_env.setenv("HTTPS_PROXY", fake_proxy.url)
    clean_proxy_env.setenv("NO_PROXY", "*")
    _attempt_request()
    assert fake_proxy.first_line is None

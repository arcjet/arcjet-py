"""Shared pyqwest transport construction.

Every Arcjet client builds its HTTP transport here, rather than each factory
constructing its own.

Prefer pyqwest's default transport. ``Client()`` / ``SyncClient()`` and
``get_default_transport()`` / ``get_default_sync_transport()`` load the
platform CA store and let ALPN pick HTTP/2 on TLS. That is enough for the
Connect Decide API — it does not require a forced-HTTP/2 transport.

A *custom* ``HTTPTransport()`` is a different object. pyqwest 0.7.0 added
``tls_include_system_certs`` defaulting to ``False``, so a transport built
without it trusts **no** root certificates and every HTTPS request fails
with ``invalid peer certificate: UnknownIssuer``. That is the 0.9.0 bug
(`#201 <https://github.com/arcjet/arcjet-py/issues/201>`_): the SDK forced
``http_version=HTTP2``, which required constructing a custom transport, which
silently dropped the system store.

We only construct a custom transport when a caller passes overrides (tests
setting ``connect_timeout``, for example). That path always sets
``tls_include_system_certs=True`` and does **not** force HTTP/2.
"""

from __future__ import annotations

from typing import Any

import pyqwest


def _custom_transport_kwargs(**overrides: Any) -> dict[str, Any]:
    return {
        # Trust the platform's CA store. See the module docstring.
        "tls_include_system_certs": True,
        **overrides,
    }


def build_async_transport(**overrides: Any) -> pyqwest.HTTPTransport:
    """Build the async transport every async Arcjet client uses.

    With no overrides this is pyqwest's shared default transport. Overrides
    build a dedicated transport that still trusts the system CA store.

    Args:
        **overrides: Extra pyqwest transport options, or replacements for the
            defaults set here.

    Returns:
        A configured :class:`pyqwest.HTTPTransport`.
    """
    if not overrides:
        return pyqwest.get_default_transport()
    return pyqwest.HTTPTransport(**_custom_transport_kwargs(**overrides))


def build_sync_transport(**overrides: Any) -> pyqwest.SyncHTTPTransport:
    """Build the sync transport every sync Arcjet client uses.

    With no overrides this is pyqwest's shared default transport. Overrides
    build a dedicated transport that still trusts the system CA store.

    Args:
        **overrides: Extra pyqwest transport options, or replacements for the
            defaults set here.

    Returns:
        A configured :class:`pyqwest.SyncHTTPTransport`.
    """
    if not overrides:
        return pyqwest.get_default_sync_transport()
    return pyqwest.SyncHTTPTransport(**_custom_transport_kwargs(**overrides))

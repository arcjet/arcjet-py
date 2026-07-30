"""Shared pyqwest transport construction.

Every Arcjet client builds its HTTP transport here, rather than each factory
constructing its own.  Four factories previously did it independently, which is
how they all came to be missing ``tls_include_system_certs``.

``tls_include_system_certs=True`` is not optional.  pyqwest 0.7.0 introduced
that parameter defaulting to ``False``, meaning a transport trusts **no** root
certificates and every HTTPS request fails with
``invalid peer certificate: UnknownIssuer``.  Before 0.7.0 the parameter did not
exist and the system store was always used, so the default flip silently broke
outbound TLS for anyone who installed a fresh pyqwest.  This is why the
dependency floor is ``pyqwest>=0.7.0``: on 0.6.2 and earlier, passing the
keyword is a ``TypeError``.
"""

from __future__ import annotations

from typing import Any

import pyqwest


def _transport_kwargs(**overrides: Any) -> dict[str, Any]:
    return {
        # Always enable HTTP/2 by default.
        "http_version": pyqwest.HTTPVersion.HTTP2,
        # Trust the platform's CA store. See the module docstring.
        "tls_include_system_certs": True,
        **overrides,
    }


def build_async_transport(**overrides: Any) -> pyqwest.HTTPTransport:
    """Build the async transport every async Arcjet client uses.

    Args:
        **overrides: Extra pyqwest transport options, or replacements for the
            defaults set here.

    Returns:
        A configured :class:`pyqwest.HTTPTransport`.
    """
    return pyqwest.HTTPTransport(**_transport_kwargs(**overrides))


def build_sync_transport(**overrides: Any) -> pyqwest.SyncHTTPTransport:
    """Build the sync transport every sync Arcjet client uses.

    Args:
        **overrides: Extra pyqwest transport options, or replacements for the
            defaults set here.

    Returns:
        A configured :class:`pyqwest.SyncHTTPTransport`.
    """
    return pyqwest.SyncHTTPTransport(**_transport_kwargs(**overrides))

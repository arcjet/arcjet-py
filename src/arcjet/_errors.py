from __future__ import annotations


class ArcjetError(Exception):
    """Base error raised by the Arcjet Python SDK."""


class ArcjetMisconfiguration(ArcjetError):
    """Raised when the SDK is configured incorrectly (e.g. missing key)."""


class ArcjetTransportError(ArcjetError):
    """Raised when Arcjet API cannot be reached or returns a transport error."""

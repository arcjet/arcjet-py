"""Pluggable detection backend for the sensitive information rule.

The default backend uses the bundled ``arcjet-analyze`` WebAssembly engine,
which detects email addresses, phone numbers, IP addresses, and credit card
numbers entirely locally. Provide a custom backend — for example
``arcjet-sensitive-info-rampart``, which runs an on-device NER model — to detect
additional sensitive information without changing the rest of the rule.

Backends are **synchronous** in the Python SDK: local rule evaluation runs on
the synchronous request path and model inference is blocking, so a backend's
latency directly affects request handling.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Callable,
    Iterable,
    Optional,
    Protocol,
    Sequence,
    runtime_checkable,
)

if TYPE_CHECKING:
    from arcjet._analyze import SensitiveInfoEntities, SensitiveInfoResult

# The sensitive info types the bundled WASM engine detects natively.
NATIVE_SENSITIVE_INFO_TYPES: frozenset[str] = frozenset(
    {"EMAIL", "PHONE_NUMBER", "IP_ADDRESS", "CREDIT_CARD_NUMBER"}
)
"""Built-in sensitive info types the default (WASM) backend detects natively."""

# Built-in sensitive info types the default (WASM) backend cannot detect. Each is
# only detected when a backend that supports it is configured (such as
# ``arcjet-sensitive-info-rampart``). ``SensitiveInfoEntityType`` in ``_rules.py``
# is kept in sync by an assertion there; ``guard/_types.py`` derives its sets from
# these frozensets.
BACKEND_ONLY_SENSITIVE_INFO_TYPES: frozenset[str] = frozenset(
    {
        "GIVEN_NAME",
        "SURNAME",
        "SSN",
        "URL",
        "TAX_ID",
        "BANK_ACCOUNT",
        "ROUTING_NUMBER",
        "GOVERNMENT_ID",
        "PASSPORT",
        "DRIVERS_LICENSE",
        "BUILDING_NUMBER",
        "STREET_NAME",
        "SECONDARY_ADDRESS",
        "CITY",
        "STATE",
        "ZIP_CODE",
    }
)
"""Built-in sensitive info types only detected by an alternative backend."""


def is_invalid_backend(backend: object) -> bool:
    """Whether a non-``None`` ``backend`` cannot be used for detection.

    A usable backend is an *instance* exposing a callable ``detect`` method;
    passing the class itself (a common mistake) or an object without ``detect``
    is rejected. Shared by the core ``SensitiveInfoDetection`` and the guard
    ``LocalDetectSensitiveInfo`` so both agree on what a valid backend is; each
    caller raises its own error type. Callers must guard for ``None`` first.
    """
    return isinstance(backend, type) or not callable(getattr(backend, "detect", None))


def unsupported_backend_only_types(specifiers: Iterable[str]) -> list[str]:
    """Return the backend-only types in ``specifiers``, deduplicated in order.

    These are the built-in types the default (WASM) backend cannot detect, so
    listing one without a supporting backend (or custom ``detect``) is a
    configuration error. Order is preserved so error messages are deterministic.
    """
    seen: dict[str, None] = {}
    for name in specifiers:
        if name in BACKEND_ONLY_SENSITIVE_INFO_TYPES:
            seen[name] = None
    return list(seen)


def backend_only_error_message(
    names: Sequence[str], *, prefix: str, mention_detect: bool
) -> str:
    """Build the "these types need a backend" error message shared by the rules.

    Args:
        names: The unsupported backend-only type names (non-empty).
        prefix: Caller-specific lead-in (e.g. the function or class name).
        mention_detect: Whether to mention the custom ``detect`` fallback (only
            the ``detect_sensitive_info`` factory exposes one).
    """
    quoted = ", ".join(f'"{name}"' for name in names)
    subject = "type is" if len(names) == 1 else "types are"
    obj = "it" if len(names) == 1 else "them"
    detect_clause = (
        " or a custom `detect` function is provided" if mention_detect else ""
    )
    return (
        f"{prefix}: the {quoted} {subject} only detected when a `backend` that "
        f"supports {obj} is configured (such as `arcjet-sensitive-info-rampart`)"
        f'{detect_clause}. The default backend only detects "EMAIL", '
        '"PHONE_NUMBER", "IP_ADDRESS", and "CREDIT_CARD_NUMBER".'
    )


def default_backend() -> SensitiveInfoBackend:
    """Return the shared default (WASM) sensitive-info backend.

    The concrete backend lives in :mod:`arcjet._local` (it wraps the WASM
    component), so it is imported lazily here to keep this module free of that
    dependency. The guard local evaluator reaches the default backend through
    this accessor rather than importing the private instance directly; the core
    evaluator lives alongside the instance in :mod:`arcjet._local` and
    references it there.
    """
    from arcjet._local import _WASM_SENSITIVE_INFO_BACKEND

    return _WASM_SENSITIVE_INFO_BACKEND


@dataclass(frozen=True, slots=True)
class SensitiveInfoBackendContext:
    """Minimal context passed to a :class:`SensitiveInfoBackend`."""

    log: logging.Logger
    """Logger for backend diagnostics."""


@dataclass(frozen=True, slots=True)
class SensitiveInfoBackendOptions:
    """Per-detection options passed to a :class:`SensitiveInfoBackend`.

    These come from the ``detect_sensitive_info`` rule configuration. A backend
    reads the ones it understands and ignores the rest, so the interface stays
    stable as options are added.
    """

    context_window_size: Optional[int] = None
    """Number of tokens to pass to ``detect``."""

    detect: Optional[Callable[[list[str]], Sequence[Optional[str]]]] = None
    """Custom token-based detection function (optional)."""


@runtime_checkable
class SensitiveInfoBackend(Protocol):
    """Pluggable detection backend for the sensitive info rule.

    The default backend uses the bundled ``arcjet-analyze`` WebAssembly engine,
    which detects email addresses, phone numbers, IP addresses, and credit card
    numbers entirely locally. Provide a custom backend — for example
    ``arcjet-sensitive-info-rampart``, which runs an on-device NER model — to
    detect additional sensitive information without changing the rest of the
    rule.

    A backend receives the text to scan together with the configured allow/deny
    ``entities`` and must return which detected spans are ``allowed`` and which
    are ``denied``. This matches the shape of ``detect_sensitive_info`` in
    ``arcjet._analyze``, so the default backend is a thin wrapper over it.
    """

    def detect(
        self,
        context: SensitiveInfoBackendContext,
        value: str,
        entities: SensitiveInfoEntities,
        options: Optional[SensitiveInfoBackendOptions] = None,
    ) -> SensitiveInfoResult:
        """Detect sensitive information in ``value``.

        Args:
            context: Backend context (currently just a logger).
            value: Text to scan.
            entities: Configured allow/deny entities.
            options: Per-detection options from the rule configuration.

        Returns:
            The allowed and denied spans.
        """
        ...

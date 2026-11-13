"""Pluggable detection backend for the sensitive information rule.

The recommended backend is ``arcjet-sensitive-info-rampart``
(``pip install "arcjet[sensitive-info-rampart]"``), which runs the on-device
Rampart NER model entirely locally. Pass ``backend=rampart()`` to the rule.

Backends are **synchronous** in the Python SDK: local rule evaluation runs on
the synchronous request path and model inference is blocking, so a backend's
latency directly affects request handling.

A backend can declare the largest input it scans with an optional
``max_input_chars`` attribute (see :class:`SensitiveInfoBackend`). The SDK rules
deny input over that limit without calling the backend, so content past the
limit is never let through unscanned.
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

from arcjet._logging import logger

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


def backend_input_limit(backend: object) -> Optional[int]:
    """Return the input limit ``backend`` declares, or ``None`` if it has none.

    A backend declares a limit with an optional ``max_input_chars`` attribute or
    property. It is optional so third-party backends written before it existed
    keep working unchanged. Only a positive ``int`` counts as a limit: a missing,
    non-integer, boolean, or non-positive value, or a property that raises, is
    treated as no limit, which is the behavior before backends could declare one.
    """
    try:
        limit = getattr(backend, "max_input_chars", None)
    except Exception:
        return None
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        return None
    return limit


def oversize_input_message(backend: object, value: str) -> Optional[str]:
    """Check ``value`` against the limit ``backend`` declares.

    The SDK rules call this before ``backend.detect`` and deny the input when it
    returns a message, so no inference runs on it and nothing past the limit is
    let through unscanned. Length is counted in code points (``len(value)``),
    the unit the Rampart backend uses.

    Logs one warning with the input length and the limit. The message and the
    log never include the text itself.

    Returns:
        A message describing the overflow when ``value`` is longer than the
        declared limit, otherwise ``None``.
    """
    limit = backend_input_limit(backend)
    if limit is None or len(value) <= limit:
        return None
    message = (
        f"sensitive info input of {len(value)} characters exceeds the backend "
        f"limit of {limit}"
    )
    logger.warning("%s; denying without scanning", message)
    return message


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

    The recommended backend is ``arcjet_sensitive_info_rampart.rampart()``,
    which runs the on-device Rampart NER model entirely locally. Implement this
    protocol only to plug in your own detector.

    A backend receives the text to scan together with the configured allow/deny
    ``entities`` and must return which detected spans are ``allowed`` and which
    are ``denied``.

    A backend may also expose an optional ``max_input_chars`` attribute or
    property: a positive ``int`` giving the largest input, in characters (code
    points), that it scans. It is not part of this protocol, so existing
    backends need not define it. When it is set, the ``detect_sensitive_info``
    rule and ``arcjet.guard`` sensitive info detection deny any longer input
    without calling :meth:`detect`, rather than letting the unscanned remainder
    through. Without it, every input is passed to :meth:`detect` as before.
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

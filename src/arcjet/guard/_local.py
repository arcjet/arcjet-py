"""Local rule evaluation for ``arcjet.guard``.

Evaluates sensitive info detection rules locally, using the bundled
arcjet-analyze WASM backend by default or an alternative ``backend`` when one
is configured.  The raw text never leaves the SDK — only a SHA-256 hash is
sent to the server alongside the locally-computed result.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from arcjet._logging import logger
from arcjet._sensitive_info_backend import (
    SensitiveInfoBackend,
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
    default_backend,
)

if TYPE_CHECKING:
    from arcjet._analyze import DetectedSensitiveInfoEntity


def _get_component():  # noqa: ANN202
    """Return the shared AnalyzeComponent singleton, or ``None``."""
    # Import lazily to avoid hard dep on WASM at import time.
    from arcjet._local import _get_component

    return _get_component()


def _to_wasm_entity(specifier: str):  # noqa: ANN202
    """Convert an entity type string to a WASM entity value."""
    from arcjet._local import _to_wasm_entity

    return _to_wasm_entity(specifier)


def _detected_entity_type_str(entity: DetectedSensitiveInfoEntity) -> str:
    """Extract a string type name from a ``DetectedSensitiveInfoEntity``."""
    from arcjet._local import _detected_entity_type_str

    return _detected_entity_type_str(entity)


def _accepted_types(allow: tuple[str, ...], deny: tuple[str, ...]) -> frozenset[str]:
    """Types a third-party backend result may report (shared with the core path)."""
    from arcjet._local import accepted_sensitive_info_types

    return accepted_sensitive_info_types(allow, deny)


def _filter_recognized(
    entities: list[DetectedSensitiveInfoEntity], accepted: frozenset[str]
) -> list[DetectedSensitiveInfoEntity]:
    """Drop detected entities whose type is not accepted (shared with core)."""
    from arcjet._local import filter_recognized_entities

    return filter_recognized_entities(entities, accepted)


def hash_text(text: str) -> str:
    """Return a SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class LocalSensitiveInfoResult:
    """Result of running sensitive info detection locally."""

    conclusion: str
    detected_entity_types: list[str]
    detected_entities: list[tuple[str, int, int]]
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class LocalSensitiveInfoError:
    """Indicates a local evaluation error."""

    message: str
    code: str


def evaluate_sensitive_info_locally(
    text: str,
    *,
    allow: tuple[str, ...] = (),
    deny: tuple[str, ...] = (),
    backend: Optional[SensitiveInfoBackend] = None,
) -> LocalSensitiveInfoResult | LocalSensitiveInfoError | None:
    """Run sensitive info detection via the configured backend.

    Uses ``backend`` when provided, otherwise the bundled WASM engine. Returns a
    :class:`LocalSensitiveInfoResult` on success, a
    :class:`LocalSensitiveInfoError` on failure, or ``None`` if the default WASM
    component is unavailable (so the caller falls through to the server) or when
    ``text`` is empty.
    """
    from arcjet._analyze import (
        SensitiveInfoEntitiesAllow,
        SensitiveInfoEntitiesDeny,
    )

    if not text:
        return None

    # Remember whether the caller supplied a third-party backend; only its
    # output needs validating (the default WASM path returns built-ins only).
    provided_backend = backend
    if backend is None:
        # Gate the default path on WASM availability so an unavailable component
        # falls through to the server rather than producing a local decision.
        if _get_component() is None:
            return None
        backend = default_backend()

    if allow:
        wasm_entities = [_to_wasm_entity(e) for e in allow]
        entities_cfg: SensitiveInfoEntitiesAllow | SensitiveInfoEntitiesDeny = (
            SensitiveInfoEntitiesAllow(entities=wasm_entities)
        )
    elif deny:
        wasm_entities = [_to_wasm_entity(e) for e in deny]
        entities_cfg = SensitiveInfoEntitiesDeny(entities=wasm_entities)
    else:
        entities_cfg = SensitiveInfoEntitiesDeny(entities=[])

    options = SensitiveInfoBackendOptions(context_window_size=None, detect=None)

    start = time.monotonic()
    try:
        result = backend.detect(
            SensitiveInfoBackendContext(log=logger),
            text,
            entities_cfg,
            options,
        )
        # Read and process the result shape inside the exception boundary too: a
        # malformed backend return (e.g. not a SensitiveInfoResult, or malformed
        # entities) makes this access raise, which should fail closed to a
        # LocalSensitiveInfoError rather than crash request handling.
        denied = result.denied
        if provided_backend is not None:
            # Validate the types a third-party backend returned rather than
            # trusting them; drop anything outside the recognized built-ins and
            # the types this rule configured, reusing the same helper as the core
            # evaluator in ``arcjet._local``. The default WASM path returns
            # built-ins only, so it is left untouched.
            denied = _filter_recognized(denied, _accepted_types(allow, deny))
        denied_types = [_detected_entity_type_str(e) for e in denied]
    except Exception as exc:
        # A user-provided backend that raises would otherwise fail silently, so
        # surface it at error level in addition to returning the error result.
        # The default WASM path logs at debug, aligning with the other guard
        # local evaluators, since it falls through to the server. Log only the
        # exception type — its message can embed the scanned value (PII), so the
        # full string is kept out of application logs.
        log = logger.error if provided_backend is not None else logger.debug
        log("guard: local sensitive info detection error: %s", type(exc).__name__)
        # Report only the exception type, not str(exc): this message is
        # serialized into the guard proto and sent upstream, and a backend's
        # exception can embed the scanned value (PII).
        return LocalSensitiveInfoError(
            message=f"sensitive info backend error: {type(exc).__name__}",
            code="SENSITIVE_INFO_ERROR",
        )
    elapsed_ms = int((time.monotonic() - start) * 1000)

    has_deny = len(denied_types) > 0
    conclusion = "DENY" if has_deny else "ALLOW"

    return LocalSensitiveInfoResult(
        conclusion=conclusion,
        detected_entity_types=denied_types,
        detected_entities=[
            (_detected_entity_type_str(entity), entity.start, entity.end)
            for entity in denied
        ],
        elapsed_ms=elapsed_ms,
    )

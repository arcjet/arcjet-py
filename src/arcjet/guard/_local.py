"""Local WASM-based rule evaluation for ``arcjet.guard``.

Evaluates ``local_detect_sensitive_info`` rules via the arcjet-analyze WASM
component.  The raw text never leaves the SDK — only a SHA-256 hash is sent
to the server alongside the locally-computed result.
"""

from __future__ import annotations

import hashlib
import time
from typing import TYPE_CHECKING

from arcjet._logging import logger

if TYPE_CHECKING:
    from .rules import SensitiveInfoWithInput


def _get_component():  # noqa: ANN202
    """Return the shared AnalyzeComponent singleton, or ``None``."""
    # Import lazily to avoid hard dep on WASM at import time.
    from arcjet._local import _get_component

    return _get_component()


def _to_wasm_entity(specifier: str):  # noqa: ANN202
    """Convert an entity type string to a WASM entity value."""
    from arcjet._local import _to_wasm_entity

    return _to_wasm_entity(specifier)


def _detected_entity_type_str(entity: object) -> str:
    """Extract a string type name from a ``DetectedSensitiveInfoEntity``."""
    from arcjet._local import _detected_entity_type_str

    return _detected_entity_type_str(entity)  # type: ignore[arg-type]


def hash_text(text: str) -> str:
    """Return a SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LocalSensitiveInfoResult:
    """Result of running sensitive info detection locally via WASM."""

    __slots__ = ("conclusion", "detected_entity_types", "elapsed_ms")

    def __init__(
        self,
        *,
        conclusion: str,
        detected_entity_types: list[str],
        elapsed_ms: int,
    ) -> None:
        self.conclusion = conclusion
        self.detected_entity_types = detected_entity_types
        self.elapsed_ms = elapsed_ms


class LocalSensitiveInfoError:
    """Indicates a local evaluation error."""

    __slots__ = ("message", "code")

    def __init__(self, *, message: str, code: str) -> None:
        self.message = message
        self.code = code


def evaluate_sensitive_info_locally(
    rule: SensitiveInfoWithInput,
) -> LocalSensitiveInfoResult | LocalSensitiveInfoError | None:
    """Run sensitive info detection via WASM.

    Returns a :class:`LocalSensitiveInfoResult` on success,
    a :class:`LocalSensitiveInfoError` on failure, or ``None`` if the
    WASM component is unavailable.
    """
    from arcjet._analyze import (
        SensitiveInfoConfig,
        SensitiveInfoEntitiesAllow,
        SensitiveInfoEntitiesDeny,
    )

    component = _get_component()
    if component is None:
        return None

    text = rule.text
    if not text:
        return None

    config = rule.config

    if config.allow:
        wasm_entities = [_to_wasm_entity(e) for e in config.allow]
        entities_cfg = SensitiveInfoEntitiesAllow(entities=wasm_entities)
    elif config.deny:
        wasm_entities = [_to_wasm_entity(e) for e in config.deny]
        entities_cfg = SensitiveInfoEntitiesDeny(entities=wasm_entities)
    else:
        entities_cfg = SensitiveInfoEntitiesDeny(entities=[])

    wasm_config = SensitiveInfoConfig(
        entities=entities_cfg,
        context_window_size=None,
        skip_custom_detect=True,
    )

    start = time.monotonic()
    try:
        result = component.detect_sensitive_info(text, wasm_config)
    except Exception as exc:
        logger.debug("guard: local sensitive info detection error: %s", exc)
        return LocalSensitiveInfoError(message=str(exc), code="WASM_ERROR")
    elapsed_ms = int((time.monotonic() - start) * 1000)

    denied_types = [_detected_entity_type_str(e) for e in result.denied]
    has_deny = len(denied_types) > 0
    conclusion = "DENY" if has_deny else "ALLOW"

    return LocalSensitiveInfoResult(
        conclusion=conclusion,
        detected_entity_types=denied_types,
        elapsed_ms=elapsed_ms,
    )

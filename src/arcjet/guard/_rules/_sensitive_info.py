"""Sensitive information detection rule."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence, overload

from arcjet._errors import ArcjetError

from .._types import (
    SENSITIVE_INFO_ENTITY_TYPES,
    Decision,
    Mode,
    RuleResultError,
    RuleResultSensitiveInfo,
)
from ._base import (
    _error_result_for_config,
    _error_result_for_input,
    _get_internal_results,
    _merge_metadata,
)


@dataclass(frozen=True, slots=True)
class SensitiveInfoConfig:
    """Sensitive information detection configuration.

    Specify either ``allow`` or ``deny`` to control which entity types are
    evaluated.  Only entity types in :data:`~arcjet.guard._types.SENSITIVE_INFO_ENTITY_TYPES`
    are accepted.

    Attributes:
        allow: Entity types to detect and **allow** through (report only).
        deny: Entity types to detect and **deny** on.
    """

    allow: tuple[str, ...] = ()
    """Entity types to detect and **allow** through (report only)."""

    deny: tuple[str, ...] = ()
    """Entity types to detect and **deny** on."""


@dataclass(frozen=True, slots=True)
class SensitiveInfoWithInput:
    """A sensitive info detection rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    config: SensitiveInfoConfig
    text: str
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def results(self, decision: Decision) -> list[RuleResultSensitiveInfo]:
        """Get this input's results as a list (empty or single-element)."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and ir.input_id == self._input_id
            and isinstance(ir.result, RuleResultSensitiveInfo)
        ]

    def result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get this input's result from a decision."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None

    def error_result(self, decision: Decision) -> RuleResultError | None:
        """Get this invocation's errored result, or ``None`` if it didn't error.

        Returns the :class:`RuleResultError` only — never the non-error
        result. The non-error accessors (``result``/``results``/
        ``denied_result``) exclude it.
        """
        return _error_result_for_input(decision, self._config_id, self._input_id)


class LocalDetectSensitiveInfo:
    """Sensitive information detection rule (local WASM evaluation).

    Detects PII (email addresses, phone numbers, etc.) in text locally
    via WASM.  The raw text never leaves the SDK — only a SHA-256 hash
    is sent to the server alongside the locally-computed result.

    Specify either ``allow`` or ``deny`` to control which entity types
    are evaluated.  Valid types: ``"EMAIL"``, ``"PHONE_NUMBER"``,
    ``"IP_ADDRESS"``, ``"CREDIT_CARD_NUMBER"``.

    Args:
        allow: Entity types to detect and report without blocking.
        deny: Entity types to detect and block on.
        mode: ``"LIVE"`` (default) enforces; ``"DRY_RUN"`` evaluates only.
        label: Optional human-readable label for observability.
            Validated server-side as a slug: lowercase letters, digits,
            dash (``-``), and dot (``.``) only; must start and end with a
            lowercase letter or digit; max 256 bytes.
        metadata: Optional key-value metadata for analytics.

    Raises:
        ArcjetError: If any entity type in *allow* or *deny* is not a
            valid built-in type, or if both *allow* and *deny* are
            specified.

    Example::

        sensitive = LocalDetectSensitiveInfo(deny=["EMAIL"])
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[sensitive(user_message)],
        )
    """

    @overload
    def __init__(
        self,
        *,
        allow: Sequence[str],
        mode: Mode = ...,
        label: Optional[str] = ...,
        metadata: Optional[Mapping[str, str]] = ...,
    ) -> None: ...

    @overload
    def __init__(
        self,
        *,
        deny: Sequence[str],
        mode: Mode = ...,
        label: Optional[str] = ...,
        metadata: Optional[Mapping[str, str]] = ...,
    ) -> None: ...

    @overload
    def __init__(
        self,
        *,
        mode: Mode = ...,
        label: Optional[str] = ...,
        metadata: Optional[Mapping[str, str]] = ...,
    ) -> None: ...

    def __init__(
        self,
        *,
        allow: Sequence[str] = (),
        deny: Sequence[str] = (),
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        if allow and deny:
            raise ArcjetError("Specify either 'allow' or 'deny', not both.")
        for entity in allow:
            if entity not in SENSITIVE_INFO_ENTITY_TYPES:
                raise ArcjetError(
                    f"Invalid sensitive info entity type: {entity!r}. "
                    f"Valid types: {sorted(SENSITIVE_INFO_ENTITY_TYPES)}"
                )
        for entity in deny:
            if entity not in SENSITIVE_INFO_ENTITY_TYPES:
                raise ArcjetError(
                    f"Invalid sensitive info entity type: {entity!r}. "
                    f"Valid types: {sorted(SENSITIVE_INFO_ENTITY_TYPES)}"
                )
        self._config_id = str(uuid.uuid4())
        self._config = SensitiveInfoConfig(allow=tuple(allow), deny=tuple(deny))
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(
        self,
        text: str,
        *,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> SensitiveInfoWithInput:
        return SensitiveInfoWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            text=text,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
        )

    def results(self, decision: Decision) -> list[RuleResultSensitiveInfo]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultSensitiveInfo)
        ]

    def result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get the first result for this rule, or ``None``."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None

    def error_result(self, decision: Decision) -> RuleResultError | None:
        """Get the first errored result for this rule, or ``None``."""
        return _error_result_for_config(decision, self._config_id)

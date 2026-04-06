"""Rule factory functions for ``arcjet.guard``.

Each exported function creates a configured rule.  Calling the returned
value with input produces a concrete ``*WithInput`` ready for ``.guard()``.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import (
    Mapping,
    Optional,
    Sequence,
    Union,
)

from arcjet._errors import ArcjetError

from .types import (
    SENSITIVE_INFO_ENTITY_TYPES,
    Conclusion,
    Decision,
    InternalResult,
    Mode,
    RuleResultCustom,
    RuleResultFixedWindow,
    RuleResultPromptInjection,
    RuleResultSensitiveInfo,
    RuleResultSlidingWindow,
    RuleResultTokenBucket,
)


def _get_internal_results(decision: Decision) -> tuple[InternalResult, ...]:
    """Extract internal results from a decision (empty tuple if absent)."""
    return decision._internal_results


def _hash_key(key: str) -> str:
    """SHA-256 hash of a rate-limit key.

    The raw key never leaves the SDK — only the hash is sent to the server.
    This ensures IPv6 addresses and other formats work without users needing
    to know the character constraints.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


_VALID_CONCLUSIONS: frozenset[str] = frozenset({"ALLOW", "DENY"})


@dataclass(frozen=True, slots=True)
class TokenBucketConfig:
    """Token bucket rate limiting configuration.

    Attributes:
        refill_rate: Number of tokens added to the bucket each interval.
        interval_seconds: Duration in seconds between each token refill.
        max_tokens: Maximum capacity of the token bucket.  Tokens beyond
            this limit are discarded.
    """

    refill_rate: int
    """Number of tokens added to the bucket each interval."""

    interval_seconds: int
    """Duration in seconds between each token refill."""

    max_tokens: int
    """Maximum capacity of the token bucket.  Tokens beyond this limit
    are discarded."""


@dataclass(frozen=True, slots=True)
class FixedWindowConfig:
    """Fixed window rate limiting configuration.

    Attributes:
        max_requests: Maximum number of requests allowed per window.
        window_seconds: Duration of each rate limit window in seconds.
    """

    max_requests: int
    """Maximum number of requests allowed per window."""

    window_seconds: int
    """Duration of each rate limit window in seconds."""


@dataclass(frozen=True, slots=True)
class SlidingWindowConfig:
    """Sliding window rate limiting configuration.

    Attributes:
        max_requests: Maximum number of requests allowed per sliding interval.
        interval_seconds: Duration of the sliding interval in seconds.
    """

    max_requests: int
    """Maximum number of requests allowed per sliding interval."""

    interval_seconds: int
    """Duration of the sliding interval in seconds."""


@dataclass(frozen=True, slots=True)
class LocalDetectSensitiveInfoConfig:
    """Sensitive information detection configuration.

    Specify either ``allow`` or ``deny`` to control which entity types are
    evaluated.  Only entity types in :data:`~arcjet.guard.types.SENSITIVE_INFO_ENTITY_TYPES`
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
class LocalCustomConfig:
    """Custom local rule configuration.

    Attributes:
        data: Key-value configuration data sent to the server for analytics.
    """

    data: Mapping[str, str] = field(default_factory=dict)
    """Key-value configuration data sent to the server for analytics."""


@dataclass(frozen=True, slots=True)
class TokenBucketWithInput:
    """A token bucket rule with bound input, ready for ``.guard()``.

    The ``key`` value is SHA-256 hashed before being sent to the server —
    the raw key never leaves the client.
    """

    _input_id: str
    _config_id: str
    config: TokenBucketConfig
    key: str
    requested: int = 1
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    @property
    def key_hash(self) -> str:
        """SHA-256 hex digest of the key, as sent to the server."""
        return _hash_key(self.key)

    def result(self, decision: Decision) -> RuleResultTokenBucket | None:
        """Get this input's result from a decision."""
        for ir in _get_internal_results(decision):
            if ir.config_id == self._config_id and ir.input_id == self._input_id:
                if isinstance(ir.result, RuleResultTokenBucket):
                    return ir.result
        return None

    def denied_result(self, decision: Decision) -> RuleResultTokenBucket | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


@dataclass(frozen=True, slots=True)
class FixedWindowWithInput:
    """A fixed window rule with bound input, ready for ``.guard()``.

    The ``key`` value is SHA-256 hashed before being sent to the server —
    the raw key never leaves the client.
    """

    _input_id: str
    _config_id: str
    config: FixedWindowConfig
    key: str
    requested: int = 1
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    @property
    def key_hash(self) -> str:
        """SHA-256 hex digest of the key, as sent to the server."""
        return _hash_key(self.key)

    def result(self, decision: Decision) -> RuleResultFixedWindow | None:
        """Get this input's result from a decision."""
        for ir in _get_internal_results(decision):
            if ir.config_id == self._config_id and ir.input_id == self._input_id:
                if isinstance(ir.result, RuleResultFixedWindow):
                    return ir.result
        return None

    def denied_result(self, decision: Decision) -> RuleResultFixedWindow | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


@dataclass(frozen=True, slots=True)
class SlidingWindowWithInput:
    """A sliding window rule with bound input, ready for ``.guard()``.

    The ``key`` value is SHA-256 hashed before being sent to the server —
    the raw key never leaves the client.
    """

    _input_id: str
    _config_id: str
    config: SlidingWindowConfig
    key: str
    requested: int = 1
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    @property
    def key_hash(self) -> str:
        """SHA-256 hex digest of the key, as sent to the server."""
        return _hash_key(self.key)

    def result(self, decision: Decision) -> RuleResultSlidingWindow | None:
        """Get this input's result from a decision."""
        for ir in _get_internal_results(decision):
            if ir.config_id == self._config_id and ir.input_id == self._input_id:
                if isinstance(ir.result, RuleResultSlidingWindow):
                    return ir.result
        return None

    def denied_result(self, decision: Decision) -> RuleResultSlidingWindow | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


@dataclass(frozen=True, slots=True)
class PromptInjectionWithInput:
    """A prompt injection detection rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    text: str
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def result(self, decision: Decision) -> RuleResultPromptInjection | None:
        """Get this input's result from a decision."""
        for ir in _get_internal_results(decision):
            if ir.config_id == self._config_id and ir.input_id == self._input_id:
                if isinstance(ir.result, RuleResultPromptInjection):
                    return ir.result
        return None

    def denied_result(self, decision: Decision) -> RuleResultPromptInjection | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


@dataclass(frozen=True, slots=True)
class SensitiveInfoWithInput:
    """A sensitive info detection rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    config: LocalDetectSensitiveInfoConfig
    text: str
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get this input's result from a decision."""
        for ir in _get_internal_results(decision):
            if ir.config_id == self._config_id and ir.input_id == self._input_id:
                if isinstance(ir.result, RuleResultSensitiveInfo):
                    return ir.result
        return None

    def denied_result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


@dataclass(frozen=True, slots=True)
class CustomWithInput:
    """A custom local rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    config: LocalCustomConfig
    data: Mapping[str, str]
    conclusion: Optional[Conclusion] = None
    result_data: Optional[Mapping[str, str]] = None
    elapsed_ms: Optional[int] = None
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def result(self, decision: Decision) -> RuleResultCustom | None:
        """Get this input's result from a decision."""
        for ir in _get_internal_results(decision):
            if ir.config_id == self._config_id and ir.input_id == self._input_id:
                if isinstance(ir.result, RuleResultCustom):
                    return ir.result
        return None

    def denied_result(self, decision: Decision) -> RuleResultCustom | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


RuleWithInput = Union[
    TokenBucketWithInput,
    FixedWindowWithInput,
    SlidingWindowWithInput,
    PromptInjectionWithInput,
    SensitiveInfoWithInput,
    CustomWithInput,
]
"""Union of all ``*WithInput`` types."""


class _TokenBucketRule:
    """A configured token bucket rule — call with input to get a
    :class:`TokenBucketWithInput`.
    """

    def __init__(
        self,
        config: TokenBucketConfig,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = config
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(
        self,
        *,
        key: str,
        requested: int = 1,
    ) -> TokenBucketWithInput:
        return TokenBucketWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            key=key,
            requested=requested,
            mode=self._mode,
            label=self._label,
            metadata=self._metadata,
        )

    def results(self, decision: Decision) -> list[RuleResultTokenBucket]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultTokenBucket)
        ]

    def denied_result(self, decision: Decision) -> RuleResultTokenBucket | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None


def token_bucket(
    *,
    refill_rate: int,
    interval_seconds: int,
    max_tokens: int,
    mode: Mode = "LIVE",
    label: Optional[str] = None,
    metadata: Optional[Mapping[str, str]] = None,
) -> _TokenBucketRule:
    """Create a token bucket rate limiting rule.

    Example::

        user_limit = token_bucket(
            refill_rate=10,
            interval_seconds=60,
            max_tokens=100,
        )
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[user_limit(key=user_id)],
        )
    """
    config = TokenBucketConfig(
        refill_rate=refill_rate,
        interval_seconds=interval_seconds,
        max_tokens=max_tokens,
    )
    return _TokenBucketRule(config, mode=mode, label=label, metadata=metadata)


class _FixedWindowRule:
    """A configured fixed window rule — call with input to get a
    :class:`FixedWindowWithInput`.
    """

    def __init__(
        self,
        config: FixedWindowConfig,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = config
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(
        self,
        *,
        key: str,
        requested: int = 1,
    ) -> FixedWindowWithInput:
        return FixedWindowWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            key=key,
            requested=requested,
            mode=self._mode,
            label=self._label,
            metadata=self._metadata,
        )

    def results(self, decision: Decision) -> list[RuleResultFixedWindow]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultFixedWindow)
        ]

    def denied_result(self, decision: Decision) -> RuleResultFixedWindow | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None


def fixed_window(
    *,
    max_requests: int,
    window_seconds: int,
    mode: Mode = "LIVE",
    label: Optional[str] = None,
    metadata: Optional[Mapping[str, str]] = None,
) -> _FixedWindowRule:
    """Create a fixed window rate limiting rule.

    Example::

        team_limit = fixed_window(
            max_requests=1000,
            window_seconds=3600,
        )
    """
    config = FixedWindowConfig(max_requests=max_requests, window_seconds=window_seconds)
    return _FixedWindowRule(config, mode=mode, label=label, metadata=metadata)


class _SlidingWindowRule:
    """A configured sliding window rule — call with input to get a
    :class:`SlidingWindowWithInput`.
    """

    def __init__(
        self,
        config: SlidingWindowConfig,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = config
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(
        self,
        *,
        key: str,
        requested: int = 1,
    ) -> SlidingWindowWithInput:
        return SlidingWindowWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            key=key,
            requested=requested,
            mode=self._mode,
            label=self._label,
            metadata=self._metadata,
        )

    def results(self, decision: Decision) -> list[RuleResultSlidingWindow]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultSlidingWindow)
        ]

    def denied_result(self, decision: Decision) -> RuleResultSlidingWindow | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None


def sliding_window(
    *,
    max_requests: int,
    interval_seconds: int,
    mode: Mode = "LIVE",
    label: Optional[str] = None,
    metadata: Optional[Mapping[str, str]] = None,
) -> _SlidingWindowRule:
    """Create a sliding window rate limiting rule.

    Example::

        api_limit = sliding_window(
            max_requests=500,
            interval_seconds=60,
        )
    """
    config = SlidingWindowConfig(
        max_requests=max_requests, interval_seconds=interval_seconds
    )
    return _SlidingWindowRule(config, mode=mode, label=label, metadata=metadata)


class _DetectPromptInjectionRule:
    """A configured prompt injection detection rule — call with text to get a
    :class:`PromptInjectionWithInput`.
    """

    def __init__(
        self,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(self, text: str) -> PromptInjectionWithInput:
        return PromptInjectionWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            text=text,
            mode=self._mode,
            label=self._label,
            metadata=self._metadata,
        )

    def results(self, decision: Decision) -> list[RuleResultPromptInjection]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultPromptInjection)
        ]

    def denied_result(self, decision: Decision) -> RuleResultPromptInjection | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None


def detect_prompt_injection(
    *,
    mode: Mode = "LIVE",
    label: Optional[str] = None,
    metadata: Optional[Mapping[str, str]] = None,
) -> _DetectPromptInjectionRule:
    """Create a prompt injection detection rule.

    Example::

        prompt_scan = detect_prompt_injection()
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[prompt_scan(user_message)],
        )
    """
    return _DetectPromptInjectionRule(mode=mode, label=label, metadata=metadata)


class _LocalDetectSensitiveInfoRule:
    """A configured sensitive info detection rule — call with text to get a
    :class:`SensitiveInfoWithInput`.
    """

    def __init__(
        self,
        config: LocalDetectSensitiveInfoConfig,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = config
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(self, text: str) -> SensitiveInfoWithInput:
        return SensitiveInfoWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            text=text,
            mode=self._mode,
            label=self._label,
            metadata=self._metadata,
        )

    def results(self, decision: Decision) -> list[RuleResultSensitiveInfo]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultSensitiveInfo)
        ]

    def denied_result(self, decision: Decision) -> RuleResultSensitiveInfo | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None


def local_detect_sensitive_info(
    *,
    allow: Sequence[str] = (),
    deny: Sequence[str] = (),
    mode: Mode = "LIVE",
    label: Optional[str] = None,
    metadata: Optional[Mapping[str, str]] = None,
) -> _LocalDetectSensitiveInfoRule:
    """Create a local sensitive information detection rule.

    The SDK evaluates this locally via wasm and reports the result to the
    server.  The actual text never leaves the SDK — only a hash is sent.

    Args:
        allow: Entity types to detect and report without blocking.
        deny: Entity types to detect and block on.
        mode: ``"LIVE"`` (default) enforces; ``"DRY_RUN"`` evaluates only.
        label: Optional human-readable label for observability.
        metadata: Optional key-value metadata for analytics.

    Raises:
        ArcjetError: If any entity type in *allow* or *deny* is not a
            valid built-in type.  Valid types:
            ``"EMAIL"``, ``"PHONE_NUMBER"``, ``"IP_ADDRESS"``,
            ``"CREDIT_CARD_NUMBER"``.

    Example::

        sensitive = local_detect_sensitive_info(deny=["EMAIL"])
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[sensitive(user_message)],
        )
    """
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
    config = LocalDetectSensitiveInfoConfig(allow=tuple(allow), deny=tuple(deny))
    return _LocalDetectSensitiveInfoRule(
        config, mode=mode, label=label, metadata=metadata
    )


class _LocalCustomRule:
    """A configured custom local rule — call with data to get a
    :class:`CustomWithInput`.
    """

    def __init__(
        self,
        config: LocalCustomConfig,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = config
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(
        self,
        *,
        data: Mapping[str, str] | None = None,
        conclusion: Conclusion | None = None,
        result_data: Mapping[str, str] | None = None,
        elapsed_ms: int | None = None,
    ) -> CustomWithInput:
        if conclusion is not None and conclusion not in _VALID_CONCLUSIONS:
            raise ArcjetError(
                f'Invalid conclusion: {conclusion!r}. Must be "ALLOW" or "DENY".'
            )
        return CustomWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            data=dict(data) if data else {},
            conclusion=conclusion,
            result_data=dict(result_data) if result_data else None,
            elapsed_ms=elapsed_ms,
            mode=self._mode,
            label=self._label,
            metadata=self._metadata,
        )

    def results(self, decision: Decision) -> list[RuleResultCustom]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultCustom)
        ]

    def denied_result(self, decision: Decision) -> RuleResultCustom | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None


def local_custom(
    *,
    data: Mapping[str, str] | None = None,
    mode: Mode = "LIVE",
    label: Optional[str] = None,
    metadata: Optional[Mapping[str, str]] = None,
) -> _LocalCustomRule:
    """Create a custom local rule — a generic escape hatch for user-defined
    evaluation functions whose results are reported to the server.

    Example::

        custom = local_custom(data={"threshold": "0.5"})
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[custom(data={"score": "0.8"})],
        )
    """
    config = LocalCustomConfig(data=dict(data) if data else {})
    return _LocalCustomRule(config, mode=mode, label=label, metadata=metadata)


RuleWithConfig = Union[
    _TokenBucketRule,
    _FixedWindowRule,
    _SlidingWindowRule,
    _DetectPromptInjectionRule,
    _LocalDetectSensitiveInfoRule,
    _LocalCustomRule,
]
"""Union of all configured rule types."""

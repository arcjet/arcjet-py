"""Rate limiting rules: token bucket, fixed window, sliding window."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Mapping, Optional

from ..types import (
    Decision,
    Mode,
    RuleResultFixedWindow,
    RuleResultSlidingWindow,
    RuleResultTokenBucket,
)
from ._base import (
    _get_internal_results,
    _hash_key,
    _merge_metadata,
)


@dataclass(frozen=True, slots=True)
class TokenBucketConfig:
    """Token bucket rate limiting configuration.

    Attributes:
        refill_rate: Number of tokens added to the bucket each interval.
        interval_seconds: Duration in seconds between each token refill.
        max_tokens: Maximum capacity of the token bucket.  Tokens beyond
            this limit are discarded.
        bucket: Optional bucket name for counter grouping.  Defaults to
            ``"default"``.  Different configs sharing the same bucket name
            still get independent counters (isolated by config hash).
    """

    refill_rate: int
    """Number of tokens added to the bucket each interval."""

    interval_seconds: int
    """Duration in seconds between each token refill."""

    max_tokens: int
    """Maximum capacity of the token bucket.  Tokens beyond this limit
    are discarded."""

    bucket: str = "default-token-bucket"
    """Bucket name for counter grouping."""


@dataclass(frozen=True, slots=True)
class FixedWindowConfig:
    """Fixed window rate limiting configuration.

    Attributes:
        max_requests: Maximum number of requests allowed per window.
        window_seconds: Duration of each rate limit window in seconds.
        bucket: Optional bucket name for counter grouping.
    """

    max_requests: int
    """Maximum number of requests allowed per window."""

    window_seconds: int
    """Duration of each rate limit window in seconds."""

    bucket: str = "default-fixed-window"
    """Bucket name for counter grouping."""


@dataclass(frozen=True, slots=True)
class SlidingWindowConfig:
    """Sliding window rate limiting configuration.

    Attributes:
        max_requests: Maximum number of requests allowed per sliding interval.
        interval_seconds: Duration of the sliding interval in seconds.
        bucket: Optional bucket name for counter grouping.
    """

    max_requests: int
    """Maximum number of requests allowed per sliding interval."""

    interval_seconds: int
    """Duration of the sliding interval in seconds."""

    bucket: str = "default-sliding-window"
    """Bucket name for counter grouping."""


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

    @property
    def config_bucket(self) -> str:
        """Bucket name sent to the server for counter grouping."""
        return self.config.bucket

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

    @property
    def config_bucket(self) -> str:
        """Bucket name sent to the server for counter grouping."""
        return self.config.bucket

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

    @property
    def config_bucket(self) -> str:
        """Bucket name sent to the server for counter grouping."""
        return self.config.bucket

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


class TokenBucket:
    """Token bucket rate limiting rule.

    Instantiate with rate limit parameters, then call with a ``key``
    to produce a :class:`TokenBucketWithInput` for ``.guard()``.

    Args:
        refill_rate: Tokens added per interval.
        interval_seconds: Seconds between refills.
        max_tokens: Maximum bucket capacity.
        bucket: Bucket name for counter grouping (default ``"default"``).
        mode: ``"LIVE"`` or ``"DRY_RUN"``.
        label: Optional observability label.
        metadata: Config-level key-value metadata.  Merged with
            per-input metadata on each call — input keys replace
            config keys on conflict.

    Example::

        user_limit = TokenBucket(
            refill_rate=10,
            interval_seconds=60,
            max_tokens=100,
        )
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[user_limit(key=user_id)],
        )
    """

    def __init__(
        self,
        *,
        refill_rate: int,
        interval_seconds: int,
        max_tokens: int,
        bucket: str = "default-token-bucket",
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = TokenBucketConfig(
            refill_rate=refill_rate,
            interval_seconds=interval_seconds,
            max_tokens=max_tokens,
            bucket=bucket,
        )
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
        metadata: Optional[Mapping[str, str]] = None,
    ) -> TokenBucketWithInput:
        return TokenBucketWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            key=key,
            requested=requested,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
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


class FixedWindow:
    """Fixed window rate limiting rule.

    Instantiate with rate limit parameters, then call with a ``key``
    to produce a :class:`FixedWindowWithInput` for ``.guard()``.

    Args:
        max_requests: Maximum requests per window.
        window_seconds: Window duration in seconds.
        bucket: Bucket name for counter grouping (default ``"default"``).
        mode: ``"LIVE"`` or ``"DRY_RUN"``.
        label: Optional observability label.
        metadata: Config-level key-value metadata.  Merged with
            per-input metadata on each call — input keys replace
            config keys on conflict.

    Example::

        team_limit = FixedWindow(
            max_requests=1000,
            window_seconds=3600,
        )
    """

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: int,
        bucket: str = "default-fixed-window",
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = FixedWindowConfig(
            max_requests=max_requests,
            window_seconds=window_seconds,
            bucket=bucket,
        )
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
        metadata: Optional[Mapping[str, str]] = None,
    ) -> FixedWindowWithInput:
        return FixedWindowWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            key=key,
            requested=requested,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
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


class SlidingWindow:
    """Sliding window rate limiting rule.

    Instantiate with rate limit parameters, then call with a ``key``
    to produce a :class:`SlidingWindowWithInput` for ``.guard()``.

    Args:
        max_requests: Maximum requests per interval.
        interval_seconds: Sliding interval in seconds.
        bucket: Bucket name for counter grouping (default ``"default"``).
        mode: ``"LIVE"`` or ``"DRY_RUN"``.
        label: Optional observability label.
        metadata: Config-level key-value metadata.  Merged with
            per-input metadata on each call — input keys replace
            config keys on conflict.

    Example::

        api_limit = SlidingWindow(
            max_requests=500,
            interval_seconds=60,
        )
    """

    def __init__(
        self,
        *,
        max_requests: int,
        interval_seconds: int,
        bucket: str = "default-sliding-window",
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config = SlidingWindowConfig(
            max_requests=max_requests,
            interval_seconds=interval_seconds,
            bucket=bucket,
        )
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
        metadata: Optional[Mapping[str, str]] = None,
    ) -> SlidingWindowWithInput:
        return SlidingWindowWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config=self._config,
            key=key,
            requested=requested,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
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

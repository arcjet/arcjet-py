"""Public SDK types for ``arcjet.guard``.

These are independent of protobuf — the SDK exposes plain frozen dataclasses,
not proto messages.  The type system is designed for progressive disclosure:

- **Layer 1:** ``decision.conclusion`` (``"ALLOW"`` | ``"DENY"``) and ``decision.reason``.
- **Layer 2:** ``decision.has_error()`` — out-of-band signal helpers.
- **Layer 3:** ``rule.results(decision)`` — typed per-rule results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    Literal,
    Mapping,
    Union,
)

Conclusion = Literal["ALLOW", "DENY"]
"""The outcome of a guard decision — only ``"ALLOW"`` or ``"DENY"``."""

Reason = Literal[
    "RATE_LIMIT",
    "PROMPT_INJECTION",
    "SENSITIVE_INFO",
    "CUSTOM",
    "ERROR",
    "NOT_RUN",
    "UNKNOWN",
]
"""Broad reason category for a decision or rule result."""

Mode = Literal["LIVE", "DRY_RUN"]
"""Rule evaluation mode."""


@dataclass(frozen=True, slots=True)
class RuleResultTokenBucket:
    """Result from a token bucket rate limit evaluation."""

    conclusion: Conclusion
    reason: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    type: Literal["TOKEN_BUCKET"] = "TOKEN_BUCKET"
    remaining_tokens: int = 0
    max_tokens: int = 0
    reset_at_unix_seconds: int = 0
    refill_rate: int = 0
    refill_interval_seconds: int = 0


@dataclass(frozen=True, slots=True)
class RuleResultFixedWindow:
    """Result from a fixed window rate limit evaluation."""

    conclusion: Conclusion
    reason: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    type: Literal["FIXED_WINDOW"] = "FIXED_WINDOW"
    remaining_requests: int = 0
    max_requests: int = 0
    reset_at_unix_seconds: int = 0
    window_seconds: int = 0


@dataclass(frozen=True, slots=True)
class RuleResultSlidingWindow:
    """Result from a sliding window rate limit evaluation."""

    conclusion: Conclusion
    reason: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    type: Literal["SLIDING_WINDOW"] = "SLIDING_WINDOW"
    remaining_requests: int = 0
    max_requests: int = 0
    reset_at_unix_seconds: int = 0
    interval_seconds: int = 0


@dataclass(frozen=True, slots=True)
class RuleResultPromptInjection:
    """Result from a prompt injection detection evaluation."""

    conclusion: Conclusion
    reason: Literal["PROMPT_INJECTION"] = "PROMPT_INJECTION"
    type: Literal["PROMPT_INJECTION"] = "PROMPT_INJECTION"


@dataclass(frozen=True, slots=True)
class RuleResultSensitiveInfo:
    """Result from a sensitive information detection evaluation."""

    conclusion: Conclusion
    reason: Literal["SENSITIVE_INFO"] = "SENSITIVE_INFO"
    type: Literal["SENSITIVE_INFO"] = "SENSITIVE_INFO"
    detected_entity_types: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleResultCustom:
    """Result from a custom local rule evaluation."""

    conclusion: Conclusion
    reason: Literal["CUSTOM"] = "CUSTOM"
    type: Literal["CUSTOM"] = "CUSTOM"
    data: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuleResultNotRun:
    """Result for a rule that was not evaluated."""

    conclusion: Literal["ALLOW"] = "ALLOW"
    reason: Reason = "NOT_RUN"
    type: Literal["NOT_RUN"] = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class RuleResultError:
    """Result for a rule that encountered an error during evaluation.

    Errors are fail-open: conclusion is always ``"ALLOW"``.
    """

    conclusion: Literal["ALLOW"] = "ALLOW"
    reason: Reason = "ERROR"
    type: Literal["RULE_ERROR"] = "RULE_ERROR"
    message: str = ""
    code: str = ""


@dataclass(frozen=True, slots=True)
class RuleResultUnknown:
    """Fallback result for unrecognized rule types."""

    conclusion: Conclusion = "ALLOW"
    reason: Literal["UNKNOWN"] = "UNKNOWN"
    type: Literal["UNKNOWN"] = "UNKNOWN"


RuleResult = Union[
    RuleResultTokenBucket,
    RuleResultFixedWindow,
    RuleResultSlidingWindow,
    RuleResultPromptInjection,
    RuleResultSensitiveInfo,
    RuleResultCustom,
    RuleResultNotRun,
    RuleResultError,
    RuleResultUnknown,
]
"""Union of all possible rule result types."""


@dataclass(frozen=True, slots=True)
class InternalResult:
    """A rule result with correlation identifiers for Layer 3 lookup."""

    result: RuleResult
    config_id: str
    input_id: str


@dataclass(frozen=True, slots=True)
class Decision:
    """A guard decision — either ``"ALLOW"`` or ``"DENY"``.

    **Layer 1**: ``decision.conclusion`` and ``decision.reason``.
    **Layer 2**: ``decision.has_error()``.
    **Layer 3**: Use ``rule.results(decision)`` or ``rule_input.result(decision)``.
    """

    conclusion: Conclusion
    """The outcome of the guard decision."""

    id: str
    """Server-generated unique identifier (TypeID, prefix ``"gdec"``)."""

    results: tuple[RuleResult, ...]
    """Per-rule results, one per submission, in submission order."""

    reason: Reason = "UNKNOWN"
    """Broad reason category (only meaningful for DENY decisions)."""

    _internal_results: tuple[InternalResult, ...] = field(
        default=(), repr=False, compare=False
    )

    def has_error(self) -> bool:
        """True if any rule errored during evaluation (Layer 2 helper)."""
        return any(r.type == "RULE_ERROR" for r in self.results)

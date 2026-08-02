"""Public SDK types for ``arcjet.guard``.

Concrete per-rule discriminated unions.  Each rule kind gets its own
``RuleResult*`` type with a ``type`` discriminant for narrowing.

These are independent of protobuf — the SDK exposes plain frozen dataclasses,
not proto messages.  The type system is designed for progressive disclosure:

- **Layer 1:** ``decision.conclusion`` (``"ALLOW"`` | ``"DENY"``) and ``decision.reason``.
- **Layer 2:** ``decision.warnings``, ``decision.error_results()``, and
  ``decision.has_failed_open()`` — out-of-band signal helpers.
- **Layer 3:** ``rule.results(decision)`` — typed per-rule results.
"""

from __future__ import annotations

import warnings as _stdlib_warnings
from dataclasses import dataclass, field
from typing import (
    Literal,
    Mapping,
    Union,
)

from arcjet._sensitive_info_backend import (
    BACKEND_ONLY_SENSITIVE_INFO_TYPES as _BACKEND_ONLY_SENSITIVE_INFO_TYPES,
)
from arcjet._sensitive_info_backend import (
    NATIVE_SENSITIVE_INFO_TYPES as _NATIVE_SENSITIVE_INFO_TYPES,
)

Conclusion = Literal["ALLOW", "DENY"]
"""The outcome of a guard decision — only ``"ALLOW"`` or ``"DENY"``."""

Reason = Literal[
    "RATE_LIMIT",
    "PROMPT_INJECTION",
    "MODERATE_CONTENT",
    "SENSITIVE_INFO",
    "INPUT_CONSTRAINT",
    "CUSTOM",
    "ERROR",
    "NOT_RUN",
    "UNKNOWN",
]
"""Broad reason category for a decision or rule result."""


@dataclass(frozen=True, slots=True)
class ArcjetWarning:
    """A warning means the decision (or a single rule result) was processed
    correctly — the result is trustworthy — but something should be fixed,
    e.g. an invalid metadata key that was stripped or an invalid label.

    Contrast with :class:`RuleResultError`, which means a rule or the
    decision *could not* be processed and the security signal is degraded.
    """

    code: str = ""
    """Machine-readable code (e.g. ``"AJ1100"``)."""

    message: str = ""
    """Human-readable description."""


Mode = Literal["LIVE", "DRY_RUN"]
"""Rule evaluation mode.  ``"LIVE"`` enforces the rule; ``"DRY_RUN"``
evaluates without blocking."""

PolicyStatus = Literal[
    "NOT_CONFIGURED", "APPLIED", "INCOMPLETE", "UNAVAILABLE", "UNKNOWN"
]
PolicyExecution = Literal["SDK", "SERVER", "UNKNOWN"]
InputConstraintType = Literal[
    "ALLOWED_STRING_VALUES", "DENIED_STRING_VALUES", "STRING_LENGTH"
]
StringMatchOperator = Literal["EXACT", "EMAIL_DOMAIN", "UNKNOWN"]

NATIVE_SENSITIVE_INFO_ENTITY_TYPES: frozenset[str] = _NATIVE_SENSITIVE_INFO_TYPES
"""Sensitive info entity types the default (WASM) backend detects natively.

- ``"EMAIL"`` — Email addresses
- ``"PHONE_NUMBER"`` — Phone numbers
- ``"IP_ADDRESS"`` — IPv4 and IPv6 addresses
- ``"CREDIT_CARD_NUMBER"`` — Credit/debit card numbers
"""

SENSITIVE_INFO_ENTITY_TYPES: frozenset[str] = (
    _NATIVE_SENSITIVE_INFO_TYPES | _BACKEND_ONLY_SENSITIVE_INFO_TYPES
)
"""All recognized sensitive information entity types.  Custom entity types are
not supported in ``arcjet.guard`` — use a custom rule instead.

The four in :data:`NATIVE_SENSITIVE_INFO_ENTITY_TYPES` are detected by the
default (WASM) backend.  The remaining types are detected only when a
``SensitiveInfoBackend`` that supports them is configured via the ``backend``
option (such as ``arcjet-sensitive-info-rampart``).  Listing one of them without
such a backend is a configuration error — :class:`LocalDetectSensitiveInfo`
raises rather than accepting a rule that can never match:

- ``"GIVEN_NAME"`` — Given (first) names
- ``"SURNAME"`` — Surnames (last names)
- ``"SSN"`` — US Social Security numbers
- ``"URL"`` — URLs
- ``"TAX_ID"`` — Tax identifiers
- ``"BANK_ACCOUNT"`` — Bank account numbers
- ``"ROUTING_NUMBER"`` — Bank routing numbers
- ``"GOVERNMENT_ID"`` — Government identifiers
- ``"PASSPORT"`` — Passport numbers
- ``"DRIVERS_LICENSE"`` — Driver's license numbers
- ``"BUILDING_NUMBER"`` — Street/building numbers
- ``"STREET_NAME"`` — Street names
- ``"SECONDARY_ADDRESS"`` — Secondary address lines (apartment, suite, etc.)
- ``"CITY"`` — Cities
- ``"STATE"`` — States/regions
- ``"ZIP_CODE"`` — Postal/ZIP codes
"""


@dataclass(frozen=True, slots=True)
class CustomEvaluateResult:
    """Result returned by a custom rule's ``evaluate`` function.

    Example::

        CustomEvaluateResult(conclusion="DENY", data={"reason": "score too high"})
    """

    conclusion: Conclusion
    """Whether the rule allows or denies — ``"ALLOW"`` or ``"DENY"``."""

    data: Mapping[str, str] = field(default_factory=dict)
    """Optional arbitrary key-value data to include in the result."""


@dataclass(frozen=True, slots=True)
class RuleResultTokenBucket:
    """Result from a token bucket rate limit evaluation."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    reason: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    """The reason category — always ``"RATE_LIMIT"`` for token bucket rules."""

    type: Literal["TOKEN_BUCKET"] = "TOKEN_BUCKET"
    """Discriminant — always ``"TOKEN_BUCKET"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""

    remaining_tokens: int = 0
    """Number of tokens remaining in the bucket after this evaluation."""

    max_tokens: int = 0
    """Maximum capacity of the token bucket."""

    reset_at_unix_seconds: int = 0
    """Unix timestamp (seconds) when the bucket will next be refilled."""

    refill_rate: int = 0
    """Number of tokens added to the bucket each refill interval."""

    refill_interval_seconds: int = 0
    """Duration in seconds between each token refill."""


@dataclass(frozen=True, slots=True)
class RuleResultFixedWindow:
    """Result from a fixed window rate limit evaluation."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    reason: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    """The reason category — always ``"RATE_LIMIT"`` for fixed window rules."""

    type: Literal["FIXED_WINDOW"] = "FIXED_WINDOW"
    """Discriminant — always ``"FIXED_WINDOW"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""

    remaining_requests: int = 0
    """Number of requests remaining in the current window."""

    max_requests: int = 0
    """Maximum requests allowed per window."""

    reset_at_unix_seconds: int = 0
    """Unix timestamp (seconds) when the current window resets."""

    window_seconds: int = 0
    """Duration of each rate limit window in seconds."""


@dataclass(frozen=True, slots=True)
class RuleResultSlidingWindow:
    """Result from a sliding window rate limit evaluation."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    reason: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    """The reason category — always ``"RATE_LIMIT"`` for sliding window rules."""

    type: Literal["SLIDING_WINDOW"] = "SLIDING_WINDOW"
    """Discriminant — always ``"SLIDING_WINDOW"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""

    remaining_requests: int = 0
    """Number of requests remaining in the current sliding interval."""

    max_requests: int = 0
    """Maximum requests allowed per sliding interval."""

    reset_at_unix_seconds: int = 0
    """Unix timestamp (seconds) when the sliding interval resets."""

    interval_seconds: int = 0
    """Duration of the sliding interval in seconds."""


@dataclass(frozen=True, slots=True)
class RuleResultPromptInjection:
    """Result from a prompt injection detection evaluation."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    reason: Literal["PROMPT_INJECTION"] = "PROMPT_INJECTION"
    """The reason category — always ``"PROMPT_INJECTION"`` for this rule."""

    type: Literal["PROMPT_INJECTION"] = "PROMPT_INJECTION"
    """Discriminant — always ``"PROMPT_INJECTION"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""


@dataclass(frozen=True, slots=True)
class RuleResultModerateContent:
    """Result from a content moderation evaluation (experimental)."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    detected: bool
    """Whether harmful content was detected in the input text."""

    reason: Literal["MODERATE_CONTENT"] = "MODERATE_CONTENT"
    """The reason category — always ``"MODERATE_CONTENT"`` for this rule."""

    type: Literal["MODERATE_CONTENT"] = "MODERATE_CONTENT"
    """Discriminant — always ``"MODERATE_CONTENT"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""


@dataclass(frozen=True, slots=True)
class RuleResultSensitiveInfo:
    """Result from a sensitive information detection evaluation."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    reason: Literal["SENSITIVE_INFO"] = "SENSITIVE_INFO"
    """The reason category — always ``"SENSITIVE_INFO"`` for this rule."""

    type: Literal["SENSITIVE_INFO"] = "SENSITIVE_INFO"
    """Discriminant — always ``"SENSITIVE_INFO"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""

    detected_entity_types: tuple[str, ...] = ()
    """Entity types detected in the input (e.g. ``"EMAIL"``, ``"PHONE_NUMBER"``)."""


@dataclass(frozen=True, slots=True)
class RuleResultCustom:
    """Result from a custom local rule evaluation."""

    conclusion: Conclusion
    """Whether the request was allowed or denied by this rule."""

    reason: Literal["CUSTOM"] = "CUSTOM"
    """The reason category — always ``"CUSTOM"`` for custom rules."""

    type: Literal["CUSTOM"] = "CUSTOM"
    """Discriminant — always ``"CUSTOM"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""

    data: Mapping[str, str] = field(default_factory=dict)
    """Arbitrary key-value data returned by the custom rule's evaluate function."""


@dataclass(frozen=True, slots=True)
class RuleResultNotRun:
    """Result for a rule that was not evaluated."""

    conclusion: Literal["ALLOW"] = "ALLOW"
    """Always ``"ALLOW"`` — unevaluated rules never deny."""

    reason: Reason = "NOT_RUN"
    """The reason category — always ``"NOT_RUN"`` for skipped rules."""

    type: Literal["NOT_RUN"] = "NOT_RUN"
    """Discriminant — always ``"NOT_RUN"``."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""


@dataclass(frozen=True, slots=True)
class RuleResultError:
    """Result for a rule that encountered an error during evaluation.

    Errors are fail-open: conclusion is always ``"ALLOW"``.
    """

    conclusion: Literal["ALLOW"] = "ALLOW"
    """Always ``"ALLOW"`` — errors are fail-open."""

    reason: Reason = "ERROR"
    """The reason category — always ``"ERROR"`` for errored rules."""

    type: Literal["RULE_ERROR"] = "RULE_ERROR"
    """Discriminant — ``"RULE_ERROR"`` (distinct from the ``"ERROR"`` reason
    to avoid ambiguity with the :class:`Reason` value)."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""

    message: str = ""
    """Human-readable error description."""

    code: str = ""
    """Machine-readable error code."""


@dataclass(frozen=True, slots=True)
class RuleResultUnknown:
    """Fallback result for unrecognized rule types."""

    conclusion: Conclusion = "ALLOW"
    """Whether the request was allowed or denied."""

    reason: Literal["UNKNOWN"] = "UNKNOWN"
    """The reason category — always ``"UNKNOWN"`` for unrecognized rules."""

    type: Literal["UNKNOWN"] = "UNKNOWN"
    """Discriminant — always ``"UNKNOWN"``."""

    warnings: tuple[ArcjetWarning, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleResultInputConstraint:
    """Result from a remotely configured typed input constraint."""

    conclusion: Conclusion
    reason: Literal["INPUT_CONSTRAINT"] = "INPUT_CONSTRAINT"
    type: InputConstraintType = "STRING_LENGTH"
    match_operator: StringMatchOperator | None = None
    """Match semantics for allowed/denied values. ``None`` for string length."""
    warnings: tuple[ArcjetWarning, ...] = ()
    """Per-rule warnings — this rule was processed correctly (the result is
    trustworthy) but something about it should be fixed. Informational; never
    changes the rule's conclusion. Empty until the Decide service emits
    per-rule diagnostics."""


RuleResult = Union[
    RuleResultTokenBucket,
    RuleResultFixedWindow,
    RuleResultSlidingWindow,
    RuleResultPromptInjection,
    RuleResultModerateContent,
    RuleResultSensitiveInfo,
    RuleResultCustom,
    RuleResultNotRun,
    RuleResultError,
    RuleResultInputConstraint,
    RuleResultUnknown,
]


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """Remote-policy selection and completeness reported by Guard."""

    revision: str
    status: PolicyStatus
    refresh_required: bool = False


@dataclass(frozen=True, slots=True)
class PolicyRuleResult:
    """A keyed remote-policy result, separate from positional SDK results."""

    policy_id: str
    policy_revision: str
    rule_id: str
    mode: Mode
    execution: PolicyExecution
    result: RuleResult
    source: Literal["REMOTE"] = "REMOTE"


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
    **Layer 2**: ``decision.warnings``, ``decision.error_results()``, and
    ``decision.has_failed_open()`` (the fail-closed gate).
    **Layer 3**: Use ``rule.results(decision)`` or ``rule_input.result(decision)``.
    """

    conclusion: Conclusion
    """The outcome of the guard decision."""

    id: str
    """Server-generated unique identifier (TypeID, prefix ``"gdec"``)."""

    results: tuple[RuleResult, ...]
    """Rule results associated with this decision.

    In a successful evaluation, contains one result per submitted rule in
    submission order. In error or fail-open scenarios (e.g. transport failure,
    validation error), this 1:1 correspondence is not guaranteed — a single
    synthetic error result may be returned for the entire decision.
    """

    reason: Reason = "UNKNOWN"
    """Broad reason category (only meaningful for DENY decisions)."""

    warnings: tuple[ArcjetWarning, ...] = ()
    """Decision-level warnings — diagnostics from request validation (e.g. an
    invalid metadata key that was stripped). The decision is still valid; these
    are informational and never change the conclusion."""

    _internal_results: tuple[InternalResult, ...] = field(
        default=(), repr=False, compare=False
    )
    policy_evaluation: PolicyEvaluation | None = None
    """Remote-policy status, or ``None`` for servers predating policy support."""

    policy_results: tuple[PolicyRuleResult, ...] = ()
    """Keyed remote-policy results; never mixed into positional ``results``."""
    _policy_errors: tuple[RuleResultError, ...] = field(
        default=(), repr=False, compare=False
    )

    def error_results(self) -> list[RuleResultError]:
        """The results that errored — rules (or the decision itself) that could
        not be processed. Empty when nothing errored. Each entry carries a
        ``code`` and ``message``; correlate one to a rule with
        ``rule.result(decision)``."""
        return [
            *(r for r in self.results if isinstance(r, RuleResultError)),
            *self._policy_errors,
        ]

    def has_failed_open(self) -> bool:
        """True when this decision returned ``"ALLOW"`` only because a rule or
        the decision could not be processed — i.e. it failed open. Gate a
        fail-closed policy on this::

            if decision.has_failed_open():
                return deny()

        "Failed open" describes an outcome of *this decision*, not the policy
        configuration.
        """
        return self.conclusion == "ALLOW" and bool(self.error_results())

    def has_error(self) -> bool:
        """True if there is any warning or any errored rule.

        .. deprecated::
            Use :attr:`warnings` for request diagnostics and
            :meth:`error_results` / :meth:`has_failed_open` for errors.
            Removed in the next major.
        """
        _stdlib_warnings.warn(
            "Decision.has_error() is deprecated: use decision.warnings for "
            "request diagnostics and error_results / has_failed_open() for "
            "errors. It will be removed in the next major release.",
            DeprecationWarning,
            stacklevel=2,
        )
        return bool(self.warnings) or bool(self.error_results())

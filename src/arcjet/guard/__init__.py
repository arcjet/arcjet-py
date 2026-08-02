"""Arcjet Guard SDK — AI guardrails for rate limiting, prompt injection
detection, and sensitive info detection.

Public API
----------

**Types** (from ``types``)::

    Conclusion, Reason, Mode, Decision,
    RuleResult, RuleResultTokenBucket, RuleResultFixedWindow,
    RuleResultSlidingWindow, RuleResultPromptInjection,
    RuleResultSensitiveInfo, RuleResultNotRun,
    RuleResultError, RuleResultUnknown

**Rule classes** (from ``rules``)::

    TokenBucket, FixedWindow, SlidingWindow,
    DetectPromptInjection, LocalDetectSensitiveInfo, LocalCustomRule

**Concrete rule input types** (from ``rules``)::

    TokenBucketWithInput, FixedWindowWithInput, SlidingWindowWithInput,
    PromptInjectionWithInput, SensitiveInfoWithInput,
    LocalCustomWithInput,
    RuleWithInput (union of all)

**Configured rule union** (from ``rules``)::

    RuleWithConfig (union of all configured rule types)

**Client factories** (from ``client``)::

    launch_arcjet, launch_arcjet_sync
    ArcjetGuard, ArcjetGuardSync

Both clients expose ``.guard()`` for decisions and ``.capture()`` /
``.flush()`` for visibility events.  ``capture()`` is fire-and-forget: it
records what your application did without affecting any decision, and is
delivered in the background in batches.
"""

from arcjet._metadata import Metadata, MetadataValue

from ._client import (
    ArcjetGuard,
    ArcjetGuardSync,
    launch_arcjet,
    launch_arcjet_sync,
)
from ._policy_input import PolicyInput, PolicyInputMap, local_input, server_input
from ._rules import (
    DetectPromptInjection,
    FixedWindow,
    FixedWindowWithInput,
    LocalCustomRule,
    LocalCustomWithInput,
    LocalDetectSensitiveInfo,
    ModerateContent,
    ModerateContentWithInput,
    PromptInjectionWithInput,
    RuleWithConfig,
    RuleWithInput,
    SensitiveInfoWithInput,
    SlidingWindow,
    SlidingWindowWithInput,
    TokenBucket,
    TokenBucketWithInput,
    TypedCustomResult,
)

# Experimental: content moderation. Exposed under an ``experimental_`` prefix on
# the PascalCase rule name (matching the other rule classes) to signal that the
# rule and its result shape may change. No moderation model is wired up
# server-side yet, so it currently returns an error result (fail open).
experimental_ModerateContent = ModerateContent
from ._types import (
    SENSITIVE_INFO_ENTITY_TYPES,
    ArcjetWarning,
    Conclusion,
    CustomEvaluateResult,
    Decision,
    Mode,
    PolicyEvaluation,
    PolicyRuleResult,
    Reason,
    RuleResult,
    RuleResultCustom,
    RuleResultError,
    RuleResultFixedWindow,
    RuleResultInputConstraint,
    RuleResultModerateContent,
    RuleResultNotRun,
    RuleResultPromptInjection,
    RuleResultSensitiveInfo,
    RuleResultSlidingWindow,
    RuleResultTokenBucket,
    RuleResultUnknown,
    StringMatchOperator,
)

__all__ = [
    # Types
    "Conclusion",
    "CustomEvaluateResult",
    "Decision",
    "Metadata",
    "MetadataValue",
    "Mode",
    "PolicyInput",
    "PolicyInputMap",
    "PolicyEvaluation",
    "PolicyRuleResult",
    "Reason",
    "RuleResult",
    "RuleResultCustom",
    "RuleResultError",
    "RuleResultFixedWindow",
    "RuleResultInputConstraint",
    "RuleResultModerateContent",
    "RuleResultNotRun",
    "RuleResultPromptInjection",
    "RuleResultSensitiveInfo",
    "RuleResultSlidingWindow",
    "RuleResultTokenBucket",
    "RuleResultUnknown",
    "StringMatchOperator",
    "SENSITIVE_INFO_ENTITY_TYPES",
    "ArcjetWarning",
    # Rule classes
    "DetectPromptInjection",
    "FixedWindow",
    "LocalCustomRule",
    "LocalDetectSensitiveInfo",
    "SlidingWindow",
    "TokenBucket",
    # Experimental rule factories
    "experimental_ModerateContent",
    # Concrete input types
    "FixedWindowWithInput",
    "LocalCustomWithInput",
    "ModerateContentWithInput",
    "PromptInjectionWithInput",
    "SensitiveInfoWithInput",
    "SlidingWindowWithInput",
    "TokenBucketWithInput",
    "TypedCustomResult",
    # Union aliases
    "RuleWithConfig",
    "RuleWithInput",
    # Client factories
    "ArcjetGuard",
    "ArcjetGuardSync",
    "launch_arcjet",
    "launch_arcjet_sync",
    "local_input",
    "server_input",
]

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
"""

from ._client import (
    ArcjetGuard,
    ArcjetGuardSync,
    launch_arcjet,
    launch_arcjet_sync,
)
from ._rules import (
    DetectPromptInjection,
    FixedWindow,
    FixedWindowWithInput,
    LocalCustomRule,
    LocalCustomWithInput,
    LocalDetectSensitiveInfo,
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
from ._types import (
    SENSITIVE_INFO_ENTITY_TYPES,
    Conclusion,
    CustomEvaluateResult,
    Decision,
    Mode,
    Reason,
    RuleResult,
    RuleResultCustom,
    RuleResultError,
    RuleResultFixedWindow,
    RuleResultNotRun,
    RuleResultPromptInjection,
    RuleResultSensitiveInfo,
    RuleResultSlidingWindow,
    RuleResultTokenBucket,
    RuleResultUnknown,
)

__all__ = [
    # Types
    "Conclusion",
    "CustomEvaluateResult",
    "Decision",
    "Mode",
    "Reason",
    "RuleResult",
    "RuleResultCustom",
    "RuleResultError",
    "RuleResultFixedWindow",
    "RuleResultNotRun",
    "RuleResultPromptInjection",
    "RuleResultSensitiveInfo",
    "RuleResultSlidingWindow",
    "RuleResultTokenBucket",
    "RuleResultUnknown",
    "SENSITIVE_INFO_ENTITY_TYPES",
    # Rule classes
    "DetectPromptInjection",
    "FixedWindow",
    "LocalCustomRule",
    "LocalDetectSensitiveInfo",
    "SlidingWindow",
    "TokenBucket",
    # Concrete input types
    "FixedWindowWithInput",
    "LocalCustomWithInput",
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
]

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
    DetectPromptInjection, DetectSensitiveInfo

**Concrete rule input types** (from ``rules``)::

    TokenBucketWithInput, FixedWindowWithInput, SlidingWindowWithInput,
    PromptInjectionWithInput, SensitiveInfoWithInput,
    RuleWithInput (union of all)

**Configured rule union** (from ``rules``)::

    RuleWithConfig (union of all configured rule types)

**Client factories** (from ``client``)::

    launch_arcjet, launch_arcjet_sync
    ArcjetGuard, ArcjetGuardSync
"""

from .client import (
    ArcjetGuard,
    ArcjetGuardSync,
    launch_arcjet,
    launch_arcjet_sync,
)
from .rules import (
    CustomRule,
    CustomWithInput,
    DetectPromptInjection,
    DetectSensitiveInfo,
    FixedWindow,
    FixedWindowWithInput,
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
from .types import (
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
    "CustomRule",
    "DetectPromptInjection",
    "DetectSensitiveInfo",
    "FixedWindow",
    "SlidingWindow",
    "TokenBucket",
    # Concrete input types
    "CustomWithInput",
    "FixedWindowWithInput",
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

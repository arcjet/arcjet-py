"""Arcjet Guard SDK — AI guardrails for rate limiting, prompt injection
detection, and sensitive info detection.

Public API
----------

**Types** (from ``types``)::

    Conclusion, Reason, Mode, Decision,
    RuleResult, RuleResultTokenBucket, RuleResultFixedWindow,
    RuleResultSlidingWindow, RuleResultPromptInjection,
    RuleResultSensitiveInfo, RuleResultCustom, RuleResultNotRun,
    RuleResultError, RuleResultUnknown

**Rule factories** (from ``rules``)::

    token_bucket, fixed_window, sliding_window,
    detect_prompt_injection, local_detect_sensitive_info, local_custom

**Concrete rule input types** (from ``rules``)::

    TokenBucketWithInput, FixedWindowWithInput, SlidingWindowWithInput,
    PromptInjectionWithInput, SensitiveInfoWithInput, CustomWithInput,
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
    CustomWithInput,
    FixedWindowWithInput,
    PromptInjectionWithInput,
    RuleWithConfig,
    RuleWithInput,
    SensitiveInfoWithInput,
    SlidingWindowWithInput,
    TokenBucketWithInput,
    detect_prompt_injection,
    fixed_window,
    local_custom,
    local_detect_sensitive_info,
    sliding_window,
    token_bucket,
)
from .types import (
    Conclusion,
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
    # Rule factories
    "detect_prompt_injection",
    "fixed_window",
    "local_custom",
    "local_detect_sensitive_info",
    "sliding_window",
    "token_bucket",
    # Concrete input types
    "CustomWithInput",
    "FixedWindowWithInput",
    "PromptInjectionWithInput",
    "SensitiveInfoWithInput",
    "SlidingWindowWithInput",
    "TokenBucketWithInput",
    # Union aliases
    "RuleWithConfig",
    "RuleWithInput",
    # Client factories
    "ArcjetGuard",
    "ArcjetGuardSync",
    "launch_arcjet",
    "launch_arcjet_sync",
]

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

**Optional registration** (from ``registry``)::

    register_arcjet, unregister_arcjet
    guard, guard_sync, capture, flush, flush_sync

Registering a client is optional and separate from launching one.  It exists so
code that cannot reach a client handle can still call ``guard()`` and
``capture()``; passing a client explicitly always works and is the recommended
path.  ``capture()`` is a single function because it queues and returns on both
clients, while ``guard``/``flush`` come in async and ``_sync`` pairs mirroring
the two client flavors.

The in-memory test client lives in :mod:`arcjet.guard.testing`.

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
from ._registry import (
    capture,
    flush,
    flush_sync,
    guard,
    guard_sync,
    register_arcjet,
    unregister_arcjet,
)
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
    Billing,
    Conclusion,
    CustomEvaluateResult,
    Decision,
    Mode,
    Reason,
    RuleResult,
    RuleResultCustom,
    RuleResultError,
    RuleResultFixedWindow,
    RuleResultModerateContent,
    RuleResultNotRun,
    RuleResultPromptInjection,
    RuleResultSensitiveInfo,
    RuleResultSlidingWindow,
    RuleResultTokenBucket,
    RuleResultUnknown,
)

__all__ = [
    # Types
    "Billing",
    "Conclusion",
    "CustomEvaluateResult",
    "Decision",
    "Metadata",
    "MetadataValue",
    "Mode",
    "Reason",
    "RuleResult",
    "RuleResultCustom",
    "RuleResultError",
    "RuleResultFixedWindow",
    "RuleResultModerateContent",
    "RuleResultNotRun",
    "RuleResultPromptInjection",
    "RuleResultSensitiveInfo",
    "RuleResultSlidingWindow",
    "RuleResultTokenBucket",
    "RuleResultUnknown",
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
    # Optional registration, and the free calls it enables. Nothing here takes
    # effect until an application calls register_arcjet(); launch_arcjet()
    # touches no global state.
    "register_arcjet",
    "unregister_arcjet",
    "capture",
    "flush",
    "flush_sync",
    "guard",
    "guard_sync",
]

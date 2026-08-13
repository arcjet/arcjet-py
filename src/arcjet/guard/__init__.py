"""Arcjet Guard SDK — AI guardrails for rate limiting, prompt injection
detection, content moderation, and sensitive info detection.

Public API
----------

**Types** (from ``types``)::

    Conclusion, Reason, Mode, Decision,
    RuleResult, RuleResultTokenBucket, RuleResultFixedWindow,
    RuleResultSlidingWindow, RuleResultPromptInjection,
    RuleResultModerateContent, RuleResultSensitiveInfo, RuleResultNotRun,
    RuleResultError, RuleResultUnknown

**Rule classes** (from ``rules``)::

    TokenBucket, FixedWindow, SlidingWindow,
    DetectPromptInjection, ModerateContent, LocalDetectSensitiveInfo,
    LocalCustomRule

**Concrete rule input types** (from ``rules``)::

    TokenBucketWithInput, FixedWindowWithInput, SlidingWindowWithInput,
    PromptInjectionWithInput, ModerateContentWithInput, SensitiveInfoWithInput,
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
from ._policy_input import PolicyInput, PolicyInputMap, local_input, server_input
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
    experimental_ModerateContent,  # ty: ignore[deprecated]
)
from ._types import (
    SENSITIVE_INFO_ENTITY_TYPES,
    ArcjetWarning,
    Billing,
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
    "Billing",
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
    "ModerateContent",
    "SlidingWindow",
    "TokenBucket",
    # Deprecated alias for ModerateContent
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

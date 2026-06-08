"""Rule classes for ``arcjet.guard``.

Each class represents a configured rule.  Calling the instance with
per-request input produces a concrete ``*WithInput`` ready for ``.guard()``.
"""

from __future__ import annotations

from typing import Any, Union

from ._custom import LocalCustomRule, LocalCustomWithInput, TypedCustomResult
from ._moderate_content import ModerateContent, ModerateContentWithInput
from ._prompt_injection import DetectPromptInjection, PromptInjectionWithInput
from ._rate_limit import (
    FixedWindow,
    FixedWindowConfig,
    FixedWindowWithInput,
    SlidingWindow,
    SlidingWindowConfig,
    SlidingWindowWithInput,
    TokenBucket,
    TokenBucketConfig,
    TokenBucketWithInput,
)
from ._sensitive_info import (
    LocalDetectSensitiveInfo,
    SensitiveInfoConfig,
    SensitiveInfoWithInput,
)

RuleWithInput = Union[
    TokenBucketWithInput,
    FixedWindowWithInput,
    SlidingWindowWithInput,
    PromptInjectionWithInput,
    ModerateContentWithInput,
    SensitiveInfoWithInput,
    LocalCustomWithInput[Any],
]
"""Union of all ``*WithInput`` types."""

RuleWithConfig = Union[
    TokenBucket,
    FixedWindow,
    SlidingWindow,
    DetectPromptInjection,
    ModerateContent,
    LocalDetectSensitiveInfo,
    LocalCustomRule[Any, Any, Any],
]
"""Union of all configured rule types."""

__all__ = [
    # Config dataclasses
    "FixedWindowConfig",
    "SensitiveInfoConfig",
    "SlidingWindowConfig",
    "TokenBucketConfig",
    # WithInput dataclasses
    "FixedWindowWithInput",
    "LocalCustomWithInput",
    "ModerateContentWithInput",
    "PromptInjectionWithInput",
    "SensitiveInfoWithInput",
    "SlidingWindowWithInput",
    "TokenBucketWithInput",
    "TypedCustomResult",
    # Rule classes
    "DetectPromptInjection",
    "FixedWindow",
    "LocalCustomRule",
    "LocalDetectSensitiveInfo",
    "ModerateContent",
    "SlidingWindow",
    "TokenBucket",
    # Unions
    "RuleWithConfig",
    "RuleWithInput",
]

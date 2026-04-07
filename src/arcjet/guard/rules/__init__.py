"""Rule classes for ``arcjet.guard``.

Each class represents a configured rule.  Calling the instance with
per-request input produces a concrete ``*WithInput`` ready for ``.guard()``.
"""

from __future__ import annotations

from typing import Any, Union

from ._base import _config_hash, _get_internal_results, _hash_key, _merge_metadata
from ._custom import CustomRule, CustomWithInput, TypedCustomResult
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
    DetectSensitiveInfo,
    SensitiveInfoConfig,
    SensitiveInfoWithInput,
)

RuleWithInput = Union[
    TokenBucketWithInput,
    FixedWindowWithInput,
    SlidingWindowWithInput,
    PromptInjectionWithInput,
    SensitiveInfoWithInput,
    CustomWithInput[Any],
]
"""Union of all ``*WithInput`` types."""

RuleWithConfig = Union[
    TokenBucket,
    FixedWindow,
    SlidingWindow,
    DetectPromptInjection,
    DetectSensitiveInfo,
]
"""Union of all configured rule types."""

__all__ = [
    # Base helpers (for internal/test use)
    "_config_hash",
    "_get_internal_results",
    "_hash_key",
    "_merge_metadata",
    # Config dataclasses
    "FixedWindowConfig",
    "SensitiveInfoConfig",
    "SlidingWindowConfig",
    "TokenBucketConfig",
    # WithInput dataclasses
    "CustomWithInput",
    "FixedWindowWithInput",
    "PromptInjectionWithInput",
    "SensitiveInfoWithInput",
    "SlidingWindowWithInput",
    "TokenBucketWithInput",
    "TypedCustomResult",
    # Rule classes
    "CustomRule",
    "DetectPromptInjection",
    "DetectSensitiveInfo",
    "FixedWindow",
    "SlidingWindow",
    "TokenBucket",
    # Unions
    "RuleWithConfig",
    "RuleWithInput",
]

from __future__ import annotations

from ._client import Arcjet, ArcjetSync, arcjet, arcjet_sync
from ._dataclasses import IpDetails
from ._decision import (
    Decision,
    IpInfo,
    Reason,  # type: ignore -- intentionally deprecated
    RuleResult,
    is_spoofed_bot,
)
from ._enums import Mode
from ._rules import (
    BotCategory,
    EmailType,
    PromptInjectionDetection,
    RuleSpec,
    SensitiveInfoEntityType,
    detect_bot,
    detect_prompt_injection,
    detect_sensitive_info,
    filter_request,
    fixed_window,
    shield,
    sliding_window,
    token_bucket,
    validate_email,
)

__all__ = [
    "arcjet_sync",
    "arcjet",
    "Arcjet",
    "ArcjetSync",
    "BotCategory",
    "Decision",
    "detect_bot",
    "detect_prompt_injection",
    "detect_sensitive_info",
    "EmailType",
    "SensitiveInfoEntityType",
    "filter_request",
    "fixed_window",
    "IpInfo",
    "IpDetails",
    "is_spoofed_bot",
    "Mode",
    "PromptInjectionDetection",
    "Reason",
    "RuleResult",
    "RuleSpec",
    "shield",
    "sliding_window",
    "token_bucket",
    "validate_email",
]

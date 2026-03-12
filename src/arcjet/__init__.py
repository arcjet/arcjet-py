from __future__ import annotations

from ._enums import Mode
from .client import Arcjet, ArcjetSync, arcjet, arcjet_sync
from .dataclasses import IpDetails
from .decision import (
    Decision,
    IpInfo,
    Reason,  # type: ignore -- intentionally deprecated
    RuleResult,
    is_spoofed_bot,
)
from .rules import (
    BotCategory,
    EmailType,
    RuleSpec,
    SensitiveInfoEntityType,
    detect_bot,
    detect_sensitive_info,
    fixed_window,
    shield,
    sliding_window,
    token_bucket,
    validate_email,
)
from .rules import (
    detect_prompt_injection as experimental_detect_prompt_injection,
)

__all__ = [
    "arcjet_sync",
    "arcjet",
    "Arcjet",
    "ArcjetSync",
    "BotCategory",
    "Decision",
    "detect_bot",
    "detect_sensitive_info",
    "experimental_detect_prompt_injection",
    "EmailType",
    "SensitiveInfoEntityType",
    "fixed_window",
    "IpInfo",
    "IpDetails",
    "is_spoofed_bot",
    "Mode",
    "Reason",
    "RuleResult",
    "RuleSpec",
    "shield",
    "sliding_window",
    "token_bucket",
    "validate_email",
]

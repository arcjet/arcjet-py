from __future__ import annotations

from ._enums import Mode
from .client import Arcjet, ArcjetSync, arcjet, arcjet_sync
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
    detect_bot,
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
    "EmailType",
    "fixed_window",
    "IpInfo",
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

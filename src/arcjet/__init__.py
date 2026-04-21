from __future__ import annotations

from ._client import Arcjet, ArcjetSync, arcjet, arcjet_sync
from ._context import RequestContext
from ._dataclasses import (
    BotReason,
    EmailReason,
    ErrorReason,
    FilterReason,
    IdentifiedEntity,
    IpDetails,
    PromptInjectionReason,
    RateLimitReason,
    SensitiveInfoReason,
    ShieldReason,
)
from ._decision import (
    Decision,
    IpInfo,
    Reason,  # type: ignore -- intentionally deprecated
    RuleResult,
    is_spoofed_bot,
)
from ._enums import Mode
from ._errors import ArcjetError, ArcjetMisconfiguration, ArcjetTransportError
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
    "ArcjetError",
    "ArcjetMisconfiguration",
    "ArcjetSync",
    "ArcjetTransportError",
    "BotCategory",
    "BotReason",
    "Decision",
    "detect_bot",
    "detect_prompt_injection",
    "detect_sensitive_info",
    "EmailReason",
    "EmailType",
    "ErrorReason",
    "FilterReason",
    "SensitiveInfoEntityType",
    "filter_request",
    "fixed_window",
    "IdentifiedEntity",
    "IpInfo",
    "IpDetails",
    "is_spoofed_bot",
    "Mode",
    "PromptInjectionDetection",
    "PromptInjectionReason",
    "RateLimitReason",
    "Reason",
    "RequestContext",
    "RuleResult",
    "RuleSpec",
    "SensitiveInfoReason",
    "shield",
    "ShieldReason",
    "sliding_window",
    "token_bucket",
    "validate_email",
]

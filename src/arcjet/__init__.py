from __future__ import annotations

from ._client import Arcjet, ArcjetSync, arcjet, arcjet_sync
from ._dataclasses import IpDetails, ThreatIntelligence
from ._decision import (
    Decision,
    IpInfo,
    Reason,  # type: ignore -- intentionally deprecated
    RuleResult,
    is_missing_user_agent,
    is_spoofed_bot,
    is_verified_bot,
)
from ._enums import Mode
from ._headers import set_rate_limit_headers
from ._metadata import Metadata, MetadataValue
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
    protect_signup,
    shield,
    sliding_window,
    token_bucket,
    validate_email,
)
from ._sensitive_info_backend import (
    SensitiveInfoBackend,
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
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
    "SensitiveInfoBackend",
    "SensitiveInfoBackendContext",
    "SensitiveInfoBackendOptions",
    "filter_request",
    "fixed_window",
    "IpInfo",
    "IpDetails",
    "ThreatIntelligence",
    "is_missing_user_agent",
    "is_spoofed_bot",
    "is_verified_bot",
    "set_rate_limit_headers",
    "Metadata",
    "MetadataValue",
    "Mode",
    "PromptInjectionDetection",
    "protect_signup",
    "Reason",
    "RuleResult",
    "RuleSpec",
    "shield",
    "sliding_window",
    "token_bucket",
    "validate_email",
]

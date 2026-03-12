from __future__ import annotations

from typing import Union

from typing_extensions import deprecated

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
    PromptInjectionDetection,
    RuleSpec,
    detect_bot,
    detect_prompt_injection,
    fixed_window,
    shield,
    sliding_window,
    token_bucket,
    validate_email,
)


@deprecated(
    "experimental_detect_prompt_injection is deprecated. Use detect_prompt_injection instead."
)
def experimental_detect_prompt_injection(
    *, mode: Union[str, Mode] = Mode.LIVE, threshold: float = 0.5
) -> PromptInjectionDetection:
    """Detect prompt injection attacks in user messages.

    .. deprecated::
        Use :func:`detect_prompt_injection` instead.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        threshold: Detection confidence threshold (0.0 to 1.0). Higher values
            are more conservative. Defaults to ``0.5``.

    Returns:
        A ``PromptInjectionDetection`` rule to include in the ``rules`` list of
        ``arcjet()``.
    """
    return detect_prompt_injection(mode=mode, threshold=threshold)


__all__ = [
    "arcjet_sync",
    "arcjet",
    "Arcjet",
    "ArcjetSync",
    "BotCategory",
    "Decision",
    "detect_bot",
    "detect_prompt_injection",
    "experimental_detect_prompt_injection",
    "EmailType",
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

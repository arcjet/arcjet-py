"""Default import implementations for arcjet:js-req interfaces.

This file is NOT generated — it contains domain-specific default callbacks
that are imported by the generated _imports.py.
"""

from __future__ import annotations

from ._types import SensitiveInfoEntity

FREE_EMAIL_PROVIDERS = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "aol.com",
        "hotmail.co.uk",
    }
)


def _default_ip_lookup(_ip: str) -> str | None:
    return None


def _default_bot_detect(_request: str) -> list[str]:
    return []


def _default_bot_verify(_bot_id: str, _ip: str) -> str:
    return "unverifiable"


def _default_is_free_email(domain: str) -> str:
    if domain in FREE_EMAIL_PROVIDERS:
        return "yes"
    return "unknown"


def _default_is_disposable_email(_domain_or_email: str) -> str:
    return "unknown"


def _default_has_mx_records(_domain_or_email: str) -> str:
    return "unknown"


def _default_has_gravatar(_domain_or_email: str) -> str:
    return "unknown"


def _default_sensitive_info_detect(
    tokens: list[str],
) -> list[SensitiveInfoEntity | None]:
    return [None] * len(tokens)  # type: ignore[invalid-return-type]

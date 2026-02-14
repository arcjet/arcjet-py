from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast

from typing_extensions import deprecated


@dataclass(frozen=True, slots=True)
class BotReason:
    """Bot reason."""

    allowed: Sequence[str]
    """List of allowed bot identifiers."""

    denied: Sequence[str]
    """List of denied bot identifiers."""

    spoofed: bool
    """Whether the bot is spoofed."""

    verified: bool
    """Whether the bot is verified."""

    type: Literal["BOT"] = "BOT"
    """Kind."""


EmailType = Literal[
    "DISPOSABLE", "FREE", "INVALID", "NO_GRAVATAR", "NO_MX_RECORDS", "UNSPECIFIED"
]
"""Kinds of email addresses."""


@dataclass(frozen=True, slots=True)
class EmailReason:
    """Email reason."""

    email_types: Sequence[EmailType]
    """List of email types that are allowed."""

    type: Literal["EMAIL"] = "EMAIL"
    """Kind."""


@dataclass(frozen=True, slots=True)
class ErrorReason:
    """Error reason."""

    message: str
    """Error message."""

    type: Literal["ERROR"] = "ERROR"
    """Kind."""


@dataclass(frozen=True, slots=True)
class FilterReason:
    """Filter reason."""

    matched_expressions: Sequence[str]
    """Expressions that matched."""

    undetermined_expressions: Sequence[str]
    """Expression that could not be matched."""

    type: Literal["FILTER"] = "FILTER"
    """Kind."""


@dataclass(frozen=True, slots=True)
class RateLimitReason:
    """Rate limit reason."""

    max: int
    """Maximum number of allowed requests."""

    remaining: int
    """Remaining number of requests."""

    reset_time: datetime | None
    """When the rate limit resets."""

    reset: timedelta
    """Duration until the rate limit resets."""

    window: timedelta
    """Duration until the window resets."""

    type: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    """Kind."""


@dataclass(frozen=True, slots=True)
class ShieldReason:
    """Shield reason."""

    shield_triggered: bool
    """Whether the shield was triggered."""

    type: Literal["SHIELD"] = "SHIELD"
    """Kind."""


Reason = (
    BotReason
    | EmailReason
    | ErrorReason
    | FilterReason
    | RateLimitReason
    | ShieldReason
)
"""Reason returned by a rule."""


@dataclass(frozen=True, slots=True)
class IpDetails:
    """Typed IP enrichment details from Arcjet decisions.

    Fields may be ``None`` when Arcjet did not provide that value for a
    specific IP.
    """

    latitude: float | None = None
    longitude: float | None = None
    accuracy_radius: int | None = None
    timezone: str | None = None
    postal_code: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    country_name: str | None = None
    continent: str | None = None
    continent_name: str | None = None
    asn: str | None = None
    asn_name: str | None = None
    asn_domain: str | None = None
    asn_type: str | None = None
    asn_country: str | None = None
    service: str | None = None
    is_hosting: bool | None = None
    is_vpn: bool | None = None
    is_proxy: bool | None = None
    is_tor: bool | None = None
    is_relay: bool | None = None

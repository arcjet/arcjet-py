from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast

from typing_extensions import deprecated


@dataclass(frozen=True, slots=True)
class BotReason:
    """Reason returned when a bot detection rule triggers.

    Access via ``decision.reason_v2`` or a per-rule ``result.reason_v2``
    when ``reason_v2.type == "BOT"``.

    Example::

        if decision.reason_v2.type == "BOT":
            reason = decision.reason_v2  # BotReason
            if reason.spoofed:
                return jsonify(error="Spoofed bot"), 403
            if reason.denied:
                print("Denied bots:", ", ".join(reason.denied))
    """

    allowed: Sequence[str]
    """Bot identifiers that matched the allow list for this request."""

    denied: Sequence[str]
    """Bot identifiers that matched the deny list for this request."""

    spoofed: bool
    """``True`` if the bot claimed to be a known crawler (e.g. Googlebot) but
    its IP did not match the verified ranges for that crawler."""

    verified: bool
    """``True`` if the bot was positively identified as a known, legitimate bot
    by verifying its IP against official ranges."""

    type: Literal["BOT"] = "BOT"
    """Discriminator field. Always ``"BOT"``."""


EmailType = Literal[
    "DISPOSABLE", "FREE", "INVALID", "NO_GRAVATAR", "NO_MX_RECORDS", "UNSPECIFIED"
]
"""Email address classifier label returned in ``EmailReason.email_types``.

Possible values:

- ``"DISPOSABLE"``: Temporary or throw-away email address.
- ``"FREE"``: Address from a free email provider (e.g. Gmail, Yahoo).
- ``"INVALID"``: Address that fails syntax or format validation.
- ``"NO_GRAVATAR"``: Address with no associated Gravatar profile.
- ``"NO_MX_RECORDS"``: Domain has no valid MX DNS records — mail cannot be
  delivered.
"""


@dataclass(frozen=True, slots=True)
class EmailReason:
    """Reason returned when an email validation rule triggers.

    Access via ``decision.reason_v2`` when ``reason_v2.type == "EMAIL"``.
    ``email_types`` lists the classifier labels applied to the submitted
    address (e.g. ``["DISPOSABLE", "NO_MX_RECORDS"]``).

    Example::

        if decision.reason_v2.type == "EMAIL":
            print("Email issues:", decision.reason_v2.email_types)
    """

    email_types: Sequence[EmailType]
    """Classifier labels applied to the email address (e.g. ``["DISPOSABLE"]``)."""

    type: Literal["EMAIL"] = "EMAIL"
    """Discriminator field. Always ``"EMAIL"``."""


@dataclass(frozen=True, slots=True)
class ErrorReason:
    """Reason returned when the Arcjet API encounters an internal error.

    Typically set when ``fail_open=True`` and a transport or API error occurs.
    Check ``decision.is_error()`` first, then inspect ``message`` for details.
    """

    message: str
    """Human-readable description of the error."""

    type: Literal["ERROR"] = "ERROR"
    """Discriminator field. Always ``"ERROR"``."""


@dataclass(frozen=True, slots=True)
class FilterReason:
    """Reason returned when a request filter rule triggers.

    Access via ``decision.reason_v2`` when ``reason_v2.type == "FILTER"``.
    """

    matched_expressions: Sequence[str]
    """Filter expressions that matched this request."""

    undetermined_expressions: Sequence[str]
    """Filter expressions that could not be definitively matched or excluded."""

    type: Literal["FILTER"] = "FILTER"
    """Discriminator field. Always ``"FILTER"``."""


@dataclass(frozen=True, slots=True)
class RateLimitReason:
    """Reason returned when a rate limiting rule triggers.

    Access via ``decision.reason_v2`` when ``reason_v2.type == "RATE_LIMIT"``.
    Use ``remaining`` to populate ``RateLimit-Remaining`` response headers, or
    ``reset_time`` / ``reset`` to tell clients when they can retry.

    Example::

        if decision.reason_v2.type == "RATE_LIMIT":
            r = decision.reason_v2  # RateLimitReason
            print(f"{r.remaining}/{r.max} requests remaining")
            print(f"Resets at: {r.reset_time}")
    """

    max: int
    """Maximum number of requests allowed in the current window."""

    remaining: int
    """Number of requests remaining in the current window."""

    reset_time: datetime | None
    """Absolute timestamp when the current rate limit window resets."""

    reset: timedelta
    """Time remaining until the current rate limit window resets."""

    window: timedelta
    """Total duration of the rate limit window."""

    type: Literal["RATE_LIMIT"] = "RATE_LIMIT"
    """Discriminator field. Always ``"RATE_LIMIT"``."""


@dataclass(frozen=True, slots=True)
class ShieldReason:
    """Reason returned when the Shield WAF rule triggers.

    Access via ``decision.reason_v2`` when ``reason_v2.type == "SHIELD"``.
    ``shield_triggered`` is ``True`` when the WAF detected a known attack
    pattern such as SQL injection or XSS in the request.
    """

    shield_triggered: bool
    """``True`` when Shield detected a known attack pattern in the request."""

    type: Literal["SHIELD"] = "SHIELD"
    """Discriminator field. Always ``"SHIELD"``."""


Reason = (
    BotReason
    | EmailReason
    | ErrorReason
    | FilterReason
    | RateLimitReason
    | ShieldReason
)
"""Decision reason returned by ``decision.reason_v2`` or ``result.reason_v2``.

Each variant has a ``type`` discriminator field you can use to narrow the type:

- ``"BOT"`` → ``BotReason`` (bot detection)
- ``"EMAIL"`` → ``EmailReason`` (email validation)
- ``"ERROR"`` → ``ErrorReason`` (API or transport error)
- ``"FILTER"`` → ``FilterReason`` (request filter)
- ``"RATE_LIMIT"`` → ``RateLimitReason`` (rate limiting)
- ``"SHIELD"`` → ``ShieldReason`` (Shield WAF)

Example::

    reason = decision.reason_v2
    if reason.type == "RATE_LIMIT":
        print(f"Rate limited. Remaining: {reason.remaining}")
    elif reason.type == "BOT":
        print(f"Bot detected. Spoofed: {reason.spoofed}")
    elif reason.type == "SHIELD":
        print(f"Attack detected: {reason.shield_triggered}")
"""


@dataclass(frozen=True, slots=True)
class IpDetails:
    """IP analysis data returned as part of a ``Decision``.

    Access via ``decision.ip_details``. All fields are ``None`` when Arcjet
    did not return that value for the request's IP address.

    For simple boolean reputation checks (VPN, hosting, Tor) prefer
    ``decision.ip`` which exposes ``is_vpn()``, ``is_hosting()``, etc.

    Example::

        ip = decision.ip_details
        if ip and ip.city and ip.country_name:
            print(f"Request from {ip.city}, {ip.country_name}")
    """

    latitude: float | None = None
    """Geographic latitude of the IP address."""

    longitude: float | None = None
    """Geographic longitude of the IP address."""

    accuracy_radius: int | None = None
    """Estimated accuracy radius in kilometres for the geolocation coordinates."""

    timezone: str | None = None
    """IANA timezone identifier for the IP's region (e.g. ``"America/New_York"``)."""

    postal_code: str | None = None
    """Postal or ZIP code associated with the IP address."""

    city: str | None = None
    """City name associated with the IP address."""

    region: str | None = None
    """Region or state name associated with the IP address."""

    country: str | None = None
    """ISO 3166-1 alpha-2 country code (e.g. ``"US"``)."""

    country_name: str | None = None
    """Full country name (e.g. ``"United States"``)."""

    continent: str | None = None
    """Two-letter continent code (e.g. ``"NA"`` for North America)."""

    continent_name: str | None = None
    """Full continent name (e.g. ``"North America"``)."""

    asn: str | None = None
    """Autonomous System Number (e.g. ``"AS15169"``)."""

    asn_name: str | None = None
    """Organization name for the ASN (e.g. ``"Google LLC"``)."""

    asn_domain: str | None = None
    """Primary domain associated with the ASN."""

    asn_type: str | None = None
    """ASN category: one of ``"isp"``, ``"hosting"``, ``"business"``, or ``"education"``."""

    asn_country: str | None = None
    """ISO 3166-1 alpha-2 country code for the ASN's registered country."""

    service: str | None = None
    """Name of the cloud or hosting service when the IP belongs to a known provider."""

    is_hosting: bool | None = None
    """``True`` if the IP belongs to a cloud or hosting provider."""

    is_vpn: bool | None = None
    """``True`` if the IP is associated with a VPN provider."""

    is_proxy: bool | None = None
    """``True`` if the IP is associated with a known proxy service."""

    is_tor: bool | None = None
    """``True`` if the IP is a Tor exit node."""

    is_relay: bool | None = None
    """``True`` if the IP is part of a privacy relay network (e.g. Apple Private Relay)."""

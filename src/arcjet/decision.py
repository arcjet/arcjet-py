"""Wrappers around Decide API protobuf messages.

This module provides small dataclasses that wrap underlying protobuf types
returned by the Arcjet Decide API.

Core types:
- `Decision`: top-level result with convenience methods (`is_allowed()`,
  `is_denied()`, etc.), JSON/`dict` conversion, and access to rule results.
- `RuleResult`: per-rule result with a `Reason` and conclusion helpers.
- `Reason`: tagged union helpers (`which()`, `is_rate_limit()`, etc.) with
  JSON/`dict` conversion.
- `IpInfo`: helper for IP analysis such as VPN, proxy, and tor flags.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from google.protobuf.json_format import MessageToDict
from typing_extensions import deprecated

import arcjet.dataclasses
from arcjet._convert import _ip_details_from_proto, _reason_from_proto
from arcjet.proto.decide.v1alpha1 import decide_pb2


@dataclass(frozen=True, slots=True)
class IpInfo:
    """High-level boolean checks for IP reputation data in a ``Decision``.

    Access this via ``decision.ip``. For typed field access (geolocation, ASN,
    etc.) use ``decision.ip_details``.

    Example::

        if decision.ip.is_hosting():
            # Likely a cloud/hosting provider — often a sign of bot traffic
            return JSONResponse({"error": "Blocked"}, status_code=403)

        if decision.ip.is_vpn() or decision.ip.is_tor():
            # Handle according to your security policy
            pass
    """

    _ip: decide_pb2.IpDetails | None

    def is_hosting(self) -> bool:
        """``True`` if the IP belongs to a known cloud or hosting provider.

        Hosting IPs are commonly used by bots and automated tools. Consider
        blocking these for user-facing endpoints, but allow them if your API
        is intended to be called programmatically by other services.

        See https://docs.arcjet.com/blueprints/vpn-proxy-detection.
        """
        return bool(self._ip and self._ip.is_hosting)

    def is_vpn(self) -> bool:
        """``True`` if the IP is associated with a VPN provider."""
        return bool(self._ip and self._ip.is_vpn)

    def is_proxy(self) -> bool:
        """``True`` if the IP is associated with a known proxy service."""
        return bool(self._ip and self._ip.is_proxy)

    def is_tor(self) -> bool:
        """``True`` if the IP is a Tor exit node."""
        return bool(self._ip and self._ip.is_tor)

    @property
    def details(self) -> arcjet.dataclasses.IpDetails | None:
        """IP analysis fields, or ``None`` when unavailable.

        Provides geolocation, ASN, and reputation data. See ``IpDetails``
        for the full list of available fields.
        """
        return _ip_details_from_proto(self._ip)


@dataclass(frozen=True, slots=True)
@deprecated("Use `arcjet.dataclasses.Reason` instead.")
class Reason:
    """Tagged reason for a rule conclusion or overall decision.

    Provides an ergonomic way to inspect which reason variant was set without
    dealing with protobuf oneof internals.
    """

    _reason: decide_pb2.Reason | None

    def which(self) -> str | None:
        """Return the active `oneof` field name (e.g., "rate_limit")."""
        return self._reason.WhichOneof("reason") if self._reason else None

    def is_rate_limit(self) -> bool:
        return self.which() == "rate_limit"

    def is_bot(self) -> bool:
        return self.which() in ("bot", "bot_v2")

    def is_shield(self) -> bool:
        return self.which() == "shield"

    def is_email(self) -> bool:
        return self.which() == "email"

    def is_sensitive_info(self) -> bool:
        return self.which() == "sensitive_info"

    def is_filter(self) -> bool:
        return self.which() == "filter"

    def is_error(self) -> bool:
        return self.which() == "error"

    @property
    def raw(self) -> decide_pb2.Reason | None:
        """Access the underlying protobuf message (may be None)."""
        return self._reason

    def to_dict(self) -> dict | None:
        """Serialize the reason to a Python dict (or None)."""
        if not self._reason:
            return None
        return MessageToDict(
            self._reason,
            preserving_proto_field_name=True,
        )

    def to_json(self) -> str:
        """Return a JSON string for the reason, or "null" when absent."""
        d = self.to_dict()
        return json.dumps(d) if d is not None else "null"


@dataclass(frozen=True, slots=True)
class RuleResult:
    """Result of evaluating a single configured rule.

    Iterate over ``decision.results`` to inspect each rule individually. The
    order matches the order rules were passed to ``arcjet()`` / ``arcjet_sync()``.

    Example::

        for result in decision.results:
            if result.is_denied():
                print(f"Rule {result.rule_id} denied the request")
                print(f"Reason: {result.reason_v2}")
    """

    _rr: decide_pb2.RuleResult

    @property
    def rule_id(self) -> str:
        """Opaque identifier for this rule, assigned by the Arcjet API."""
        return self._rr.rule_id

    @property
    def state(self) -> int:
        """Raw integer rule state from the Arcjet API.

        Prefer ``is_allowed()`` and ``is_denied()`` for common checks.
        """
        return self._rr.state

    @property
    def conclusion(self) -> int:
        """Raw integer conclusion code for this rule.

        Prefer ``is_allowed()`` and ``is_denied()`` for common checks.
        """
        return self._rr.conclusion

    @property
    # TODO: Replace with reason_v2 behavior and deprecate reason_v2 in future.
    @deprecated("Use `reason_v2` property instead.")
    def reason(self) -> Reason:  # type: ignore -- intentionally deprecated
        """Reason for the decision.

        Deprecated. Use `reason_v2` instead.
        """
        return Reason(self._rr.reason if self._rr.HasField("reason") else None)  # type: ignore -- intentionally deprecated

    @property
    def reason_v2(self) -> arcjet.dataclasses.Reason:
        """Typed reason for this rule's conclusion.

        Inspect ``reason_v2.type`` to determine which kind of reason was
        returned (``"BOT"``, ``"RATE_LIMIT"``, ``"SHIELD"``, ``"EMAIL"``,
        ``"ERROR"``, or ``"FILTER"``), then access type-specific fields.

        Example::

            if result.reason_v2.type == "BOT":
                print("Spoofed:", result.reason_v2.spoofed)
            elif result.reason_v2.type == "RATE_LIMIT":
                print("Remaining:", result.reason_v2.remaining)
        """
        return _reason_from_proto(self._rr.reason)

    @property
    def fingerprint(self) -> str | None:
        """Client fingerprint string used to track this client for the rule, or ``None``."""
        return self._rr.fingerprint or None

    def is_denied(self) -> bool:
        """True when the rule's conclusion is DENY."""
        return self._rr.conclusion == decide_pb2.CONCLUSION_DENY

    def is_allowed(self) -> bool:
        """True when the rule's conclusion is ALLOW."""
        return self._rr.conclusion == decide_pb2.CONCLUSION_ALLOW

    @property
    def raw(self) -> decide_pb2.RuleResult:
        """Access the underlying protobuf message."""
        return self._rr


@dataclass(frozen=True, slots=True)
class Decision:
    """Top-level result returned by ``aj.protect()``.

    Wraps the Arcjet decision and provides convenience methods for
    the most common patterns: checking whether a request should be allowed or
    denied, inspecting the rule that triggered the decision, and accessing IP
    metadata.

    Example::

        decision = await aj.protect(request, requested=1)

        # Simple allow / deny check
        if decision.is_denied():
            status = 429 if decision.reason_v2.type == "RATE_LIMIT" else 403
            return JSONResponse({"error": "Forbidden"}, status_code=status)

        # Inspect per-rule results
        for result in decision.results:
            if result.is_denied():
                print("Denied by rule:", result.rule_id)

        # Access IP reputation helpers
        if decision.ip.is_vpn():
            pass  # handle VPN traffic

        # Access IP details (geolocation, ASN, etc.)
        ip = decision.ip_details
        if ip and ip.city:
            print(f"Request from {ip.city}, {ip.country_name}")
    """

    _d: decide_pb2.Decision

    @property
    def id(self) -> str:
        """Unique identifier for this decision, assigned by Arcjet.

        Use this to correlate decisions with Arcjet dashboard events or logs.
        """
        return self._d.id

    @property
    def conclusion(self) -> int:
        """Raw integer conclusion code from Arcjet.

        Prefer the helper methods ``is_allowed()``, ``is_denied()``,
        ``is_challenged()``, and ``is_error()`` over comparing this value
        directly.
        """
        return self._d.conclusion

    @property
    def ttl(self) -> int:
        """How many seconds this decision can be cached client-side.

        When greater than zero, the SDK caches the decision and reports
        subsequent matching requests without making a new Arcjet API call.
        """
        return self._d.ttl

    @property
    # TODO: Replace with reason_v2 behavior and deprecate reason_v2 in future.
    @deprecated("Use `reason_v2` property instead.")
    def reason(self) -> Reason:  # type: ignore -- intentionally deprecated
        """Reason for the decision.

        Deprecated. Use `reason_v2` instead.
        """
        return Reason(self._d.reason if self._d.HasField("reason") else None)  # type: ignore -- intentionally deprecated

    @property
    def reason_v2(self) -> arcjet.dataclasses.Reason:
        """Reason for the overall decision.

        A typed union of ``BotReason``, ``RateLimitReason``, ``ShieldReason``,
        ``EmailReason``, ``ErrorReason``, or ``FilterReason``. Check the
        ``type`` field to discriminate:

        Example::

            if decision.reason_v2.type == "RATE_LIMIT":
                remaining = decision.reason_v2.remaining
            elif decision.reason_v2.type == "BOT":
                denied_bots = decision.reason_v2.denied
            elif decision.reason_v2.type == "SHIELD":
                triggered = decision.reason_v2.shield_triggered
        """
        return _reason_from_proto(self._d.reason)

    @property
    def ip(self) -> IpInfo:
        """High-level IP analysis helpers for this request.

        Provides boolean checks for common analysis signals. For geolocation
        and ASN fields use ``ip_details`` instead.

        Example::

            if decision.ip.is_hosting():
                return JSONResponse({"error": "Blocked"}, status_code=403)
        """
        return IpInfo(self._d.ip_details if self._d.HasField("ip_details") else None)

    @property
    def ip_details(self) -> arcjet.dataclasses.IpDetails | None:
        """IP analysis details when available.

        - Geolocation: `latitude`, `longitude`, `accuracy_radius`, `timezone`,
          `postal_code`, `city`, `region`, `country`, `country_name`,
          `continent`, `continent_name`
        - ASN / network: `asn`, `asn_name`, `asn_domain`, `asn_type` (isp,
          hosting, business, education), `asn_country`
        - Service: service name (when present) and boolean
          indicators for `is_vpn`, `is_proxy`, `is_tor`, `is_hosting`,
          `is_relay`
        """
        return self.ip.details

    @property
    def results(self) -> tuple[RuleResult, ...]:
        """Per-rule results that contributed to this decision.

        Iterate over this to inspect each rule's individual conclusion and
        reason. The overall ``Decision`` conclusion is the most restrictive
        outcome across all rules.

        In ``DRY_RUN`` mode, the individual rules will show their actual
        conclusions (``ALLOW`` or ``DENY``) but the overall ``Decision`` will
        always show ``ALLOW``. In other modes, the rule conclusions will match the
        overall decision or be less restrictive (e.g. a rule may ``ALLOW`` while
        the overall decision is ``DENY`` if another rule triggered a ``DENY``).
        """
        return tuple(RuleResult(rr) for rr in self._d.rule_results)

    def is_denied(self) -> bool:
        """True when the overall conclusion is DENY."""
        return self._d.conclusion == decide_pb2.CONCLUSION_DENY

    def is_allowed(self) -> bool:
        """True when the overall conclusion is ALLOW."""
        return self._d.conclusion == decide_pb2.CONCLUSION_ALLOW

    def is_challenged(self) -> bool:
        """True when the overall conclusion is CHALLENGE."""
        return self._d.conclusion == decide_pb2.CONCLUSION_CHALLENGE

    def is_error(self) -> bool:
        """True when the overall conclusion indicates an error."""
        return self._d.conclusion == decide_pb2.CONCLUSION_ERROR

    def to_proto(self) -> decide_pb2.Decision:
        """Access the underlying protobuf message."""
        return self._d

    def __repr__(self) -> str:
        return f"Decision(conclusion={decide_pb2.Conclusion.Name(self._d.conclusion)}, reason={self.reason.which()})"

    def to_dict(self) -> dict:
        """Serialize the decision to a Python dict suitable for logging."""
        return MessageToDict(
            self._d,
            preserving_proto_field_name=True,
        )

    def to_json(self) -> str:
        """Return a JSON string representation of the decision."""
        return json.dumps(self.to_dict())


def is_spoofed_bot(result: RuleResult) -> bool:
    """Return ``True`` if a bot detection rule found a spoofed user agent.

    A spoofed bot claims to be a well-known crawler (e.g. Googlebot) but
    originates from an IP address that does not match the verified ranges for
    that crawler.

    Args:
        result: A single ``RuleResult`` from ``decision.results``.

    Returns:
        ``True`` when the bot rule detected a spoofed user agent.

    Example::

        from arcjet import is_spoofed_bot

        if any(is_spoofed_bot(r) for r in decision.results):
            return jsonify(error="Spoofed bot detected"), 403
    """
    r = result.raw.reason
    if not r:
        return False
    if r.WhichOneof("reason") == "bot_v2":
        return bool(r.bot_v2.spoofed)
    return False

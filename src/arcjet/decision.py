"""Wrappers around Decide API protobuf messages.

This module provides small dataclasses that wrap underlying protobuf types
returned by the Arcjet Decide API.

Core types:
- `Decision`: top-level result with convenience methods (`is_allowed()`,
  `is_denied()`, etc.), JSON/`dict` conversion, and access to rule results.
- `RuleResult`: per-rule result with a `Reason` and conclusion helpers.
- `Reason`: tagged union helpers (`which()`, `is_rate_limit()`, etc.) with
  JSON/`dict` conversion.
- `IpInfo`: helper for IP enrichments such as VPN, proxy, and tor flags.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from proto.decide.v1alpha1 import decide_pb2
from google.protobuf.json_format import MessageToDict


@dataclass(frozen=True, slots=True)
class IpInfo:
    """Convenience accessors for IP-related enrichments.

    Wraps `decide_pb2.IpDetails` to provide simple boolean checks.
    """

    _ip: decide_pb2.IpDetails | None

    def is_hosting(self) -> bool:
        """True if the IP belongs to known hosting/cloud ranges."""
        return bool(self._ip and self._ip.is_hosting)

    def is_vpn(self) -> bool:
        """True if the IP appears to be from a VPN provider."""
        return bool(self._ip and self._ip.is_vpn)

    def is_proxy(self) -> bool:
        """True if the IP is behind a known proxy."""
        return bool(self._ip and self._ip.is_proxy)

    def is_tor(self) -> bool:
        """True if the IP is a Tor exit node."""
        return bool(self._ip and self._ip.is_tor)


@dataclass(frozen=True, slots=True)
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
    """Result of evaluating a single rule.

    Exposes identifiers, conclusion/state integers (see `decide_pb2` enums),
    and the computed `Reason`. Convenience boolean checks are included.
    """

    _rr: decide_pb2.RuleResult

    @property
    def rule_id(self) -> str:
        return self._rr.rule_id

    @property
    def state(self) -> int:
        return self._rr.state

    @property
    def conclusion(self) -> int:
        return self._rr.conclusion

    @property
    def reason(self) -> Reason:
        return Reason(self._rr.reason if self._rr.HasField("reason") else None)

    @property
    def fingerprint(self) -> str | None:
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
    """Top-level decision returned by the Decide API.

    Provides convenience properties and predicates for common flows, plus
    `to_dict()`/`to_json()` for logging and debugging.
    """

    _d: decide_pb2.Decision

    @property
    def id(self) -> str:
        return self._d.id

    @property
    def conclusion(self) -> int:
        return self._d.conclusion

    @property
    def ttl(self) -> int:
        return self._d.ttl

    @property
    def reason(self) -> Reason:
        return Reason(self._d.reason if self._d.HasField("reason") else None)

    @property
    def ip(self) -> IpInfo:
        return IpInfo(self._d.ip_details if self._d.HasField("ip_details") else None)

    @property
    def results(self) -> tuple[RuleResult, ...]:
        """All per-rule results in evaluation order."""
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
    """Return True when the bot rule detected a spoofed user agent.

    This checks the `bot_v2` reason variant for the `spoofed` flag.
    """
    r = result.raw.reason
    if not r:
        return False
    if r.WhichOneof("reason") == "bot_v2":
        return bool(r.bot_v2.spoofed)
    return False

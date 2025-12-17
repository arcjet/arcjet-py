"""In-memory TTL cache for Arcjet decisions.

This module provides a simple, thread-safe cache keyed by a derived
request identity. Entries expire after the decision's TTL.

The cache stores the `Decision` wrapper directly and tracks expiry using
`time.monotonic()`.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
import hashlib
from typing import Mapping, Sequence

from .context import RequestContext
from .decision import Decision
from .rules import RuleSpec


@dataclass(frozen=True)
class _CacheEntry:
    decision: Decision
    expires_at: float


class DecisionCache:
    """Thread-safe TTL cache for `Decision` objects."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._store: dict[str, _CacheEntry] = {}

    def get(self, key: str) -> Decision | None:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            if entry.expires_at <= now:
                # Expired; remove and miss.
                try:
                    del self._store[key]
                except Exception:
                    pass
                return None
            return entry.decision

    def set(self, key: str, decision: Decision, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        expires_at = time.monotonic() + float(ttl_seconds)
        with self._lock:
            self._store[key] = _CacheEntry(decision=decision, expires_at=expires_at)


def make_cache_key(ctx: RequestContext, rules: Sequence[RuleSpec]) -> str | None:
    """Derive cache key from rule characteristics only, with IP fallback.

    - For each rule: use its `characteristics` exactly as provided.
      Values are read from `ctx.extra` using the same keys.
    - If a rule has no characteristics, use `ctx.ip` as that rule's identity.
    - If none of the rules yield any identity (e.g., no characteristics and no IP),
      return None to signal "do not cache".
    """
    h = hashlib.sha256()

    any_identity = False

    def _value_for_char(key: str) -> str:
        if not key:
            return ""
        if isinstance(ctx.extra, Mapping):
            v = ctx.extra.get(key)
            return "" if v is None else str(v)
        return ""

    for r in rules:
        which = type(r).__name__
        h.update(b"rule:")
        h.update(which.encode("utf-8"))
        h.update(b"|")

        chars: Sequence[str] = r.get_characteristics()
        identity_parts: list[str] = []
        if chars:
            for c in chars:
                identity_parts.append(f"{c}:{_value_for_char(c)}")
        else:
            # Fallback to IP when no characteristics configured
            ip = str(ctx.ip or "")
            if not ip:
                # No identity for this rule; skip including it
                continue
            identity_parts.append(f"ip:{ip}")

        identity = "|".join(identity_parts)
        h.update(identity.encode("utf-8"))
        h.update(b"\x00")
        any_identity = True

    if not any_identity:
        return None
    return h.hexdigest()

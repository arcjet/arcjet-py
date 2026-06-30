"""Shared helpers used by all rule modules."""

from __future__ import annotations

import hashlib
from typing import Mapping, Optional

from .._types import Decision, InternalResult, RuleResultError


def _get_internal_results(decision: Decision) -> tuple[InternalResult, ...]:
    """Extract internal results from a decision (empty tuple if absent)."""
    return decision._internal_results


def _error_result_for_input(
    decision: Decision, config_id: str, input_id: str
) -> RuleResultError | None:
    """Get the errored result for one specific rule invocation, or ``None``.

    Matched by both ``config_id`` and ``input_id`` so two invocations of the
    same rule resolve to distinct errors. Returns only :class:`RuleResultError`
    — the non-error accessors (``result``/``results``/``denied_result``)
    exclude it.
    """
    for ir in _get_internal_results(decision):
        if (
            ir.config_id == config_id
            and ir.input_id == input_id
            and isinstance(ir.result, RuleResultError)
        ):
            return ir.result
    return None


def _error_result_for_config(
    decision: Decision, config_id: str
) -> RuleResultError | None:
    """Get the first errored result for a configured rule, or ``None``.

    Matched by ``config_id`` only. If multiple invocations of the same rule
    errored, returns one arbitrarily — mirroring ``denied_result``. There is
    deliberately no plural ``error_results``: retrieve per-invocation via the
    bound input's ``error_result`` instead.
    """
    for ir in _get_internal_results(decision):
        if ir.config_id == config_id and isinstance(ir.result, RuleResultError):
            return ir.result
    return None


def _hash_key(key: str) -> str:
    """SHA-256 hash of a rate-limit key.

    The raw key never leaves the SDK — only the hash is sent to the server.
    This ensures IPv6 addresses and other formats work without users needing
    to know the character constraints.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _merge_metadata(
    config_metadata: Optional[Mapping[str, str]],
    input_metadata: Optional[Mapping[str, str]],
) -> Optional[Mapping[str, str]]:
    """Merge config-level and input-level metadata.

    Config metadata is added first; input metadata is merged on top.
    Duplicate keys are replaced by input values.  Returns ``None`` if
    both are empty.
    """
    if not config_metadata and not input_metadata:
        return None
    merged: dict[str, str] = {}
    if config_metadata:
        merged.update(config_metadata)
    if input_metadata:
        merged.update(input_metadata)
    return merged

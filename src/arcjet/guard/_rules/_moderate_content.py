"""Content moderation rule (experimental).

Mirrors :mod:`._prompt_injection`.  Publicly exported from ``arcjet.guard``
as ``experimental_ModerateContent`` to signal that the rule and its result
shape may change.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Mapping, Optional

from .._types import Decision, Mode, RuleResultError, RuleResultModerateContent
from ._base import (
    _error_result_for_config,
    _error_result_for_input,
    _get_internal_results,
    _merge_metadata,
)


@dataclass(frozen=True, slots=True)
class ModerateContentWithInput:
    """A content moderation rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    text: str
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def results(self, decision: Decision) -> list[RuleResultModerateContent]:
        """Get this input's results as a list (empty or single-element)."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and ir.input_id == self._input_id
            and isinstance(ir.result, RuleResultModerateContent)
        ]

    def result(self, decision: Decision) -> RuleResultModerateContent | None:
        """Get this input's result from a decision."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> RuleResultModerateContent | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None

    def error_result(self, decision: Decision) -> RuleResultError | None:
        """Get this invocation's errored result, or ``None`` if it didn't error.

        Returns the :class:`RuleResultError` only — never the non-error
        result. The non-error accessors (``result``/``results``/
        ``denied_result``) exclude it.
        """
        return _error_result_for_input(decision, self._config_id, self._input_id)


class ModerateContent:
    """Content moderation rule (experimental).

    Exported publicly as ``experimental_ModerateContent``.  Instantiate
    (optionally with ``mode``/``label``/``metadata``), then call with
    ``text`` to produce a :class:`ModerateContentWithInput` for ``.guard()``.

    .. warning::

        Experimental — the rule name and its result shape may change.
        This functionality may not be available yet, so while this rule is
        experimental a call may simply return an error result.
        Errors are fail-open: the decision reports an error while the
        conclusion stays ``"ALLOW"``.  Check the latest version of this SDK
        to see whether the rule is now stable.

    Args:
        mode: ``"LIVE"`` or ``"DRY_RUN"``.
        label: Optional observability label.
        metadata: Config-level key-value metadata.  Merged with
            per-input metadata on each call — input keys replace
            config keys on conflict.

    Example::

        from arcjet.guard import experimental_ModerateContent

        moderate = experimental_ModerateContent()
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[moderate(user_message)],
        )
    """

    def __init__(
        self,
        *,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def __call__(
        self,
        text: str,
        *,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> ModerateContentWithInput:
        return ModerateContentWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            text=text,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
        )

    def results(self, decision: Decision) -> list[RuleResultModerateContent]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultModerateContent)
        ]

    def result(self, decision: Decision) -> RuleResultModerateContent | None:
        """Get the first result for this rule, or ``None``."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> RuleResultModerateContent | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None

    def error_result(self, decision: Decision) -> RuleResultError | None:
        """Get the first errored result for this rule, or ``None``."""
        return _error_result_for_config(decision, self._config_id)

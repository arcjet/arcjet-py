"""Prompt injection detection rule."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Mapping, Optional

from .._types import Decision, Mode, RuleResultError, RuleResultPromptInjection
from ._base import (
    _error_result_for_config,
    _error_result_for_input,
    _get_internal_results,
    _merge_metadata,
)


@dataclass(frozen=True, slots=True)
class PromptInjectionWithInput:
    """A prompt injection detection rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    text: str
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def results(self, decision: Decision) -> list[RuleResultPromptInjection]:
        """Get this input's results as a list (empty or single-element)."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and ir.input_id == self._input_id
            and isinstance(ir.result, RuleResultPromptInjection)
        ]

    def result(self, decision: Decision) -> RuleResultPromptInjection | None:
        """Get this input's result from a decision."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> RuleResultPromptInjection | None:
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


class DetectPromptInjection:
    """Prompt injection detection rule.

    Instantiate (optionally with ``mode``/``label``/``metadata``),
    then call with ``text`` to produce a :class:`PromptInjectionWithInput`
    for ``.guard()``.

    Args:
        mode: ``"LIVE"`` or ``"DRY_RUN"``.
        label: Optional observability label. Validated server-side as a
            slug: lowercase letters, digits, dash (``-``), and dot (``.``)
            only; must start and end with a lowercase letter or digit;
            max 256 bytes.
        metadata: Config-level key-value metadata.  Merged with
            per-input metadata on each call — input keys replace
            config keys on conflict.

    Example::

        prompt_scan = DetectPromptInjection()
        decision = await arcjet.guard(
            label="tools.weather",
            rules=[prompt_scan(user_message)],
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
    ) -> PromptInjectionWithInput:
        return PromptInjectionWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            text=text,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
        )

    def results(self, decision: Decision) -> list[RuleResultPromptInjection]:
        """Get all results for this configured rule from a decision."""
        return [
            ir.result
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultPromptInjection)
        ]

    def result(self, decision: Decision) -> RuleResultPromptInjection | None:
        """Get the first result for this rule, or ``None``."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> RuleResultPromptInjection | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None

    def error_result(self, decision: Decision) -> RuleResultError | None:
        """Get the first errored result for this rule, or ``None``."""
        return _error_result_for_config(decision, self._config_id)

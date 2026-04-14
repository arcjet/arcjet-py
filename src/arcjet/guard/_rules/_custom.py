"""Custom local rule — user-defined evaluate logic.

The ``CustomRule`` base class lets users define typed custom rules that
run locally.  Subclass it, override ``evaluate`` (and optionally
``evaluate_async``), and the result is sent to the server alongside
the config/input data.  The raw data stays as ``dict[str, str]`` on
the wire but type parameters give full IDE/type-checker support.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Generic, Literal, Mapping, Optional, TypeVar, cast

from arcjet._logging import logger

from .._types import CustomEvaluateResult, Decision, Mode, RuleResultCustom
from ._base import _get_internal_results, _merge_metadata

TConfig = TypeVar("TConfig")
TInput = TypeVar("TInput")
TData = TypeVar("TData")


def _to_str_dict(obj: Any) -> dict[str, str]:
    """Convert a TypedDict / Mapping to ``dict[str, str]`` for the wire.

    Non-string keys are dropped with a warning.  Non-string values are
    replaced with a descriptive placeholder.
    """
    result: dict[str, str] = {}
    for k, v in obj.items():
        if not isinstance(k, str):
            logger.warning("guard: dropping non-string key %r from custom rule data", k)
            continue
        if not isinstance(v, str):
            logger.warning("guard: non-string value for key %r in custom rule data", k)
            result[k] = f"[non-string: {type(v).__name__}]"
        else:
            result[k] = v
    return result


class TypedCustomResult(Generic[TData]):
    """A typed view over :class:`RuleResultCustom`.

    Wraps the non-generic ``RuleResultCustom`` so that ``.data`` is
    typed as ``TData`` on the accessors returned by
    ``CustomWithInput[TData].result()`` and ``CustomRule.results()``.

    The underlying ``RuleResultCustom`` is accessible via ``._inner``
    if needed.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner: RuleResultCustom) -> None:
        self._inner = inner

    @property
    def conclusion(self) -> Literal["ALLOW", "DENY"]:
        """Whether the request was allowed or denied."""
        return self._inner.conclusion

    @property
    def reason(self) -> Literal["CUSTOM"]:
        """Always ``"CUSTOM"``."""
        return self._inner.reason

    @property
    def type(self) -> Literal["CUSTOM"]:
        """Discriminant — always ``"CUSTOM"``."""
        return self._inner.type

    @property
    def data(self) -> TData:
        """Typed result data from the custom rule's evaluate function."""
        return cast(TData, self._inner.data)

    def __repr__(self) -> str:
        return f"TypedCustomResult({self._inner!r})"


@dataclass(frozen=True, slots=True)
class LocalCustomWithInput(Generic[TData]):
    """A custom rule with bound input, ready for ``.guard()``."""

    _input_id: str
    _config_id: str
    config_data: Mapping[str, str]
    input_data: Mapping[str, str]
    evaluate_result: CustomEvaluateResult | None
    evaluate_error: str | None
    evaluate_duration_ms: int
    mode: Mode = "LIVE"
    label: Optional[str] = None
    metadata: Optional[Mapping[str, str]] = None

    def results(self, decision: Decision) -> list[TypedCustomResult[TData]]:
        """Get this input's results as a list (empty or single-element)."""
        return [
            TypedCustomResult(ir.result)
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and ir.input_id == self._input_id
            and isinstance(ir.result, RuleResultCustom)
        ]

    def result(self, decision: Decision) -> TypedCustomResult[TData] | None:
        """Get this input's result from a decision."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> TypedCustomResult[TData] | None:
        """Get this input's result only if it was DENY."""
        r = self.result(decision)
        if r is not None and r.conclusion == "DENY":
            return r
        return None


class LocalCustomRule(Generic[TConfig, TInput, TData]):
    """Base class for user-defined custom rules (local evaluation).

    Subclass and override :meth:`evaluate` (sync) and/or
    :meth:`evaluate_async` (async) to implement local evaluation logic.
    The result is serialized as string maps on the wire and sent to the
    server for logging/analytics.

    Type parameters:

    - ``TConfig`` — shape of config data (must be ``Mapping[str, str]``).
    - ``TInput`` — shape of per-request input data.
    - ``TData`` — shape of the result data returned by ``evaluate``.

    Args:
        config: Config data passed to ``evaluate`` on each call.
        mode: ``"LIVE"`` or ``"DRY_RUN"``.
        label: Optional observability label.
        metadata: Config-level key-value metadata.

    Example::

        from typing import TypedDict

        class TopicConfig(TypedDict):
            blocked_topic: str

        class TopicInput(TypedDict):
            topic: str

        class TopicData(TypedDict):
            matched: str

        class TopicBlockRule(LocalCustomRule[TopicConfig, TopicInput, TopicData]):
            def evaluate(
                self,
                config: TopicConfig,
                input: TopicInput,
            ) -> CustomEvaluateResult:
                if input["topic"] == config["blocked_topic"]:
                    return CustomEvaluateResult(
                        conclusion="DENY",
                        data={"matched": input["topic"]},
                    )
                return CustomEvaluateResult(conclusion="ALLOW")

        rule = TopicBlockRule(config={"blocked_topic": "weapons"})
        inp = rule(data={"topic": "weapons"})
        decision = await arcjet.guard(rules=[inp], label="content")
        r = inp.result(decision)
    """

    def __init__(
        self,
        *,
        config: TConfig,
        mode: Mode = "LIVE",
        label: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._config_id = str(uuid.uuid4())
        self._config: TConfig = config
        self._mode: Mode = mode
        self._label = label
        self._metadata = metadata

    @property
    def config_id(self) -> str:
        """Stable config identifier shared by all invocations."""
        return self._config_id

    def evaluate(
        self,
        config: TConfig,
        input: TInput,
    ) -> CustomEvaluateResult:
        """Synchronous local evaluation — override in subclasses.

        Called by :meth:`__call__` to evaluate the rule locally.
        The default implementation returns ``ALLOW`` with no data.
        """
        return CustomEvaluateResult(conclusion="ALLOW")

    async def evaluate_async(
        self,
        config: TConfig,
        input: TInput,
    ) -> CustomEvaluateResult:
        """Async local evaluation — override in subclasses.

        Called by :meth:`call_async` for async clients.  The default
        falls back to the synchronous :meth:`evaluate`.
        """
        return self.evaluate(config, input)

    def __call__(
        self,
        *,
        data: TInput,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> LocalCustomWithInput[TData]:
        """Run sync evaluation and produce a ``LocalCustomWithInput``.

        The ``evaluate`` method is called immediately.  Its result (or
        error) is captured and attached so ``convert.py`` can serialize
        it into the proto without re-running the callback.
        """
        evaluate_result: CustomEvaluateResult | None = None
        evaluate_error: str | None = None
        elapsed_ms = 0

        start = time.monotonic()
        try:
            evaluate_result = self.evaluate(self._config, data)
        except Exception as exc:
            logger.debug("guard: custom rule evaluate error: %s", exc)
            evaluate_error = str(exc)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return LocalCustomWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config_data=_to_str_dict(self._config),
            input_data=_to_str_dict(data),
            evaluate_result=evaluate_result,
            evaluate_error=evaluate_error,
            evaluate_duration_ms=elapsed_ms,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
        )

    async def call_async(
        self,
        *,
        data: TInput,
        metadata: Optional[Mapping[str, str]] = None,
    ) -> LocalCustomWithInput[TData]:
        """Run async evaluation and produce a ``LocalCustomWithInput``.

        Like :meth:`__call__` but awaits :meth:`evaluate_async`.
        """
        evaluate_result: CustomEvaluateResult | None = None
        evaluate_error: str | None = None
        elapsed_ms = 0

        start = time.monotonic()
        try:
            evaluate_result = await self.evaluate_async(self._config, data)
        except Exception as exc:
            logger.debug("guard: custom rule evaluate_async error: %s", exc)
            evaluate_error = str(exc)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return LocalCustomWithInput(
            _input_id=str(uuid.uuid4()),
            _config_id=self._config_id,
            config_data=_to_str_dict(self._config),
            input_data=_to_str_dict(data),
            evaluate_result=evaluate_result,
            evaluate_error=evaluate_error,
            evaluate_duration_ms=elapsed_ms,
            mode=self._mode,
            label=self._label,
            metadata=_merge_metadata(self._metadata, metadata),
        )

    def results(self, decision: Decision) -> list[TypedCustomResult[TData]]:
        """Get all results for this configured rule from a decision."""
        return [
            TypedCustomResult(ir.result)
            for ir in _get_internal_results(decision)
            if ir.config_id == self._config_id
            and isinstance(ir.result, RuleResultCustom)
        ]

    def result(self, decision: Decision) -> TypedCustomResult[TData] | None:
        """Get the first result for this rule, or ``None``."""
        r = self.results(decision)
        return r[0] if r else None

    def denied_result(self, decision: Decision) -> TypedCustomResult[TData] | None:
        """Get the first denied result for this rule, or ``None``."""
        for r in self.results(decision):
            if r.conclusion == "DENY":
                return r
        return None

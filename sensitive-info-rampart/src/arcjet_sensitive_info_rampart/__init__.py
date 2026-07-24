"""On-device Rampart NER backend for Arcjet sensitive info detection.

Provides :func:`rampart`, a pluggable ``SensitiveInfoBackend`` powered by the
bundled on-device `Rampart <https://huggingface.co/nationaldesignstudio/rampart>`_
named-entity-recognition model. Pass the returned backend to the
``detect_sensitive_info`` rule (or ``arcjet.guard.LocalDetectSensitiveInfo``):

    from arcjet import arcjet, detect_sensitive_info, Mode
    from arcjet_sensitive_info_rampart import rampart

    aj = arcjet(
        key=...,
        rules=[
            detect_sensitive_info(
                mode=Mode.LIVE,
                deny=["EMAIL", "GIVEN_NAME", "SURNAME"],
                backend=rampart(),
            ),
        ],
    )

It runs entirely locally using the model weights bundled with this package, so
no data leaves your environment. The model is loaded once on first use and
reused for every subsequent request.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Optional, Sequence

from arcjet._analyze import (
    DetectedSensitiveInfoEntity,
    SensitiveInfoEntities,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoResult,
)
from arcjet._sensitive_info_backend import (
    SensitiveInfoBackend,
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
)

from ._entities import (
    from_analyze_entity,
    normalize_label,
    rampart_entities,
    to_analyze_entity,
)
from ._model import (
    ModelOptions,
    ModelRunner,
    RawToken,
    aggregate_tokens,
    create_model_runner,
)
from ._recognizers import DetectedSpan, Recognizer, default_recognizers, run_recognizers

__all__ = [
    "rampart",
    "RampartOptions",
    "DEFAULT_MAX_INPUT_CHARS",
    "rampart_entities",
    "default_recognizers",
    "run_recognizers",
    "DetectedSpan",
    "Recognizer",
    "ModelOptions",
    "ModelRunner",
    "RawToken",
    "aggregate_tokens",
    "normalize_label",
]


# Default ceiling on the number of characters scanned per request. Model
# inference is synchronous and its cost grows with the input length (each
# overlapping window is a full inference pass), so unbounded input is a
# denial-of-service vector; input beyond this is truncated before detection.
# Generous enough for typical request fields while bounding worst-case CPU.
DEFAULT_MAX_INPUT_CHARS = 100_000


@dataclass(frozen=True, slots=True)
class RampartOptions:
    """Options for the :func:`rampart` backend."""

    model_path: Optional[str] = None
    """Directory containing the bundled model files (default: the ``models``
    directory shipped with this package)."""

    threshold: float = 0.5
    """Minimum confidence score for a model token to count (default: ``0.5``)."""

    max_input_chars: Optional[int] = None
    """Maximum number of characters scanned per request (default:
    :data:`DEFAULT_MAX_INPUT_CHARS`). Model inference runs synchronously on the
    request path, so an unbounded input would be a denial-of-service vector.
    Longer input is truncated to this many characters before detection and a
    warning is logged; raise it if you need to scan larger payloads and can
    afford the latency, or lower it to tighten the request-cost bound."""

    providers: Optional[tuple[str, ...]] = None
    """ONNX Runtime execution providers (default: ``("CPUExecutionProvider",)``)."""

    recognizers: Optional[Sequence[Recognizer]] = None
    """Deterministic recognizers to run alongside the model (default:
    :data:`~arcjet_sensitive_info_rampart._recognizers.default_recognizers`).
    These handle structured, validatable types and are the supported extension
    point for custom detection. Pass ``()`` to rely on the model alone."""

    run_model: Optional[ModelRunner] = None
    """Override the model runner. Intended for testing — supply a function that
    returns spans without loading the ONNX model."""


def _overlaps(a: DetectedSpan, b: DetectedSpan) -> bool:
    return a.start < b.end and b.start < a.end


def merge_spans(groups: Sequence[Sequence[DetectedSpan]]) -> list[DetectedSpan]:
    """Merge spans from several sources, resolving overlaps.

    A higher-precedence group wins over any lower-precedence group it overlaps,
    regardless of length: the deterministic, validated recognizers are
    authoritative over the model on overlapping text (as the caller relies on —
    see :meth:`_RampartBackend.detect`). Without this, a longer model span could
    swallow a recognizer span and relabel it, so an allow-listed type detected by
    a recognizer could be mis-bucketed as denied. Within a single group the
    longer span wins (so a short match cannot delete a longer, distinct entity it
    overlaps), and remaining ties break by earliest start.

    Args:
        groups: Span groups in precedence order (highest first).

    Returns:
        Non-overlapping spans, ordered by start offset.
    """
    ranked: list[tuple[DetectedSpan, int]] = []
    for priority, group in enumerate(groups):
        for span in group:
            ranked.append((span, priority))

    # Higher-precedence group first, then longest, then earliest start.
    ranked.sort(
        key=lambda item: (item[1], -(item[0].end - item[0].start), item[0].start)
    )

    # Accept spans in rank order, skipping any that overlaps one already kept.
    # The accepted spans are held sorted by start and are pairwise disjoint, so a
    # candidate can only overlap its immediate neighbours — a binary search finds
    # them without scanning the whole set (the earlier ``any(_overlaps ...)`` scan
    # was O(n^2), a CPU spike on input with many detected spans).
    accepted: list[DetectedSpan] = []
    starts: list[int] = []
    for span, _priority in ranked:
        i = bisect.bisect_right(starts, span.start)
        left_overlaps = i > 0 and accepted[i - 1].end > span.start
        right_overlaps = i < len(accepted) and accepted[i].start < span.end
        if left_overlaps or right_overlaps:
            continue
        accepted.insert(i, span)
        starts.insert(i, span.start)

    return accepted


class _RampartBackend:
    """A :class:`SensitiveInfoBackend` backed by the Rampart model + recognizers."""

    def __init__(
        self,
        run_model: ModelRunner,
        recognizers: Sequence[Recognizer],
        max_input_chars: int,
    ) -> None:
        self._run_model = run_model
        self._recognizers = recognizers
        self._max_input_chars = max_input_chars

    def detect(
        self,
        context: SensitiveInfoBackendContext,
        value: str,
        entities: SensitiveInfoEntities,
        options: Optional[SensitiveInfoBackendOptions] = None,
    ) -> SensitiveInfoResult:
        """Detect sensitive information in ``value`` (see :class:`SensitiveInfoBackend`)."""
        if options is not None and options.detect is not None:
            context.log.debug(
                "the `detect` callback is ignored by the Rampart backend; use "
                "the `recognizers` option instead"
            )

        # Bound synchronous inference cost: scan only the first
        # ``max_input_chars`` characters. Truncating a prefix keeps span offsets
        # valid; log a warning so silently-unscanned trailing content is visible.
        if len(value) > self._max_input_chars:
            context.log.warning(
                "input of %d characters exceeds the Rampart backend limit of "
                "%d; scanning only the first %d (raise "
                "RampartOptions.max_input_chars to scan more)",
                len(value),
                self._max_input_chars,
                self._max_input_chars,
            )
            value = value[: self._max_input_chars]

        model_spans = self._run_model(value)
        recognizer_spans = run_recognizers(value, self._recognizers)

        # Recognizers take precedence over the model on overlapping text.
        merged = merge_spans([recognizer_spans, model_spans])

        listed = {from_analyze_entity(e) for e in entities.entities}
        deny_listed = isinstance(entities, SensitiveInfoEntitiesDeny)

        allowed: list[DetectedSensitiveInfoEntity] = []
        denied: list[DetectedSensitiveInfoEntity] = []
        for span in merged:
            entity = DetectedSensitiveInfoEntity(
                start=span.start,
                end=span.end,
                identified_type=to_analyze_entity(span.type),
            )
            is_listed = span.type in listed
            # deny mode: deny the listed types. allow mode: deny everything else.
            if is_listed if deny_listed else not is_listed:
                denied.append(entity)
            else:
                allowed.append(entity)

        return SensitiveInfoResult(allowed=allowed, denied=denied)


def rampart(options: RampartOptions = RampartOptions()) -> SensitiveInfoBackend:
    """Create a sensitive info detection backend powered by the Rampart model.

    Pass the returned backend to the ``detect_sensitive_info`` rule via its
    ``backend`` option. It runs entirely locally using the bundled model
    weights, so no data leaves your environment.

    Supported types detected by the on-device NER model: ``GIVEN_NAME``,
    ``SURNAME``, ``EMAIL``, ``PHONE_NUMBER``, ``URL``, ``TAX_ID``,
    ``BANK_ACCOUNT``, ``ROUTING_NUMBER``, ``GOVERNMENT_ID``, ``PASSPORT``,
    ``DRIVERS_LICENSE``, ``BUILDING_NUMBER``, ``STREET_NAME``,
    ``SECONDARY_ADDRESS``, ``CITY``, ``STATE``, ``ZIP_CODE``. Detected by
    deterministic recognizers: ``EMAIL``, ``URL``, ``IP_ADDRESS``,
    ``PHONE_NUMBER``, ``SSN``, ``CREDIT_CARD_NUMBER``.

    The token-based ``detect`` callback of the ``detect_sensitive_info`` rule is
    **not** used by this backend (the model works on spans, not tokens). Use the
    :attr:`RampartOptions.recognizers` option to add custom detection instead.

    Args:
        options: Backend options.

    Returns:
        A backend for ``detect_sensitive_info(backend=...)``.
    """
    recognizers = (
        options.recognizers if options.recognizers is not None else default_recognizers
    )
    run_model = options.run_model or create_model_runner(
        ModelOptions(
            model_path=options.model_path,
            threshold=options.threshold,
            providers=options.providers,
        )
    )
    max_input_chars = (
        options.max_input_chars
        if options.max_input_chars is not None
        else DEFAULT_MAX_INPUT_CHARS
    )
    return _RampartBackend(
        run_model=run_model,
        recognizers=recognizers,
        max_input_chars=max_input_chars,
    )

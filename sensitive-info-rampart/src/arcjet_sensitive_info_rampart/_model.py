"""Run the bundled Rampart ONNX NER model and aggregate its output into spans.

The heavy runtime (``onnxruntime``, ``tokenizers``, ``numpy``) is imported lazily
inside the loader, so importing this module — and configuring a rule — stays
cheap. The model is loaded once per unique configuration and reused for every
request.

Ported from ``sensitive-info-rampart/src/model.ts`` in arcjet-js. Unlike the JS
port, the Hugging Face ``tokenizers`` library provides character offsets
directly, so the token-offset reconstruction (``normalizeWithMap`` /
``assignOffsets``) the JS version needed is unnecessary here.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from ._entities import normalize_label
from ._recognizers import DetectedSpan

DEFAULT_THRESHOLD = 0.5

# The model has a 512-token window; longer input would error. We scan in
# overlapping character windows that cannot exceed it (each wordpiece token
# consumes at least one character, so <=480 characters stays under 512 tokens
# even before whitespace splitting, leaving room for the two special tokens). The
# overlap keeps entities that straddle a boundary intact, since detected spans
# are far shorter than it.
MAX_INPUT_CHARS = 480
CHUNK_OVERLAP = 64


@dataclass(slots=True)
class RawToken:
    """A single token classified by the model, with reconstructed offsets."""

    entity: str
    """Raw label (such as ``"B-GIVEN_NAME"``)."""

    score: float
    """Confidence score in the range ``[0, 1]``."""

    start: int
    """Start offset (inclusive) into the text."""

    end: int
    """End offset (exclusive) into the text."""


@dataclass(frozen=True, slots=True)
class ModelOptions:
    """Options controlling how the Rampart model is loaded and run."""

    model_path: Optional[str] = None
    """Directory containing the bundled model files (default: the ``models``
    directory shipped with this package). Pass this to load weights elsewhere."""

    threshold: float = DEFAULT_THRESHOLD
    """Minimum confidence score for a token to count (default: ``0.5``)."""

    providers: Optional[tuple[str, ...]] = None
    """ONNX Runtime execution providers (default: ``("CPUExecutionProvider",)``).
    Set to select a GPU provider when the runtime supports it."""


# Function that runs the model over ``value`` and returns detected spans.
ModelRunner = Callable[[str], list[DetectedSpan]]


def _is_whitespace(value: str) -> bool:
    """Whether ``value`` is empty or only whitespace."""
    return value == "" or value.isspace()


def aggregate_tokens(
    value: str,
    tokens: Sequence[RawToken],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[DetectedSpan]:
    """Aggregate per-token model output into entity spans.

    Consecutive tokens of the same type are merged into a single span when the
    text between them is only whitespace, so sub-word tokens (and adjacent words
    of one entity) collapse into one span. Tokens below ``threshold`` and tokens
    labelled outside (``O``) break the current span.

    Pure so it can be unit-tested without loading the model.

    Args:
        value: The text the tokens were produced from.
        tokens: Per-token model output, in order, with offsets assigned.
        threshold: Minimum confidence score (default: ``0.5``).

    Returns:
        Aggregated, non-overlapping spans in order.
    """
    spans: list[DetectedSpan] = []
    current: DetectedSpan | None = None

    for token in tokens:
        entity_type = normalize_label(token.entity)
        if entity_type is None or token.score < threshold:
            if current is not None:
                spans.append(current)
                current = None
            continue

        is_begin = token.entity[:2].lower() == "b-"
        if (
            current is not None
            and current.type == entity_type
            and not is_begin
            and _is_whitespace(value[current.end : token.start])
        ):
            current.end = token.end
            continue

        if current is not None:
            spans.append(current)
        current = DetectedSpan(start=token.start, end=token.end, type=entity_type)

    if current is not None:
        spans.append(current)
    return spans


def _merge_windowed_spans(spans: list[DetectedSpan]) -> list[DetectedSpan]:
    """Union overlapping same-type spans produced by overlapping windows.

    An entity that straddles a window boundary is detected as two partial spans
    in adjacent windows; because the windows overlap, those partials overlap
    too, so they are unioned into the full span here (rather than left as a
    truncated fragment). Only *overlapping* same-type spans are merged, so two
    distinct same-type entities separated by other text are left untouched. Also
    collapses the exact-duplicate spans the overlap region produces.

    This *unions* overlapping partials into one longer span, which is distinct
    from ``merge_spans`` in the package root — that *selects* one winner among
    competing spans and discards the rest. They are deliberately not shared:
    running windowed partials through ``merge_spans`` would keep only the longest
    partial and so truncate an entity split across a boundary instead of
    reconstructing it.

    Pure so it can be unit-tested without loading the model.
    """
    if not spans:
        return spans
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    merged: list[DetectedSpan] = []
    # Track the running span *per type* rather than only the last merged span,
    # so two same-type fragments still union even when a different-type span
    # starts between them in sort order. Within a type the spans arrive in start
    # order, so a standard interval sweep against the running span is correct.
    running: dict[str, DetectedSpan] = {}
    for span in ordered:
        current = running.get(span.type)
        if current is not None and span.start < current.end:
            if span.end > current.end:
                current.end = span.end
        else:
            new = DetectedSpan(start=span.start, end=span.end, type=span.type)
            merged.append(new)
            running[span.type] = new
    return merged


def _default_model_path() -> str:
    """Resolve the bundled ``models/rampart`` directory."""
    from importlib.resources import files

    return str(files("arcjet_sensitive_info_rampart") / "models" / "rampart")


# The loaded session/tokenizer is cached per unique configuration and reused
# across every request — model loading is the expensive part. Guarded by a lock
# so concurrent first-use calls don't load the model twice.
_model_cache: dict[str, "_LoadedModel"] = {}
_load_lock = threading.Lock()


class _LoadedModel:
    """A loaded ONNX session, tokenizer, and label map."""

    def __init__(
        self, model_path: str, providers: Sequence[str]
    ) -> None:  # pragma: no cover - requires onnxruntime + model
        import os

        import onnxruntime
        from tokenizers import Tokenizer

        with open(os.path.join(model_path, "config.json"), encoding="utf-8") as fh:
            config = json.load(fh)
        # ``id2label`` keys are strings in JSON; index by int.
        self.id2label: dict[int, str] = {
            int(k): v for k, v in config["id2label"].items()
        }

        self.tokenizer = Tokenizer.from_file(os.path.join(model_path, "tokenizer.json"))
        # We chunk manually, so disable any tokenizer-level truncation/padding.
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()

        self.session = onnxruntime.InferenceSession(
            os.path.join(model_path, "onnx", "model_q4.onnx"),
            providers=list(providers),
        )
        self.input_names = {i.name for i in self.session.get_inputs()}


def _load_model(
    options: ModelOptions,
) -> _LoadedModel:  # pragma: no cover - requires onnxruntime + model
    """Load (or return a cached) model for ``options``."""
    model_path = options.model_path or _default_model_path()
    providers = options.providers or ("CPUExecutionProvider",)
    key = json.dumps({"model_path": model_path, "providers": list(providers)})

    cached = _model_cache.get(key)
    if cached is not None:
        return cached

    with _load_lock:
        cached = _model_cache.get(key)
        if cached is not None:
            return cached
        loaded = _LoadedModel(model_path, providers)
        _model_cache[key] = loaded
        return loaded


def _classify_chunk(
    model: _LoadedModel, chunk: str
) -> list[RawToken]:  # pragma: no cover - requires onnxruntime + model
    """Tokenize and classify a single chunk into raw tokens with offsets."""
    import numpy as np

    encoding = model.tokenizer.encode(chunk)
    ids = encoding.ids
    if not ids:
        return []

    feed: dict[str, Any] = {}
    ids_arr = np.array([ids], dtype=np.int64)
    if "input_ids" in model.input_names:
        feed["input_ids"] = ids_arr
    if "attention_mask" in model.input_names:
        feed["attention_mask"] = np.array([encoding.attention_mask], dtype=np.int64)
    if "token_type_ids" in model.input_names:
        feed["token_type_ids"] = np.array([encoding.type_ids], dtype=np.int64)

    outputs = model.session.run(None, feed)
    logits = np.asarray(outputs[0])[0]  # [seq, num_labels]
    # Softmax over the label axis for per-token confidence scores.
    shifted = logits - logits.max(axis=-1, keepdims=True)
    exp = np.exp(shifted)
    probs = exp / exp.sum(axis=-1, keepdims=True)
    label_ids = probs.argmax(axis=-1)
    scores = probs.max(axis=-1)

    offsets = encoding.offsets
    special = encoding.special_tokens_mask

    tokens: list[RawToken] = []
    for i, (start, end) in enumerate(offsets):
        # Skip special tokens ([CLS]/[SEP]) and zero-width tokens.
        if special[i] == 1 or end <= start:
            continue
        tokens.append(
            RawToken(
                entity=model.id2label.get(int(label_ids[i]), "O"),
                score=float(scores[i]),
                start=int(start),
                end=int(end),
            )
        )
    return tokens


def create_model_runner(options: ModelOptions = ModelOptions()) -> ModelRunner:
    """Create a :data:`ModelRunner` bound to ``options``.

    The returned function lazily loads the model on first use and reuses it for
    every subsequent call.

    Args:
        options: Model options.

    Returns:
        A function that detects spans in text using the model.
    """
    threshold = options.threshold

    def run_model(
        value: str,
    ) -> list[DetectedSpan]:  # pragma: no cover - requires onnxruntime + model
        model = _load_model(options)

        if len(value) <= MAX_INPUT_CHARS:
            return aggregate_tokens(value, _classify_chunk(model, value), threshold)

        # Scan long input in overlapping windows and rebase each window's spans
        # to absolute offsets. The overlap keeps an entity that straddles a
        # window boundary intact: it is detected in both windows and the partial
        # spans are unioned by _merge_windowed_spans (which also drops the
        # duplicate spans the overlap region produces).
        spans: list[DetectedSpan] = []
        step = MAX_INPUT_CHARS - CHUNK_OVERLAP
        start = 0
        while True:
            chunk = value[start : start + MAX_INPUT_CHARS]
            for span in aggregate_tokens(
                chunk, _classify_chunk(model, chunk), threshold
            ):
                spans.append(
                    DetectedSpan(
                        start=span.start + start,
                        end=span.end + start,
                        type=span.type,
                    )
                )
            # Once a window reaches the end, the whole input is covered; advancing
            # would only re-scan an already-covered tail (a wasted inference pass).
            if start + MAX_INPUT_CHARS >= len(value):
                break
            start += step
        return _merge_windowed_spans(spans)

    return run_model

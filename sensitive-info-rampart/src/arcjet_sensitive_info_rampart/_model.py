"""Run the bundled Rampart ONNX NER model and aggregate its output into spans.

The heavy runtime (``onnxruntime``, ``tokenizers``, ``numpy``) is imported lazily
inside the loader, so importing this module — and configuring a rule — stays
cheap. The model is loaded once per unique configuration and reused for every
request.

Ported from ``sensitive-info-rampart/src/model.ts`` in arcjet-js. Unlike the JS
port, the Hugging Face ``tokenizers`` library provides character offsets
directly, so the token-offset reconstruction (``normalizeWithMap`` /
``assignOffsets``) the JS version needed is unnecessary here. Those offsets
index the text they came from even where normalization changes it (Hangul is
decomposed into Jamo, so several tokens can share one character's offsets).
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from ._entities import normalize_label
from ._recognizers import DetectedSpan

DEFAULT_THRESHOLD = 0.5

# The model has a 512-token window, including [CLS] and [SEP]; longer input
# would error. Input is scanned in overlapping 480-character windows, which is
# the context the model detects best in: its phone recall drops when given
# windows closer to the full 512 tokens. Character count does not bound token
# count, though (normalization can expand one character into several tokens, as
# a Hangul syllable becomes three Jamo), so a character window that does not fit
# is itself scanned in overlapping token windows that do. The overlaps keep
# entities that straddle a boundary intact, since detected spans are far shorter
# than them.
MAX_SEQUENCE_TOKENS = 512
MAX_INPUT_CHARS = 480
CHUNK_OVERLAP = 64
CHUNK_OVERLAP_TOKENS = 64


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


def _plan_windows(
    word_ids: Sequence[Optional[int]], budget: int, overlap: int
) -> list[tuple[int, int]]:
    """Split a token sequence into overlapping ``[start, end)`` windows.

    Each window holds at most ``budget`` tokens, and together they cover every
    token. Each window after the first starts ``overlap`` tokens before the
    previous one ended, moved back to the start of the word there so a window
    does not open on a sub-word continuation. It always starts after the
    previous window's start, so planning progresses even when one word (or one
    original character) spans more tokens than the overlap.

    Pure so it can be unit-tested without loading the model.

    Args:
        word_ids: The word index of each token, as reported by the tokenizer.
        budget: Maximum tokens per window, excluding special tokens.
        overlap: Tokens shared by adjacent windows (less than ``budget``).

    Returns:
        Window bounds in order; empty when there are no tokens.
    """
    count = len(word_ids)
    windows: list[tuple[int, int]] = []
    start = 0
    while start < count:
        end = min(start + budget, count)
        windows.append((start, end))
        if end == count:
            break
        next_start = end - overlap
        while (
            next_start - 1 > start and word_ids[next_start] == word_ids[next_start - 1]
        ):
            next_start -= 1
        start = next_start
    return windows


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
        self.max_tokens: int = config.get(
            "max_position_embeddings", MAX_SEQUENCE_TOKENS
        )
        # Windows are tokenized without special tokens, then wrapped as
        # [CLS] ... [SEP], which is what the tokenizer's post-processor does.
        cls_id = self.tokenizer.token_to_id("[CLS]")
        sep_id = self.tokenizer.token_to_id("[SEP]")
        if cls_id is None or sep_id is None:
            raise ValueError("Rampart tokenizer is missing [CLS] or [SEP]")
        self.cls_id: int = cls_id
        self.sep_id: int = sep_id
        self.window_budget = self.max_tokens - self.tokenizer.num_special_tokens_to_add(
            False
        )
        if self.window_budget < 1:
            raise ValueError(
                f"Rampart model allows {self.max_tokens} positions, which leaves "
                "no room for input tokens beside [CLS] and [SEP]"
            )

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


def _classify_window(
    model: _LoadedModel,
    token_ids: Sequence[int],
    offsets: Sequence[tuple[int, int]],
    start: int,
    end: int,
) -> list[RawToken]:  # pragma: no cover - requires onnxruntime + model
    """Classify tokens ``[start, end)`` of a tokenized chunk into raw tokens.

    ``token_ids`` and ``offsets`` are the chunk tokenized without special
    tokens, so the returned offsets index the chunk. They are read from the
    encoding once by the caller, because each read copies the whole list.
    """
    import numpy as np

    ids = [model.cls_id, *token_ids[start:end], model.sep_id]
    if len(ids) > model.max_tokens:
        raise ValueError(
            f"Rampart window of {len(ids)} tokens exceeds the model limit of "
            f"{model.max_tokens}"
        )

    feed: dict[str, Any] = {}
    if "input_ids" in model.input_names:
        feed["input_ids"] = np.array([ids], dtype=np.int64)
    if "attention_mask" in model.input_names:
        feed["attention_mask"] = np.ones((1, len(ids)), dtype=np.int64)
    if "token_type_ids" in model.input_names:
        feed["token_type_ids"] = np.zeros((1, len(ids)), dtype=np.int64)

    outputs = model.session.run(None, feed)
    logits = np.asarray(outputs[0])[0]  # [seq, num_labels]
    # Softmax over the label axis for per-token confidence scores.
    shifted = logits - logits.max(axis=-1, keepdims=True)
    exp = np.exp(shifted)
    probs = exp / exp.sum(axis=-1, keepdims=True)
    label_ids = probs.argmax(axis=-1)
    scores = probs.max(axis=-1)

    tokens: list[RawToken] = []
    # Position 0 is [CLS]; the window's tokens follow it, then [SEP].
    for i, (token_start, token_end) in enumerate(offsets[start:end], 1):
        # Skip zero-width tokens.
        if token_end <= token_start:
            continue
        tokens.append(
            RawToken(
                entity=model.id2label.get(int(label_ids[i]), "O"),
                score=float(scores[i]),
                start=int(token_start),
                end=int(token_end),
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
        budget = model.window_budget
        overlap = min(CHUNK_OVERLAP_TOKENS, budget - 1)

        def scan(chunk: str, offset: int, spans: list[DetectedSpan]) -> int:
            """Scan one character window, splitting it by tokens if needed.

            Appends spans rebased by ``offset`` and returns how many model
            invocations the chunk took.
            """
            encoding = model.tokenizer.encode(chunk, add_special_tokens=False)
            token_ids, offsets = encoding.ids, encoding.offsets
            windows = _plan_windows(encoding.word_ids, budget, overlap)
            for start, end in windows:
                tokens = _classify_window(model, token_ids, offsets, start, end)
                for span in aggregate_tokens(chunk, tokens, threshold):
                    spans.append(
                        DetectedSpan(
                            start=span.start + offset,
                            end=span.end + offset,
                            type=span.type,
                        )
                    )
            return len(windows)

        spans: list[DetectedSpan] = []
        if len(value) <= MAX_INPUT_CHARS:
            if scan(value, 0, spans) <= 1:
                return spans
            return _merge_windowed_spans(spans)

        # Scan long input in overlapping windows and rebase each window's spans
        # to absolute offsets. The overlap keeps an entity that straddles a
        # window boundary intact: it is detected in both windows and the partial
        # spans are unioned by _merge_windowed_spans (which also drops the
        # duplicate spans the overlap region produces).
        step = MAX_INPUT_CHARS - CHUNK_OVERLAP
        start = 0
        while True:
            scan(value[start : start + MAX_INPUT_CHARS], start, spans)
            # Once a window reaches the end, the whole input is covered; advancing
            # would only re-scan an already-covered tail (a wasted inference pass).
            if start + MAX_INPUT_CHARS >= len(value):
                break
            start += step
        return _merge_windowed_spans(spans)

    return run_model

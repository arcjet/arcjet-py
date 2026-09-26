"""Real-model integration tests for the Rampart backend.

Gated behind ``ARCJET_RAMPART_INTEGRATION`` and ``importorskip`` so a minimal
CI run (without onnxruntime installed) skips them. When enabled, they load the
bundled ONNX model and run inference end to end.

Run with::

    ARCJET_RAMPART_INTEGRATION=1 uv run pytest tests/sensitive_info_rampart/test_integration.py
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("ARCJET_RAMPART_INTEGRATION") != "1",
    reason="set ARCJET_RAMPART_INTEGRATION=1 to run the real-model integration tests",
)

pytest.importorskip("onnxruntime")
pytest.importorskip("tokenizers")


def test_model_detects_name_and_email():
    import logging

    from arcjet_sensitive_info_rampart import rampart, rampart_entities
    from arcjet_sensitive_info_rampart._entities import (
        from_analyze_entity,
        to_analyze_entity,
    )

    from arcjet._analyze import SensitiveInfoEntitiesDeny
    from arcjet._sensitive_info_backend import (
        SensitiveInfoBackendContext,
        SensitiveInfoBackendOptions,
    )

    backend = rampart()
    ctx = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    entities = SensitiveInfoEntitiesDeny(
        entities=[to_analyze_entity(t) for t in rampart_entities]
    )
    text = "My name is Alex Rivera and my email is alex@example.com."
    result = backend.detect(ctx, text, entities, SensitiveInfoBackendOptions())

    denied = {from_analyze_entity(e.identified_type) for e in result.denied}
    assert "EMAIL" in denied
    # The model should identify at least one name component.
    assert denied & {"GIVEN_NAME", "SURNAME"}


def test_model_returns_whole_entities_when_subwords_repeat_begin_labels():
    import logging

    from arcjet_sensitive_info_rampart import rampart

    from arcjet._analyze import SensitiveInfoEntitiesAllow
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    backend = rampart()
    context = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    examples = [
        (
            "This Agreement is entered into by and between John Anderson "
            "(Taxpayer Identification Number 123-45-6789) and the financial "
            "institution holding the IBAN US64SVBKUS6S3300958879. Mr. Anderson,",
            ("US64SVBKUS6S3300958879",),
        ),
        (
            "Name: Aurélie Henry-Leroy\nBBAN: LVLU04836212442259\n"
            "Property Address: 1199 Perez Burgs\n",
            ("Aurélie", "LVLU04836212442259", "1199"),
        ),
        (
            "je viens d'emménager au 27A, Allée des Chênes, 2350 Luxembourg",
            ("27A", "Allée des Chênes", "2350", "Luxembourg"),
        ),
    ]

    for text, values in examples:
        result = backend.detect(context, text, SensitiveInfoEntitiesAllow(entities=[]))
        for value in values:
            start = text.index(value)
            end = start + len(value)
            overlapping = [
                (entity.start, entity.end)
                for entity in result.denied
                if entity.start < end and entity.end > start
            ]
            assert overlapping == [(start, end)], (value, overlapping)


def test_model_does_not_join_touching_emails_across_a_separator():
    import logging

    from arcjet_sensitive_info_rampart import RampartOptions, rampart
    from arcjet_sensitive_info_rampart._entities import to_analyze_entity

    from arcjet._analyze import SensitiveInfoEntitiesDeny
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    text = "Email alice@example.com$bob@example.com"
    separator = text.index("$")
    context = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    entities = SensitiveInfoEntitiesDeny(entities=[to_analyze_entity("EMAIL")])

    # Run the model without recognizers so their higher precedence cannot hide
    # an incorrect model span that crosses two distinct email addresses.
    model_only = rampart(RampartOptions(recognizers=()))
    result = model_only.detect(context, text, entities)
    assert not any(
        span.start < separator and span.end > separator + 1 for span in result.denied
    )

    # The default validated recognizer still returns complete email addresses.
    result = rampart().detect(context, text, entities)
    assert [text[span.start : span.end] for span in result.denied] == [
        "alice@example.com",
        "bob@example.com",
    ]


def test_model_distinguishes_bank_accounts_and_routing_numbers_from_phones():
    import logging

    from arcjet_sensitive_info_rampart import rampart, rampart_entities
    from arcjet_sensitive_info_rampart._entities import (
        from_analyze_entity,
        to_analyze_entity,
    )

    from arcjet._analyze import SensitiveInfoEntitiesDeny
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    backend = rampart()
    ctx = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    entities = SensitiveInfoEntitiesDeny(
        entities=[to_analyze_entity(entity) for entity in rampart_entities]
    )
    text = (
        "Details on file: name: Alex Morgan; "
        "email: alex.morgan@client-corp.example; ssn: 431-55-9928; "
        "bank_account: 0123456789; routing_number: 022000020"
    )
    result = backend.detect(ctx, text, entities)

    found: dict[str, list[str]] = {}
    for entity in result.denied:
        entity_type = from_analyze_entity(entity.identified_type)
        found.setdefault(entity_type, []).append(text[entity.start : entity.end])

    assert "BANK_ACCOUNT" in found
    assert "ROUTING_NUMBER" in found
    assert "".join(found["BANK_ACCOUNT"]) == "0123456789"
    assert "".join(found["ROUTING_NUMBER"]) == "022000020"
    # There are no unrelated phone numbers in this fixture, so this stronger
    # assertion also proves neither financial identifier was relabeled.
    assert "PHONE_NUMBER" not in found


def test_model_detects_formatted_phone_without_phone_recognizer():
    import logging

    from arcjet_sensitive_info_rampart import rampart
    from arcjet_sensitive_info_rampart._entities import to_analyze_entity

    from arcjet._analyze import SensitiveInfoEntitiesDeny
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    backend = rampart()
    ctx = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    entities = SensitiveInfoEntitiesDeny(entities=[to_analyze_entity("PHONE_NUMBER")])
    text = "Call me at +1 (415) 555-2671."
    result = backend.detect(ctx, text, entities)

    assert any(
        "555-2671" in text[entity.start : entity.end] for entity in result.denied
    )


def test_full_core_evaluation_path():
    from arcjet_sensitive_info_rampart import rampart

    from arcjet import Mode, detect_sensitive_info
    from arcjet._context import RequestContext
    from arcjet._local import evaluate_sensitive_info_locally
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    rule = detect_sensitive_info(
        mode=Mode.LIVE, deny=["EMAIL", "SSN"], backend=rampart()
    )
    ctx = RequestContext(sensitive_info_value="Email alex@example.com, SSN 472-81-0094")
    result = evaluate_sensitive_info_locally(ctx, rule)
    assert result is not None
    assert result.conclusion == decide_pb2.CONCLUSION_DENY
    denied = {d.identified_type for d in result.reason.sensitive_info.denied}
    assert "EMAIL" in denied
    assert "SSN" in denied


def test_long_input_is_chunked():
    """Input longer than the model window is scanned in overlapping chunks."""
    import logging

    from arcjet_sensitive_info_rampart import rampart
    from arcjet_sensitive_info_rampart._entities import (
        from_analyze_entity,
        to_analyze_entity,
    )

    from arcjet._analyze import SensitiveInfoEntitiesDeny
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    backend = rampart()
    ctx = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    entities = SensitiveInfoEntitiesDeny(entities=[to_analyze_entity("EMAIL")])
    # Push the email well past the 480-char chunk boundary.
    text = ("lorem ipsum dolor sit amet " * 40) + " contact zoe@example.com"
    assert len(text) > 480
    result = backend.detect(ctx, text, entities)
    denied = {from_analyze_entity(e.identified_type) for e in result.denied}
    assert "EMAIL" in denied


# The model's position-embedding limit, including [CLS] and [SEP].
_MODEL_MAX_TOKENS = 512


class _SessionSpy:
    """Records the sequence length of every model invocation."""

    def __init__(self, session):
        self._session = session
        self.lengths: list[int] = []

    def run(self, output_names, feed):
        self.lengths.append(int(feed["input_ids"].shape[1]))
        return self._session.run(output_names, feed)


@pytest.fixture
def model_calls(monkeypatch):
    """Spy on the cached default model's ONNX session."""
    from arcjet_sensitive_info_rampart._model import ModelOptions, _load_model

    model = _load_model(ModelOptions())
    spy = _SessionSpy(model.session)
    monkeypatch.setattr(model, "session", spy)
    return spy


def _content_tokens(text: str) -> int:
    from arcjet_sensitive_info_rampart._model import ModelOptions, _load_model

    tokenizer = _load_model(ModelOptions()).tokenizer
    return len(tokenizer.encode(text, add_special_tokens=False).ids)


def _found(text, spans):
    return [(text[s.start : s.end], s.type) for s in spans]


def test_hangul_token_expansion_does_not_overflow_the_model(model_calls):
    """Regression: 341 characters of Hangul became 513 tokens and ONNX failed.

    BertNormalizer decomposes each syllable into three Jamo tokens that share
    one original-character offset, so the character count did not bound the
    token count.
    """
    import logging

    from arcjet_sensitive_info_rampart import rampart

    from arcjet._analyze import SensitiveInfoEntitiesAllow
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    text = "각 " * 170 + "x"
    assert len(text) == 341
    assert _content_tokens(text) + 2 == 513

    rampart().detect(
        SensitiveInfoBackendContext(log=logging.getLogger("test")),
        text,
        SensitiveInfoEntitiesAllow(entities=[]),
    )
    assert len(model_calls.lengths) == 2
    assert max(model_calls.lengths) <= _MODEL_MAX_TOKENS


def test_token_budget_boundary(model_calls):
    """Exactly the budget is one full-length call; one more token is two."""
    from arcjet_sensitive_info_rampart._model import create_model_runner

    run = create_model_runner()

    at_budget = "각 " * 170
    assert _content_tokens(at_budget) + 2 == _MODEL_MAX_TOKENS
    run(at_budget)
    assert model_calls.lengths == [_MODEL_MAX_TOKENS]

    model_calls.lengths.clear()
    run(at_budget + "x")
    assert len(model_calls.lengths) == 2
    assert max(model_calls.lengths) <= _MODEL_MAX_TOKENS


def test_long_multilingual_input_scans_to_the_end(model_calls):
    """Entities after many windows of multilingual text keep exact offsets."""
    from arcjet_sensitive_info_rampart._model import create_model_runner

    filler = (
        "회의록 정리했습니다. 会议记录已经整理好了。議事録をまとめました。 Notes are done. "
        * 200
    )
    tail = "Contact Maria Garcia at 415-555-2671."
    text = filler + tail
    assert _content_tokens(text) > 10 * _MODEL_MAX_TOKENS

    found = _found(text, create_model_runner()(text))

    assert ("Maria", "GIVEN_NAME") in found
    assert ("Garcia", "SURNAME") in found
    assert ("415-555-2671", "PHONE_NUMBER") in found
    assert len(model_calls.lengths) > 10
    assert max(model_calls.lengths) <= _MODEL_MAX_TOKENS


def test_detection_crossing_a_window_boundary_is_reconstructed(model_calls):
    """A phone number split by the first window edge is reported whole."""
    from arcjet_sensitive_info_rampart._model import create_model_runner

    budget = _MODEL_MAX_TOKENS - 2
    phone = "415-555-2671"
    prefix = "Please call Maria Garcia on "
    # Hangul filler costs three tokens per syllable; pad so the phone number's
    # tokens straddle the end of the first window.
    filler = "각 " * ((budget - _content_tokens(prefix) - 2) // 3)
    text = filler + prefix + phone + " tomorrow."
    before = _content_tokens(filler + prefix)
    assert before < budget < before + _content_tokens(phone)

    found = _found(text, create_model_runner()(text))

    assert (phone, "PHONE_NUMBER") in found
    assert len(model_calls.lengths) == 2
    assert max(model_calls.lengths) <= _MODEL_MAX_TOKENS


def test_model_with_no_room_for_input_tokens_is_rejected(tmp_path):
    """A config whose position limit leaves no window budget fails at load."""
    import json
    import shutil

    from arcjet_sensitive_info_rampart._model import (
        ModelOptions,
        _default_model_path,
        _load_model,
    )

    source = _default_model_path()
    shutil.copy(os.path.join(source, "tokenizer.json"), tmp_path)
    with open(os.path.join(source, "config.json"), encoding="utf-8") as fh:
        config = json.load(fh)
    config["max_position_embeddings"] = 2
    (tmp_path / "config.json").write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="no room for input tokens"):
        _load_model(ModelOptions(model_path=str(tmp_path)))


def test_windows_that_fit_keep_the_character_windows(model_calls):
    """Chunks within the token budget are scanned exactly as before the fix.

    The model's phone recall drops in longer windows, so a 480-character window
    that fits the model is sent whole rather than merged into a longer one.
    """
    from arcjet_sensitive_info_rampart._model import (
        ModelOptions,
        _load_model,
        create_model_runner,
    )

    # The pre-fix windows: 480 characters, overlapping by 64.
    size, step = 480, 480 - 64
    tokenizer = _load_model(ModelOptions()).tokenizer
    text = "Please call the office about the invoice. " * 40
    expected = []
    for start in range(0, len(text), step):
        expected.append(len(tokenizer.encode(text[start : start + size]).ids))
        if start + size >= len(text):
            break

    create_model_runner()(text)

    assert len(expected) > 2
    assert model_calls.lengths == expected

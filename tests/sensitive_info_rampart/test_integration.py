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

    assert "".join(found["BANK_ACCOUNT"]) == "0123456789"
    assert "".join(found["ROUTING_NUMBER"]) == "022000020"
    assert "PHONE_NUMBER" not in found


def test_model_detects_formatted_phone_without_phone_recognizer():
    import logging

    from arcjet_sensitive_info_rampart import rampart
    from arcjet_sensitive_info_rampart._entities import to_analyze_entity

    from arcjet._analyze import SensitiveInfoEntitiesDeny
    from arcjet._sensitive_info_backend import SensitiveInfoBackendContext

    backend = rampart()
    ctx = SensitiveInfoBackendContext(log=logging.getLogger("test"))
    entities = SensitiveInfoEntitiesDeny(
        entities=[to_analyze_entity("PHONE_NUMBER")]
    )
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

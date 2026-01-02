from __future__ import annotations

import pytest

from arcjet.rules import (
    shield,
    detect_bot,
    token_bucket,
    fixed_window,
    sliding_window,
    validate_email,
    BotCategory,
    EmailType,
    Mode,
)
from arcjet.decide.v1alpha1 import decide_pb2


def test_shield_to_proto_and_characteristics():
    r = shield(mode=Mode.LIVE, characteristics=("uid", "ip"))
    pb = r.to_proto()
    assert pb.shield is not None
    assert pb.shield.mode == decide_pb2.MODE_LIVE
    assert pb.shield.characteristics == ["uid", "ip"]


def test_detect_bot_allows_categories_and_names():
    r = detect_bot(allow=(BotCategory.GOOGLE, "OPENAI_CRAWLER_SEARCH"))
    pb = r.to_proto()
    assert pb.bot_v2.allow == [BotCategory.GOOGLE.value, "OPENAI_CRAWLER_SEARCH"]


def test_rate_limit_builders_validation_and_proto():
    tb = token_bucket(mode=Mode.DRY_RUN, refill_rate=10, interval=60, capacity=20)
    pb = tb.to_proto()
    assert pb.rate_limit.algorithm == decide_pb2.RATE_LIMIT_ALGORITHM_TOKEN_BUCKET
    assert pb.rate_limit.interval == 60

    fw = fixed_window(max=100, window=60)
    pb2 = fw.to_proto()
    assert pb2.rate_limit.max == 100

    sw = sliding_window(max=77, interval=30)
    pb3 = sw.to_proto()
    assert pb3.rate_limit.interval == 30

    with pytest.raises(ValueError):
        token_bucket(refill_rate=0, interval=1, capacity=1)

    with pytest.raises(ValueError):
        fixed_window(max=0, window=1)

    with pytest.raises(ValueError):
        sliding_window(max=1, interval=0)


def test_validate_email_coercion_and_proto():
    r = validate_email(deny=(EmailType.DISPOSABLE, "INVALID"))
    pb = r.to_proto()
    # Should map string and enum to email type ints
    assert decide_pb2.EMAIL_TYPE_DISPOSABLE in pb.email.deny
    assert decide_pb2.EMAIL_TYPE_INVALID in pb.email.deny

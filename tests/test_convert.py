import datetime

from arcjet.dataclasses import ErrorReason


def test_converting_bot_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import BotReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(bot=decide_pb2.BotReason())

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, ErrorReason)
    assert reason.type == "ERROR"
    assert (
        reason.message
        == 'decide_pb2.Reason(type="bot") is unsupported (use "bot_v2" instead).'
    )


def test_converting_bot_v2_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import BotReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        bot_v2=decide_pb2.BotV2Reason(
            allowed=[],
            denied=[],
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, BotReason)
    assert reason.type == "BOT"
    assert reason.allowed == []
    assert reason.denied == []
    assert reason.spoofed == False
    assert reason.verified == False


def test_converting_bot_v2_reason_spoofed_and_verified() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import BotReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        bot_v2=decide_pb2.BotV2Reason(
            allowed=[],
            denied=[],
            spoofed=True,
            verified=True,
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, BotReason)
    assert reason.type == "BOT"
    assert reason.allowed == []
    assert reason.denied == []
    assert reason.spoofed == True
    assert reason.verified == True


def test_converting_edge_rule_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import ErrorReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(edge_rule=decide_pb2.EdgeRuleReason())

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, ErrorReason)
    assert reason.type == "ERROR"
    assert reason.message == 'decide_pb2.Reason(type="edge_rule") is unsupported.'


def test_converting_email_reason_empty() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import EmailReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(email=decide_pb2.EmailReason())

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, EmailReason)
    assert reason.type == "EMAIL"
    assert reason.email_types == []


def test_converting_email_reason_type() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import EmailReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        email=decide_pb2.EmailReason(
            email_types=[decide_pb2.EmailType.EMAIL_TYPE_DISPOSABLE]
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, EmailReason)
    assert reason.type == "EMAIL"
    assert reason.email_types == ["DISPOSABLE"]


def test_converting_error_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import ErrorReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        error=decide_pb2.ErrorReason(
            message="An error occurred.",
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, ErrorReason)
    assert reason.type == "ERROR"
    assert reason.message == "An error occurred."


def test_converting_filter_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import FilterReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        filter=decide_pb2.FilterReason(
            matched_expressions=["ip.src == 1.2.3.4"],
            undetermined_expressions=[],
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, FilterReason)
    assert reason.type == "FILTER"
    assert reason.matched_expressions == ["ip.src == 1.2.3.4"]
    assert reason.undetermined_expressions == []


def test_converting_rate_limit_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import RateLimitReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        rate_limit=decide_pb2.RateLimitReason(
            count=2,
            max=1,
            remaining=0,
            reset_in_seconds=1000,
            window_in_seconds=1000,
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, RateLimitReason)
    assert reason.type == "RATE_LIMIT"
    assert reason.max == 1
    assert reason.remaining == 0
    assert reason.reset_time == None
    assert reason.reset == datetime.timedelta(seconds=1000)
    assert reason.window == datetime.timedelta(seconds=1000)


def test_converting_rate_limit_reason_with_reset_time() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import RateLimitReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    reset_time = datetime.datetime.now(datetime.timezone.utc)

    proto_reason = decide_pb2.Reason(
        rate_limit=decide_pb2.RateLimitReason(
            count=2,
            max=1,
            remaining=0,
            reset_in_seconds=1000,
            reset_time=reset_time,
            window_in_seconds=1000,
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, RateLimitReason)
    assert reason.type == "RATE_LIMIT"
    assert reason.max == 1
    assert reason.remaining == 0
    assert reason.reset_time == reset_time
    assert reason.reset == datetime.timedelta(seconds=1000)
    assert reason.window == datetime.timedelta(seconds=1000)


def test_converting_shield_reason_triggered() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import ShieldReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        shield=decide_pb2.ShieldReason(shield_triggered=True)
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, ShieldReason)
    assert reason.type == "SHIELD"
    assert reason.shield_triggered == True


def test_converting_shield_reason_not_triggered() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import ShieldReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        shield=decide_pb2.ShieldReason(shield_triggered=False)
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, ShieldReason)
    assert reason.type == "SHIELD"
    assert reason.shield_triggered == False

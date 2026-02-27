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


def test_converting_prompt_injection_detection_reason() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import PromptInjectionDetectionReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        prompt_injection_detection=decide_pb2.PromptInjectionDetectionReason(
            injection_detected=True,
            score=0.95,
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, PromptInjectionDetectionReason)
    assert reason.type == "PROMPT_INJECTION_DETECTION"
    assert reason.injection_detected == True
    assert reason.score == 0.95


def test_converting_prompt_injection_detection_reason_not_detected() -> None:
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import PromptInjectionDetectionReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_reason = decide_pb2.Reason(
        prompt_injection_detection=decide_pb2.PromptInjectionDetectionReason(
            injection_detected=False,
            score=0.2,
        )
    )

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, PromptInjectionDetectionReason)
    assert reason.type == "PROMPT_INJECTION_DETECTION"
    assert reason.injection_detected == False
    assert reason.score == 0.2


def test_converting_email_type_free() -> None:
    from arcjet._convert import _email_type_from_proto
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    email_type = _email_type_from_proto(decide_pb2.EmailType.EMAIL_TYPE_FREE)
    assert email_type == "FREE"


def test_converting_email_type_invalid() -> None:
    from arcjet._convert import _email_type_from_proto
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    email_type = _email_type_from_proto(decide_pb2.EmailType.EMAIL_TYPE_INVALID)
    assert email_type == "INVALID"


def test_converting_email_type_no_gravatar() -> None:
    from arcjet._convert import _email_type_from_proto
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    email_type = _email_type_from_proto(decide_pb2.EmailType.EMAIL_TYPE_NO_GRAVATAR)
    assert email_type == "NO_GRAVATAR"


def test_converting_email_type_no_mx_records() -> None:
    from arcjet._convert import _email_type_from_proto
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    email_type = _email_type_from_proto(decide_pb2.EmailType.EMAIL_TYPE_NO_MX_RECORDS)
    assert email_type == "NO_MX_RECORDS"


def test_converting_email_type_unspecified() -> None:
    from arcjet._convert import _email_type_from_proto
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    # Test with EMAIL_TYPE_UNSPECIFIED (value 0)
    email_type = _email_type_from_proto(decide_pb2.EmailType.EMAIL_TYPE_UNSPECIFIED)
    assert email_type == "UNSPECIFIED"


def test_converting_ip_details() -> None:
    from arcjet._convert import _ip_details_from_proto
    from arcjet.dataclasses import IpDetails
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_ip = decide_pb2.IpDetails(
        latitude=37.7749,
        longitude=-122.4194,
        asn="AS15169",
        asn_name="Google LLC",
        service="google",
        is_hosting=True,
        is_vpn=False,
        is_proxy=False,
        is_tor=False,
        is_relay=False,
    )

    ip = _ip_details_from_proto(proto_ip)

    assert isinstance(ip, IpDetails)
    assert ip.latitude == 37.7749
    assert ip.longitude == -122.4194
    assert ip.asn == "AS15169"
    assert ip.asn_name == "Google LLC"
    assert ip.service == "google"
    assert ip.is_hosting is True
    # The converter intentionally treats boolean IP flags that are False or unset
    # in the protobuf as "unknown" and represents them as None in the dataclass.
    # This test asserts that behavior for is_vpn, even though the protobuf field
    # is explicitly set to False.
    assert ip.is_vpn is None


def test_ip_details_boolean_flag_conversion() -> None:
    """
    Document and verify that _ip_details_from_proto converts False boolean flags
    (or unset fields) from the protobuf into None in the IpDetails dataclass,
    while preserving True values.
    """
    from arcjet._convert import _ip_details_from_proto
    from arcjet.dataclasses import IpDetails
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    proto_ip = decide_pb2.IpDetails(
        latitude=0.0,
        longitude=0.0,
        asn="AS0",
        asn_name="Example",
        service="example",
        is_hosting=True,
        is_vpn=False,
        is_proxy=False,
        is_tor=False,
        is_relay=False,
    )

    ip = _ip_details_from_proto(proto_ip)

    assert isinstance(ip, IpDetails)
    # True values are preserved.
    assert ip.is_hosting is True
    # False values are normalized to None to represent "no signal"/unknown,
    # rather than a strong negative assertion.
    assert ip.is_vpn is None
    assert getattr(ip, "is_proxy", None) is None
    assert getattr(ip, "is_tor", None) is None
    assert getattr(ip, "is_relay", None) is None


def test_converting_missing_ip_details() -> None:
    from arcjet._convert import _ip_details_from_proto

    assert _ip_details_from_proto(None) is None


def test_converting_unsupported_reason_type() -> None:
    """Test that unsupported reason types return ErrorReason."""
    from arcjet._convert import _reason_from_proto
    from arcjet.dataclasses import ErrorReason
    from arcjet.proto.decide.v1alpha1 import decide_pb2

    # Create a Reason with no fields set
    proto_reason = decide_pb2.Reason()

    reason = _reason_from_proto(proto_reason)

    assert isinstance(reason, ErrorReason)
    assert reason.type == "ERROR"
    assert "unsupported" in reason.message.lower()

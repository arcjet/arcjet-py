from collections.abc import Sequence
from datetime import timedelta, timezone
from typing import Any

from google.protobuf.json_format import MessageToDict

from arcjet.proto.decide.v1alpha1 import decide_pb2

from .dataclasses import (
    BotReason,
    EmailReason,
    EmailType,
    ErrorReason,
    FilterReason,
    IpDetails,
    PromptInjectionDetectionReason,
    RateLimitReason,
    Reason,
    ShieldReason,
)


def _email_type_from_proto(proto: decide_pb2.EmailType) -> EmailType:
    """Convert a protobuf EmailType to a python EmailType."""

    if proto == decide_pb2.EmailType.EMAIL_TYPE_DISPOSABLE:
        return "DISPOSABLE"
    if proto == decide_pb2.EmailType.EMAIL_TYPE_FREE:
        return "FREE"
    if proto == decide_pb2.EmailType.EMAIL_TYPE_INVALID:
        return "INVALID"
    if proto == decide_pb2.EmailType.EMAIL_TYPE_NO_GRAVATAR:
        return "NO_GRAVATAR"
    if proto == decide_pb2.EmailType.EMAIL_TYPE_NO_MX_RECORDS:
        return "NO_MX_RECORDS"

    return "UNSPECIFIED"


def _reason_from_proto(proto: decide_pb2.Reason) -> Reason:
    """Convert a protobuf Reason to a python Reason."""

    if proto.HasField("bot_v2"):
        bot = proto.bot_v2

        return BotReason(
            allowed=list(bot.allowed),
            denied=list(bot.denied),
            spoofed=bot.spoofed,
            verified=bot.verified,
        )
    if proto.HasField("email"):
        email = proto.email

        email_types: Sequence[EmailType] = []
        for email_type_proto in email.email_types:
            email_types.append(_email_type_from_proto(email_type_proto))

        return EmailReason(
            email_types=email_types,
        )
    if proto.HasField("error"):
        error = proto.error

        return ErrorReason(
            message=error.message,
        )
    if proto.HasField("filter"):
        filter = proto.filter

        return FilterReason(
            matched_expressions=list(filter.matched_expressions),
            undetermined_expressions=list(filter.undetermined_expressions),
        )
    if proto.HasField("rate_limit"):
        rate_limit = proto.rate_limit

        reset_time = None
        if rate_limit.HasField("reset_time"):
            reset_time = rate_limit.reset_time.ToDatetime(tzinfo=timezone.utc)

        return RateLimitReason(
            max=rate_limit.max,
            remaining=rate_limit.remaining,
            reset_time=reset_time,
            reset=timedelta(seconds=rate_limit.reset_in_seconds),
            window=timedelta(seconds=rate_limit.window_in_seconds),
        )
    if proto.HasField("shield"):
        shield = proto.shield

        return ShieldReason(
            shield_triggered=shield.shield_triggered,
        )
    if proto.HasField("prompt_injection_detection"):
        pid = proto.prompt_injection_detection

        return PromptInjectionDetectionReason(
            injection_detected=pid.injection_detected,
            score=pid.score,
        )

    # Handle unexpected reason types by returning an ErrorReason

    if proto.HasField("bot"):
        return ErrorReason(
            message='decide_pb2.Reason(type="bot") is unsupported (use "bot_v2" instead).',
        )
    if proto.HasField("edge_rule"):
        return ErrorReason(
            message='decide_pb2.Reason(type="edge_rule") is unsupported.',
        )

    reason = proto.WhichOneof("reason")
    if reason is not None and type(reason) is str:
        return ErrorReason(
            message=f'decide_pb2.Reason(type="{reason}") is unsupported.',
        )
    return ErrorReason(
        message="decide_pb2.Reason(type=unknown) is unsupported.",
    )


def _ip_details_from_proto(proto: decide_pb2.IpDetails | None) -> IpDetails | None:
    """Convert protobuf IpDetails to typed IpDetails.

    Returns ``None`` when no IP details are present.
    """
    if proto is None:
        return None

    data: dict[str, Any] = MessageToDict(
        proto,
        preserving_proto_field_name=True,
    )

    return IpDetails(
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        accuracy_radius=data.get("accuracy_radius"),
        timezone=data.get("timezone"),
        postal_code=data.get("postal_code"),
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country"),
        country_name=data.get("country_name"),
        continent=data.get("continent"),
        continent_name=data.get("continent_name"),
        asn=data.get("asn"),
        asn_name=data.get("asn_name"),
        asn_domain=data.get("asn_domain"),
        asn_type=data.get("asn_type"),
        asn_country=data.get("asn_country"),
        service=data.get("service"),
        is_hosting=data.get("is_hosting"),
        is_vpn=data.get("is_vpn"),
        is_proxy=data.get("is_proxy"),
        is_tor=data.get("is_tor"),
        is_relay=data.get("is_relay"),
    )

import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class BotType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BOT_TYPE_UNSPECIFIED: _ClassVar[BotType]
    BOT_TYPE_NOT_ANALYZED: _ClassVar[BotType]
    BOT_TYPE_AUTOMATED: _ClassVar[BotType]
    BOT_TYPE_LIKELY_AUTOMATED: _ClassVar[BotType]
    BOT_TYPE_LIKELY_NOT_A_BOT: _ClassVar[BotType]
    BOT_TYPE_VERIFIED_BOT: _ClassVar[BotType]

class EmailType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EMAIL_TYPE_UNSPECIFIED: _ClassVar[EmailType]
    EMAIL_TYPE_DISPOSABLE: _ClassVar[EmailType]
    EMAIL_TYPE_FREE: _ClassVar[EmailType]
    EMAIL_TYPE_NO_MX_RECORDS: _ClassVar[EmailType]
    EMAIL_TYPE_NO_GRAVATAR: _ClassVar[EmailType]
    EMAIL_TYPE_INVALID: _ClassVar[EmailType]

class Mode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MODE_UNSPECIFIED: _ClassVar[Mode]
    MODE_DRY_RUN: _ClassVar[Mode]
    MODE_LIVE: _ClassVar[Mode]

class RuleState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RULE_STATE_UNSPECIFIED: _ClassVar[RuleState]
    RULE_STATE_RUN: _ClassVar[RuleState]
    RULE_STATE_NOT_RUN: _ClassVar[RuleState]
    RULE_STATE_DRY_RUN: _ClassVar[RuleState]
    RULE_STATE_CACHED: _ClassVar[RuleState]

class Conclusion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONCLUSION_UNSPECIFIED: _ClassVar[Conclusion]
    CONCLUSION_ALLOW: _ClassVar[Conclusion]
    CONCLUSION_DENY: _ClassVar[Conclusion]
    CONCLUSION_CHALLENGE: _ClassVar[Conclusion]
    CONCLUSION_ERROR: _ClassVar[Conclusion]

class SDKStack(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SDK_STACK_UNSPECIFIED: _ClassVar[SDKStack]
    SDK_STACK_NODEJS: _ClassVar[SDKStack]
    SDK_STACK_NEXTJS: _ClassVar[SDKStack]
    SDK_STACK_PYTHON: _ClassVar[SDKStack]
    SDK_STACK_DJANGO: _ClassVar[SDKStack]
    SDK_STACK_BUN: _ClassVar[SDKStack]
    SDK_STACK_DENO: _ClassVar[SDKStack]
    SDK_STACK_SVELTEKIT: _ClassVar[SDKStack]
    SDK_STACK_HONO: _ClassVar[SDKStack]
    SDK_STACK_NUXT: _ClassVar[SDKStack]
    SDK_STACK_NESTJS: _ClassVar[SDKStack]
    SDK_STACK_REMIX: _ClassVar[SDKStack]
    SDK_STACK_ASTRO: _ClassVar[SDKStack]
    SDK_STACK_FASTIFY: _ClassVar[SDKStack]
    SDK_STACK_REACT_ROUTER: _ClassVar[SDKStack]

class RateLimitAlgorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RATE_LIMIT_ALGORITHM_UNSPECIFIED: _ClassVar[RateLimitAlgorithm]
    RATE_LIMIT_ALGORITHM_TOKEN_BUCKET: _ClassVar[RateLimitAlgorithm]
    RATE_LIMIT_ALGORITHM_FIXED_WINDOW: _ClassVar[RateLimitAlgorithm]
    RATE_LIMIT_ALGORITHM_SLIDING_WINDOW: _ClassVar[RateLimitAlgorithm]

class RateLimitRuleVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RATE_LIMIT_RULE_VERSION_UNSPECIFIED: _ClassVar[RateLimitRuleVersion]

class BotV2RuleVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BOT_V2_RULE_VERSION_UNSPECIFIED: _ClassVar[BotV2RuleVersion]

class EmailRuleVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EMAIL_RULE_VERSION_UNSPECIFIED: _ClassVar[EmailRuleVersion]

class SensitiveInfoRuleVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SENSITIVE_INFO_RULE_VERSION_UNSPECIFIED: _ClassVar[SensitiveInfoRuleVersion]

class ShieldRuleVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SHIELD_RULE_VERSION_UNSPECIFIED: _ClassVar[ShieldRuleVersion]

class FilterRuleVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FILTER_RULE_VERSION_UNSPECIFIED: _ClassVar[FilterRuleVersion]

BOT_TYPE_UNSPECIFIED: BotType
BOT_TYPE_NOT_ANALYZED: BotType
BOT_TYPE_AUTOMATED: BotType
BOT_TYPE_LIKELY_AUTOMATED: BotType
BOT_TYPE_LIKELY_NOT_A_BOT: BotType
BOT_TYPE_VERIFIED_BOT: BotType
EMAIL_TYPE_UNSPECIFIED: EmailType
EMAIL_TYPE_DISPOSABLE: EmailType
EMAIL_TYPE_FREE: EmailType
EMAIL_TYPE_NO_MX_RECORDS: EmailType
EMAIL_TYPE_NO_GRAVATAR: EmailType
EMAIL_TYPE_INVALID: EmailType
MODE_UNSPECIFIED: Mode
MODE_DRY_RUN: Mode
MODE_LIVE: Mode
RULE_STATE_UNSPECIFIED: RuleState
RULE_STATE_RUN: RuleState
RULE_STATE_NOT_RUN: RuleState
RULE_STATE_DRY_RUN: RuleState
RULE_STATE_CACHED: RuleState
CONCLUSION_UNSPECIFIED: Conclusion
CONCLUSION_ALLOW: Conclusion
CONCLUSION_DENY: Conclusion
CONCLUSION_CHALLENGE: Conclusion
CONCLUSION_ERROR: Conclusion
SDK_STACK_UNSPECIFIED: SDKStack
SDK_STACK_NODEJS: SDKStack
SDK_STACK_NEXTJS: SDKStack
SDK_STACK_PYTHON: SDKStack
SDK_STACK_DJANGO: SDKStack
SDK_STACK_BUN: SDKStack
SDK_STACK_DENO: SDKStack
SDK_STACK_SVELTEKIT: SDKStack
SDK_STACK_HONO: SDKStack
SDK_STACK_NUXT: SDKStack
SDK_STACK_NESTJS: SDKStack
SDK_STACK_REMIX: SDKStack
SDK_STACK_ASTRO: SDKStack
SDK_STACK_FASTIFY: SDKStack
SDK_STACK_REACT_ROUTER: SDKStack
RATE_LIMIT_ALGORITHM_UNSPECIFIED: RateLimitAlgorithm
RATE_LIMIT_ALGORITHM_TOKEN_BUCKET: RateLimitAlgorithm
RATE_LIMIT_ALGORITHM_FIXED_WINDOW: RateLimitAlgorithm
RATE_LIMIT_ALGORITHM_SLIDING_WINDOW: RateLimitAlgorithm
RATE_LIMIT_RULE_VERSION_UNSPECIFIED: RateLimitRuleVersion
BOT_V2_RULE_VERSION_UNSPECIFIED: BotV2RuleVersion
EMAIL_RULE_VERSION_UNSPECIFIED: EmailRuleVersion
SENSITIVE_INFO_RULE_VERSION_UNSPECIFIED: SensitiveInfoRuleVersion
SHIELD_RULE_VERSION_UNSPECIFIED: ShieldRuleVersion
FILTER_RULE_VERSION_UNSPECIFIED: FilterRuleVersion

class IpDetails(_message.Message):
    __slots__ = ()
    LATITUDE_FIELD_NUMBER: _ClassVar[int]
    LONGITUDE_FIELD_NUMBER: _ClassVar[int]
    ACCURACY_RADIUS_FIELD_NUMBER: _ClassVar[int]
    TIMEZONE_FIELD_NUMBER: _ClassVar[int]
    POSTAL_CODE_FIELD_NUMBER: _ClassVar[int]
    CITY_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_NAME_FIELD_NUMBER: _ClassVar[int]
    CONTINENT_FIELD_NUMBER: _ClassVar[int]
    CONTINENT_NAME_FIELD_NUMBER: _ClassVar[int]
    ASN_FIELD_NUMBER: _ClassVar[int]
    ASN_NAME_FIELD_NUMBER: _ClassVar[int]
    ASN_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ASN_TYPE_FIELD_NUMBER: _ClassVar[int]
    ASN_COUNTRY_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    IS_HOSTING_FIELD_NUMBER: _ClassVar[int]
    IS_VPN_FIELD_NUMBER: _ClassVar[int]
    IS_PROXY_FIELD_NUMBER: _ClassVar[int]
    IS_TOR_FIELD_NUMBER: _ClassVar[int]
    IS_RELAY_FIELD_NUMBER: _ClassVar[int]
    latitude: float
    longitude: float
    accuracy_radius: int
    timezone: str
    postal_code: str
    city: str
    region: str
    country: str
    country_name: str
    continent: str
    continent_name: str
    asn: str
    asn_name: str
    asn_domain: str
    asn_type: str
    asn_country: str
    service: str
    is_hosting: bool
    is_vpn: bool
    is_proxy: bool
    is_tor: bool
    is_relay: bool
    def __init__(
        self,
        latitude: _Optional[float] = ...,
        longitude: _Optional[float] = ...,
        accuracy_radius: _Optional[int] = ...,
        timezone: _Optional[str] = ...,
        postal_code: _Optional[str] = ...,
        city: _Optional[str] = ...,
        region: _Optional[str] = ...,
        country: _Optional[str] = ...,
        country_name: _Optional[str] = ...,
        continent: _Optional[str] = ...,
        continent_name: _Optional[str] = ...,
        asn: _Optional[str] = ...,
        asn_name: _Optional[str] = ...,
        asn_domain: _Optional[str] = ...,
        asn_type: _Optional[str] = ...,
        asn_country: _Optional[str] = ...,
        service: _Optional[str] = ...,
        is_hosting: _Optional[bool] = ...,
        is_vpn: _Optional[bool] = ...,
        is_proxy: _Optional[bool] = ...,
        is_tor: _Optional[bool] = ...,
        is_relay: _Optional[bool] = ...,
    ) -> None: ...

class Reason(_message.Message):
    __slots__ = ()
    RATE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    EDGE_RULE_FIELD_NUMBER: _ClassVar[int]
    BOT_FIELD_NUMBER: _ClassVar[int]
    SHIELD_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    BOT_V2_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    rate_limit: RateLimitReason
    edge_rule: EdgeRuleReason
    bot: BotReason
    shield: ShieldReason
    email: EmailReason
    error: ErrorReason
    sensitive_info: SensitiveInfoReason
    bot_v2: BotV2Reason
    filter: FilterReason
    def __init__(
        self,
        rate_limit: _Optional[_Union[RateLimitReason, _Mapping]] = ...,
        edge_rule: _Optional[_Union[EdgeRuleReason, _Mapping]] = ...,
        bot: _Optional[_Union[BotReason, _Mapping]] = ...,
        shield: _Optional[_Union[ShieldReason, _Mapping]] = ...,
        email: _Optional[_Union[EmailReason, _Mapping]] = ...,
        error: _Optional[_Union[ErrorReason, _Mapping]] = ...,
        sensitive_info: _Optional[_Union[SensitiveInfoReason, _Mapping]] = ...,
        bot_v2: _Optional[_Union[BotV2Reason, _Mapping]] = ...,
        filter: _Optional[_Union[FilterReason, _Mapping]] = ...,
    ) -> None: ...

class RateLimitReason(_message.Message):
    __slots__ = ()
    MAX_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    REMAINING_FIELD_NUMBER: _ClassVar[int]
    RESET_TIME_FIELD_NUMBER: _ClassVar[int]
    RESET_IN_SECONDS_FIELD_NUMBER: _ClassVar[int]
    WINDOW_IN_SECONDS_FIELD_NUMBER: _ClassVar[int]
    max: int
    count: int
    remaining: int
    reset_time: _timestamp_pb2.Timestamp
    reset_in_seconds: int
    window_in_seconds: int
    def __init__(
        self,
        max: _Optional[int] = ...,
        count: _Optional[int] = ...,
        remaining: _Optional[int] = ...,
        reset_time: _Optional[
            _Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]
        ] = ...,
        reset_in_seconds: _Optional[int] = ...,
        window_in_seconds: _Optional[int] = ...,
    ) -> None: ...

class EdgeRuleReason(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BotReason(_message.Message):
    __slots__ = ()
    BOT_TYPE_FIELD_NUMBER: _ClassVar[int]
    BOT_SCORE_FIELD_NUMBER: _ClassVar[int]
    USER_AGENT_MATCH_FIELD_NUMBER: _ClassVar[int]
    IP_HOSTING_FIELD_NUMBER: _ClassVar[int]
    IP_VPN_FIELD_NUMBER: _ClassVar[int]
    IP_PROXY_FIELD_NUMBER: _ClassVar[int]
    IP_TOR_FIELD_NUMBER: _ClassVar[int]
    IP_RELAY_FIELD_NUMBER: _ClassVar[int]
    bot_type: BotType
    bot_score: int
    user_agent_match: bool
    ip_hosting: bool
    ip_vpn: bool
    ip_proxy: bool
    ip_tor: bool
    ip_relay: bool
    def __init__(
        self,
        bot_type: _Optional[_Union[BotType, str]] = ...,
        bot_score: _Optional[int] = ...,
        user_agent_match: _Optional[bool] = ...,
        ip_hosting: _Optional[bool] = ...,
        ip_vpn: _Optional[bool] = ...,
        ip_proxy: _Optional[bool] = ...,
        ip_tor: _Optional[bool] = ...,
        ip_relay: _Optional[bool] = ...,
    ) -> None: ...

class BotV2Reason(_message.Message):
    __slots__ = ()
    ALLOWED_FIELD_NUMBER: _ClassVar[int]
    DENIED_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_FIELD_NUMBER: _ClassVar[int]
    SPOOFED_FIELD_NUMBER: _ClassVar[int]
    allowed: _containers.RepeatedScalarFieldContainer[str]
    denied: _containers.RepeatedScalarFieldContainer[str]
    verified: bool
    spoofed: bool
    def __init__(
        self,
        allowed: _Optional[_Iterable[str]] = ...,
        denied: _Optional[_Iterable[str]] = ...,
        verified: _Optional[bool] = ...,
        spoofed: _Optional[bool] = ...,
    ) -> None: ...

class ShieldReason(_message.Message):
    __slots__ = ()
    SHIELD_TRIGGERED_FIELD_NUMBER: _ClassVar[int]
    SUSPICIOUS_FIELD_NUMBER: _ClassVar[int]
    shield_triggered: bool
    suspicious: bool
    def __init__(
        self, shield_triggered: _Optional[bool] = ..., suspicious: _Optional[bool] = ...
    ) -> None: ...

class FilterReason(_message.Message):
    __slots__ = ()
    MATCHED_EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    MATCHED_EXPRESSIONS_FIELD_NUMBER: _ClassVar[int]
    UNDETERMINED_EXPRESSIONS_FIELD_NUMBER: _ClassVar[int]
    matched_expression: str
    matched_expressions: _containers.RepeatedScalarFieldContainer[str]
    undetermined_expressions: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        matched_expression: _Optional[str] = ...,
        matched_expressions: _Optional[_Iterable[str]] = ...,
        undetermined_expressions: _Optional[_Iterable[str]] = ...,
    ) -> None: ...

class EmailReason(_message.Message):
    __slots__ = ()
    EMAIL_TYPES_FIELD_NUMBER: _ClassVar[int]
    email_types: _containers.RepeatedScalarFieldContainer[EmailType]
    def __init__(
        self, email_types: _Optional[_Iterable[_Union[EmailType, str]]] = ...
    ) -> None: ...

class ErrorReason(_message.Message):
    __slots__ = ()
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class IdentifiedEntity(_message.Message):
    __slots__ = ()
    IDENTIFIED_TYPE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    identified_type: str
    start: int
    end: int
    def __init__(
        self,
        identified_type: _Optional[str] = ...,
        start: _Optional[int] = ...,
        end: _Optional[int] = ...,
    ) -> None: ...

class SensitiveInfoReason(_message.Message):
    __slots__ = ()
    ALLOWED_FIELD_NUMBER: _ClassVar[int]
    DENIED_FIELD_NUMBER: _ClassVar[int]
    allowed: _containers.RepeatedCompositeFieldContainer[IdentifiedEntity]
    denied: _containers.RepeatedCompositeFieldContainer[IdentifiedEntity]
    def __init__(
        self,
        allowed: _Optional[_Iterable[_Union[IdentifiedEntity, _Mapping]]] = ...,
        denied: _Optional[_Iterable[_Union[IdentifiedEntity, _Mapping]]] = ...,
    ) -> None: ...

class RateLimitRule(_message.Message):
    __slots__ = ()
    MODE_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTICS_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    REFILL_RATE_FIELD_NUMBER: _ClassVar[int]
    INTERVAL_FIELD_NUMBER: _ClassVar[int]
    CAPACITY_FIELD_NUMBER: _ClassVar[int]
    WINDOW_IN_SECONDS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    match: str
    characteristics: _containers.RepeatedScalarFieldContainer[str]
    window: str
    max: int
    timeout: str
    algorithm: RateLimitAlgorithm
    refill_rate: int
    interval: int
    capacity: int
    window_in_seconds: int
    version: RateLimitRuleVersion
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        match: _Optional[str] = ...,
        characteristics: _Optional[_Iterable[str]] = ...,
        window: _Optional[str] = ...,
        max: _Optional[int] = ...,
        timeout: _Optional[str] = ...,
        algorithm: _Optional[_Union[RateLimitAlgorithm, str]] = ...,
        refill_rate: _Optional[int] = ...,
        interval: _Optional[int] = ...,
        capacity: _Optional[int] = ...,
        window_in_seconds: _Optional[int] = ...,
        version: _Optional[_Union[RateLimitRuleVersion, str]] = ...,
    ) -> None: ...

class BotRule(_message.Message):
    __slots__ = ()

    class Patterns(_message.Message):
        __slots__ = ()

        class AddEntry(_message.Message):
            __slots__ = ()
            KEY_FIELD_NUMBER: _ClassVar[int]
            VALUE_FIELD_NUMBER: _ClassVar[int]
            key: str
            value: BotType
            def __init__(
                self,
                key: _Optional[str] = ...,
                value: _Optional[_Union[BotType, str]] = ...,
            ) -> None: ...

        ADD_FIELD_NUMBER: _ClassVar[int]
        REMOVE_FIELD_NUMBER: _ClassVar[int]
        add: _containers.ScalarMap[str, BotType]
        remove: _containers.RepeatedScalarFieldContainer[str]
        def __init__(
            self,
            add: _Optional[_Mapping[str, BotType]] = ...,
            remove: _Optional[_Iterable[str]] = ...,
        ) -> None: ...

    MODE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    PATTERNS_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    block: _containers.RepeatedScalarFieldContainer[BotType]
    patterns: BotRule.Patterns
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        block: _Optional[_Iterable[_Union[BotType, str]]] = ...,
        patterns: _Optional[_Union[BotRule.Patterns, _Mapping]] = ...,
    ) -> None: ...

class BotV2Rule(_message.Message):
    __slots__ = ()
    MODE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    DENY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    allow: _containers.RepeatedScalarFieldContainer[str]
    deny: _containers.RepeatedScalarFieldContainer[str]
    version: BotV2RuleVersion
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        allow: _Optional[_Iterable[str]] = ...,
        deny: _Optional[_Iterable[str]] = ...,
        version: _Optional[_Union[BotV2RuleVersion, str]] = ...,
    ) -> None: ...

class EmailRule(_message.Message):
    __slots__ = ()
    MODE_FIELD_NUMBER: _ClassVar[int]
    BLOCK_FIELD_NUMBER: _ClassVar[int]
    REQUIRE_TOP_LEVEL_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ALLOW_DOMAIN_LITERAL_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    DENY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    block: _containers.RepeatedScalarFieldContainer[EmailType]
    require_top_level_domain: bool
    allow_domain_literal: bool
    allow: _containers.RepeatedScalarFieldContainer[EmailType]
    deny: _containers.RepeatedScalarFieldContainer[EmailType]
    version: EmailRuleVersion
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        block: _Optional[_Iterable[_Union[EmailType, str]]] = ...,
        require_top_level_domain: _Optional[bool] = ...,
        allow_domain_literal: _Optional[bool] = ...,
        allow: _Optional[_Iterable[_Union[EmailType, str]]] = ...,
        deny: _Optional[_Iterable[_Union[EmailType, str]]] = ...,
        version: _Optional[_Union[EmailRuleVersion, str]] = ...,
    ) -> None: ...

class SensitiveInfoRule(_message.Message):
    __slots__ = ()
    MODE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    DENY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    allow: _containers.RepeatedScalarFieldContainer[str]
    deny: _containers.RepeatedScalarFieldContainer[str]
    version: SensitiveInfoRuleVersion
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        allow: _Optional[_Iterable[str]] = ...,
        deny: _Optional[_Iterable[str]] = ...,
        version: _Optional[_Union[SensitiveInfoRuleVersion, str]] = ...,
    ) -> None: ...

class ShieldRule(_message.Message):
    __slots__ = ()
    MODE_FIELD_NUMBER: _ClassVar[int]
    AUTO_ADDED_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTICS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    auto_added: bool
    characteristics: _containers.RepeatedScalarFieldContainer[str]
    version: ShieldRuleVersion
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        auto_added: _Optional[bool] = ...,
        characteristics: _Optional[_Iterable[str]] = ...,
        version: _Optional[_Union[ShieldRuleVersion, str]] = ...,
    ) -> None: ...

class FilterRule(_message.Message):
    __slots__ = ()
    MODE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    DENY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    mode: Mode
    allow: _containers.RepeatedScalarFieldContainer[str]
    deny: _containers.RepeatedScalarFieldContainer[str]
    version: FilterRuleVersion
    def __init__(
        self,
        mode: _Optional[_Union[Mode, str]] = ...,
        allow: _Optional[_Iterable[str]] = ...,
        deny: _Optional[_Iterable[str]] = ...,
        version: _Optional[_Union[FilterRuleVersion, str]] = ...,
    ) -> None: ...

class Rule(_message.Message):
    __slots__ = ()
    RATE_LIMIT_FIELD_NUMBER: _ClassVar[int]
    BOTS_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    SHIELD_FIELD_NUMBER: _ClassVar[int]
    SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    BOT_V2_FIELD_NUMBER: _ClassVar[int]
    FILTER_FIELD_NUMBER: _ClassVar[int]
    rate_limit: RateLimitRule
    bots: BotRule
    email: EmailRule
    shield: ShieldRule
    sensitive_info: SensitiveInfoRule
    bot_v2: BotV2Rule
    filter: FilterRule
    def __init__(
        self,
        rate_limit: _Optional[_Union[RateLimitRule, _Mapping]] = ...,
        bots: _Optional[_Union[BotRule, _Mapping]] = ...,
        email: _Optional[_Union[EmailRule, _Mapping]] = ...,
        shield: _Optional[_Union[ShieldRule, _Mapping]] = ...,
        sensitive_info: _Optional[_Union[SensitiveInfoRule, _Mapping]] = ...,
        bot_v2: _Optional[_Union[BotV2Rule, _Mapping]] = ...,
        filter: _Optional[_Union[FilterRule, _Mapping]] = ...,
    ) -> None: ...

class RuleResult(_message.Message):
    __slots__ = ()
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    state: RuleState
    conclusion: Conclusion
    reason: Reason
    ttl: int
    fingerprint: str
    def __init__(
        self,
        rule_id: _Optional[str] = ...,
        state: _Optional[_Union[RuleState, str]] = ...,
        conclusion: _Optional[_Union[Conclusion, str]] = ...,
        reason: _Optional[_Union[Reason, _Mapping]] = ...,
        ttl: _Optional[int] = ...,
        fingerprint: _Optional[str] = ...,
    ) -> None: ...

class RequestDetails(_message.Message):
    __slots__ = ()

    class HeadersEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(
            self, key: _Optional[str] = ..., value: _Optional[str] = ...
        ) -> None: ...

    class ExtraEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(
            self, key: _Optional[str] = ..., value: _Optional[str] = ...
        ) -> None: ...

    IP_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    EXTRA_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    COOKIES_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    ip: str
    method: str
    protocol: str
    host: str
    path: str
    headers: _containers.ScalarMap[str, str]
    body: bytes
    extra: _containers.ScalarMap[str, str]
    email: str
    cookies: str
    query: str
    def __init__(
        self,
        ip: _Optional[str] = ...,
        method: _Optional[str] = ...,
        protocol: _Optional[str] = ...,
        host: _Optional[str] = ...,
        path: _Optional[str] = ...,
        headers: _Optional[_Mapping[str, str]] = ...,
        body: _Optional[bytes] = ...,
        extra: _Optional[_Mapping[str, str]] = ...,
        email: _Optional[str] = ...,
        cookies: _Optional[str] = ...,
        query: _Optional[str] = ...,
    ) -> None: ...

class Decision(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    RULE_RESULTS_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    IP_DETAILS_FIELD_NUMBER: _ClassVar[int]
    id: str
    conclusion: Conclusion
    reason: Reason
    rule_results: _containers.RepeatedCompositeFieldContainer[RuleResult]
    ttl: int
    ip_details: IpDetails
    def __init__(
        self,
        id: _Optional[str] = ...,
        conclusion: _Optional[_Union[Conclusion, str]] = ...,
        reason: _Optional[_Union[Reason, _Mapping]] = ...,
        rule_results: _Optional[_Iterable[_Union[RuleResult, _Mapping]]] = ...,
        ttl: _Optional[int] = ...,
        ip_details: _Optional[_Union[IpDetails, _Mapping]] = ...,
    ) -> None: ...

class DecideRequest(_message.Message):
    __slots__ = ()
    SDK_STACK_FIELD_NUMBER: _ClassVar[int]
    SDK_VERSION_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTICS_FIELD_NUMBER: _ClassVar[int]
    sdk_stack: SDKStack
    sdk_version: str
    details: RequestDetails
    rules: _containers.RepeatedCompositeFieldContainer[Rule]
    characteristics: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        sdk_stack: _Optional[_Union[SDKStack, str]] = ...,
        sdk_version: _Optional[str] = ...,
        details: _Optional[_Union[RequestDetails, _Mapping]] = ...,
        rules: _Optional[_Iterable[_Union[Rule, _Mapping]]] = ...,
        characteristics: _Optional[_Iterable[str]] = ...,
    ) -> None: ...

class DecideResponse(_message.Message):
    __slots__ = ()

    class ExtraEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(
            self, key: _Optional[str] = ..., value: _Optional[str] = ...
        ) -> None: ...

    DECISION_FIELD_NUMBER: _ClassVar[int]
    EXTRA_FIELD_NUMBER: _ClassVar[int]
    decision: Decision
    extra: _containers.ScalarMap[str, str]
    def __init__(
        self,
        decision: _Optional[_Union[Decision, _Mapping]] = ...,
        extra: _Optional[_Mapping[str, str]] = ...,
    ) -> None: ...

class ReportRequest(_message.Message):
    __slots__ = ()
    SDK_STACK_FIELD_NUMBER: _ClassVar[int]
    SDK_VERSION_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTICS_FIELD_NUMBER: _ClassVar[int]
    sdk_stack: SDKStack
    sdk_version: str
    details: RequestDetails
    decision: Decision
    rules: _containers.RepeatedCompositeFieldContainer[Rule]
    characteristics: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        sdk_stack: _Optional[_Union[SDKStack, str]] = ...,
        sdk_version: _Optional[str] = ...,
        details: _Optional[_Union[RequestDetails, _Mapping]] = ...,
        decision: _Optional[_Union[Decision, _Mapping]] = ...,
        rules: _Optional[_Iterable[_Union[Rule, _Mapping]]] = ...,
        characteristics: _Optional[_Iterable[str]] = ...,
    ) -> None: ...

class ReportResponse(_message.Message):
    __slots__ = ()

    class ExtraEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(
            self, key: _Optional[str] = ..., value: _Optional[str] = ...
        ) -> None: ...

    EXTRA_FIELD_NUMBER: _ClassVar[int]
    extra: _containers.ScalarMap[str, str]
    def __init__(self, extra: _Optional[_Mapping[str, str]] = ...) -> None: ...

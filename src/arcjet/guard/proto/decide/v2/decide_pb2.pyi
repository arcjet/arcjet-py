from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GuardConclusion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_CONCLUSION_UNSPECIFIED: _ClassVar[GuardConclusion]
    GUARD_CONCLUSION_ALLOW: _ClassVar[GuardConclusion]
    GUARD_CONCLUSION_DENY: _ClassVar[GuardConclusion]

class GuardReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_REASON_UNSPECIFIED: _ClassVar[GuardReason]
    GUARD_REASON_ERROR: _ClassVar[GuardReason]
    GUARD_REASON_NOT_RUN: _ClassVar[GuardReason]
    GUARD_REASON_CUSTOM: _ClassVar[GuardReason]
    GUARD_REASON_RATE_LIMIT: _ClassVar[GuardReason]
    GUARD_REASON_PROMPT_INJECTION: _ClassVar[GuardReason]
    GUARD_REASON_SENSITIVE_INFO: _ClassVar[GuardReason]
    GUARD_REASON_MODERATE_CONTENT: _ClassVar[GuardReason]
    GUARD_REASON_INPUT_CONSTRAINT: _ClassVar[GuardReason]

class GuardRuleType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_RULE_TYPE_UNSPECIFIED: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_TOKEN_BUCKET: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_FIXED_WINDOW: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_SLIDING_WINDOW: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_PROMPT_INJECTION: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_MODERATE_CONTENT: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_ALLOWED_STRING_VALUES: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_DENIED_STRING_VALUES: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_STRING_LENGTH: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_STRING_LIST_MEMBERSHIP: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_LOCAL_CUSTOM: _ClassVar[GuardRuleType]

class GuardRuleMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_RULE_MODE_UNSPECIFIED: _ClassVar[GuardRuleMode]
    GUARD_RULE_MODE_LIVE: _ClassVar[GuardRuleMode]
    GUARD_RULE_MODE_DRY_RUN: _ClassVar[GuardRuleMode]

class GuardRuleSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_RULE_SOURCE_UNSPECIFIED: _ClassVar[GuardRuleSource]
    GUARD_RULE_SOURCE_SDK: _ClassVar[GuardRuleSource]
    GUARD_RULE_SOURCE_REMOTE: _ClassVar[GuardRuleSource]

class GuardRuleExecution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_RULE_EXECUTION_UNSPECIFIED: _ClassVar[GuardRuleExecution]
    GUARD_RULE_EXECUTION_SDK: _ClassVar[GuardRuleExecution]
    GUARD_RULE_EXECUTION_SERVER: _ClassVar[GuardRuleExecution]

class GuardStringMatchOperator(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_STRING_MATCH_OPERATOR_UNSPECIFIED: _ClassVar[GuardStringMatchOperator]
    GUARD_STRING_MATCH_OPERATOR_EXACT: _ClassVar[GuardStringMatchOperator]
    GUARD_STRING_MATCH_OPERATOR_EMAIL_DOMAIN: _ClassVar[GuardStringMatchOperator]

class GuardPolicyInputKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_INPUT_KIND_UNSPECIFIED: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_STRING: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_BOOLEAN: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_INTEGER: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_NUMBER: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_STRING_LIST: _ClassVar[GuardPolicyInputKind]

class GuardPolicyStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_STATUS_UNSPECIFIED: _ClassVar[GuardPolicyStatus]
    GUARD_POLICY_STATUS_NOT_CONFIGURED: _ClassVar[GuardPolicyStatus]
    GUARD_POLICY_STATUS_APPLIED: _ClassVar[GuardPolicyStatus]
    GUARD_POLICY_STATUS_INCOMPLETE: _ClassVar[GuardPolicyStatus]
    GUARD_POLICY_STATUS_UNAVAILABLE: _ClassVar[GuardPolicyStatus]

class GuardPolicyLookupStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_LOOKUP_STATUS_UNSPECIFIED: _ClassVar[GuardPolicyLookupStatus]
    GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED: _ClassVar[GuardPolicyLookupStatus]
    GUARD_POLICY_LOOKUP_STATUS_AVAILABLE: _ClassVar[GuardPolicyLookupStatus]
    GUARD_POLICY_LOOKUP_STATUS_UNAVAILABLE: _ClassVar[GuardPolicyLookupStatus]
GUARD_CONCLUSION_UNSPECIFIED: GuardConclusion
GUARD_CONCLUSION_ALLOW: GuardConclusion
GUARD_CONCLUSION_DENY: GuardConclusion
GUARD_REASON_UNSPECIFIED: GuardReason
GUARD_REASON_ERROR: GuardReason
GUARD_REASON_NOT_RUN: GuardReason
GUARD_REASON_CUSTOM: GuardReason
GUARD_REASON_RATE_LIMIT: GuardReason
GUARD_REASON_PROMPT_INJECTION: GuardReason
GUARD_REASON_SENSITIVE_INFO: GuardReason
GUARD_REASON_MODERATE_CONTENT: GuardReason
GUARD_REASON_INPUT_CONSTRAINT: GuardReason
GUARD_RULE_TYPE_UNSPECIFIED: GuardRuleType
GUARD_RULE_TYPE_TOKEN_BUCKET: GuardRuleType
GUARD_RULE_TYPE_FIXED_WINDOW: GuardRuleType
GUARD_RULE_TYPE_SLIDING_WINDOW: GuardRuleType
GUARD_RULE_TYPE_PROMPT_INJECTION: GuardRuleType
GUARD_RULE_TYPE_MODERATE_CONTENT: GuardRuleType
GUARD_RULE_TYPE_ALLOWED_STRING_VALUES: GuardRuleType
GUARD_RULE_TYPE_DENIED_STRING_VALUES: GuardRuleType
GUARD_RULE_TYPE_STRING_LENGTH: GuardRuleType
GUARD_RULE_TYPE_STRING_LIST_MEMBERSHIP: GuardRuleType
GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO: GuardRuleType
GUARD_RULE_TYPE_LOCAL_CUSTOM: GuardRuleType
GUARD_RULE_MODE_UNSPECIFIED: GuardRuleMode
GUARD_RULE_MODE_LIVE: GuardRuleMode
GUARD_RULE_MODE_DRY_RUN: GuardRuleMode
GUARD_RULE_SOURCE_UNSPECIFIED: GuardRuleSource
GUARD_RULE_SOURCE_SDK: GuardRuleSource
GUARD_RULE_SOURCE_REMOTE: GuardRuleSource
GUARD_RULE_EXECUTION_UNSPECIFIED: GuardRuleExecution
GUARD_RULE_EXECUTION_SDK: GuardRuleExecution
GUARD_RULE_EXECUTION_SERVER: GuardRuleExecution
GUARD_STRING_MATCH_OPERATOR_UNSPECIFIED: GuardStringMatchOperator
GUARD_STRING_MATCH_OPERATOR_EXACT: GuardStringMatchOperator
GUARD_STRING_MATCH_OPERATOR_EMAIL_DOMAIN: GuardStringMatchOperator
GUARD_POLICY_INPUT_KIND_UNSPECIFIED: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_STRING: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_BOOLEAN: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_INTEGER: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_NUMBER: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_STRING_LIST: GuardPolicyInputKind
GUARD_POLICY_STATUS_UNSPECIFIED: GuardPolicyStatus
GUARD_POLICY_STATUS_NOT_CONFIGURED: GuardPolicyStatus
GUARD_POLICY_STATUS_APPLIED: GuardPolicyStatus
GUARD_POLICY_STATUS_INCOMPLETE: GuardPolicyStatus
GUARD_POLICY_STATUS_UNAVAILABLE: GuardPolicyStatus
GUARD_POLICY_LOOKUP_STATUS_UNSPECIFIED: GuardPolicyLookupStatus
GUARD_POLICY_LOOKUP_STATUS_NOT_CONFIGURED: GuardPolicyLookupStatus
GUARD_POLICY_LOOKUP_STATUS_AVAILABLE: GuardPolicyLookupStatus
GUARD_POLICY_LOOKUP_STATUS_UNAVAILABLE: GuardPolicyLookupStatus

class RuleTokenBucket(_message.Message):
    __slots__ = ()
    CONFIG_REFILL_RATE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_MAX_TOKENS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_BUCKET_FIELD_NUMBER: _ClassVar[int]
    INPUT_KEY_HASH_FIELD_NUMBER: _ClassVar[int]
    INPUT_REQUESTED_FIELD_NUMBER: _ClassVar[int]
    config_refill_rate: int
    config_interval_seconds: int
    config_max_tokens: int
    config_bucket: str
    input_key_hash: str
    input_requested: int
    def __init__(self, config_refill_rate: _Optional[int] = ..., config_interval_seconds: _Optional[int] = ..., config_max_tokens: _Optional[int] = ..., config_bucket: _Optional[str] = ..., input_key_hash: _Optional[str] = ..., input_requested: _Optional[int] = ...) -> None: ...

class RuleFixedWindow(_message.Message):
    __slots__ = ()
    CONFIG_MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_WINDOW_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_BUCKET_FIELD_NUMBER: _ClassVar[int]
    INPUT_KEY_HASH_FIELD_NUMBER: _ClassVar[int]
    INPUT_REQUESTED_FIELD_NUMBER: _ClassVar[int]
    config_max_requests: int
    config_window_seconds: int
    config_bucket: str
    input_key_hash: str
    input_requested: int
    def __init__(self, config_max_requests: _Optional[int] = ..., config_window_seconds: _Optional[int] = ..., config_bucket: _Optional[str] = ..., input_key_hash: _Optional[str] = ..., input_requested: _Optional[int] = ...) -> None: ...

class RuleSlidingWindow(_message.Message):
    __slots__ = ()
    CONFIG_MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_BUCKET_FIELD_NUMBER: _ClassVar[int]
    INPUT_KEY_HASH_FIELD_NUMBER: _ClassVar[int]
    INPUT_REQUESTED_FIELD_NUMBER: _ClassVar[int]
    config_max_requests: int
    config_interval_seconds: int
    config_bucket: str
    input_key_hash: str
    input_requested: int
    def __init__(self, config_max_requests: _Optional[int] = ..., config_interval_seconds: _Optional[int] = ..., config_bucket: _Optional[str] = ..., input_key_hash: _Optional[str] = ..., input_requested: _Optional[int] = ...) -> None: ...

class RuleDetectPromptInjection(_message.Message):
    __slots__ = ()
    INPUT_TEXT_FIELD_NUMBER: _ClassVar[int]
    input_text: str
    def __init__(self, input_text: _Optional[str] = ...) -> None: ...

class RuleModerateContent(_message.Message):
    __slots__ = ()
    INPUT_TEXT_FIELD_NUMBER: _ClassVar[int]
    input_text: str
    def __init__(self, input_text: _Optional[str] = ...) -> None: ...

class EntityList(_message.Message):
    __slots__ = ()
    ENTITIES_FIELD_NUMBER: _ClassVar[int]
    entities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, entities: _Optional[_Iterable[str]] = ...) -> None: ...

class RuleLocalSensitiveInfo(_message.Message):
    __slots__ = ()
    CONFIG_ENTITIES_ALLOW_FIELD_NUMBER: _ClassVar[int]
    CONFIG_ENTITIES_DENY_FIELD_NUMBER: _ClassVar[int]
    INPUT_TEXT_HASH_FIELD_NUMBER: _ClassVar[int]
    RESULT_COMPUTED_FIELD_NUMBER: _ClassVar[int]
    RESULT_ERROR_FIELD_NUMBER: _ClassVar[int]
    RESULT_NOT_RUN_FIELD_NUMBER: _ClassVar[int]
    RESULT_DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    config_entities_allow: EntityList
    config_entities_deny: EntityList
    input_text_hash: str
    result_computed: ResultLocalSensitiveInfo
    result_error: ResultError
    result_not_run: ResultNotRun
    result_duration_ms: int
    def __init__(self, config_entities_allow: _Optional[_Union[EntityList, _Mapping]] = ..., config_entities_deny: _Optional[_Union[EntityList, _Mapping]] = ..., input_text_hash: _Optional[str] = ..., result_computed: _Optional[_Union[ResultLocalSensitiveInfo, _Mapping]] = ..., result_error: _Optional[_Union[ResultError, _Mapping]] = ..., result_not_run: _Optional[_Union[ResultNotRun, _Mapping]] = ..., result_duration_ms: _Optional[int] = ...) -> None: ...

class RuleLocalCustom(_message.Message):
    __slots__ = ()
    class ConfigDataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class InputDataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CONFIG_DATA_FIELD_NUMBER: _ClassVar[int]
    INPUT_DATA_FIELD_NUMBER: _ClassVar[int]
    RESULT_COMPUTED_FIELD_NUMBER: _ClassVar[int]
    RESULT_ERROR_FIELD_NUMBER: _ClassVar[int]
    RESULT_NOT_RUN_FIELD_NUMBER: _ClassVar[int]
    RESULT_DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    config_data: _containers.ScalarMap[str, str]
    input_data: _containers.ScalarMap[str, str]
    result_computed: ResultLocalCustom
    result_error: ResultError
    result_not_run: ResultNotRun
    result_duration_ms: int
    def __init__(self, config_data: _Optional[_Mapping[str, str]] = ..., input_data: _Optional[_Mapping[str, str]] = ..., result_computed: _Optional[_Union[ResultLocalCustom, _Mapping]] = ..., result_error: _Optional[_Union[ResultError, _Mapping]] = ..., result_not_run: _Optional[_Union[ResultNotRun, _Mapping]] = ..., result_duration_ms: _Optional[int] = ...) -> None: ...

class GuardRule(_message.Message):
    __slots__ = ()
    TOKEN_BUCKET_FIELD_NUMBER: _ClassVar[int]
    FIXED_WINDOW_FIELD_NUMBER: _ClassVar[int]
    SLIDING_WINDOW_FIELD_NUMBER: _ClassVar[int]
    DETECT_PROMPT_INJECTION_FIELD_NUMBER: _ClassVar[int]
    MODERATE_CONTENT_FIELD_NUMBER: _ClassVar[int]
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    LOCAL_CUSTOM_FIELD_NUMBER: _ClassVar[int]
    token_bucket: RuleTokenBucket
    fixed_window: RuleFixedWindow
    sliding_window: RuleSlidingWindow
    detect_prompt_injection: RuleDetectPromptInjection
    moderate_content: RuleModerateContent
    local_sensitive_info: RuleLocalSensitiveInfo
    local_custom: RuleLocalCustom
    def __init__(self, token_bucket: _Optional[_Union[RuleTokenBucket, _Mapping]] = ..., fixed_window: _Optional[_Union[RuleFixedWindow, _Mapping]] = ..., sliding_window: _Optional[_Union[RuleSlidingWindow, _Mapping]] = ..., detect_prompt_injection: _Optional[_Union[RuleDetectPromptInjection, _Mapping]] = ..., moderate_content: _Optional[_Union[RuleModerateContent, _Mapping]] = ..., local_sensitive_info: _Optional[_Union[RuleLocalSensitiveInfo, _Mapping]] = ..., local_custom: _Optional[_Union[RuleLocalCustom, _Mapping]] = ...) -> None: ...

class GuardRuleSubmission(_message.Message):
    __slots__ = ()
    class MetadataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class MetadataJsonEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CONFIG_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    METADATA_JSON_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    config_id: str
    input_id: str
    label: str
    metadata: _containers.ScalarMap[str, str]
    metadata_json: _containers.ScalarMap[str, str]
    rule: GuardRule
    mode: GuardRuleMode
    def __init__(self, config_id: _Optional[str] = ..., input_id: _Optional[str] = ..., label: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ..., metadata_json: _Optional[_Mapping[str, str]] = ..., rule: _Optional[_Union[GuardRule, _Mapping]] = ..., mode: _Optional[_Union[GuardRuleMode, str]] = ...) -> None: ...

class ResultTokenBucket(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REMAINING_TOKENS_FIELD_NUMBER: _ClassVar[int]
    MAX_TOKENS_FIELD_NUMBER: _ClassVar[int]
    RESET_AT_UNIX_SECONDS_FIELD_NUMBER: _ClassVar[int]
    REFILL_RATE_FIELD_NUMBER: _ClassVar[int]
    REFILL_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    remaining_tokens: int
    max_tokens: int
    reset_at_unix_seconds: int
    refill_rate: int
    refill_interval_seconds: int
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., remaining_tokens: _Optional[int] = ..., max_tokens: _Optional[int] = ..., reset_at_unix_seconds: _Optional[int] = ..., refill_rate: _Optional[int] = ..., refill_interval_seconds: _Optional[int] = ...) -> None: ...

class ResultFixedWindow(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REMAINING_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    RESET_AT_UNIX_SECONDS_FIELD_NUMBER: _ClassVar[int]
    WINDOW_SECONDS_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    remaining_requests: int
    max_requests: int
    reset_at_unix_seconds: int
    window_seconds: int
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., remaining_requests: _Optional[int] = ..., max_requests: _Optional[int] = ..., reset_at_unix_seconds: _Optional[int] = ..., window_seconds: _Optional[int] = ...) -> None: ...

class ResultSlidingWindow(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REMAINING_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    RESET_AT_UNIX_SECONDS_FIELD_NUMBER: _ClassVar[int]
    INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    remaining_requests: int
    max_requests: int
    reset_at_unix_seconds: int
    interval_seconds: int
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., remaining_requests: _Optional[int] = ..., max_requests: _Optional[int] = ..., reset_at_unix_seconds: _Optional[int] = ..., interval_seconds: _Optional[int] = ...) -> None: ...

class Billing(_message.Message):
    __slots__ = ()
    UNIT_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    unit: str
    count: int
    def __init__(self, unit: _Optional[str] = ..., count: _Optional[int] = ...) -> None: ...

class ResultPromptInjection(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    BILLING_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    detected: bool
    billing: Billing
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., detected: _Optional[bool] = ..., billing: _Optional[_Union[Billing, _Mapping]] = ...) -> None: ...

class ResultModerateContent(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    BILLING_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    detected: bool
    billing: Billing
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., detected: _Optional[bool] = ..., billing: _Optional[_Union[Billing, _Mapping]] = ...) -> None: ...

class ResultStringConstraint(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    MATCH_OPERATOR_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    match_operator: GuardStringMatchOperator
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., match_operator: _Optional[_Union[GuardStringMatchOperator, str]] = ...) -> None: ...

class ResultStringListMembership(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    MATCHED_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    matched: bool
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., matched: _Optional[bool] = ...) -> None: ...

class ResultLocalSensitiveInfo(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    DETECTED_ENTITY_TYPES_FIELD_NUMBER: _ClassVar[int]
    DETECTED_ENTITIES_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    detected: bool
    detected_entity_types: _containers.RepeatedScalarFieldContainer[str]
    detected_entities: _containers.RepeatedCompositeFieldContainer[GuardSensitiveInfoEntity]
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., detected: _Optional[bool] = ..., detected_entity_types: _Optional[_Iterable[str]] = ..., detected_entities: _Optional[_Iterable[_Union[GuardSensitiveInfoEntity, _Mapping]]] = ...) -> None: ...

class GuardSensitiveInfoEntity(_message.Message):
    __slots__ = ()
    TYPE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    type: str
    start: int
    end: int
    def __init__(self, type: _Optional[str] = ..., start: _Optional[int] = ..., end: _Optional[int] = ...) -> None: ...

class ResultLocalCustom(_message.Message):
    __slots__ = ()
    class DataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    data: _containers.ScalarMap[str, str]
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., data: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ResultNotRun(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ResultError(_message.Message):
    __slots__ = ()
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    message: str
    code: str
    def __init__(self, message: _Optional[str] = ..., code: _Optional[str] = ...) -> None: ...

class Warning(_message.Message):
    __slots__ = ()
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    code: str
    message: str
    def __init__(self, code: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class GuardRuleResult(_message.Message):
    __slots__ = ()
    RESULT_ID_FIELD_NUMBER: _ClassVar[int]
    CONFIG_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_BUCKET_FIELD_NUMBER: _ClassVar[int]
    FIXED_WINDOW_FIELD_NUMBER: _ClassVar[int]
    SLIDING_WINDOW_FIELD_NUMBER: _ClassVar[int]
    PROMPT_INJECTION_FIELD_NUMBER: _ClassVar[int]
    MODERATE_CONTENT_FIELD_NUMBER: _ClassVar[int]
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    LOCAL_CUSTOM_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NOT_RUN_FIELD_NUMBER: _ClassVar[int]
    result_id: str
    config_id: str
    input_id: str
    type: GuardRuleType
    source: GuardRuleSource
    execution: GuardRuleExecution
    mode: GuardRuleMode
    token_bucket: ResultTokenBucket
    fixed_window: ResultFixedWindow
    sliding_window: ResultSlidingWindow
    prompt_injection: ResultPromptInjection
    moderate_content: ResultModerateContent
    local_sensitive_info: ResultLocalSensitiveInfo
    local_custom: ResultLocalCustom
    error: ResultError
    not_run: ResultNotRun
    def __init__(self, result_id: _Optional[str] = ..., config_id: _Optional[str] = ..., input_id: _Optional[str] = ..., type: _Optional[_Union[GuardRuleType, str]] = ..., source: _Optional[_Union[GuardRuleSource, str]] = ..., execution: _Optional[_Union[GuardRuleExecution, str]] = ..., mode: _Optional[_Union[GuardRuleMode, str]] = ..., token_bucket: _Optional[_Union[ResultTokenBucket, _Mapping]] = ..., fixed_window: _Optional[_Union[ResultFixedWindow, _Mapping]] = ..., sliding_window: _Optional[_Union[ResultSlidingWindow, _Mapping]] = ..., prompt_injection: _Optional[_Union[ResultPromptInjection, _Mapping]] = ..., moderate_content: _Optional[_Union[ResultModerateContent, _Mapping]] = ..., local_sensitive_info: _Optional[_Union[ResultLocalSensitiveInfo, _Mapping]] = ..., local_custom: _Optional[_Union[ResultLocalCustom, _Mapping]] = ..., error: _Optional[_Union[ResultError, _Mapping]] = ..., not_run: _Optional[_Union[ResultNotRun, _Mapping]] = ...) -> None: ...

class GuardPolicyEvaluation(_message.Message):
    __slots__ = ()
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REFRESH_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    revision: str
    status: GuardPolicyStatus
    refresh_required: bool
    def __init__(self, revision: _Optional[str] = ..., status: _Optional[_Union[GuardPolicyStatus, str]] = ..., refresh_required: _Optional[bool] = ...) -> None: ...

class GuardPolicyRuleResult(_message.Message):
    __slots__ = ()
    RESULT_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_REVISION_FIELD_NUMBER: _ClassVar[int]
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROMPT_INJECTION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_STRING_VALUES_FIELD_NUMBER: _ClassVar[int]
    DENIED_STRING_VALUES_FIELD_NUMBER: _ClassVar[int]
    STRING_LENGTH_FIELD_NUMBER: _ClassVar[int]
    STRING_LIST_MEMBERSHIP_FIELD_NUMBER: _ClassVar[int]
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NOT_RUN_FIELD_NUMBER: _ClassVar[int]
    result_id: str
    policy_id: str
    policy_revision: str
    rule_id: str
    type: GuardRuleType
    mode: GuardRuleMode
    execution: GuardRuleExecution
    source: GuardRuleSource
    prompt_injection: ResultPromptInjection
    allowed_string_values: ResultStringConstraint
    denied_string_values: ResultStringConstraint
    string_length: ResultStringConstraint
    string_list_membership: ResultStringListMembership
    local_sensitive_info: ResultLocalSensitiveInfo
    error: ResultError
    not_run: ResultNotRun
    def __init__(self, result_id: _Optional[str] = ..., policy_id: _Optional[str] = ..., policy_revision: _Optional[str] = ..., rule_id: _Optional[str] = ..., type: _Optional[_Union[GuardRuleType, str]] = ..., mode: _Optional[_Union[GuardRuleMode, str]] = ..., execution: _Optional[_Union[GuardRuleExecution, str]] = ..., source: _Optional[_Union[GuardRuleSource, str]] = ..., prompt_injection: _Optional[_Union[ResultPromptInjection, _Mapping]] = ..., allowed_string_values: _Optional[_Union[ResultStringConstraint, _Mapping]] = ..., denied_string_values: _Optional[_Union[ResultStringConstraint, _Mapping]] = ..., string_length: _Optional[_Union[ResultStringConstraint, _Mapping]] = ..., string_list_membership: _Optional[_Union[ResultStringListMembership, _Mapping]] = ..., local_sensitive_info: _Optional[_Union[ResultLocalSensitiveInfo, _Mapping]] = ..., error: _Optional[_Union[ResultError, _Mapping]] = ..., not_run: _Optional[_Union[ResultNotRun, _Mapping]] = ...) -> None: ...

class GuardDecision(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    RULE_RESULTS_FIELD_NUMBER: _ClassVar[int]
    POLICY_EVALUATION_FIELD_NUMBER: _ClassVar[int]
    POLICY_RULE_RESULTS_FIELD_NUMBER: _ClassVar[int]
    id: str
    conclusion: GuardConclusion
    reason: GuardReason
    rule_results: _containers.RepeatedCompositeFieldContainer[GuardRuleResult]
    policy_evaluation: GuardPolicyEvaluation
    policy_rule_results: _containers.RepeatedCompositeFieldContainer[GuardPolicyRuleResult]
    def __init__(self, id: _Optional[str] = ..., conclusion: _Optional[_Union[GuardConclusion, str]] = ..., reason: _Optional[_Union[GuardReason, str]] = ..., rule_results: _Optional[_Iterable[_Union[GuardRuleResult, _Mapping]]] = ..., policy_evaluation: _Optional[_Union[GuardPolicyEvaluation, _Mapping]] = ..., policy_rule_results: _Optional[_Iterable[_Union[GuardPolicyRuleResult, _Mapping]]] = ...) -> None: ...

class GuardStringList(_message.Message):
    __slots__ = ()
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, values: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardPolicyServerInput(_message.Message):
    __slots__ = ()
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    INTEGER_VALUE_FIELD_NUMBER: _ClassVar[int]
    NUMBER_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_LIST_VALUE_FIELD_NUMBER: _ClassVar[int]
    string_value: str
    boolean_value: bool
    integer_value: int
    number_value: float
    string_list_value: GuardStringList
    def __init__(self, string_value: _Optional[str] = ..., boolean_value: _Optional[bool] = ..., integer_value: _Optional[int] = ..., number_value: _Optional[float] = ..., string_list_value: _Optional[_Union[GuardStringList, _Mapping]] = ...) -> None: ...

class GuardPolicyLocalInput(_message.Message):
    __slots__ = ()
    KIND_FIELD_NUMBER: _ClassVar[int]
    VALUE_SHA256_FIELD_NUMBER: _ClassVar[int]
    kind: GuardPolicyInputKind
    value_sha256: bytes
    def __init__(self, kind: _Optional[_Union[GuardPolicyInputKind, str]] = ..., value_sha256: _Optional[bytes] = ...) -> None: ...

class GuardPolicyInput(_message.Message):
    __slots__ = ()
    SERVER_FIELD_NUMBER: _ClassVar[int]
    LOCAL_FIELD_NUMBER: _ClassVar[int]
    server: GuardPolicyServerInput
    local: GuardPolicyLocalInput
    def __init__(self, server: _Optional[_Union[GuardPolicyServerInput, _Mapping]] = ..., local: _Optional[_Union[GuardPolicyLocalInput, _Mapping]] = ...) -> None: ...

class GuardLocalPolicyResult(_message.Message):
    __slots__ = ()
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_REVISION_FIELD_NUMBER: _ClassVar[int]
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_SHA256_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NOT_RUN_FIELD_NUMBER: _ClassVar[int]
    policy_id: str
    policy_revision: str
    rule_id: str
    input_name: str
    value_sha256: bytes
    type: GuardRuleType
    duration_ms: int
    local_sensitive_info: ResultLocalSensitiveInfo
    error: ResultError
    not_run: ResultNotRun
    def __init__(self, policy_id: _Optional[str] = ..., policy_revision: _Optional[str] = ..., rule_id: _Optional[str] = ..., input_name: _Optional[str] = ..., value_sha256: _Optional[bytes] = ..., type: _Optional[_Union[GuardRuleType, str]] = ..., duration_ms: _Optional[int] = ..., local_sensitive_info: _Optional[_Union[ResultLocalSensitiveInfo, _Mapping]] = ..., error: _Optional[_Union[ResultError, _Mapping]] = ..., not_run: _Optional[_Union[ResultNotRun, _Mapping]] = ...) -> None: ...

class GuardRequest(_message.Message):
    __slots__ = ()
    class MetadataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class MetadataJsonEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class PolicyInputsEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: GuardPolicyInput
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[GuardPolicyInput, _Mapping]] = ...) -> None: ...
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    LOCAL_EVAL_DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    SENT_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    RULE_SUBMISSIONS_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    METADATA_JSON_FIELD_NUMBER: _ClassVar[int]
    LOCAL_WARNINGS_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    POLICY_INPUTS_FIELD_NUMBER: _ClassVar[int]
    LOCAL_POLICY_REVISION_FIELD_NUMBER: _ClassVar[int]
    LOCAL_POLICY_RESULTS_FIELD_NUMBER: _ClassVar[int]
    POLICY_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    user_agent: str
    local_eval_duration_ms: int
    sent_at_unix_ms: int
    label: str
    metadata: _containers.ScalarMap[str, str]
    rule_submissions: _containers.RepeatedCompositeFieldContainer[GuardRuleSubmission]
    correlation_id: str
    metadata_json: _containers.ScalarMap[str, str]
    local_warnings: _containers.RepeatedCompositeFieldContainer[Warning]
    actor: str
    policy_inputs: _containers.MessageMap[str, GuardPolicyInput]
    local_policy_revision: str
    local_policy_results: _containers.RepeatedCompositeFieldContainer[GuardLocalPolicyResult]
    policy_capabilities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, user_agent: _Optional[str] = ..., local_eval_duration_ms: _Optional[int] = ..., sent_at_unix_ms: _Optional[int] = ..., label: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ..., rule_submissions: _Optional[_Iterable[_Union[GuardRuleSubmission, _Mapping]]] = ..., correlation_id: _Optional[str] = ..., metadata_json: _Optional[_Mapping[str, str]] = ..., local_warnings: _Optional[_Iterable[_Union[Warning, _Mapping]]] = ..., actor: _Optional[str] = ..., policy_inputs: _Optional[_Mapping[str, GuardPolicyInput]] = ..., local_policy_revision: _Optional[str] = ..., local_policy_results: _Optional[_Iterable[_Union[GuardLocalPolicyResult, _Mapping]]] = ..., policy_capabilities: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardResponse(_message.Message):
    __slots__ = ()
    DECISION_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    decision: GuardDecision
    errors: _containers.RepeatedCompositeFieldContainer[ResultError]
    def __init__(self, decision: _Optional[_Union[GuardDecision, _Mapping]] = ..., errors: _Optional[_Iterable[_Union[ResultError, _Mapping]]] = ...) -> None: ...

class GetGuardPolicyRequest(_message.Message):
    __slots__ = ()
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    POLICY_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    user_agent: str
    label: str
    policy_capabilities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, user_agent: _Optional[str] = ..., label: _Optional[str] = ..., policy_capabilities: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardLocalPolicyInputRequirement(_message.Message):
    __slots__ = ()
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: GuardPolicyInputKind
    required: bool
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[GuardPolicyInputKind, str]] = ..., required: _Optional[bool] = ...) -> None: ...

class GuardLocalSensitiveInfoRule(_message.Message):
    __slots__ = ()
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    ENTITIES_ALLOW_FIELD_NUMBER: _ClassVar[int]
    ENTITIES_DENY_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    input_name: str
    mode: GuardRuleMode
    entities_allow: EntityList
    entities_deny: EntityList
    def __init__(self, rule_id: _Optional[str] = ..., input_name: _Optional[str] = ..., mode: _Optional[_Union[GuardRuleMode, str]] = ..., entities_allow: _Optional[_Union[EntityList, _Mapping]] = ..., entities_deny: _Optional[_Union[EntityList, _Mapping]] = ...) -> None: ...

class GuardLocalPolicyProjection(_message.Message):
    __slots__ = ()
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    REQUIRES_ACTOR_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    SENSITIVE_INFO_RULES_FIELD_NUMBER: _ClassVar[int]
    policy_id: str
    revision: str
    label: str
    requires_actor: bool
    inputs: _containers.RepeatedCompositeFieldContainer[GuardLocalPolicyInputRequirement]
    sensitive_info_rules: _containers.RepeatedCompositeFieldContainer[GuardLocalSensitiveInfoRule]
    def __init__(self, policy_id: _Optional[str] = ..., revision: _Optional[str] = ..., label: _Optional[str] = ..., requires_actor: _Optional[bool] = ..., inputs: _Optional[_Iterable[_Union[GuardLocalPolicyInputRequirement, _Mapping]]] = ..., sensitive_info_rules: _Optional[_Iterable[_Union[GuardLocalSensitiveInfoRule, _Mapping]]] = ...) -> None: ...

class GetGuardPolicyResponse(_message.Message):
    __slots__ = ()
    STATUS_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    SERVER_TIME_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    status: GuardPolicyLookupStatus
    policy: GuardLocalPolicyProjection
    server_time_unix_ms: int
    def __init__(self, status: _Optional[_Union[GuardPolicyLookupStatus, str]] = ..., policy: _Optional[_Union[GuardLocalPolicyProjection, _Mapping]] = ..., server_time_unix_ms: _Optional[int] = ...) -> None: ...

class CaptureEvent(_message.Message):
    __slots__ = ()
    class MetadataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class MetadataJsonEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    OCCURRED_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    METADATA_JSON_FIELD_NUMBER: _ClassVar[int]
    LOCAL_WARNINGS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    occurred_at_unix_ms: int
    correlation_id: str
    decision_id: str
    action: str
    metadata: _containers.ScalarMap[str, str]
    metadata_json: _containers.ScalarMap[str, str]
    local_warnings: _containers.RepeatedCompositeFieldContainer[Warning]
    source: str
    def __init__(self, occurred_at_unix_ms: _Optional[int] = ..., correlation_id: _Optional[str] = ..., decision_id: _Optional[str] = ..., action: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ..., metadata_json: _Optional[_Mapping[str, str]] = ..., local_warnings: _Optional[_Iterable[_Union[Warning, _Mapping]]] = ..., source: _Optional[str] = ...) -> None: ...

class CaptureRequest(_message.Message):
    __slots__ = ()
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    SENT_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    user_agent: str
    sent_at_unix_ms: int
    events: _containers.RepeatedCompositeFieldContainer[CaptureEvent]
    def __init__(self, user_agent: _Optional[str] = ..., sent_at_unix_ms: _Optional[int] = ..., events: _Optional[_Iterable[_Union[CaptureEvent, _Mapping]]] = ...) -> None: ...

class CaptureResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

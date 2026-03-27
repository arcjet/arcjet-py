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

class GuardRuleType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_RULE_TYPE_UNSPECIFIED: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_TOKEN_BUCKET: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_FIXED_WINDOW: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_SLIDING_WINDOW: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_PROMPT_INJECTION: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO: _ClassVar[GuardRuleType]
    GUARD_RULE_TYPE_LOCAL_CUSTOM: _ClassVar[GuardRuleType]

class GuardRuleMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_RULE_MODE_UNSPECIFIED: _ClassVar[GuardRuleMode]
    GUARD_RULE_MODE_LIVE: _ClassVar[GuardRuleMode]
    GUARD_RULE_MODE_DRY_RUN: _ClassVar[GuardRuleMode]
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
GUARD_RULE_TYPE_UNSPECIFIED: GuardRuleType
GUARD_RULE_TYPE_TOKEN_BUCKET: GuardRuleType
GUARD_RULE_TYPE_FIXED_WINDOW: GuardRuleType
GUARD_RULE_TYPE_SLIDING_WINDOW: GuardRuleType
GUARD_RULE_TYPE_PROMPT_INJECTION: GuardRuleType
GUARD_RULE_TYPE_LOCAL_SENSITIVE_INFO: GuardRuleType
GUARD_RULE_TYPE_LOCAL_CUSTOM: GuardRuleType
GUARD_RULE_MODE_UNSPECIFIED: GuardRuleMode
GUARD_RULE_MODE_LIVE: GuardRuleMode
GUARD_RULE_MODE_DRY_RUN: GuardRuleMode

class RuleTokenBucket(_message.Message):
    __slots__ = ()
    CONFIG_REFILL_RATE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_MAX_TOKENS_FIELD_NUMBER: _ClassVar[int]
    INPUT_KEY_FIELD_NUMBER: _ClassVar[int]
    INPUT_REQUESTED_FIELD_NUMBER: _ClassVar[int]
    config_refill_rate: int
    config_interval_seconds: int
    config_max_tokens: int
    input_key: str
    input_requested: int
    def __init__(self, config_refill_rate: _Optional[int] = ..., config_interval_seconds: _Optional[int] = ..., config_max_tokens: _Optional[int] = ..., input_key: _Optional[str] = ..., input_requested: _Optional[int] = ...) -> None: ...

class RuleFixedWindow(_message.Message):
    __slots__ = ()
    CONFIG_MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_WINDOW_SECONDS_FIELD_NUMBER: _ClassVar[int]
    INPUT_KEY_FIELD_NUMBER: _ClassVar[int]
    INPUT_REQUESTED_FIELD_NUMBER: _ClassVar[int]
    config_max_requests: int
    config_window_seconds: int
    input_key: str
    input_requested: int
    def __init__(self, config_max_requests: _Optional[int] = ..., config_window_seconds: _Optional[int] = ..., input_key: _Optional[str] = ..., input_requested: _Optional[int] = ...) -> None: ...

class RuleSlidingWindow(_message.Message):
    __slots__ = ()
    CONFIG_MAX_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    INPUT_KEY_FIELD_NUMBER: _ClassVar[int]
    INPUT_REQUESTED_FIELD_NUMBER: _ClassVar[int]
    config_max_requests: int
    config_interval_seconds: int
    input_key: str
    input_requested: int
    def __init__(self, config_max_requests: _Optional[int] = ..., config_interval_seconds: _Optional[int] = ..., input_key: _Optional[str] = ..., input_requested: _Optional[int] = ...) -> None: ...

class RuleDetectPromptInjection(_message.Message):
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
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    LOCAL_CUSTOM_FIELD_NUMBER: _ClassVar[int]
    token_bucket: RuleTokenBucket
    fixed_window: RuleFixedWindow
    sliding_window: RuleSlidingWindow
    detect_prompt_injection: RuleDetectPromptInjection
    local_sensitive_info: RuleLocalSensitiveInfo
    local_custom: RuleLocalCustom
    def __init__(self, token_bucket: _Optional[_Union[RuleTokenBucket, _Mapping]] = ..., fixed_window: _Optional[_Union[RuleFixedWindow, _Mapping]] = ..., sliding_window: _Optional[_Union[RuleSlidingWindow, _Mapping]] = ..., detect_prompt_injection: _Optional[_Union[RuleDetectPromptInjection, _Mapping]] = ..., local_sensitive_info: _Optional[_Union[RuleLocalSensitiveInfo, _Mapping]] = ..., local_custom: _Optional[_Union[RuleLocalCustom, _Mapping]] = ...) -> None: ...

class GuardRuleSubmission(_message.Message):
    __slots__ = ()
    class MetadataEntry(_message.Message):
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
    RULE_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    config_id: str
    input_id: str
    label: str
    metadata: _containers.ScalarMap[str, str]
    rule: GuardRule
    mode: GuardRuleMode
    def __init__(self, config_id: _Optional[str] = ..., input_id: _Optional[str] = ..., label: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ..., rule: _Optional[_Union[GuardRule, _Mapping]] = ..., mode: _Optional[_Union[GuardRuleMode, str]] = ...) -> None: ...

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

class ResultPromptInjection(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    detected: bool
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., detected: _Optional[bool] = ...) -> None: ...

class ResultLocalSensitiveInfo(_message.Message):
    __slots__ = ()
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_FIELD_NUMBER: _ClassVar[int]
    DETECTED_ENTITY_TYPES_FIELD_NUMBER: _ClassVar[int]
    conclusion: GuardConclusion
    detected: bool
    detected_entity_types: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, conclusion: _Optional[_Union[GuardConclusion, str]] = ..., detected: _Optional[bool] = ..., detected_entity_types: _Optional[_Iterable[str]] = ...) -> None: ...

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

class GuardRuleResult(_message.Message):
    __slots__ = ()
    RESULT_ID_FIELD_NUMBER: _ClassVar[int]
    CONFIG_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_BUCKET_FIELD_NUMBER: _ClassVar[int]
    FIXED_WINDOW_FIELD_NUMBER: _ClassVar[int]
    SLIDING_WINDOW_FIELD_NUMBER: _ClassVar[int]
    PROMPT_INJECTION_FIELD_NUMBER: _ClassVar[int]
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    LOCAL_CUSTOM_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    NOT_RUN_FIELD_NUMBER: _ClassVar[int]
    result_id: str
    config_id: str
    input_id: str
    type: GuardRuleType
    token_bucket: ResultTokenBucket
    fixed_window: ResultFixedWindow
    sliding_window: ResultSlidingWindow
    prompt_injection: ResultPromptInjection
    local_sensitive_info: ResultLocalSensitiveInfo
    local_custom: ResultLocalCustom
    error: ResultError
    not_run: ResultNotRun
    def __init__(self, result_id: _Optional[str] = ..., config_id: _Optional[str] = ..., input_id: _Optional[str] = ..., type: _Optional[_Union[GuardRuleType, str]] = ..., token_bucket: _Optional[_Union[ResultTokenBucket, _Mapping]] = ..., fixed_window: _Optional[_Union[ResultFixedWindow, _Mapping]] = ..., sliding_window: _Optional[_Union[ResultSlidingWindow, _Mapping]] = ..., prompt_injection: _Optional[_Union[ResultPromptInjection, _Mapping]] = ..., local_sensitive_info: _Optional[_Union[ResultLocalSensitiveInfo, _Mapping]] = ..., local_custom: _Optional[_Union[ResultLocalCustom, _Mapping]] = ..., error: _Optional[_Union[ResultError, _Mapping]] = ..., not_run: _Optional[_Union[ResultNotRun, _Mapping]] = ...) -> None: ...

class GuardDecision(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    RULE_RESULTS_FIELD_NUMBER: _ClassVar[int]
    id: str
    conclusion: GuardConclusion
    reason: GuardReason
    rule_results: _containers.RepeatedCompositeFieldContainer[GuardRuleResult]
    def __init__(self, id: _Optional[str] = ..., conclusion: _Optional[_Union[GuardConclusion, str]] = ..., reason: _Optional[_Union[GuardReason, str]] = ..., rule_results: _Optional[_Iterable[_Union[GuardRuleResult, _Mapping]]] = ...) -> None: ...

class GuardRequest(_message.Message):
    __slots__ = ()
    class MetadataEntry(_message.Message):
        __slots__ = ()
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    LOCAL_EVAL_DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    SENT_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    RULE_SUBMISSIONS_FIELD_NUMBER: _ClassVar[int]
    user_agent: str
    local_eval_duration_ms: int
    sent_at_unix_ms: int
    label: str
    metadata: _containers.ScalarMap[str, str]
    rule_submissions: _containers.RepeatedCompositeFieldContainer[GuardRuleSubmission]
    def __init__(self, user_agent: _Optional[str] = ..., local_eval_duration_ms: _Optional[int] = ..., sent_at_unix_ms: _Optional[int] = ..., label: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ..., rule_submissions: _Optional[_Iterable[_Union[GuardRuleSubmission, _Mapping]]] = ...) -> None: ...

class GuardResponse(_message.Message):
    __slots__ = ()
    DECISION_FIELD_NUMBER: _ClassVar[int]
    decision: GuardDecision
    def __init__(self, decision: _Optional[_Union[GuardDecision, _Mapping]] = ...) -> None: ...

from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GuardPolicyInputKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_INPUT_KIND_UNSPECIFIED: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_STRING: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_BOOLEAN: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_INTEGER: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_NUMBER: _ClassVar[GuardPolicyInputKind]
    GUARD_POLICY_INPUT_KIND_STRING_LIST: _ClassVar[GuardPolicyInputKind]

class GuardPolicyInputExposure(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_INPUT_EXPOSURE_UNSPECIFIED: _ClassVar[GuardPolicyInputExposure]
    GUARD_POLICY_INPUT_EXPOSURE_SERVER: _ClassVar[GuardPolicyInputExposure]
    GUARD_POLICY_INPUT_EXPOSURE_LOCAL: _ClassVar[GuardPolicyInputExposure]

class GuardPolicyRuleMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_RULE_MODE_UNSPECIFIED: _ClassVar[GuardPolicyRuleMode]
    GUARD_POLICY_RULE_MODE_LIVE: _ClassVar[GuardPolicyRuleMode]
    GUARD_POLICY_RULE_MODE_DRY_RUN: _ClassVar[GuardPolicyRuleMode]

class GuardPolicyRuleExecution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_RULE_EXECUTION_UNSPECIFIED: _ClassVar[GuardPolicyRuleExecution]
    GUARD_POLICY_RULE_EXECUTION_SDK: _ClassVar[GuardPolicyRuleExecution]
    GUARD_POLICY_RULE_EXECUTION_SERVER: _ClassVar[GuardPolicyRuleExecution]

class GuardPolicyStringMatchOperator(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_STRING_MATCH_OPERATOR_UNSPECIFIED: _ClassVar[GuardPolicyStringMatchOperator]
    GUARD_POLICY_STRING_MATCH_OPERATOR_EXACT: _ClassVar[GuardPolicyStringMatchOperator]
    GUARD_POLICY_STRING_MATCH_OPERATOR_EMAIL_DOMAIN: _ClassVar[GuardPolicyStringMatchOperator]
GUARD_POLICY_INPUT_KIND_UNSPECIFIED: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_STRING: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_BOOLEAN: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_INTEGER: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_NUMBER: GuardPolicyInputKind
GUARD_POLICY_INPUT_KIND_STRING_LIST: GuardPolicyInputKind
GUARD_POLICY_INPUT_EXPOSURE_UNSPECIFIED: GuardPolicyInputExposure
GUARD_POLICY_INPUT_EXPOSURE_SERVER: GuardPolicyInputExposure
GUARD_POLICY_INPUT_EXPOSURE_LOCAL: GuardPolicyInputExposure
GUARD_POLICY_RULE_MODE_UNSPECIFIED: GuardPolicyRuleMode
GUARD_POLICY_RULE_MODE_LIVE: GuardPolicyRuleMode
GUARD_POLICY_RULE_MODE_DRY_RUN: GuardPolicyRuleMode
GUARD_POLICY_RULE_EXECUTION_UNSPECIFIED: GuardPolicyRuleExecution
GUARD_POLICY_RULE_EXECUTION_SDK: GuardPolicyRuleExecution
GUARD_POLICY_RULE_EXECUTION_SERVER: GuardPolicyRuleExecution
GUARD_POLICY_STRING_MATCH_OPERATOR_UNSPECIFIED: GuardPolicyStringMatchOperator
GUARD_POLICY_STRING_MATCH_OPERATOR_EXACT: GuardPolicyStringMatchOperator
GUARD_POLICY_STRING_MATCH_OPERATOR_EMAIL_DOMAIN: GuardPolicyStringMatchOperator

class GuardPolicyBundle(_message.Message):
    __slots__ = ()
    LANGUAGE_VERSION_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICIES_FIELD_NUMBER: _ClassVar[int]
    language_version: int
    revision: str
    policies: _containers.RepeatedCompositeFieldContainer[GuardPolicy]
    def __init__(self, language_version: _Optional[int] = ..., revision: _Optional[str] = ..., policies: _Optional[_Iterable[_Union[GuardPolicy, _Mapping]]] = ...) -> None: ...

class GuardPolicy(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    REQUIRES_ACTOR_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    id: str
    label: str
    requires_actor: bool
    inputs: _containers.RepeatedCompositeFieldContainer[GuardPolicyInputRequirement]
    rules: _containers.RepeatedCompositeFieldContainer[GuardPolicyRule]
    def __init__(self, id: _Optional[str] = ..., label: _Optional[str] = ..., requires_actor: _Optional[bool] = ..., inputs: _Optional[_Iterable[_Union[GuardPolicyInputRequirement, _Mapping]]] = ..., rules: _Optional[_Iterable[_Union[GuardPolicyRule, _Mapping]]] = ...) -> None: ...

class GuardPolicyInputRequirement(_message.Message):
    __slots__ = ()
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    EXPOSURE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: GuardPolicyInputKind
    exposure: GuardPolicyInputExposure
    required: bool
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[GuardPolicyInputKind, str]] = ..., exposure: _Optional[_Union[GuardPolicyInputExposure, str]] = ..., required: _Optional[bool] = ...) -> None: ...

class GuardPolicyRule(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_STRING_VALUES_FIELD_NUMBER: _ClassVar[int]
    DENIED_STRING_VALUES_FIELD_NUMBER: _ClassVar[int]
    STRING_LENGTH_FIELD_NUMBER: _ClassVar[int]
    PROMPT_INJECTION_FIELD_NUMBER: _ClassVar[int]
    STRING_LIST_MEMBERSHIP_FIELD_NUMBER: _ClassVar[int]
    LOCAL_SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    id: str
    mode: GuardPolicyRuleMode
    execution: GuardPolicyRuleExecution
    allowed_string_values: GuardPolicyAllowedStringValues
    denied_string_values: GuardPolicyDeniedStringValues
    string_length: GuardPolicyStringLength
    prompt_injection: GuardPolicyPromptInjection
    string_list_membership: GuardPolicyStringListMembership
    local_sensitive_info: GuardPolicyLocalSensitiveInfo
    def __init__(self, id: _Optional[str] = ..., mode: _Optional[_Union[GuardPolicyRuleMode, str]] = ..., execution: _Optional[_Union[GuardPolicyRuleExecution, str]] = ..., allowed_string_values: _Optional[_Union[GuardPolicyAllowedStringValues, _Mapping]] = ..., denied_string_values: _Optional[_Union[GuardPolicyDeniedStringValues, _Mapping]] = ..., string_length: _Optional[_Union[GuardPolicyStringLength, _Mapping]] = ..., prompt_injection: _Optional[_Union[GuardPolicyPromptInjection, _Mapping]] = ..., string_list_membership: _Optional[_Union[GuardPolicyStringListMembership, _Mapping]] = ..., local_sensitive_info: _Optional[_Union[GuardPolicyLocalSensitiveInfo, _Mapping]] = ...) -> None: ...

class GuardPolicyStringValues(_message.Message):
    __slots__ = ()
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, values: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardPolicyAllowedStringValues(_message.Message):
    __slots__ = ()
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    MATCH_OPERATOR_FIELD_NUMBER: _ClassVar[int]
    input_name: str
    values: GuardPolicyStringValues
    match_operator: GuardPolicyStringMatchOperator
    def __init__(self, input_name: _Optional[str] = ..., values: _Optional[_Union[GuardPolicyStringValues, _Mapping]] = ..., match_operator: _Optional[_Union[GuardPolicyStringMatchOperator, str]] = ...) -> None: ...

class GuardPolicyDeniedStringValues(_message.Message):
    __slots__ = ()
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    MATCH_OPERATOR_FIELD_NUMBER: _ClassVar[int]
    input_name: str
    values: GuardPolicyStringValues
    match_operator: GuardPolicyStringMatchOperator
    def __init__(self, input_name: _Optional[str] = ..., values: _Optional[_Union[GuardPolicyStringValues, _Mapping]] = ..., match_operator: _Optional[_Union[GuardPolicyStringMatchOperator, str]] = ...) -> None: ...

class GuardPolicyStringLength(_message.Message):
    __slots__ = ()
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    MIN_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    input_name: str
    min_bytes: int
    max_bytes: int
    def __init__(self, input_name: _Optional[str] = ..., min_bytes: _Optional[int] = ..., max_bytes: _Optional[int] = ...) -> None: ...

class GuardPolicyPromptInjection(_message.Message):
    __slots__ = ()
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    input_name: str
    def __init__(self, input_name: _Optional[str] = ...) -> None: ...

class GuardPolicyStringListMembership(_message.Message):
    __slots__ = ()
    STRING_INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    STRING_LIST_INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    string_input_name: str
    string_list_input_name: str
    def __init__(self, string_input_name: _Optional[str] = ..., string_list_input_name: _Optional[str] = ...) -> None: ...

class GuardPolicyEntityList(_message.Message):
    __slots__ = ()
    ENTITIES_FIELD_NUMBER: _ClassVar[int]
    entities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, entities: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardPolicyLocalSensitiveInfo(_message.Message):
    __slots__ = ()
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    ENTITIES_ALLOW_FIELD_NUMBER: _ClassVar[int]
    ENTITIES_DENY_FIELD_NUMBER: _ClassVar[int]
    input_name: str
    entities_allow: GuardPolicyEntityList
    entities_deny: GuardPolicyEntityList
    def __init__(self, input_name: _Optional[str] = ..., entities_allow: _Optional[_Union[GuardPolicyEntityList, _Mapping]] = ..., entities_deny: _Optional[_Union[GuardPolicyEntityList, _Mapping]] = ...) -> None: ...

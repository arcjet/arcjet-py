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

class GuardPolicyRuleKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_RULE_KIND_UNSPECIFIED: _ClassVar[GuardPolicyRuleKind]
    GUARD_POLICY_RULE_KIND_EXPRESSION: _ClassVar[GuardPolicyRuleKind]
    GUARD_POLICY_RULE_KIND_DETECTOR: _ClassVar[GuardPolicyRuleKind]

class GuardPolicyDetectorKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_DETECTOR_KIND_UNSPECIFIED: _ClassVar[GuardPolicyDetectorKind]
    GUARD_POLICY_DETECTOR_KIND_PROMPT_INJECTION: _ClassVar[GuardPolicyDetectorKind]
    GUARD_POLICY_DETECTOR_KIND_LOCAL_SENSITIVE_INFO: _ClassVar[GuardPolicyDetectorKind]

class GuardPolicyBuilderOperator(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_BUILDER_OPERATOR_UNSPECIFIED: _ClassVar[GuardPolicyBuilderOperator]
    GUARD_POLICY_BUILDER_OPERATOR_AND: _ClassVar[GuardPolicyBuilderOperator]
    GUARD_POLICY_BUILDER_OPERATOR_OR: _ClassVar[GuardPolicyBuilderOperator]

class GuardPolicyBuilderComparison(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GUARD_POLICY_BUILDER_COMPARISON_UNSPECIFIED: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_EQUALS: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_NOT_EQUALS: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_IN: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_NOT_IN: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_CONTAINS: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_STARTS_WITH: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_ENDS_WITH: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_EMAIL_DOMAIN_IS: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_LENGTH_AT_LEAST: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_LENGTH_AT_MOST: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_GREATER_THAN: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_LESS_THAN: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_DETECTED: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_NOT_CONTAINS: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_NOT_STARTS_WITH: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_NOT_ENDS_WITH: _ClassVar[GuardPolicyBuilderComparison]
    GUARD_POLICY_BUILDER_COMPARISON_EMAIL_DOMAIN_IS_NOT: _ClassVar[GuardPolicyBuilderComparison]
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
GUARD_POLICY_RULE_KIND_UNSPECIFIED: GuardPolicyRuleKind
GUARD_POLICY_RULE_KIND_EXPRESSION: GuardPolicyRuleKind
GUARD_POLICY_RULE_KIND_DETECTOR: GuardPolicyRuleKind
GUARD_POLICY_DETECTOR_KIND_UNSPECIFIED: GuardPolicyDetectorKind
GUARD_POLICY_DETECTOR_KIND_PROMPT_INJECTION: GuardPolicyDetectorKind
GUARD_POLICY_DETECTOR_KIND_LOCAL_SENSITIVE_INFO: GuardPolicyDetectorKind
GUARD_POLICY_BUILDER_OPERATOR_UNSPECIFIED: GuardPolicyBuilderOperator
GUARD_POLICY_BUILDER_OPERATOR_AND: GuardPolicyBuilderOperator
GUARD_POLICY_BUILDER_OPERATOR_OR: GuardPolicyBuilderOperator
GUARD_POLICY_BUILDER_COMPARISON_UNSPECIFIED: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_EQUALS: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_NOT_EQUALS: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_IN: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_NOT_IN: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_CONTAINS: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_STARTS_WITH: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_ENDS_WITH: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_EMAIL_DOMAIN_IS: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_LENGTH_AT_LEAST: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_LENGTH_AT_MOST: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_GREATER_THAN: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_LESS_THAN: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_DETECTED: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_NOT_CONTAINS: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_NOT_STARTS_WITH: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_NOT_ENDS_WITH: GuardPolicyBuilderComparison
GUARD_POLICY_BUILDER_COMPARISON_EMAIL_DOMAIN_IS_NOT: GuardPolicyBuilderComparison

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
    DETECTORS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    id: str
    label: str
    requires_actor: bool
    inputs: _containers.RepeatedCompositeFieldContainer[GuardPolicyInputRequirement]
    detectors: _containers.RepeatedCompositeFieldContainer[GuardPolicyDetector]
    rules: _containers.RepeatedCompositeFieldContainer[GuardPolicyRuleDeclaration]
    artifact: str
    def __init__(self, id: _Optional[str] = ..., label: _Optional[str] = ..., requires_actor: _Optional[bool] = ..., inputs: _Optional[_Iterable[_Union[GuardPolicyInputRequirement, _Mapping]]] = ..., detectors: _Optional[_Iterable[_Union[GuardPolicyDetector, _Mapping]]] = ..., rules: _Optional[_Iterable[_Union[GuardPolicyRuleDeclaration, _Mapping]]] = ..., artifact: _Optional[str] = ...) -> None: ...

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

class GuardPolicyDetector(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    SENSITIVE_INFO_FIELD_NUMBER: _ClassVar[int]
    id: str
    kind: GuardPolicyDetectorKind
    input_name: str
    sensitive_info: GuardPolicySensitiveInfoConfig
    def __init__(self, id: _Optional[str] = ..., kind: _Optional[_Union[GuardPolicyDetectorKind, str]] = ..., input_name: _Optional[str] = ..., sensitive_info: _Optional[_Union[GuardPolicySensitiveInfoConfig, _Mapping]] = ...) -> None: ...

class GuardPolicySensitiveInfoConfig(_message.Message):
    __slots__ = ()
    ENTITIES_ALLOW_FIELD_NUMBER: _ClassVar[int]
    ENTITIES_DENY_FIELD_NUMBER: _ClassVar[int]
    entities_allow: GuardPolicyEntityList
    entities_deny: GuardPolicyEntityList
    def __init__(self, entities_allow: _Optional[_Union[GuardPolicyEntityList, _Mapping]] = ..., entities_deny: _Optional[_Union[GuardPolicyEntityList, _Mapping]] = ...) -> None: ...

class GuardPolicyEntityList(_message.Message):
    __slots__ = ()
    ENTITIES_FIELD_NUMBER: _ClassVar[int]
    entities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, entities: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardPolicyRuleDeclaration(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DETECTOR_ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    mode: GuardPolicyRuleMode
    execution: GuardPolicyRuleExecution
    kind: GuardPolicyRuleKind
    description: str
    detector_id: str
    def __init__(self, id: _Optional[str] = ..., mode: _Optional[_Union[GuardPolicyRuleMode, str]] = ..., execution: _Optional[_Union[GuardPolicyRuleExecution, str]] = ..., kind: _Optional[_Union[GuardPolicyRuleKind, str]] = ..., description: _Optional[str] = ..., detector_id: _Optional[str] = ...) -> None: ...

class GuardPolicyDefinition(_message.Message):
    __slots__ = ()
    LANGUAGE_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICIES_FIELD_NUMBER: _ClassVar[int]
    language_version: int
    policies: _containers.RepeatedCompositeFieldContainer[GuardPolicyDefinitionEntry]
    def __init__(self, language_version: _Optional[int] = ..., policies: _Optional[_Iterable[_Union[GuardPolicyDefinitionEntry, _Mapping]]] = ...) -> None: ...

class GuardPolicyDefinitionEntry(_message.Message):
    __slots__ = ()
    ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    REQUIRES_ACTOR_FIELD_NUMBER: _ClassVar[int]
    INPUTS_FIELD_NUMBER: _ClassVar[int]
    DETECTORS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    id: str
    label: str
    requires_actor: bool
    inputs: _containers.RepeatedCompositeFieldContainer[GuardPolicyInputRequirement]
    detectors: _containers.RepeatedCompositeFieldContainer[GuardPolicyDetector]
    rules: _containers.RepeatedCompositeFieldContainer[GuardPolicyRuleDeclaration]
    source: GuardPolicySource
    tests: _containers.RepeatedCompositeFieldContainer[GuardPolicyTest]
    def __init__(self, id: _Optional[str] = ..., label: _Optional[str] = ..., requires_actor: _Optional[bool] = ..., inputs: _Optional[_Iterable[_Union[GuardPolicyInputRequirement, _Mapping]]] = ..., detectors: _Optional[_Iterable[_Union[GuardPolicyDetector, _Mapping]]] = ..., rules: _Optional[_Iterable[_Union[GuardPolicyRuleDeclaration, _Mapping]]] = ..., source: _Optional[_Union[GuardPolicySource, _Mapping]] = ..., tests: _Optional[_Iterable[_Union[GuardPolicyTest, _Mapping]]] = ...) -> None: ...

class GuardPolicySource(_message.Message):
    __slots__ = ()
    REGO_FIELD_NUMBER: _ClassVar[int]
    BUILDER_FIELD_NUMBER: _ClassVar[int]
    rego: str
    builder: GuardPolicyBuilderSpec
    def __init__(self, rego: _Optional[str] = ..., builder: _Optional[_Union[GuardPolicyBuilderSpec, _Mapping]] = ...) -> None: ...

class GuardPolicyBuilderSpec(_message.Message):
    __slots__ = ()
    RULES_FIELD_NUMBER: _ClassVar[int]
    rules: _containers.RepeatedCompositeFieldContainer[GuardPolicyBuilderRule]
    def __init__(self, rules: _Optional[_Iterable[_Union[GuardPolicyBuilderRule, _Mapping]]] = ...) -> None: ...

class GuardPolicyBuilderRule(_message.Message):
    __slots__ = ()
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    CONDITION_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    condition: GuardPolicyBuilderGroup
    def __init__(self, rule_id: _Optional[str] = ..., condition: _Optional[_Union[GuardPolicyBuilderGroup, _Mapping]] = ...) -> None: ...

class GuardPolicyBuilderGroup(_message.Message):
    __slots__ = ()
    OPERATOR_FIELD_NUMBER: _ClassVar[int]
    NEGATED_FIELD_NUMBER: _ClassVar[int]
    CONDITIONS_FIELD_NUMBER: _ClassVar[int]
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    operator: GuardPolicyBuilderOperator
    negated: bool
    conditions: _containers.RepeatedCompositeFieldContainer[GuardPolicyBuilderCondition]
    groups: _containers.RepeatedCompositeFieldContainer[GuardPolicyBuilderGroup]
    def __init__(self, operator: _Optional[_Union[GuardPolicyBuilderOperator, str]] = ..., negated: _Optional[bool] = ..., conditions: _Optional[_Iterable[_Union[GuardPolicyBuilderCondition, _Mapping]]] = ..., groups: _Optional[_Iterable[_Union[GuardPolicyBuilderGroup, _Mapping]]] = ...) -> None: ...

class GuardPolicyBuilderCondition(_message.Message):
    __slots__ = ()
    COMPARISON_FIELD_NUMBER: _ClassVar[int]
    INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    DETECTOR_ID_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    INTEGER_VALUE_FIELD_NUMBER: _ClassVar[int]
    NUMBER_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_LIST_VALUE_FIELD_NUMBER: _ClassVar[int]
    OTHER_INPUT_NAME_FIELD_NUMBER: _ClassVar[int]
    comparison: GuardPolicyBuilderComparison
    input_name: str
    detector_id: str
    string_value: str
    boolean_value: bool
    integer_value: int
    number_value: float
    string_list_value: GuardPolicyStringList
    other_input_name: str
    def __init__(self, comparison: _Optional[_Union[GuardPolicyBuilderComparison, str]] = ..., input_name: _Optional[str] = ..., detector_id: _Optional[str] = ..., string_value: _Optional[str] = ..., boolean_value: _Optional[bool] = ..., integer_value: _Optional[int] = ..., number_value: _Optional[float] = ..., string_list_value: _Optional[_Union[GuardPolicyStringList, _Mapping]] = ..., other_input_name: _Optional[str] = ...) -> None: ...

class GuardPolicyStringList(_message.Message):
    __slots__ = ()
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, values: _Optional[_Iterable[str]] = ...) -> None: ...

class GuardPolicyTest(_message.Message):
    __slots__ = ()
    NAME_FIELD_NUMBER: _ClassVar[int]
    INPUT_JSON_FIELD_NUMBER: _ClassVar[int]
    EXPECT_RULE_IDS_FIELD_NUMBER: _ClassVar[int]
    name: str
    input_json: str
    expect_rule_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, name: _Optional[str] = ..., input_json: _Optional[str] = ..., expect_rule_ids: _Optional[_Iterable[str]] = ...) -> None: ...

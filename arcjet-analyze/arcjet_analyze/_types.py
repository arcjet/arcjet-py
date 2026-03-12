"""Python types for the arcjet:js-req WIT world.

GENERATOR-NOTE: This entire file will be replaced by witgen output.
The public type names and field names defined here form the stable API contract
that the generator must reproduce exactly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar, Union

T = TypeVar("T")
E = TypeVar("E")


# ---------------------------------------------------------------------------
# Result wrappers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    """Wraps the success value from a WIT ``result<T, E>``."""

    value: T


@dataclass(frozen=True, slots=True)
class Err(Generic[E]):
    """Wraps the error value from a WIT ``result<T, E>``."""

    value: E


Result = Union[Ok[T], Err[E]]


# ---------------------------------------------------------------------------
# filter-result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FilterResult:
    """WIT ``filter-result`` record."""

    allowed: bool
    matched_expressions: list[str]
    undetermined_expressions: list[str]


# ---------------------------------------------------------------------------
# bot types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AllowedBotConfig:
    """WIT ``allowed-bot-config`` record."""

    entities: list[str]
    skip_custom_detect: bool


@dataclass(frozen=True, slots=True)
class DeniedBotConfig:
    """WIT ``denied-bot-config`` record."""

    entities: list[str]
    skip_custom_detect: bool


BotConfig = Union[AllowedBotConfig, DeniedBotConfig]


@dataclass(frozen=True, slots=True)
class BotResult:
    """WIT ``bot-result`` record."""

    allowed: list[str]
    denied: list[str]
    verified: bool
    spoofed: bool


# ---------------------------------------------------------------------------
# email types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AllowEmailValidationConfig:
    """WIT ``allow-email-validation-config`` record."""

    require_top_level_domain: bool
    allow_domain_literal: bool
    allow: list[str]


@dataclass(frozen=True, slots=True)
class DenyEmailValidationConfig:
    """WIT ``deny-email-validation-config`` record."""

    require_top_level_domain: bool
    allow_domain_literal: bool
    deny: list[str]


EmailValidationConfig = Union[AllowEmailValidationConfig, DenyEmailValidationConfig]


@dataclass(frozen=True, slots=True)
class EmailValidationResult:
    """WIT ``email-validation-result`` record."""

    validity: str
    blocked: list[str]


# ---------------------------------------------------------------------------
# sensitive-info types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntityEmail:
    """WIT ``sensitive-info-entity::email`` (unit variant case)."""


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntityPhoneNumber:
    """WIT ``sensitive-info-entity::phone-number`` (unit variant case)."""


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntityIpAddress:
    """WIT ``sensitive-info-entity::ip-address`` (unit variant case)."""


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntityCreditCardNumber:
    """WIT ``sensitive-info-entity::credit-card-number`` (unit variant case)."""


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntityCustom:
    """WIT ``sensitive-info-entity::custom(string)`` variant case."""

    value: str


SensitiveInfoEntity = Union[
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityPhoneNumber,
    SensitiveInfoEntityIpAddress,
    SensitiveInfoEntityCreditCardNumber,
    SensitiveInfoEntityCustom,
]


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntitiesAllow:
    """WIT ``sensitive-info-entities::allow(list<sensitive-info-entity>)``."""

    entities: list[SensitiveInfoEntity]


@dataclass(frozen=True, slots=True)
class SensitiveInfoEntitiesDeny:
    """WIT ``sensitive-info-entities::deny(list<sensitive-info-entity>)``."""

    entities: list[SensitiveInfoEntity]


SensitiveInfoEntities = Union[SensitiveInfoEntitiesAllow, SensitiveInfoEntitiesDeny]


@dataclass(frozen=True, slots=True)
class SensitiveInfoConfig:
    """WIT ``sensitive-info-config`` record."""

    entities: SensitiveInfoEntities
    context_window_size: int | None
    skip_custom_detect: bool


@dataclass(frozen=True, slots=True)
class DetectedSensitiveInfoEntity:
    """WIT ``detected-sensitive-info-entity`` record."""

    start: int
    end: int
    identified_type: SensitiveInfoEntity


@dataclass(frozen=True, slots=True)
class SensitiveInfoResult:
    """WIT ``sensitive-info-result`` record."""

    allowed: list[DetectedSensitiveInfoEntity]
    denied: list[DetectedSensitiveInfoEntity]

"""Intermediate representation for parsed WIT definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

# ---------------------------------------------------------------------------
# Type nodes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WitPrimitive:
    name: str  # "string", "bool", "u32"


@dataclass(frozen=True, slots=True)
class WitList:
    element: WitType


@dataclass(frozen=True, slots=True)
class WitOption:
    inner: WitType


@dataclass(frozen=True, slots=True)
class WitResult:
    ok: WitType | None  # None for result<_, E>
    err: WitType | None  # None allowed: WIT permits result<T> without an error type


@dataclass(frozen=True, slots=True)
class WitRef:
    name: str  # kebab-case reference to a named type


WitType = Union[WitPrimitive, WitList, WitOption, WitResult, WitRef]


# ---------------------------------------------------------------------------
# Definition nodes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WitField:
    name: str  # kebab-case
    type: WitType


@dataclass(frozen=True, slots=True)
class WitRecord:
    name: str
    fields: list[WitField]


@dataclass(frozen=True, slots=True)
class WitVariantCase:
    name: str
    payload: WitType | None


@dataclass(frozen=True, slots=True)
class WitVariant:
    name: str
    cases: list[WitVariantCase]


@dataclass(frozen=True, slots=True)
class WitEnum:
    name: str
    cases: list[str]


@dataclass(frozen=True, slots=True)
class WitTypeAlias:
    name: str
    target: WitType


@dataclass(frozen=True, slots=True)
class WitFunc:
    name: str  # kebab-case
    params: list[WitField]
    result: WitType | None


@dataclass(frozen=True, slots=True)
class WitUse:
    interface: str
    names: list[str]


WitTypeDef = Union[WitRecord, WitVariant, WitEnum, WitTypeAlias]


# ---------------------------------------------------------------------------
# Top-level containers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WitInterface:
    name: str
    types: list[WitTypeDef] = field(default_factory=list)
    funcs: list[WitFunc] = field(default_factory=list)


@dataclass(slots=True)
class WitWorld:
    name: str
    package: str
    imports: list[WitInterface] = field(default_factory=list)
    exports: list[WitFunc] = field(default_factory=list)
    types: list[WitTypeDef] = field(default_factory=list)
    uses: list[WitUse] = field(default_factory=list)

"""Explicitly typed values for remotely configured Guard policy."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Mapping, TypeAlias

PolicyInputKind = Literal["STRING", "BOOLEAN", "INTEGER", "NUMBER", "STRING_LIST"]
PolicyInputExposure = Literal["SERVER", "LOCAL"]
PolicyInputValue: TypeAlias = str | bool | int | float | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicyInput:
    """A typed value with an explicit server or local exposure."""

    exposure: PolicyInputExposure
    kind: PolicyInputKind
    value: PolicyInputValue


PolicyInputMap: TypeAlias = Mapping[str, PolicyInput]


class _ServerInput:
    @staticmethod
    def string(value: str) -> PolicyInput:
        return PolicyInput("SERVER", "STRING", value)

    @staticmethod
    def boolean(value: bool) -> PolicyInput:
        return PolicyInput("SERVER", "BOOLEAN", value)

    @staticmethod
    def integer(value: int) -> PolicyInput:
        return PolicyInput("SERVER", "INTEGER", value)

    @staticmethod
    def number(value: int | float) -> PolicyInput:
        return PolicyInput("SERVER", "NUMBER", value)

    @staticmethod
    def string_list(value: list[str] | tuple[str, ...]) -> PolicyInput:
        return PolicyInput("SERVER", "STRING_LIST", tuple(value))


class _LocalInput:
    @staticmethod
    def string(value: str) -> PolicyInput:
        return PolicyInput("LOCAL", "STRING", value)


server_input = _ServerInput()
"""Construct values that Arcjet evaluates and retains as policy evidence."""

local_input = _LocalInput()
"""Construct values that remain in SDK memory; v1 supports strings only."""


def immutable_inputs(inputs: PolicyInputMap) -> PolicyInputMap:
    """Take an immutable shallow snapshot of an application's input mapping."""
    return MappingProxyType(dict(inputs))

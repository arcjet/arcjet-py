"""Optional LangChain tool checkpoint integration.

Install ``arcjet[langchain]`` to use this module. Core Guard clients do not
import LangChain.

A guarded tool is an instance of the wrapped tool's own class — a generated
subclass — that evaluates policy and then hands the call to the tool it wraps.
Everything the framework derives from a tool — its schema, its arguments — is
asked of the wrapped tool rather than recomputed here, so a guarded tool
advertises and executes exactly what the unguarded one did.
"""

from __future__ import annotations

from ._tool import (
    ActorResolver,
    ArcjetToolDeniedError,
    ArcjetToolUnavailableError,
    AsyncActorResolver,
    AsyncInputResolver,
    InputResolver,
    OnGuardError,
    guard_tool,
)

__all__ = [
    "ActorResolver",
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "AsyncActorResolver",
    "AsyncInputResolver",
    "InputResolver",
    "OnGuardError",
    "guard_tool",
]

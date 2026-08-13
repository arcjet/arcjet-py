"""Optional LangChain tool checkpoint integration.

Install ``arcjet[langchain]`` to use this module. Core Guard clients do not
import LangChain.

A guarded tool is an instance of the wrapped tool's own class — a generated
subclass — that evaluates policy and then hands the call to the tool it wraps.
Everything the framework derives from a tool — its schema, its arguments — is
asked of the wrapped tool rather than recomputed here, so a guarded tool
advertises and executes exactly what the unguarded one did.

A guarded tool reads its correlation ID from ``arcjet_correlation_id`` in a
``RunnableConfig``, preferring ``configurable`` over ``metadata``, and falls
back to the enclosing :func:`arcjet.guard.arcjet_sequence`.  LangChain's own
``run_id`` is deliberately **not** used, and should not be adopted later: a
Sequence is meant to be joinable from the user-facing session a human would
go looking for, and an id the framework mints per run produces a Sequence
nobody would think to query.
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

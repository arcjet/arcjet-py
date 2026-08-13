"""Observe-only capture across the LangChain lifecycle.

Callbacks are dispatched without their return value being inspected, so a
handler here cannot deny a call, rewrite it, or delay it. That makes this the
right home for capture and the wrong home for policy: enforcement lives in
``guard_tool`` and ``ArcjetMiddleware``. **Never call guard() from this
module.**

Needs only ``arcjet[langchain]`` — ``BaseCallbackHandler`` is a
``langchain-core`` type and involves no LangGraph.
"""

from __future__ import annotations

from typing import Any, Optional, Union
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler

from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._client import ArcjetGuard, ArcjetGuardSync
from .._context import current_correlation_id
from .._registry import capture as _registry_capture

__all__ = [
    "ArcjetAsyncCaptureHandler",
    "ArcjetCaptureHandler",
]


class _ArcjetCaptureBase:
    """Shared construction and emission for both capture handlers.

    The two handlers differ only in whether their hooks are ``def`` or ``async
    def``; what they do with an event is identical, so it lives here once.

    Metadata records shapes only — action names, run ids, counts. Chain inputs,
    model prompts, tool arguments and tool output never reach it. These hooks
    see exactly the raw user content the rest of the design refuses to move, so
    this is a hard rule rather than a preference.
    """

    _guard: Union[ArcjetGuard, ArcjetGuardSync, None]
    _correlation_id: Optional[str]
    _metadata: Optional[Metadata]
    _prefix: str

    def __init__(
        self,
        *,
        guard: Union[ArcjetGuard, ArcjetGuardSync, None] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        prefix: str = "langchain",
    ) -> None:
        """Configure how lifecycle events are recorded.

        Args:
            guard: The client to emit captures through. ``None`` uses the
                registered client via the free ``capture()``.
            correlation_id: Explicit correlation ID. When omitted, each event
                resolves the ambient ContextVar at emit time rather than at
                construction: a handler is typically built once and reused
                across many runs, so binding the ID here would stamp every
                later run with the first run's Sequence.
            metadata: Metadata attached to every capture from this handler.
            prefix: Prepended to action names, e.g. ``"langchain.chain.started"``.
        """
        super().__init__()
        self._guard = guard
        self._correlation_id = correlation_id
        self._metadata = metadata
        self._prefix = prefix

    def _emit(self, action: str, **extra: Any) -> None:
        """Record one lifecycle event. Never raises.

        A callback that throws would surface as a failure of the chain it was
        only watching. Capture is best-effort telemetry; an observation problem
        must never become the application's problem.

        The correlation ID is resolved here, per event, rather than in
        ``__init__``: one handler is reused across many runs, so a value bound
        at construction would put every later run on the first run's Sequence.

        ``Exception`` and not ``BaseException``, so ``KeyboardInterrupt`` and
        ``SystemExit`` still reach the caller.
        """
        try:
            correlation_id = (
                self._correlation_id
                if self._correlation_id is not None
                else current_correlation_id()
            )
            metadata = {**(self._metadata or {}), **extra}
            if self._guard is None:
                _registry_capture(
                    action=action, correlation_id=correlation_id, metadata=metadata
                )
            else:
                self._guard.capture(
                    action=action, correlation_id=correlation_id, metadata=metadata
                )
        except Exception:
            logger.warning("arcjet: failed to capture %r", action)


class ArcjetCaptureHandler(_ArcjetCaptureBase, BaseCallbackHandler):
    """Synchronous callback handler capturing LangChain lifecycle events."""

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chain starts."""
        action = f"{self._prefix}.chain.started"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chain ends."""
        action = f"{self._prefix}.chain.completed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chain errors."""
        action = f"{self._prefix}.chain.failed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM starts."""
        action = f"{self._prefix}.model.started"
        extra = {"run_id": str(run_id), "prompt_count": len(prompts)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM ends."""
        action = f"{self._prefix}.model.completed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM errors."""
        action = f"{self._prefix}.model.failed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        inputs: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool starts."""
        action = f"{self._prefix}.tool.started"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool ends."""
        action = f"{self._prefix}.tool.completed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool errors."""
        action = f"{self._prefix}.tool.failed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)


class ArcjetAsyncCaptureHandler(_ArcjetCaptureBase, AsyncCallbackHandler):
    """Asynchronous callback handler capturing LangChain lifecycle events.

    Mirrors ArcjetCaptureHandler with async def hooks calling the same
    synchronous _emit. capture() queues and returns on both client flavors,
    so there is nothing to await and no second code path.

    """

    async def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chain starts."""
        action = f"{self._prefix}.chain.started"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chain ends."""
        action = f"{self._prefix}.chain.completed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a chain errors."""
        action = f"{self._prefix}.chain.failed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM starts."""
        action = f"{self._prefix}.model.started"
        extra = {"run_id": str(run_id), "prompt_count": len(prompts)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM ends."""
        action = f"{self._prefix}.model.completed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when an LLM errors."""
        action = f"{self._prefix}.model.failed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        inputs: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool starts."""
        action = f"{self._prefix}.tool.started"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool ends."""
        action = f"{self._prefix}.tool.completed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

    async def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called when a tool errors."""
        action = f"{self._prefix}.tool.failed"
        extra = {"run_id": str(run_id)}
        if parent_run_id is not None:
            extra["parent_run_id"] = str(parent_run_id)
        self._emit(action, **extra)

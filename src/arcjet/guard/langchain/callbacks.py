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


class ArcjetCaptureHandler(BaseCallbackHandler):
    """Synchronous callback handler capturing LangChain lifecycle events.

    Metadata records only event shapes and structural information: run IDs,
    action names, counts of inputs or outputs. Never puts chain inputs,
    model prompts, tool inputs/outputs, or any user content into metadata,
    as this handler sees exactly the raw data the rest of the design refuses
    to move.
    """

    def __init__(
        self,
        *,
        guard: Union[ArcjetGuard, ArcjetGuardSync, None] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        prefix: str = "langchain",
    ) -> None:
        """Initialize the synchronous capture handler.

        Args:
            guard: The Arcjet guard client to emit captures through. If None,
                uses the registered client via the free capture() function.
            correlation_id: Explicit correlation ID. When omitted, each event
                resolves the ambient ContextVar **at emit time**, not at
                construction. A handler is typically built once and reused
                across many runs, so binding the ID at construction would stamp
                every later run with the first run's Sequence. Resolve it inside
                _emit and comment why.
            metadata: Additional metadata to attach to all captures from this
                handler.
            prefix: String prepended to action names. Defaults to "langchain".
                Builds action names like f"{prefix}.chain.started".
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


class ArcjetAsyncCaptureHandler(AsyncCallbackHandler):
    """Asynchronous callback handler capturing LangChain lifecycle events.

    Mirrors ArcjetCaptureHandler with async def hooks calling the same
    synchronous _emit. capture() queues and returns on both client flavors,
    so there is nothing to await and no second code path.

    Metadata records only event shapes and structural information: run IDs,
    action names, counts of inputs or outputs. Never puts chain inputs,
    model prompts, tool inputs/outputs, or any user content into metadata,
    as this handler sees exactly the raw data the rest of the design refuses
    to move.
    """

    def __init__(
        self,
        *,
        guard: Union[ArcjetGuard, ArcjetGuardSync, None] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Metadata] = None,
        prefix: str = "langchain",
    ) -> None:
        """Initialize the asynchronous capture handler.

        Args:
            guard: The Arcjet guard client to emit captures through. If None,
                uses the registered client via the free capture() function.
            correlation_id: Explicit correlation ID. When omitted, each event
                resolves the ambient ContextVar **at emit time**, not at
                construction. A handler is typically built once and reused
                across many runs, so binding the ID at construction would stamp
                every later run with the first run's Sequence. Resolve it inside
                _emit and comment why.
            metadata: Additional metadata to attach to all captures from this
                handler.
            prefix: String prepended to action names. Defaults to "langchain".
                Builds action names like f"{prefix}.chain.started".
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

"""AnalyzeComponent: typed wrapper for arcjet_analyze_js_req.component.wasm.

GENERATOR-NOTE: The _call() helper and all export method wrappers will be
auto-generated. The class name (AnalyzeComponent) and method signatures form
the stable public API that the generator must reproduce.
"""

from __future__ import annotations

from typing import Any

from wasmtime import Engine, Store
from wasmtime import component as cm

from ._convert import (
    from_wasm_bot_result,
    from_wasm_email_validation_result,
    from_wasm_filter_result,
    from_wasm_fingerprint_result,
    from_wasm_sensitive_info_result,
    from_wasm_validate_characteristics_result,
    to_wasm_bot_config,
    to_wasm_email_validation_config,
    to_wasm_sensitive_info_config,
)
from ._imports import ImportCallbacks, wire_imports
from ._types import (
    BotConfig,
    BotResult,
    EmailValidationConfig,
    EmailValidationResult,
    FilterResult,
    Result,
    SensitiveInfoConfig,
    SensitiveInfoResult,
)


class AnalyzeComponent:
    """Reusable wrapper around the full arcjet-analyze WASM component.

    Engine, Component, and Linker are created once and reused.
    Each export call creates a fresh Store + instance (required by wasmtime).
    """

    def __init__(
        self,
        wasm_path: str,
        callbacks: ImportCallbacks | None = None,
    ) -> None:
        self._engine = Engine()
        self._component = cm.Component.from_file(self._engine, wasm_path)
        self._linker = cm.Linker(self._engine)
        self._linker.allow_shadowing = True

        wire_imports(self._linker, self._component, callbacks)

    def _call(self, export_name: str, *args: Any) -> Any:
        """Call a named export with a fresh Store."""
        store = Store(self._engine)
        instance = self._linker.instantiate(store, self._component)
        func = instance.get_func(store, export_name)
        if func is None:
            raise RuntimeError(f"{export_name} export not found in component")
        return func(store, *args)

    # ------------------------------------------------------------------
    # Exported functions
    # ------------------------------------------------------------------

    def match_filters(
        self,
        request: str,
        expressions: list[str],
        allow_if_match: bool,
    ) -> Result[FilterResult, str]:
        """Run ``match-filters`` on the component.

        Returns ``Ok(FilterResult)`` on success or ``Err(str)`` on failure.
        """
        raw = self._call("match-filters", request, expressions, allow_if_match)
        return from_wasm_filter_result(raw)

    def detect_bot(
        self,
        request: str,
        options: BotConfig,
    ) -> Result[BotResult, str]:
        """Run ``detect-bot`` on the component.

        *options* is either an ``AllowedBotConfig`` or ``DeniedBotConfig``.
        """
        raw = self._call("detect-bot", request, to_wasm_bot_config(options))
        return from_wasm_bot_result(raw)

    def generate_fingerprint(
        self,
        request: str,
        characteristics: list[str],
    ) -> Result[str, str]:
        """Run ``generate-fingerprint`` on the component.

        Returns ``Ok(str)`` with the fingerprint or ``Err(str)`` on failure.
        Note: ``result<string, string>`` is tagged in wasmtime-py.
        """
        raw = self._call("generate-fingerprint", request, characteristics)
        return from_wasm_fingerprint_result(raw)

    def validate_characteristics(
        self,
        request: str,
        characteristics: list[str],
    ) -> Result[None, str]:
        """Run ``validate-characteristics`` on the component.

        Returns ``Ok(None)`` if valid, ``Err(str)`` with an error message.
        """
        raw = self._call("validate-characteristics", request, characteristics)
        return from_wasm_validate_characteristics_result(raw)

    def is_valid_email(
        self,
        candidate: str,
        options: EmailValidationConfig,
    ) -> Result[EmailValidationResult, str]:
        """Run ``is-valid-email`` on the component.

        *options* is either ``AllowEmailValidationConfig`` or
        ``DenyEmailValidationConfig``.
        """
        raw = self._call(
            "is-valid-email",
            candidate,
            to_wasm_email_validation_config(options),
        )
        return from_wasm_email_validation_result(raw)

    def detect_sensitive_info(
        self,
        content: str,
        options: SensitiveInfoConfig,
    ) -> SensitiveInfoResult:
        """Run ``detect-sensitive-info`` on the component.

        Unlike the other exports, this returns a ``SensitiveInfoResult``
        directly (not wrapped in ``result<T, E>``).
        """
        raw = self._call(
            "detect-sensitive-info",
            content,
            to_wasm_sensitive_info_config(options),
        )
        return from_wasm_sensitive_info_result(raw)

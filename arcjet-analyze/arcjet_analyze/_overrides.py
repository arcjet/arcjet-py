"""Hand-maintained overrides for AnalyzeComponentBase.

This file is NOT generated — it provides the per-call callback override
for ``detect_sensitive_info`` via inheritance and linker shadowing.
"""

from __future__ import annotations

from typing import Callable

from wasmtime import Store
from wasmtime.component._types import Variant

from ._component import AnalyzeComponentBase
from ._convert import (
    from_wasm_detect_sensitive_info,
    to_wasm_sensitive_info_config,
    to_wasm_sensitive_info_entity,
)
from ._import_defaults import _default_sensitive_info_detect
from ._imports import ImportCallbacks
from ._types import SensitiveInfoConfig, SensitiveInfoEntity, SensitiveInfoResult


class AnalyzeComponent(AnalyzeComponentBase):
    """AnalyzeComponentBase with per-call callback override for detect_sensitive_info."""

    def __init__(
        self,
        wasm_path: str,
        callbacks: ImportCallbacks | None = None,
    ) -> None:
        super().__init__(wasm_path, callbacks)

        # Mutable container for per-call callback swapping
        cb = callbacks or ImportCallbacks()
        self._si_detect_ref: list[
            Callable[[list[str]], list[SensitiveInfoEntity | None]] | None
        ] = [cb.sensitive_info_detect or _default_sensitive_info_detect]

        # Re-wire si-detect to read from mutable ref (linker.allow_shadowing = True).
        # Only mutate index 0; never reassign the list itself — the closure
        # below captures this reference and would not see a new list object.
        si_detect_ref = self._si_detect_ref

        with self._linker.root() as root:
            with root.add_instance(
                "arcjet:js-req/sensitive-information-identifier"
            ) as iface:

                def _si_detect(
                    _store: Store, tokens: list[str]
                ) -> list[Variant | None]:
                    fn = si_detect_ref[0]
                    if fn is None:
                        return [None] * len(tokens)
                    results = fn(tokens)
                    if len(results) != len(tokens):
                        raise ValueError(
                            f"sensitive_info_detect callback returned "
                            f"{len(results)} results for {len(tokens)} tokens"
                        )
                    return [
                        None if r is None else to_wasm_sensitive_info_entity(r)
                        for r in results
                    ]

                iface.add_func("detect", _si_detect)

    def detect_sensitive_info(
        self,
        content: str,
        options: SensitiveInfoConfig,
        detect: Callable[[list[str]], list[SensitiveInfoEntity | None]] | None = None,
    ) -> SensitiveInfoResult:
        """Run ``detect-sensitive-info`` with optional per-call callback override.

        If *detect* is provided, it temporarily overrides the default
        ``sensitive_info_detect`` import callback for this single invocation
        (thread-safe — swapped under the instance lock).
        """
        wasm_opts = to_wasm_sensitive_info_config(options)
        if detect is not None:
            with self._call_lock:
                prev = self._si_detect_ref[0]
                self._si_detect_ref[0] = detect
                try:
                    store = Store(self._engine)
                    instance = self._linker.instantiate(store, self._component)
                    func = instance.get_func(store, "detect-sensitive-info")
                    if func is None:
                        raise RuntimeError(
                            "detect-sensitive-info export not found in component"
                        )
                    raw = func(store, content, wasm_opts)
                finally:
                    self._si_detect_ref[0] = prev
        else:
            raw = self._call("detect-sensitive-info", content, wasm_opts)
        return from_wasm_detect_sensitive_info(raw)

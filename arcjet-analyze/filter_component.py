"""Typed host-side wrapper for the arcjet-analyze filter WASM component."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar, Union

from wasmtime import Engine, Store
from wasmtime import component as cm

T = TypeVar("T")
E = TypeVar("E")


@dataclass
class Ok(Generic[T]):
    value: T


@dataclass(frozen=True)
class Err(Generic[E], Exception):
    value: E


Result = Union[Ok[T], Err[E]]


@dataclass
class FilterResult:
    allowed: bool
    matched_expressions: list[str]
    undetermined_expressions: list[str]


class FilterComponent:
    """Reusable wrapper around the filter WASM component.

    Engine, Component, and Linker are created once and reused.
    Each call to match_filters creates a fresh Store and instance.
    """

    def __init__(
        self,
        wasm_path: str,
        ip_lookup: Callable[[str], str | None] | None = None,
    ) -> None:
        self._engine = Engine()
        self._component = cm.Component.from_file(self._engine, wasm_path)
        self._linker = cm.Linker(self._engine)
        self._linker.allow_shadowing = True

        # Trap all imports we don't explicitly provide
        self._linker.define_unknown_imports_as_traps(self._component)

        # Wire up the ip-lookup override
        if ip_lookup is None:
            ip_lookup = lambda _ip: None

        lookup_fn = ip_lookup

        def _ip_lookup(_store: Store, ip: str) -> None | str:
            return lookup_fn(ip)

        with self._linker.root() as root:
            with root.add_instance("arcjet:js-req/filter-overrides") as iface:
                iface.add_func("ip-lookup", _ip_lookup)

    def match_filters(
        self,
        request: str,
        expressions: list[str],
        allow_if_match: bool,
    ) -> Result[FilterResult, str]:
        """Run match-filters on the WASM component.

        Returns Ok(FilterResult) on success or Err(str) on failure.
        A fresh Store and instance are created for each call because the
        component cannot be called twice on the same Store.
        """
        store = Store(self._engine)
        instance = self._linker.instantiate(store, self._component)

        func = instance.get_func(store, "match-filters")
        if func is None:
            raise RuntimeError("match-filters export not found in component")

        raw = func(store, request, expressions, allow_if_match)

        # wasmtime-py v40 returns result<T, E> as:
        #   Ok  -> a Record object with kebab-case attributes
        #   Err -> a plain value (str in our case)
        if isinstance(raw, str):
            return Err(raw)

        return Ok(
            FilterResult(
                allowed=raw.allowed,
                matched_expressions=getattr(raw, "matched-expressions"),
                undetermined_expressions=getattr(raw, "undetermined-expressions"),
            )
        )


if __name__ == "__main__":
    wasm = os.path.join(
        os.path.dirname(__file__), "arcjet_analyze_js_req.component.wasm"
    )
    fc = FilterComponent(wasm)

    def print_result(label: str, result: Result) -> None:
        print(f"{label}: {result}")
        if isinstance(result, Ok):
            fr = result.value
            print(f"  allowed: {fr.allowed}")
            print(f"  matched: {fr.matched_expressions}")
            print(f"  undetermined: {fr.undetermined_expressions}")
        else:
            print(f"  error: {result.value}")

    # Test Ok path: no expressions -> always allowed
    print_result("Ok path (no exprs)", fc.match_filters("{}", [], True))

    # Test Err path: invalid expression syntax
    print_result(
        "Err path (bad expr)",
        fc.match_filters('{"protocol":"http"}', ['protocol == "http"'], True),
    )

    # Test multiple calls work (fresh Store each time)
    print_result("Second call", fc.match_filters("{}", [], False))

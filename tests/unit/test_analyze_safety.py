"""Tests for wasmtime slab-safety helpers (no WASM required)."""

from __future__ import annotations

import gc

from arcjet._analyze._safety import collect_wasmtime_finalizers, wasmtime_section


def test_wasmtime_section_disables_gc_and_restores() -> None:
    assert gc.isenabled()
    with wasmtime_section():
        assert not gc.isenabled()
    assert gc.isenabled()


def test_wasmtime_section_is_reentrant() -> None:
    assert gc.isenabled()
    with wasmtime_section():
        assert not gc.isenabled()
        with wasmtime_section():
            assert not gc.isenabled()
        assert not gc.isenabled()
    assert gc.isenabled()


def test_wasmtime_section_preserves_already_disabled_gc() -> None:
    gc.disable()
    try:
        with wasmtime_section():
            assert not gc.isenabled()
        assert not gc.isenabled()
    finally:
        gc.enable()
    assert gc.isenabled()


def test_collect_wasmtime_finalizers_runs() -> None:
    # Just prove the helper is callable and does not raise.
    collect_wasmtime_finalizers()

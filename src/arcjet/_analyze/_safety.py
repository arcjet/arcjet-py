"""Workarounds for wasmtime-py process-global slabs and cyclic finalizers.

wasmtime-py keeps host functions in a process-global ``Slab`` (see
bytecodealliance/wasmtime-py#254). ``Slab.allocate`` is not reentrant: if a
``__del__`` finalizer deallocates a handle while another allocation is in
progress, ``self.next`` can become a function and the next ``allocate``
raises ``TypeError: list indices must be integers or slices, not function``.

pytest 9.1 reduced inter-test ``gc.collect()`` passes from 5 to 1 on CPython
(pytest#14441), which left more of those cyclic finalizers pending and
surfaced the race in CI (arcjet-py#154).

``wasmtime_section`` serializes slab-touching operations and suspends GC so a
finalizer cannot run mid-allocate. ``collect_wasmtime_finalizers`` drains the
cycles at a known point (test teardown) rather than during the next
component's construction.
"""

from __future__ import annotations

import gc
import threading
from collections.abc import Iterator
from contextlib import contextmanager

_lock = threading.RLock()
_depth = 0


@contextmanager
def wasmtime_section() -> Iterator[None]:
    """Hold the process-global wasmtime lock and suspend GC.

    Re-entrant on the same thread so ``__init__``, ``_call``, and ``close``
    can nest. Distinct threads — and distinct ``AnalyzeComponent`` instances
    — fully serialize for the duration of the section, including the WASM
    call itself. That is required: wasmtime-py's function slab is
    process-global and unsynchronized, so a per-instance lock is not enough
    and must not be restored in place of this section.

    GC is disabled only at depth 0 and re-enabled in an outer ``finally`` so
    an interrupt between ``gc.disable()`` and the depth increment cannot
    leave collection permanently off.
    """
    global _depth
    with _lock:
        restore_gc = False
        try:
            if _depth == 0:
                restore_gc = gc.isenabled()
                gc.disable()
            _depth += 1
            try:
                yield
            finally:
                _depth -= 1
        finally:
            if _depth == 0 and restore_gc:
                gc.enable()


def collect_wasmtime_finalizers() -> None:
    """Run enough cyclic GC passes to drain wasmtime ``__del__`` finalizers.

    CPython needs multiple passes when finalizers themselves produce
    garbage — the situation pytest 9.1 no longer handles between tests.
    """
    for _ in range(5):
        gc.collect()

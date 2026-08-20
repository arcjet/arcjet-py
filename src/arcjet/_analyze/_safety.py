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
_restore_gc = False


@contextmanager
def wasmtime_section() -> Iterator[None]:
    """Hold the process-global wasmtime lock and suspend GC.

    Re-entrant on the same thread so ``__init__``, ``_call``, and ``close``
    can nest. Distinct threads serialize, which also covers wasmtime-py's
    unsynchronized slabs.
    """
    global _depth, _restore_gc
    with _lock:
        if _depth == 0:
            _restore_gc = gc.isenabled()
            gc.disable()
        _depth += 1
        try:
            yield
        finally:
            _depth -= 1
            if _depth == 0 and _restore_gc:
                gc.enable()


def collect_wasmtime_finalizers() -> None:
    """Run enough cyclic GC passes to drain wasmtime ``__del__`` finalizers.

    CPython needs multiple passes when finalizers themselves produce
    garbage — the situation pytest 9.1 no longer handles between tests.
    """
    for _ in range(5):
        gc.collect()

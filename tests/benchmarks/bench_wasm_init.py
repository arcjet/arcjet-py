"""Cold-start WASM benchmarks — one-time initialisation cost.

Measures the full cost of creating an AnalyzeComponent from scratch:
Engine creation, WASM file compilation (JIT), Linker setup, and wire_imports.

Uses pedantic mode with few rounds since init is inherently slow.
"""

from __future__ import annotations

from arcjet._analyze import AnalyzeComponent


def test_bench_analyze_component_init(benchmark, wasm_path: str):
    """Full cold-start: Engine + JIT compile + Linker + wire_imports."""
    benchmark.pedantic(
        AnalyzeComponent,
        args=(wasm_path,),
        rounds=5,
        warmup_rounds=1,
    )

"""Python-side serialization benchmarks — no WASM involved.

Isolates the cost of converting RequestContext to the JSON/proto shapes
expected by WASM and the remote Decide API respectively.
"""

from __future__ import annotations

from arcjet._local import _context_to_analyze_request
from arcjet.context import RequestContext, request_details_from_context


def test_bench_context_to_analyze_request(benchmark, bot_ctx: RequestContext):
    """Serialize a typical RequestContext to WASM JSON."""
    benchmark(_context_to_analyze_request, bot_ctx)


def test_bench_context_to_analyze_request_many_headers(
    benchmark, many_headers_ctx: RequestContext
):
    """Serialize a RequestContext with 20 headers — worst-case header normalisation."""
    benchmark(_context_to_analyze_request, many_headers_ctx)


def test_bench_request_details_from_context(benchmark, bot_ctx: RequestContext):
    """Build proto RequestDetails from context — remote-path baseline."""
    benchmark(request_details_from_context, bot_ctx)

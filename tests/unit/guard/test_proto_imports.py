"""Regression test: the generated Connect module must be importable.

buf generates ``decide_connect.py`` with a top-level ``import proto.decide...``
that must be rewritten to the vendored ``arcjet.guard.proto...`` package.
Nothing else imports the module at collection time (the clients import it
lazily), so without this test a bad regeneration only fails at runtime.
"""

from __future__ import annotations


def test_decide_connect_is_importable() -> None:
    from arcjet.guard.proto.decide.v2 import decide_connect

    assert hasattr(decide_connect, "DecideServiceClient")
    assert hasattr(decide_connect, "DecideServiceClientSync")

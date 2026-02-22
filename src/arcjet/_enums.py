from __future__ import annotations

from enum import Enum

from arcjet.proto.decide.v1alpha1 import decide_pb2


class Mode(str, Enum):
    """Rule enforcement mode.

    - Use ``LIVE`` to actively enforce a rule.
    - Use ``DRY_RUN`` to observe rule results - useful for testing a new rule
    before enabling enforcement.

    In ``DRY_RUN`` mode, individual rule results will return as if there in
    ``LIVE`` mode (e.g. a rule match will return a conclusion of DENY), but the
    top level conclusion will always be ``ALLOW`` and ``is_denied()`` will
    return ``False``. Log or loop through the rule results to see which rules
    returned a ``DENY`` conclusion.

    Example::

        from arcjet import Mode, shield, token_bucket

        # ...
        rules = [
            # Shield runs in LIVE mode
            shield(mode=Mode.LIVE),
            # Detect bot runs in DRY_RUN mode
            detect_bot(
                mode=Mode.DRY_RUN, allow=[
                    BotCategory.SEARCH_ENGINE,
                ]
            ),
        ]
    """

    DRY_RUN = "DRY_RUN"
    """Observe only — rule will return a conclusion of DENY, but the top level
    conclusion will be ``ALLOW`` and ``is_denied()`` will return ``False``.
    Useful for testing a new rule before enabling enforcement."""

    LIVE = "LIVE"
    """Enforce — requests that match the rule return a conclusion of
    ``DENY``."""

    def to_proto(self) -> decide_pb2.Mode:
        if self is Mode.DRY_RUN:
            return decide_pb2.MODE_DRY_RUN
        return decide_pb2.MODE_LIVE


def _mode_to_proto(mode: str | Mode) -> decide_pb2.Mode:
    if isinstance(mode, Mode):
        return mode.to_proto()
    m = str(mode).upper()
    if m in ("DRY_RUN", "DRYRUN", "DRY-RUN"):
        return decide_pb2.MODE_DRY_RUN
    if m == "LIVE":
        return decide_pb2.MODE_LIVE
    raise ValueError(f"Unknown mode: {mode!r}. Expected 'LIVE' or 'DRY_RUN'.")

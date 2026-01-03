from __future__ import annotations

from enum import Enum
from arcjet.proto.decide.v1alpha1 import decide_pb2


class Mode(str, Enum):
    DRY_RUN = "DRY_RUN"
    LIVE = "LIVE"

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

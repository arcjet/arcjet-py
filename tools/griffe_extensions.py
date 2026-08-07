"""Extensions for checking the public Python API with Griffe."""

from typing import Any

import griffe


class IgnoreProtobufDescriptors(griffe.Extension):
    """Exclude generated protobuf descriptors from API compatibility checks."""

    def on_module(self, *, mod: griffe.Module, **kwargs: Any) -> None:
        if ".proto." in mod.path and mod.name.endswith("_pb2"):
            mod.members.pop("DESCRIPTOR", None)

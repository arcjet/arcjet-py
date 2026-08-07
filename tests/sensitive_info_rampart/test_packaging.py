"""Lightweight packaging / import smoke tests for the optional Rampart package.

Unlike ``test_integration.py`` (gated behind ``ARCJET_RAMPART_INTEGRATION`` and a
real ``onnxruntime``), these run in the default CI job so a missing model asset,
packaging metadata problem, or import regression is caught before release —
without loading the ONNX model or requiring the heavy runtime.
"""

from __future__ import annotations

import os
from importlib.resources import files

import arcjet_sensitive_info_rampart as pkg
from arcjet_sensitive_info_rampart._model import _default_model_path


def test_package_imports():
    assert callable(pkg.rampart)


def test_public_api_surface_is_importable():
    for name in pkg.__all__:
        assert hasattr(pkg, name), f"{name!r} is exported in __all__ but missing"


def test_bundled_model_assets_present():
    # The loader reads these at first use; if the build omits them, first use
    # fails at runtime. Assert they ship in the installed package so a packaging
    # regression is caught here rather than in production.
    root = files("arcjet_sensitive_info_rampart") / "models" / "rampart"
    for rel in ("config.json", "tokenizer.json", "onnx/model_q4.onnx"):
        asset = root
        for part in rel.split("/"):
            asset = asset / part
        assert asset.is_file(), f"missing bundled model asset: {rel}"


def test_default_model_path_resolves_to_a_directory():
    assert os.path.isdir(_default_model_path())


def test_rampart_constructs_without_loading_model():
    # Building the backend must not load the ONNX model (deferred to the first
    # detect call), so this succeeds even without onnxruntime installed.
    backend = pkg.rampart()
    assert hasattr(backend, "detect")

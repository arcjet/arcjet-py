"""The guard label rule, held to the cases every Arcjet validator agrees on.

A label is compared against a published policy exactly, so a label the service
would reject matches nothing and the guard silently does not run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcjet.guard import ArcjetInvalidLabelError, validate_guard_label
from arcjet.guard._label import MAX_LABEL_BYTES, label_problem

_CASES_PATH = Path(__file__).parents[2] / "fixtures" / "guard-label-cases.json"
_DOC = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
_CASES = _DOC["cases"]


def test_the_shared_cases_loaded() -> None:
    # A fixture that read as empty would leave every case below passing while
    # testing none of them.
    assert len(_CASES) > 0


@pytest.mark.parametrize("case", _CASES, ids=[c["label"] or "<empty>" for c in _CASES])
def test_label_problem_agrees_with_the_shared_cases(case: dict) -> None:
    assert (label_problem(case["label"]) is None) is case["valid"], case.get("reason")


def test_accepts_256_bytes_and_rejects_257() -> None:
    # The literal is deliberate. Deriving the bound from MAX_LABEL_BYTES would
    # move this expectation with the constant, so the test would assert only
    # that the module agrees with itself.
    assert label_problem("a" * 256) is None
    assert label_problem("a" * 257) is not None


def test_the_byte_bound_is_256() -> None:
    assert MAX_LABEL_BYTES == 256


def test_reports_an_over_long_label_by_length_not_by_its_first_odd_character() -> None:
    # Every character a label may contain is ASCII, so byte count and character
    # count agree for anything that could pass. They differ only for input that
    # is rejected either way, and there the difference is the reason given.
    over_long = "a" + "\U0001f600" * 64
    problem = label_problem(over_long)
    assert problem is not None
    assert "256 bytes" in problem


def test_validate_guard_label_raises_naming_the_label_and_the_reason() -> None:
    with pytest.raises(ArcjetInvalidLabelError) as excinfo:
        validate_guard_label("getWeather.invoked")
    message = str(excinfo.value)
    assert "getWeather.invoked" in message
    assert "uppercase" in message


def test_validate_guard_label_accepts_a_label_the_service_accepts() -> None:
    validate_guard_label("send_email.invoked")


def test_the_reported_problem_names_the_offending_character() -> None:
    assert "'W'" in (label_problem("getWeather.invoked") or "")
    assert "' '" in (label_problem("tools.a b") or "")

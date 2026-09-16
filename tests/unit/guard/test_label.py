"""The guard label rule, held to the cases every Arcjet validator agrees on.

A label is compared against a published policy exactly, so a label the service
would reject matches nothing and the guard silently does not run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from guard_doubles import StubGuardClient, make_allow_decision

from arcjet.guard import (
    ArcjetInvalidLabelError,
    ArcjetUnavailableError,
    ArcjetWarning,
    Decision,
    guard_action_sync,
    validate_guard_label,
)
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


class TestAdapterEntryPointsRefuseABadLabel:
    """Every construction-time entry point refuses a label no policy can match.

    A label derived from a tool name at call time is not checked here — the
    service judges that one and AJ1023 carries the verdict back. CrewAI is
    exempt for the same reason plus one of its own: ``sanitize_tool_name``
    lowercases and separates with underscores, so its derived labels are valid
    by construction.
    """

    def test_tool_policy_dataclasses(self) -> None:
        from arcjet.guard.crewai._hooks import ToolPolicy as CrewToolPolicy
        from arcjet.guard.langchain._middleware import ToolPolicy as LangChainToolPolicy

        for policy_type in (CrewToolPolicy, LangChainToolPolicy):
            with pytest.raises(ArcjetInvalidLabelError):
                policy_type(action="getWeather.invoked")
            policy_type(action="send_email.invoked")

    def test_wrapper_factories(self) -> None:
        from arcjet.guard.claude_managed_agents import guard_custom_tool, guard_events

        with pytest.raises(ArcjetInvalidLabelError):
            guard_events(
                guard=object(), send=lambda *a, **k: None, action="getWeather.invoked"
            )
        with pytest.raises(ArcjetInvalidLabelError):
            guard_custom_tool(
                guard=object(), run=lambda e: None, action="getWeather.invoked"
            )

    def test_hooks_check_only_a_literal_action(self) -> None:
        from arcjet.guard.claude_agent_sdk import guard_hooks as claude_guard_hooks
        from arcjet.guard.crewai import register_arcjet_hooks
        from arcjet.guard.strands_agents import guard_hooks as strands_guard_hooks

        for factory in (claude_guard_hooks, strands_guard_hooks, register_arcjet_hooks):
            with pytest.raises(ArcjetInvalidLabelError):
                factory(guard=object(), action="getWeather.invoked")

            # A callable is only resolvable per call, so it must not be refused
            # here. Anything else the adapter raises — a missing optional peer,
            # for instance — is not what this asserts.
            try:
                factory(guard=object(), action=lambda *a, **k: "getWeather.invoked")
            except ArcjetInvalidLabelError:  # pragma: no cover - the failure case
                pytest.fail("a callable action must not be refused at construction")
            except Exception:
                pass

    def test_crewai_sanitizer_still_produces_valid_labels(self) -> None:
        from arcjet.guard.crewai import sanitize_tool_name

        for raw in ("Send Email", "lookupOrder", "getWeather", "refund"):
            assert label_problem(f"{sanitize_tool_name(raw)}.invoked") is None


class TestARejectedLabelIsUnevaluatedPolicy:
    """AJ1023 means the service replaced the label with ``invalid-label``.

    No published policy could have matched, so the guard did not run. The
    decision still reads ALLOW and ``has_failed_open()`` is false, which is
    exactly why this used to look like a guard that ran and permitted the call.
    """

    @staticmethod
    def _label_rejected_decision() -> Decision:
        return Decision(
            conclusion="ALLOW",
            id="gdec_invalid_label",
            reason="UNKNOWN",
            results=(),
            warnings=(
                ArcjetWarning(
                    code="AJ1023",
                    message='label is invalid and was replaced with "invalid-label"',
                ),
            ),
        )

    def test_it_denies_by_default(self) -> None:
        ran = False

        def action() -> str:
            nonlocal ran
            ran = True
            return "ran"

        client = StubGuardClient(decision=self._label_rejected_decision())
        with pytest.raises(ArcjetUnavailableError):
            guard_action_sync(
                action,
                action="tool.invoked",
                guard=client,  # type: ignore[arg-type]
            )
        assert ran is False, "the guarded callable must not run"

    def test_on_guard_error_allow_lets_it_run(self) -> None:
        client = StubGuardClient(decision=self._label_rejected_decision())
        out = guard_action_sync(
            lambda: "ran",
            action="tool.invoked",
            guard=client,  # type: ignore[arg-type]
            on_guard_error="allow",
        )
        assert out == "ran"

    def test_a_decision_without_aj1023_is_unaffected(self) -> None:
        client = StubGuardClient(decision=make_allow_decision())
        out = guard_action_sync(
            lambda: "ran",
            action="tool.invoked",
            guard=client,  # type: ignore[arg-type]
        )
        assert out == "ran"

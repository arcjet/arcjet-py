"""Typed errors raised by Arcjet checkpoints.

Split from the surfaces that raise them so the checkpoint engine can stay
framework-agnostic: :mod:`arcjet.guard.langchain` narrows these into
``ToolException`` subclasses, and a caller that guards a Celery task catches
the base pair without importing LangChain.
"""

from __future__ import annotations

from typing import Literal, Optional

from arcjet._errors import ArcjetMisconfiguration

from ._types import Decision

__all__ = [
    "ArcjetDeniedError",
    "ArcjetInvalidLabelError",
    "ArcjetUnavailableError",
    "OnGuardError",
]

OnGuardError = Literal["allow", "deny"]
"""What to do when policy could not be evaluated.

``"deny"`` is the default on every checkpoint surface, because they wrap
consequential effects.  This is the one place Arcjet diverges from its
platform-wide fail-open convention, so it is always documented alongside the
``"allow"`` opt-out.
"""


class ArcjetDeniedError(Exception):
    """Raised when Arcjet policy denied the action.

    A real decision, not a degraded one: this is raised regardless of
    ``on_guard_error``, because ``"allow"`` opts out of failing closed on an
    *unevaluated* policy, never out of an evaluated denial.
    """

    def __init__(self, action: str, decision: Decision) -> None:
        super().__init__(f'Arcjet denied action "{action}" ({decision.reason})')
        self.action = action
        self.decision = decision


class ArcjetUnavailableError(Exception):
    """Raised when a required Arcjet policy could not be evaluated.

    Distinct from :class:`ArcjetDeniedError` on purpose. Nothing decided this
    action was disallowed — the check did not happen, and the surface was
    configured to fail closed.
    """

    def __init__(self, action: str, *, cause: Optional[BaseException] = None) -> None:
        super().__init__(f'Arcjet policy for "{action}" could not be evaluated')
        self.action = action
        # Only when there is one. Assigning `None` sets `__suppress_context__`,
        # which hides the context Python would otherwise have chained on and
        # leaves the traceback saying nothing about why evaluation failed.
        if cause is not None:
            self.__cause__ = cause


class ArcjetInvalidLabelError(ArcjetMisconfiguration):
    """Raised when a guard label cannot match any policy.

    A configuration error rather than a decision: nothing was evaluated. It is
    raised where the label is written — at construction — rather than on every
    call, so a misspelling fails once at startup instead of disabling the guard
    for the life of the process.
    """

    def __init__(self, label: str, where: str, problem: str) -> None:
        super().__init__(
            f"{where}: guard label {label!r} is invalid ({problem}). "
            "No policy can match it — rename the tool or pass an explicit action."
        )
        self.label = label

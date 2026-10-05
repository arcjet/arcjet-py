"""The guard label rule, as the service enforces it.

A convenience that fails fast, not the place the rule lives. The service
enforces, and this check can be bypassed by an older SDK, another language, or
a direct API call — so it must never be stricter than the service. A check that
rejects a label the service accepts breaks working code, which is not
hypothetical: ``arcjet-go`` refused an underscore for a day after the service
began accepting one.

Too loose is recoverable, because the service still reports the rejection at
call time as ``AJ1023``. Too strict is not.

The cases both sides agree on are vendored at
``tests/fixtures/guard-label-cases.json`` from the source of truth in the
``arcjet`` monorepo. Every validator that decides whether a label is usable
reads them, so a copy that drifts fails by name. Nothing enforces that this
copy is current, because the monorepo is private and this repository is public
— a change to the grammar updates every copy in the same change.
"""

from __future__ import annotations

import re
from typing import Any, Optional

__all__ = [
    "MAX_LABEL_BYTES",
    "assert_valid_action",
    "default_tool_action",
    "label_problem",
    "label_rejected_by_service",
    "to_guard_label",
    "validate_guard_label",
]

MAX_LABEL_BYTES = 256

_EXTRA = frozenset("-._")

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_UNUSABLE_RUN = re.compile(r"[^a-z0-9._-]+")
_EDGES = "-._"


def _is_lower_ascii_letter_or_digit(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("0" <= ch <= "9")


def label_problem(label: str) -> Optional[str]:
    """Why *label* is unusable, or ``None`` when it is usable.

    Non-throwing, because capture needs to warn without failing: a capture call
    has no response to carry ``AJ1023``, so this is the only signal available
    there.
    """
    if label == "":
        return "empty"
    if len(label.encode("utf-8")) > MAX_LABEL_BYTES:
        return f"longer than {MAX_LABEL_BYTES} bytes"
    if not _is_lower_ascii_letter_or_digit(label[0]):
        return "must start with a lowercase letter or digit"
    if not _is_lower_ascii_letter_or_digit(label[-1]):
        return "must end with a lowercase letter or digit"

    for ch in label:
        if _is_lower_ascii_letter_or_digit(ch) or ch in _EXTRA:
            continue
        if "A" <= ch <= "Z":
            return f"uppercase letter {ch!r}"
        return f"invalid character {ch!r}"

    return None


def assert_valid_action(action: str, where: str) -> None:
    """Raise when *action* cannot match a policy.

    Call this where the label is known and the failure is cheap — at
    construction, never per call. A label that only exists at call time is
    judged by the service instead.
    """
    from ._errors import ArcjetInvalidLabelError

    problem = label_problem(action)
    if problem is not None:
        raise ArcjetInvalidLabelError(action, where, problem)


def validate_guard_label(label: str) -> None:
    """Raise when *label* cannot match a policy.

    The public spelling, matching Go's ``ValidateGuardLabel``. Use it to check a
    label you build yourself before handing it to a guard.

    Example:
        ::

            from arcjet.guard import validate_guard_label

            validate_guard_label("send_email.invoked")  # returns
            validate_guard_label("getWeather.invoked")  # raises
    """
    assert_valid_action(label, "validate_guard_label")


def to_guard_label(text: str) -> str:
    """*text* as a usable guard label.

    ASCII capitals become lowercase, each run of characters a label cannot hold
    becomes one ``_``, and ``-``, ``.`` and ``_`` are removed from both ends. A
    result over 256 bytes is cut to 256 and its end trimmed again. A label that
    is already usable is returned unchanged, so a policy published for one keeps
    matching.

    Use it to build a label from a name the application does not control, such
    as a tool name:

    Example:
        ::

            from arcjet.guard import to_guard_label

            to_guard_label("Bash")  # "bash"
            to_guard_label("Send Email")  # "send_email"
            f"{to_guard_label('getWeather')}.invoked"  # "getweather.invoked"

    Raises:
        ValueError: *text* contains no ASCII letter or digit, so no label can
            be made from it.
    """
    label = _UNUSABLE_RUN.sub("_", text.translate(_ASCII_LOWER)).strip(_EDGES)
    if len(label) > MAX_LABEL_BYTES:
        label = label[:MAX_LABEL_BYTES].rstrip(_EDGES)
    if label == "":
        raise ValueError(f"no guard label can be made from {text!r}")
    return label


_DEFAULT_SUFFIX = ".invoked"


def default_tool_action(name: Optional[str]) -> str:
    """The label a tool hook uses when the application gave no ``action``.

    ``"{tool_name}.invoked"`` with the name made usable by
    :func:`to_guard_label`, so a built-in tool such as ``Bash`` is labelled
    ``bash.invoked`` rather than one the service rejects. ``"tool.invoked"``
    when the name is empty or has no ASCII letter or digit.
    """
    try:
        stem = to_guard_label(name or "")
    except ValueError:
        stem = "tool"
    limit = MAX_LABEL_BYTES - len(_DEFAULT_SUFFIX)
    if len(stem) > limit:
        stem = stem[:limit].rstrip(_EDGES)
    return f"{stem}{_DEFAULT_SUFFIX}"


def label_rejected_by_service(decision: Any) -> bool:
    """Whether the service reported that it rejected this decision's label.

    When it did, the label it evaluated was ``invalid-label``, so no published
    policy could have matched and the guard did not run. That is unevaluated
    policy rather than an allow, and ``on_guard_error`` governs it.

    A capture call has no response to carry the code, so capture uses
    :func:`label_problem` instead.
    """
    from ._diagnostics import LABEL_INVALID

    warnings = getattr(decision, "warnings", ())
    return any(getattr(w, "code", None) == LABEL_INVALID for w in warnings)

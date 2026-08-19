"""Optional process-wide registration for an Arcjet guard client.

Registering exists for one reason: so code that cannot reach a client handle can
still call :func:`guard` and :func:`capture`.  Passing a client explicitly always
works and is the recommended path — this is the shortcut, not the default.

Nothing here takes effect until an application calls :func:`register_arcjet`.
``launch_arcjet()`` has no global side effects.

Why a module global rather than a :class:`~contextvars.ContextVar`
------------------------------------------------------------------

A ``ContextVar`` is the usual home for ambient state, and it is the wrong tool
here.  Each thread starts with a fresh context, so a value set once at startup
is invisible to every worker thread — which is exactly how Flask, Django and any
other WSGI server run request handlers.  Registration would appear to work in
the main thread and silently do nothing in production.

A module global is visible from every thread and every event loop, which is what
"register once at startup, call from anywhere" has to mean.  ``ContextVar`` is
still the right answer for *ambient correlation context*, which is a different
problem and deliberately out of scope.
"""

from __future__ import annotations

import inspect
import threading
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

from arcjet._metadata import Metadata

from ._client import ArcjetGuard, ArcjetGuardSync, _GuardClient, _make_error_decision
from ._diagnostics import CLIENT_ALREADY_REGISTERED, CLIENT_FLAVOR_MISMATCH
from ._rules import RuleWithInput
from ._types import Decision

__all__ = [
    "capture",
    "flush",
    "flush_sync",
    "guard",
    "guard_sync",
    "register_arcjet",
    "registered_client",
    "unregister_arcjet",
]

AnyArcjetGuard = Union[ArcjetGuard, ArcjetGuardSync]
"""Either client flavor.  Registration accepts both; the free calls do not."""

_registered: Optional[AnyArcjetGuard] = None

# Guards the check-then-set in `register_arcjet`. Assignment is atomic under the
# GIL, so the lock is not protecting the variable — it is protecting the
# decision, so two threads racing at startup cannot both observe an empty slot
# and both believe they won.
_lock = threading.Lock()


def register_arcjet(client: AnyArcjetGuard) -> None:
    """Register *client* for the free :func:`guard`, :func:`capture` and
    :func:`flush` calls.

    Guarded on purpose.  If something tries to register a second client the
    first one stays and the attempt is reported, so a library — or a stray
    second ``launch_arcjet()`` — cannot quietly redirect an application's
    telemetry to a different key.  Registering the client that is already
    registered is a no-op rather than a warning, so a module imported twice
    stays silent.

    Never raises.

    Example:
        Register once, wherever your application starts up::

            from arcjet.guard import launch_arcjet, register_arcjet

            register_arcjet(launch_arcjet(key=os.environ["ARCJET_KEY"]))
    """
    global _registered

    with _lock:
        incumbent = _registered

        if incumbent is None:
            _registered = client
            return

        if incumbent is client:
            return

    # Reported outside the lock, and on the incumbent's channel rather than the
    # late registrant's: the application that registered first configured that
    # logger, and it is the one whose telemetry an unnoticed second
    # registration would have redirected.
    _diagnose(incumbent, CLIENT_ALREADY_REGISTERED)


def unregister_arcjet() -> None:
    """Clear the registered client, if any.

    Takes no argument and clears whatever is there.  That asymmetry with
    :func:`register_arcjet` is deliberate: requiring the client back would mean
    every teardown has to keep hold of it, which is the problem registration
    exists to avoid.

    The cost is that anything calling this clears the application's client and
    every free call afterwards fails open, so **libraries should not call it**.
    Libraries take a client explicitly.  That is a convention, not something
    enforced here.

    Never raises.  Safe to call when nothing is registered.
    """
    global _registered

    with _lock:
        _registered = None


def registered_client() -> Optional[AnyArcjetGuard]:
    """Return the registered client, or ``None``.

    Internal.  Deliberately not re-exported from :mod:`arcjet.guard`: the ADR
    does not define it and neither does the JavaScript SDK, which tests that its
    equivalent stays unexported.  Publishing it now would make removing it a
    breaking change later.
    """
    return _registered


def register_arcjet_for_testing(client: AnyArcjetGuard) -> None:
    """Register *client*, refusing to displace or share with an incumbent.

    The check and the set happen under one lock, so concurrent callers cannot
    both observe an empty slot and both believe they registered — which would
    leave one of them asserting against a recorder no call ever reaches.

    The test client uses this instead of :func:`register_arcjet` because the
    failure modes invert under test.  In an application a second registration
    should be survivable, so it warns and carries on.  In a test suite a client
    left registered by an earlier test is a leak that makes the current test
    assert against the wrong recorder — quietly, and usually somewhere else.

    Raises:
        RuntimeError: If a client is already registered.
    """
    global _registered

    with _lock:
        if _registered is not None:
            raise RuntimeError(
                "An Arcjet client is already registered. Call "
                "unregister_arcjet() first — an earlier test probably left "
                "one behind."
            )
        _registered = client


def unregister_arcjet_if(client: AnyArcjetGuard) -> None:
    """Clear the registration, but only if *client* still holds it.

    Compare-and-clear under one lock.  A teardown that checked ownership and
    then cleared unconditionally could clear a *replacement* registered in
    between, so a stale handle would silently unregister somebody else's
    client.
    """
    global _registered

    with _lock:
        if _registered is client:
            _registered = None


async def guard(
    rules: Sequence[RuleWithInput],
    *,
    label: str,
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
) -> Decision:
    """Evaluate guard rules through the registered async client.

    With nothing registered — or with a *sync* client registered, which this
    cannot await — the call fails open: it returns an ALLOW carrying an error
    result, so ``decision.has_failed_open()`` is true and a caller that
    inspects the decision can see that no policy ran.  It does not raise.

    The decision is the report.  There is deliberately no log line for the
    unregistered case: the client that would have carried a logger is the thing
    that is missing, so the only available sink would be an unconfigurable
    warning on a request path.

    Example:
        ::

            from arcjet.guard import guard, DetectPromptInjection

            decision = await guard(
                label="support.reply",
                rules=[DetectPromptInjection()(user_message)],
            )
    """
    client = _registered
    method = _awaitable(client, "guard")

    if method is not None:
        return await method(
            rules,
            label=label,
            metadata=metadata,
            correlation_id=correlation_id,
        )

    _diagnose_flavor_mismatch(client)
    return _make_error_decision(
        "guard() was called with no registered async Arcjet client"
    )


def guard_sync(
    rules: Sequence[RuleWithInput],
    *,
    label: str,
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
) -> Decision:
    """Evaluate guard rules through the registered sync client.

    The blocking counterpart of :func:`guard`, for Flask, Django and other sync
    frameworks.  Fails open the same way, including when the registered client
    is the async one — which this cannot await.
    """
    client = _registered
    method = _blocking(client, "guard_sync", "guard")

    if method is not None:
        return method(
            rules,
            label=label,
            metadata=metadata,
            correlation_id=correlation_id,
        )

    _diagnose_flavor_mismatch(client)
    return _make_error_decision(
        "guard_sync() was called with no registered sync Arcjet client"
    )


def capture(
    *,
    action: str,
    correlation_id: Optional[str] = None,
    decision_id: Optional[str] = None,
    occurred_at: Optional[datetime] = None,
    metadata: Optional[Metadata] = None,
) -> None:
    """Record a fact about what the application did, through the registered
    client.

    One function for both client flavors, because ``capture()`` queues and
    returns on each of them — it does no I/O on the caller's path, so there is
    nothing to await and nothing to block.

    With nothing registered the event is dropped silently.  Capture is
    best-effort telemetry, which is what makes dropping acceptable, and there is
    no configured logger to report to when the client itself is what is missing.

    Never raises.

    Example:
        Deep in application code, with nothing passed down::

            from arcjet.guard import capture

            async def refund(invoice_id: str) -> None:
                await issue_refund(invoice_id)
                capture(action="refund.issued", metadata={"invoice": invoice_id})
    """
    client = _registered
    if client is None:
        return

    client.capture(
        action=action,
        correlation_id=correlation_id,
        decision_id=decision_id,
        occurred_at=occurred_at,
        metadata=metadata,
    )


async def flush(timeout_ms: Optional[int] = None) -> None:
    """Drain the registered async client's queued capture events.

    Returns immediately when nothing is registered, or when the registered
    client is the sync one — there is no queue this call can drain.
    """
    client = _registered
    method = _awaitable(client, "flush")

    if method is not None:
        await method(timeout_ms)
        return

    _diagnose_flavor_mismatch(client)


def flush_sync(timeout_ms: Optional[int] = None) -> None:
    """Drain the registered sync client's queued capture events.

    The blocking counterpart of :func:`flush`.
    """
    client = _registered
    method = _blocking(client, "flush_sync", "flush")

    if method is not None:
        method(timeout_ms)
        return

    _diagnose_flavor_mismatch(client)


def _awaitable(
    client: Optional[_GuardClient], name: str
) -> Optional[Callable[..., Awaitable[Any]]]:
    """The awaitable *name* on *client*, or ``None``.

    Dispatch is on whether the method is a coroutine function rather than on
    ``isinstance`` of the two concrete client classes.  That is what Python
    actually means by "is this the async flavor", and it keeps registration
    structural: the in-memory test client and any hand-rolled double satisfy the
    free calls without subclassing anything.
    """
    method = getattr(client, name, None)
    return method if inspect.iscoroutinefunction(method) else None


def _blocking(
    client: Optional[_GuardClient], preferred: str, fallback: str
) -> Optional[Callable[..., Any]]:
    """The blocking method on *client*, or ``None``.

    Tries *preferred* — the explicitly sync name — before *fallback*, because
    ``ArcjetGuardSync`` spells its blocking method ``guard``/``flush`` while a
    double offering both flavors spells them ``guard_sync``/``flush_sync``.
    Either way an awaitable is rejected: this caller cannot await it.
    """
    for name in (preferred, fallback):
        method = getattr(client, name, None)
        if callable(method) and not inspect.iscoroutinefunction(method):
            return method
    return None


def _diagnose_flavor_mismatch(client: Optional[AnyArcjetGuard]) -> None:
    """Report a call that found the other flavor of client registered.

    Only when something *is* registered.  Nothing registered is the ordinary
    unconfigured case and stays silent; a registered client of the wrong
    flavor is a wiring mistake worth a line, and there is a configured logger
    on it to put that line on.
    """
    if client is not None:
        _diagnose(client, CLIENT_FLAVOR_MISMATCH)


def _diagnose(client: AnyArcjetGuard, code: str) -> None:
    """Report *code* on a client's own diagnostics channel.

    Never raises: a diagnostics sink is observational and must not break the
    caller.  Anything can be registered — the test client is not built by
    ``launch_arcjet()``, and neither is a hand-rolled fake — so the channel is
    looked for rather than assumed.
    """
    try:
        diagnose = getattr(client, "_diagnose", None)
        if callable(diagnose):
            diagnose(code)
    except Exception:
        # Deliberately swallowed, including a logging handler that raises. A
        # diagnostics sink is observational: reporting that a client could not
        # be registered must not become a second, louder failure in the caller.
        pass

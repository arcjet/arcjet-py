"""A shared vocabulary for describing a guarded action.

Nothing here is required — ``metadata`` accepts any JSON-serializable mapping.
Consistent key names are what let the Console group and filter across
applications, so the common seven get a helper rather than being retyped as
string literals at every call site.

Matches the JavaScript ``SecurityMetadataFields``, including the one key that
is not a straight rename: ``data_class`` travels as ``data-class``.
"""

from __future__ import annotations

from typing import Optional

from arcjet._metadata import Metadata

__all__ = ["security_metadata"]


def security_metadata(
    *,
    user: Optional[str] = None,
    agent: Optional[str] = None,
    workflow: Optional[str] = None,
    data_class: Optional[str] = None,
    destination: Optional[str] = None,
    reversibility: Optional[str] = None,
    resource: Optional[str] = None,
) -> Metadata:
    """Build a metadata mapping from the common security fields.

    Fields left as ``None`` are omitted rather than sent as null, so an event
    carries only what the caller actually knew.

    Args:
        user: Who the action is on behalf of.
        agent: Which agent or model is acting.
        workflow: The workflow or chain this belongs to.
        data_class: Sensitivity of the data involved. Travels as
            ``"data-class"``.
        destination: Where an effect lands, e.g. an external service.
        reversibility: Whether the effect can be undone.
        resource: What is being acted on.

    Returns:
        A metadata mapping containing only the fields that were supplied.
        Metadata is untrusted: do not put secrets or PII in it.

    Example:
        ::

            from arcjet.guard import guard_action, security_metadata

            await guard_action(
                send_it,
                action="email.sent",
                metadata=security_metadata(
                    user=user.id,
                    destination="sendgrid",
                    reversibility="irreversible",
                ),
            )
    """
    fields = (
        ("user", user),
        ("agent", agent),
        ("workflow", workflow),
        ("data-class", data_class),
        ("destination", destination),
        ("reversibility", reversibility),
        ("resource", resource),
    )
    return {key: value for key, value in fields if value is not None}

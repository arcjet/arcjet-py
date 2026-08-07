"""Map Rampart model / recognizer labels to Arcjet sensitive info types.

Ported from ``sensitive-info-rampart/src/entities.ts`` in arcjet-js.
"""

from __future__ import annotations

import re
from typing import Optional

from arcjet._analyze import SensitiveInfoEntity
from arcjet._sensitive_info_backend import (
    BACKEND_ONLY_SENSITIVE_INFO_TYPES,
    NATIVE_SENSITIVE_INFO_TYPES,
)

# Every sensitive info type the Rampart backend can detect. All are built-in
# ``SensitiveInfoEntityType`` values, so they can be passed directly to
# ``detect_sensitive_info(deny=[...])``. Handy for denying (or allowing)
# everything Rampart knows about via ``deny=rampart_entities``.
rampart_entities: tuple[str, ...] = (
    "EMAIL",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "CREDIT_CARD_NUMBER",
    "URL",
    "SSN",
    "GIVEN_NAME",
    "SURNAME",
    "TAX_ID",
    "BANK_ACCOUNT",
    "ROUTING_NUMBER",
    "GOVERNMENT_ID",
    "PASSPORT",
    "DRIVERS_LICENSE",
    "BUILDING_NUMBER",
    "STREET_NAME",
    "SECONDARY_ADDRESS",
    "CITY",
    "STATE",
    "ZIP_CODE",
)

# Rampart covers every built-in sensitive info type. Tie the tuple to the
# canonical frozensets so adding a new built-in type without teaching Rampart
# about it (or vice versa) fails loudly here rather than silently dropping the
# type from ``deny=rampart_entities``. An explicit check (not ``assert``) so it
# still runs under ``python -O``.
if frozenset(rampart_entities) != (
    NATIVE_SENSITIVE_INFO_TYPES | BACKEND_ONLY_SENSITIVE_INFO_TYPES
):
    raise RuntimeError(
        "rampart_entities is out of sync with the sensitive-info type frozensets"
    )

# The model emits labels in its own naming (``PHONE``, ``CREDIT_CARD``); this
# aligns them to the names Arcjet already uses (``PHONE_NUMBER``,
# ``CREDIT_CARD_NUMBER``) so that, for example, ``deny=["PHONE_NUMBER"]`` works
# the same regardless of backend. Keys are upper-cased and stripped of any BIO
# prefix before lookup.
_LABEL_ALIASES: dict[str, str] = {
    # Aligned to the four types the default backend also detects.
    "EMAIL": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE": "PHONE_NUMBER",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "IP": "IP_ADDRESS",
    "IP_ADDRESS": "IP_ADDRESS",
    "CREDIT_CARD": "CREDIT_CARD_NUMBER",
    "CREDIT_CARD_NUMBER": "CREDIT_CARD_NUMBER",
    # Rampart-specific types.
    "URL": "URL",
    "SSN": "SSN",
    "GIVEN_NAME": "GIVEN_NAME",
    "SURNAME": "SURNAME",
    "TAX_ID": "TAX_ID",
    "BANK_ACCOUNT": "BANK_ACCOUNT",
    "ROUTING_NUMBER": "ROUTING_NUMBER",
    "GOVERNMENT_ID": "GOVERNMENT_ID",
    "PASSPORT": "PASSPORT",
    "DRIVERS_LICENSE": "DRIVERS_LICENSE",
    "BUILDING_NUMBER": "BUILDING_NUMBER",
    "STREET_NAME": "STREET_NAME",
    "SECONDARY_ADDRESS": "SECONDARY_ADDRESS",
    "CITY": "CITY",
    "STATE": "STATE",
    "ZIP_CODE": "ZIP_CODE",
    "ZIP": "ZIP_CODE",
    "POSTAL_CODE": "ZIP_CODE",
}

_BIO_PREFIX = re.compile(r"^[biluest]-", re.IGNORECASE)


def normalize_label(label: str) -> Optional[str]:
    """Normalize a raw model/recognizer label to an Arcjet sensitive info type.

    Args:
        label: Raw label (such as ``"B-GIVEN_NAME"`` or ``"phone"``).

    Returns:
        The matching Arcjet type string, or ``None`` when the label is ``O``
        (outside) or otherwise unknown.
    """
    stripped = _BIO_PREFIX.sub("", label).upper()
    if stripped == "O" or stripped == "":
        return None
    return _LABEL_ALIASES.get(stripped)


def to_analyze_entity(type: str) -> SensitiveInfoEntity:
    """Convert an Arcjet sensitive info type to the analyze tagged union.

    The four types the WebAssembly engine understands map to their native
    variant; every other type is carried as ``SensitiveInfoEntityCustom``. This
    is the inverse of :func:`from_analyze_entity`.

    Delegates to the SDK's own specifier→entity conversion so the four native
    mappings live in a single place.
    """
    from arcjet._local import _to_wasm_entity

    return _to_wasm_entity(type)


def from_analyze_entity(entity: SensitiveInfoEntity) -> str:
    """Convert an analyze tagged entity back to its Arcjet type string.

    Delegates to the SDK's own entity→string conversion (the inverse of
    :func:`to_analyze_entity`) so the four native mappings live in a single
    place and cannot drift from the core SDK.
    """
    from arcjet._local import _entity_type_str

    return _entity_type_str(entity)

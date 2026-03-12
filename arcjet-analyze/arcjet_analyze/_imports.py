"""Default import implementations and linker wiring for arcjet:js-req.

GENERATOR-NOTE: The linker wiring logic (add_instance/add_func calls) will be
auto-generated. Default implementations (e.g., ip_lookup returning None) will
remain as manual configuration passed to the generated component class.

Import interfaces:
  1. filter-overrides:                ip-lookup(ip) -> option<string>
  2. bot-identifier:                  detect(request) -> list<bot-entity>
  3. verify-bot:                      verify(bot-id, ip) -> validator-response
  4. email-validator-overrides:       is-free-email, is-disposable-email,
                                      has-mx-records, has-gravatar -> validator-response
  5. sensitive-information-identifier: detect(tokens) -> list<option<sensitive-info-entity>>
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from wasmtime import Store
from wasmtime import component as cm
from wasmtime.component._types import Variant

from ._convert import to_wasm_sensitive_info_entity
from ._types import SensitiveInfoEntity

# ---------------------------------------------------------------------------
# Callback types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImportCallbacks:
    """User-provided callbacks for component import interfaces.

    Any callback left as ``None`` uses a safe default implementation.
    """

    ip_lookup: Callable[[str], str | None] | None = None
    bot_detect: Callable[[str], list[str]] | None = None
    bot_verify: Callable[[str, str], str] | None = None
    is_free_email: Callable[[str], str] | None = None
    is_disposable_email: Callable[[str], str] | None = None
    has_mx_records: Callable[[str], str] | None = None
    has_gravatar: Callable[[str], str] | None = None
    sensitive_info_detect: (
        Callable[[list[str]], list[SensitiveInfoEntity | None]] | None
    ) = None


# ---------------------------------------------------------------------------
# Default implementations
# ---------------------------------------------------------------------------


def _default_ip_lookup(_ip: str) -> str | None:
    return None


def _default_bot_detect(_request: str) -> list[str]:
    return []


def _default_bot_verify(_bot_id: str, _ip: str) -> str:
    return "unverifiable"


def _default_validator_response(_domain_or_email: str) -> str:
    return "unknown"


def _default_sensitive_info_detect(
    tokens: list[str],
) -> list[SensitiveInfoEntity | None]:
    return [None] * len(tokens)


# ---------------------------------------------------------------------------
# Linker wiring
# ---------------------------------------------------------------------------


def wire_imports(
    linker: cm.Linker,
    component: cm.Component,
    callbacks: ImportCallbacks | None = None,
) -> None:
    """Wire all 5 import interfaces into *linker* using trap-then-shadow.

    ``callbacks`` provides user overrides; any ``None`` slot gets a safe
    default.
    """
    cb = callbacks or ImportCallbacks()

    # 1. Trap everything first
    linker.define_unknown_imports_as_traps(component)

    ip_lookup_fn = cb.ip_lookup or _default_ip_lookup
    bot_detect_fn = cb.bot_detect or _default_bot_detect
    bot_verify_fn = cb.bot_verify or _default_bot_verify
    is_free_fn = cb.is_free_email or _default_validator_response
    is_disposable_fn = cb.is_disposable_email or _default_validator_response
    has_mx_fn = cb.has_mx_records or _default_validator_response
    has_gravatar_fn = cb.has_gravatar or _default_validator_response
    si_detect_fn = cb.sensitive_info_detect or _default_sensitive_info_detect

    # 2. Override with real implementations
    with linker.root() as root:
        with root.add_instance("arcjet:js-req/filter-overrides") as iface:
            iface.add_func(
                "ip-lookup",
                lambda _store, ip: ip_lookup_fn(ip),
            )

        with root.add_instance("arcjet:js-req/bot-identifier") as iface:
            iface.add_func(
                "detect",
                lambda _store, req: bot_detect_fn(req),
            )

        with root.add_instance("arcjet:js-req/verify-bot") as iface:
            iface.add_func(
                "verify",
                lambda _store, bot_id, ip: bot_verify_fn(bot_id, ip),
            )

        with root.add_instance("arcjet:js-req/email-validator-overrides") as iface:
            iface.add_func(
                "is-free-email",
                lambda _store, d: is_free_fn(d),
            )
            iface.add_func(
                "is-disposable-email",
                lambda _store, d: is_disposable_fn(d),
            )
            iface.add_func(
                "has-mx-records",
                lambda _store, d: has_mx_fn(d),
            )
            iface.add_func(
                "has-gravatar",
                lambda _store, e: has_gravatar_fn(e),
            )

        with root.add_instance(
            "arcjet:js-req/sensitive-information-identifier"
        ) as iface:

            def _si_detect(_store: Store, tokens: list[str]) -> list[Variant | None]:
                results = si_detect_fn(tokens)
                # Convert SensitiveInfoEntity back to wasmtime Variant for non-None
                out: list[Variant | None] = []
                for r in results:
                    if r is None:
                        out.append(None)
                    else:
                        out.append(to_wasm_sensitive_info_entity(r))
                return out

            iface.add_func("detect", _si_detect)

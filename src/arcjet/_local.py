"""Local WASM-based rule evaluation via arcjet-analyze.

This module provides local evaluation for rules that can run without the
remote Decide API: bot detection and email validation.

The AnalyzeComponent is instantiated lazily on first use and reused for all
subsequent calls (Engine/Component/Linker are expensive to create).
"""

from __future__ import annotations

import importlib.resources as _res
import json
import threading
from typing import Callable, Iterable

from arcjet._analyze import (
    AllowedBotConfig,
    AllowEmailValidationConfig,
    AnalyzeComponent,
    DeniedBotConfig,
    DenyEmailValidationConfig,
    DetectedSensitiveInfoEntity,
    Err,
    FilterResult,
    Ok,
    SensitiveInfoConfig,
    SensitiveInfoEntitiesAllow,
    SensitiveInfoEntitiesDeny,
    SensitiveInfoEntity,
    SensitiveInfoEntityCreditCardNumber,
    SensitiveInfoEntityCustom,
    SensitiveInfoEntityEmail,
    SensitiveInfoEntityIpAddress,
    SensitiveInfoEntityPhoneNumber,
    SensitiveInfoResult,
)
from arcjet.proto.decide.v1alpha1 import decide_pb2

from ._context import RequestContext
from ._enums import Mode
from ._logging import logger
from ._rules import (
    BotDetection,
    EmailValidation,
    Filter,
    SensitiveInfoDetection,
    SensitiveInfoEntityType,
)
from ._sensitive_info_backend import (
    BACKEND_ONLY_SENSITIVE_INFO_TYPES,
    NATIVE_SENSITIVE_INFO_TYPES,
    SensitiveInfoBackendContext,
    SensitiveInfoBackendOptions,
)

# Shared mapping from WASM blocked-reason strings to proto EmailType values
_EMAIL_TYPE_MAP: dict[str, decide_pb2.EmailType] = {
    "DISPOSABLE": decide_pb2.EMAIL_TYPE_DISPOSABLE,
    "FREE": decide_pb2.EMAIL_TYPE_FREE,
    "NO_MX_RECORDS": decide_pb2.EMAIL_TYPE_NO_MX_RECORDS,
    "NO_GRAVATAR": decide_pb2.EMAIL_TYPE_NO_GRAVATAR,
    "INVALID": decide_pb2.EMAIL_TYPE_INVALID,
}

# ---------------------------------------------------------------------------
# Lazy singleton for the WASM component
# ---------------------------------------------------------------------------

_component_lock = threading.Lock()
_MISSING = object()  # sentinel: haven't tried to load yet
_FAILED = object()  # sentinel: tried and got a permanent error
_component_state: object = _MISSING  # _MISSING | _FAILED | AnalyzeComponent

# Errors that indicate the WASM binary will never load (don't retry).
_PERMANENT_ERRORS = (FileNotFoundError, ImportError, ModuleNotFoundError)


def _get_component() -> AnalyzeComponent | None:
    """Return the AnalyzeComponent singleton, or None if unavailable.

    On permanent errors (missing file/module), latches to None for the process
    lifetime.  On transient errors (e.g. OSError, RuntimeError), the next call
    retries.
    """
    global _component_state
    state = _component_state
    if state is _FAILED:
        return None
    if state is not _MISSING:
        return state  # type: ignore[return-value]
    with _component_lock:
        state = _component_state
        if state is not _MISSING:
            return state if isinstance(state, AnalyzeComponent) else None
        try:
            # The WASM binary lives inside the arcjet._analyze package
            wasm_ref = (
                _res.files("arcjet._analyze")
                / "wasm"
                / "arcjet_analyze_js_req.component.wasm"
            )
            wasm_path = str(wasm_ref)
            component = AnalyzeComponent(wasm_path)
            _component_state = component
            logger.debug("arcjet-analyze WASM component loaded from %s", wasm_path)
            return component
        except _PERMANENT_ERRORS as exc:
            logger.debug("arcjet-analyze WASM component not available: %s", exc)
            _component_state = _FAILED
            return None
        except Exception as exc:
            # Transient error — don't latch, allow retry on next call
            logger.debug(
                "arcjet-analyze WASM component load error (will retry): %s", exc
            )
            return None


# ---------------------------------------------------------------------------
# Request context → WASM JSON
# ---------------------------------------------------------------------------


# TTL (in seconds) applied to DENY results from local bot / filter evaluation,
# matching the values used by the Go decide service (bot_v2_rule.go, filter_rule.go).
_LOCAL_DENY_TTL_SECONDS = 60


def _rule_state(mode: Mode) -> decide_pb2.RuleState:
    """Map a rule Mode to the corresponding proto RuleState value."""
    if mode == Mode.DRY_RUN:
        return decide_pb2.RULE_STATE_DRY_RUN
    return decide_pb2.RULE_STATE_RUN


def _context_to_analyze_request(ctx: RequestContext) -> str:
    """Serialize a RequestContext to the JSON shape the WASM component expects."""
    headers: dict[str, str] = {}
    if ctx.headers:
        for k, v in ctx.headers.items():
            headers[str(k).lower()] = str(v)

    obj: dict[str, object] = {}
    if ctx.ip:
        obj["ip"] = ctx.ip
    if ctx.method:
        obj["method"] = ctx.method
    if ctx.host:
        obj["host"] = ctx.host
    if ctx.path:
        obj["path"] = ctx.path
    if headers:
        obj["headers"] = headers
    if ctx.cookies:
        obj["cookies"] = ctx.cookies
    if ctx.query:
        obj["query"] = ctx.query
    return json.dumps(obj)


# ---------------------------------------------------------------------------
# Local rule evaluators
# ---------------------------------------------------------------------------


def evaluate_bot_locally(
    ctx: RequestContext,
    rule: BotDetection,
) -> decide_pb2.RuleResult | None:
    """Evaluate a BotDetection rule locally via WASM.

    Returns a proto RuleResult, or None if WASM is unavailable.
    """
    component = _get_component()
    if component is None:
        return None

    request_json = _context_to_analyze_request(ctx)

    # Build the WASM config from the rule's allow/deny lists.
    # allow takes precedence over deny (matches JS SDK); the builder API
    # prevents both being set, but we handle it defensively here.
    if rule.allow:
        entities = [str(e) for e in rule.allow]
        config = AllowedBotConfig(entities=entities, skip_custom_detect=True)
    else:
        entities = [str(e) for e in rule.deny]
        config = DeniedBotConfig(entities=entities, skip_custom_detect=True)

    try:
        result = component.detect_bot(request_json, config)
    except Exception as exc:
        logger.debug("local bot detection error: %s", exc)
        return None

    if isinstance(result, Err):
        logger.debug("local bot detection returned error: %s", result.value)
        return None

    if not isinstance(result, Ok):
        logger.debug("local bot detection returned unexpected type: %s", type(result))
        return None
    bot = result.value

    has_deny = len(bot.denied) > 0
    conclusion = decide_pb2.CONCLUSION_DENY if has_deny else decide_pb2.CONCLUSION_ALLOW
    state = _rule_state(rule.mode)

    reason = decide_pb2.Reason(
        bot_v2=decide_pb2.BotV2Reason(
            allowed=list(bot.allowed),
            denied=list(bot.denied),
            verified=bot.verified,
            spoofed=bot.spoofed,
        )
    )

    ttl = _LOCAL_DENY_TTL_SECONDS if has_deny else 0

    # Intentional: server uses empty rule_id too (arcjet-decide #4740).
    # The report handler passes rules/results independently without joining
    # on rule_id, so an empty string is safe here.
    return decide_pb2.RuleResult(
        rule_id="",
        state=state,
        conclusion=conclusion,
        reason=reason,
        ttl=ttl,
    )


def evaluate_email_locally(
    ctx: RequestContext,
    rule: EmailValidation,
) -> decide_pb2.RuleResult | None:
    """Evaluate an EmailValidation rule locally via WASM.

    Returns a proto RuleResult, or None if WASM is unavailable.
    """
    component = _get_component()
    if component is None:
        return None

    email = ctx.email
    if not email:
        return None

    # Build the WASM config from the rule
    if rule.allow:
        email_config = AllowEmailValidationConfig(
            require_top_level_domain=rule.require_top_level_domain,
            allow_domain_literal=rule.allow_domain_literal,
            allow=[str(t.value) for t in rule.allow],
        )
    else:
        email_config = DenyEmailValidationConfig(
            require_top_level_domain=rule.require_top_level_domain,
            allow_domain_literal=rule.allow_domain_literal,
            deny=[str(t.value) for t in rule.deny],
        )

    try:
        result = component.is_valid_email(email, email_config)
    except Exception as exc:
        logger.debug("local email validation error: %s", exc)
        return None

    if isinstance(result, Err):
        logger.debug("local email validation returned error: %s", result.value)
        return None

    if not isinstance(result, Ok):
        logger.debug(
            "local email validation returned unexpected type: %s", type(result)
        )
        return None
    ev = result.value

    # Map blocked reasons to proto EmailType values
    email_types: list[decide_pb2.EmailType] = []
    for b in ev.blocked:
        if b in _EMAIL_TYPE_MAP:
            email_types.append(_EMAIL_TYPE_MAP[b])

    # Mark as invalid if validity check failed (avoid duplicating INVALID
    # if it was already added from the blocked list above)
    if ev.validity != "valid" and decide_pb2.EMAIL_TYPE_INVALID not in email_types:
        email_types.append(decide_pb2.EMAIL_TYPE_INVALID)

    is_denied = ev.validity != "valid" or len(ev.blocked) > 0
    conclusion = (
        decide_pb2.CONCLUSION_DENY if is_denied else decide_pb2.CONCLUSION_ALLOW
    )
    state = _rule_state(rule.mode)

    reason = decide_pb2.Reason(email=decide_pb2.EmailReason(email_types=email_types))

    # Intentional: server uses empty rule_id too (arcjet-decide #4740).
    # The report handler passes rules/results independently without joining
    # on rule_id, so an empty string is safe here.
    return decide_pb2.RuleResult(
        rule_id="",
        state=state,
        conclusion=conclusion,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Sensitive info entity mapping
# ---------------------------------------------------------------------------

# Map SDK SensitiveInfoEntityType values to WASM SensitiveInfoEntity types.
# The reverse map (_WASM_ENTITY_TYPE_TO_STR) is derived automatically so the
# two stay in sync when new entity types are added.
_SENSITIVE_INFO_ENTITY_MAP: dict[
    str,
    SensitiveInfoEntityEmail
    | SensitiveInfoEntityPhoneNumber
    | SensitiveInfoEntityIpAddress
    | SensitiveInfoEntityCreditCardNumber,
] = {
    SensitiveInfoEntityType.EMAIL: SensitiveInfoEntityEmail(),
    SensitiveInfoEntityType.PHONE_NUMBER: SensitiveInfoEntityPhoneNumber(),
    SensitiveInfoEntityType.IP_ADDRESS: SensitiveInfoEntityIpAddress(),
    SensitiveInfoEntityType.CREDIT_CARD_NUMBER: SensitiveInfoEntityCreditCardNumber(),
}

_WASM_ENTITY_TYPE_TO_STR: dict[type, str] = {
    type(v): k for k, v in _SENSITIVE_INFO_ENTITY_MAP.items()
}


def _to_wasm_entity(
    specifier: str,
) -> (
    SensitiveInfoEntityEmail
    | SensitiveInfoEntityPhoneNumber
    | SensitiveInfoEntityIpAddress
    | SensitiveInfoEntityCreditCardNumber
    | SensitiveInfoEntityCustom
):
    """Convert an SDK sensitive info specifier string to a WASM entity type."""
    if specifier in _SENSITIVE_INFO_ENTITY_MAP:
        return _SENSITIVE_INFO_ENTITY_MAP[specifier]
    return SensitiveInfoEntityCustom(value=specifier)


def _entity_type_str(entity: SensitiveInfoEntity) -> str:
    """Map a ``SensitiveInfoEntity`` to its Arcjet type string.

    Handles both a configured entity and a detected entity's
    ``identified_type``. The native variants are looked up in the
    auto-derived ``_WASM_ENTITY_TYPE_TO_STR`` map (so this stays the single
    source of truth for the reverse mapping); custom types carry their own
    value; anything else is reported as ``"UNKNOWN"``.
    """
    type_str = _WASM_ENTITY_TYPE_TO_STR.get(type(entity))
    if type_str is not None:
        return type_str
    if isinstance(entity, SensitiveInfoEntityCustom):
        return entity.value
    return "UNKNOWN"


def _detected_entity_type_str(entity: DetectedSensitiveInfoEntity) -> str:
    """Extract a string type name from a DetectedSensitiveInfoEntity."""
    return _entity_type_str(entity.identified_type)


def _to_proto_entities(
    entities: list[DetectedSensitiveInfoEntity],
) -> list[decide_pb2.IdentifiedEntity]:
    """Convert WASM DetectedSensitiveInfoEntity list to proto IdentifiedEntity list."""
    return [
        decide_pb2.IdentifiedEntity(
            identified_type=_detected_entity_type_str(e),
            start=e.start,
            end=e.end,
        )
        for e in entities
    ]


class WasmSensitiveInfoBackend:
    """Default sensitive-info backend backed by the arcjet-analyze WASM engine.

    Used when a ``SensitiveInfoDetection`` rule does not configure a ``backend``.
    Preserves the existing behavior — local detection of email addresses, phone
    numbers, IP addresses, and credit card numbers.
    """

    def detect(
        self,
        context: SensitiveInfoBackendContext,
        value: str,
        entities: SensitiveInfoEntitiesAllow | SensitiveInfoEntitiesDeny,
        options: SensitiveInfoBackendOptions | None = None,
    ) -> SensitiveInfoResult:
        """Detect sensitive info via the WASM component."""
        component = _get_component()
        if component is None:
            raise RuntimeError("arcjet-analyze WASM component is unavailable")

        user_detect = options.detect if options is not None else None
        config = SensitiveInfoConfig(
            entities=entities,
            context_window_size=(
                options.context_window_size if options is not None else None
            ),
            skip_custom_detect=user_detect is None,
        )

        # Wrap the user's detect callback (str → SensitiveInfoEntity conversion).
        wasm_detect: Callable[[list[str]], list[SensitiveInfoEntity | None]] | None = (
            None
        )
        if user_detect is not None:

            def _wrapped_detect(tokens: list[str]) -> list[SensitiveInfoEntity | None]:
                results = user_detect(tokens)
                out: list[SensitiveInfoEntity | None] = []
                for r in results:
                    if r is None:
                        out.append(None)
                    else:
                        out.append(_to_wasm_entity(r))
                return out

            wasm_detect = _wrapped_detect

        return component.detect_sensitive_info(value, config, detect=wasm_detect)


# Module-level default backend instance, reused across evaluations.
_WASM_SENSITIVE_INFO_BACKEND = WasmSensitiveInfoBackend()

# All recognized built-in sensitive-info types, used to validate the output of a
# third-party backend.
_RECOGNIZED_SENSITIVE_INFO_TYPES: frozenset[str] = (
    NATIVE_SENSITIVE_INFO_TYPES | BACKEND_ONLY_SENSITIVE_INFO_TYPES
)


def accepted_sensitive_info_types(
    allow: Iterable[SensitiveInfoEntityType | str],
    deny: Iterable[SensitiveInfoEntityType | str],
) -> frozenset[str]:
    """Types a backend result is allowed to report for a given rule.

    The recognized built-ins plus whatever the rule explicitly configured, so a
    backend can surface a custom specifier the caller opted into but not an
    arbitrary type it never asked for. Shared by the core and guard local
    evaluators so both validate backend output identically.
    """
    return _RECOGNIZED_SENSITIVE_INFO_TYPES | frozenset(
        e.value if isinstance(e, SensitiveInfoEntityType) else e
        for e in (*allow, *deny)
    )


def filter_recognized_entities(
    entities: list[DetectedSensitiveInfoEntity],
    accepted: frozenset[str],
) -> list[DetectedSensitiveInfoEntity]:
    """Drop detected entities whose type is not in ``accepted``."""
    return [e for e in entities if _detected_entity_type_str(e) in accepted]


def evaluate_sensitive_info_locally(
    ctx: RequestContext,
    rule: SensitiveInfoDetection,
) -> decide_pb2.RuleResult | None:
    """Evaluate a SensitiveInfoDetection rule locally.

    Runs the rule's configured ``backend`` (or the default WASM engine) and
    returns a proto RuleResult, or None if the backend is unavailable, no value
    was provided, or detection errored.
    """
    value = ctx.sensitive_info_value
    if not value:
        return None

    # Build the entities config from the rule's allow/deny lists.
    # Use .value for enum members; str() on 3.10 str enums returns
    # "ClassName.MEMBER" rather than the value.
    # allow takes precedence over deny (matches JS SDK and decide API).
    if rule.allow:
        wasm_entities = [
            _to_wasm_entity(e.value if isinstance(e, SensitiveInfoEntityType) else e)
            for e in rule.allow
        ]
        entities_config: SensitiveInfoEntitiesAllow | SensitiveInfoEntitiesDeny = (
            SensitiveInfoEntitiesAllow(entities=wasm_entities)
        )
    else:
        wasm_entities = [
            _to_wasm_entity(e.value if isinstance(e, SensitiveInfoEntityType) else e)
            for e in rule.deny
        ]
        entities_config = SensitiveInfoEntitiesDeny(entities=wasm_entities)

    backend = rule.backend
    if backend is None:
        # Gate the default path on WASM availability so an unavailable component
        # falls through to the remote Decide API rather than producing a local
        # allow decision.
        if _get_component() is None:
            return None
        backend = _WASM_SENSITIVE_INFO_BACKEND

    options = SensitiveInfoBackendOptions(
        context_window_size=rule.context_window_size,
        detect=rule.detect,
    )

    try:
        result = backend.detect(
            SensitiveInfoBackendContext(log=logger),
            value,
            entities_config,
            options,
        )
        # Read the result shape inside the exception boundary too: a malformed
        # backend return (e.g. not a SensitiveInfoResult) makes this access raise,
        # which should fail closed to the remote Decide API rather than crash
        # local evaluation.
        allowed, denied = result.allowed, result.denied
    except Exception as exc:
        # A user-provided backend that raises would otherwise fail silently and
        # fall through with no local detection, so surface it at error level. The
        # default WASM path logs at debug like the other local evaluators
        # (bot/email/filter), since transient component failures fall through to
        # the remote Decide API. Log only the exception type — the message can
        # embed the scanned value, and this evaluator handles sensitive input, so
        # the full string is not logged to avoid leaking PII.
        log = logger.error if rule.backend is not None else logger.debug
        log("local sensitive info detection error: %s", type(exc).__name__)
        return None

    if rule.backend is not None:
        # Validate the types a third-party backend returned rather than trusting
        # them: keep recognized built-ins and the types this rule configured, and
        # drop anything else. The default WASM path and custom `detect` callback
        # (backend is None) are left untouched to preserve their behavior.
        accepted = accepted_sensitive_info_types(rule.allow, rule.deny)
        allowed = filter_recognized_entities(allowed, accepted)
        denied = filter_recognized_entities(denied, accepted)

    allowed_entities = _to_proto_entities(allowed)
    denied_entities = _to_proto_entities(denied)

    has_deny = len(denied_entities) > 0
    conclusion = decide_pb2.CONCLUSION_DENY if has_deny else decide_pb2.CONCLUSION_ALLOW
    state = _rule_state(rule.mode)

    reason = decide_pb2.Reason(
        sensitive_info=decide_pb2.SensitiveInfoReason(
            allowed=allowed_entities,
            denied=denied_entities,
        )
    )

    # Intentional: server uses empty rule_id too (arcjet-decide #4740).
    # The report handler passes rules/results independently without joining
    # on rule_id, so an empty string is safe here.
    return decide_pb2.RuleResult(
        rule_id="",
        state=state,
        conclusion=conclusion,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Filter evaluation
# ---------------------------------------------------------------------------


def evaluate_filter_locally(
    ctx: RequestContext,
    rule: Filter,
) -> decide_pb2.RuleResult | None:
    """Evaluate a Filter rule locally via WASM.

    Returns a proto RuleResult, or None if WASM is unavailable.
    """
    component = _get_component()
    if component is None:
        return None

    request_json = _context_to_analyze_request(ctx)

    # Serialize filter_local fields to JSON for the WASM component.
    # Per ADR 2026-01-28, serialization failures must be handled gracefully
    # (not propagated as unhandled exceptions).
    local_fields = "{}"
    if ctx.filter_local:
        try:
            local_fields = json.dumps(ctx.filter_local)
        except (TypeError, ValueError) as exc:
            logger.debug("filter_local serialization error: %s", exc)
            return None

    # allow takes precedence over deny (matches JS SDK and decide API).
    if rule.allow:
        expressions = list(rule.allow)
        allow_if_match = True
    else:
        expressions = list(rule.deny)
        allow_if_match = False

    try:
        result = component.match_filters(
            request_json, local_fields, expressions, allow_if_match
        )
    except Exception as exc:
        logger.debug("local filter evaluation error: %s", exc)
        return None

    if isinstance(result, Err):
        logger.debug("local filter evaluation returned error: %s", result.value)
        return None

    if not isinstance(result, Ok):
        logger.debug(
            "local filter evaluation returned unexpected type: %s", type(result)
        )
        return None
    fr: FilterResult = result.value

    conclusion = (
        decide_pb2.CONCLUSION_ALLOW if fr.allowed else decide_pb2.CONCLUSION_DENY
    )
    state = _rule_state(rule.mode)

    reason = decide_pb2.Reason(
        filter=decide_pb2.FilterReason(
            matched_expressions=list(fr.matched_expressions),
            undetermined_expressions=list(fr.undetermined_expressions),
        )
    )

    ttl = _LOCAL_DENY_TTL_SECONDS if not fr.allowed else 0

    return decide_pb2.RuleResult(
        rule_id="",
        state=state,
        conclusion=conclusion,
        reason=reason,
        ttl=ttl,
    )

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
from typing import Callable

from arcjet_analyze import (
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
)

from arcjet.proto.decide.v1alpha1 import decide_pb2

from ._enums import Mode
from ._logging import logger
from .context import RequestContext
from .rules import (
    BotDetection,
    EmailValidation,
    Filter,
    SensitiveInfoDetection,
    SensitiveInfoEntityType,
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
            # The WASM binary lives inside the arcjet_analyze package
            wasm_ref = (
                _res.files("arcjet_analyze")
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
        config = AllowedBotConfig(entities=entities, skip_custom_detect=False)
    else:
        entities = [str(e) for e in rule.deny]
        config = DeniedBotConfig(entities=entities, skip_custom_detect=False)

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

    # Intentional: server uses empty rule_id too (arcjet-decide #4740).
    # The report handler passes rules/results independently without joining
    # on rule_id, so an empty string is safe here.
    return decide_pb2.RuleResult(
        rule_id="",
        state=state,
        conclusion=conclusion,
        reason=reason,
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


def _detected_entity_type_str(entity: DetectedSensitiveInfoEntity) -> str:
    """Extract a string type name from a DetectedSensitiveInfoEntity."""
    ident = entity.identified_type
    type_str = _WASM_ENTITY_TYPE_TO_STR.get(type(ident))
    if type_str is not None:
        return type_str
    if isinstance(ident, SensitiveInfoEntityCustom):
        return ident.value
    return "UNKNOWN"


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


def evaluate_sensitive_info_locally(
    ctx: RequestContext,
    rule: SensitiveInfoDetection,
) -> decide_pb2.RuleResult | None:
    """Evaluate a SensitiveInfoDetection rule locally via WASM.

    Returns a proto RuleResult, or None if WASM is unavailable or no content
    was provided.
    """
    component = _get_component()
    if component is None:
        return None

    content = ctx.sensitive_info_content
    if not content:
        return None

    # Build the WASM config from the rule's allow/deny lists.
    # Use .value for enum members; str() on 3.10 str enums returns
    # "ClassName.MEMBER" rather than the value.
    # allow takes precedence over deny (matches JS SDK and decide API).
    if rule.allow:
        wasm_entities = [
            _to_wasm_entity(e.value if isinstance(e, SensitiveInfoEntityType) else e)
            for e in rule.allow
        ]
        entities_config = SensitiveInfoEntitiesAllow(entities=wasm_entities)
    else:
        wasm_entities = [
            _to_wasm_entity(e.value if isinstance(e, SensitiveInfoEntityType) else e)
            for e in rule.deny
        ]
        entities_config = SensitiveInfoEntitiesDeny(entities=wasm_entities)

    config = SensitiveInfoConfig(
        entities=entities_config,
        context_window_size=rule.context_window_size,
        skip_custom_detect=rule.detect is None,
    )

    # Wrap the user's detect callback (str → SensitiveInfoEntity conversion)
    wasm_detect: Callable[[list[str]], list[SensitiveInfoEntity | None]] | None = None
    if rule.detect is not None:
        user_detect = rule.detect

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

    try:
        result = component.detect_sensitive_info(content, config, detect=wasm_detect)
    except Exception as exc:
        logger.debug("local sensitive info detection error: %s", exc)
        return None

    # detect_sensitive_info returns SensitiveInfoResult directly (not Result)
    allowed_entities = _to_proto_entities(result.allowed)
    denied_entities = _to_proto_entities(result.denied)

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

    expressions = list(rule.allow or rule.deny)
    allow_if_match = len(rule.allow) > 0

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

    return decide_pb2.RuleResult(
        rule_id="",
        state=state,
        conclusion=conclusion,
        reason=reason,
    )

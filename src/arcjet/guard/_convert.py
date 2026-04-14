"""Proto <-> SDK conversion functions for ``arcjet.guard``.

This module converts between the generated protobuf types and the public SDK
types defined in ``types.py``.  Callers should never import this module
directly.
"""

from __future__ import annotations

from arcjet._errors import ArcjetError
from arcjet._logging import logger
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

from ._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    hash_text,
)
from ._rules import (
    FixedWindowWithInput,
    LocalCustomWithInput,
    PromptInjectionWithInput,
    RuleWithInput,
    SensitiveInfoWithInput,
    SlidingWindowWithInput,
    TokenBucketWithInput,
)
from ._types import (
    Conclusion,
    Decision,
    InternalResult,
    Reason,
    RuleResult,
    RuleResultCustom,
    RuleResultError,
    RuleResultFixedWindow,
    RuleResultNotRun,
    RuleResultPromptInjection,
    RuleResultSensitiveInfo,
    RuleResultSlidingWindow,
    RuleResultTokenBucket,
    RuleResultUnknown,
)

_CONCLUSION_MAP: dict[int, Conclusion] = {
    pb.GUARD_CONCLUSION_ALLOW: "ALLOW",
    pb.GUARD_CONCLUSION_DENY: "DENY",
}


def _conclusion_from_proto(c: int) -> Conclusion:
    """Map a proto ``GuardConclusion`` to the SDK ``Conclusion`` string.

    Unrecognized values default to ``"ALLOW"`` (fail-open).
    """
    return _CONCLUSION_MAP.get(c, "ALLOW")


def _reason_from_oneof(field_name: str) -> Reason:
    """Map a proto result's oneof field name to a broad SDK ``Reason``.

    Used as a fallback when the server does not send a ``GuardReason``.
    """
    mapping: dict[str, Reason] = {
        "token_bucket": "RATE_LIMIT",
        "fixed_window": "RATE_LIMIT",
        "sliding_window": "RATE_LIMIT",
        "prompt_injection": "PROMPT_INJECTION",
        "local_sensitive_info": "SENSITIVE_INFO",
        "local_custom": "CUSTOM",
        "error": "ERROR",
        "not_run": "NOT_RUN",
    }
    return mapping.get(field_name, "UNKNOWN")


_REASON_MAP: dict[int, Reason] = {
    pb.GUARD_REASON_ERROR: "ERROR",
    pb.GUARD_REASON_NOT_RUN: "NOT_RUN",
    pb.GUARD_REASON_CUSTOM: "CUSTOM",
    pb.GUARD_REASON_RATE_LIMIT: "RATE_LIMIT",
    pb.GUARD_REASON_PROMPT_INJECTION: "PROMPT_INJECTION",
    pb.GUARD_REASON_SENSITIVE_INFO: "SENSITIVE_INFO",
}


def _reason_from_proto(r: int) -> Reason:
    """Map a proto ``GuardReason`` enum to the SDK ``Reason`` string.

    ``GUARD_REASON_UNSPECIFIED`` and unknown values map to ``"UNKNOWN"``.
    """
    return _REASON_MAP.get(r, "UNKNOWN")


def _result_from_proto(pr: pb.GuardRuleResult) -> RuleResult:
    """Convert a single proto ``GuardRuleResult`` to the SDK ``RuleResult``.

    ``ResultError`` maps to ``RuleResultError`` with ``conclusion="ALLOW"``
    (fail-open).  ``ResultNotRun`` maps to ``RuleResultNotRun``.
    """
    # Proto uses a oneof; the active field tells us which result type.
    which = pr.WhichOneof("result")

    if which == "token_bucket":
        v = pr.token_bucket
        return RuleResultTokenBucket(
            conclusion=_conclusion_from_proto(v.conclusion),
            remaining_tokens=v.remaining_tokens,
            max_tokens=v.max_tokens,
            reset_at_unix_seconds=v.reset_at_unix_seconds,
            refill_rate=v.refill_rate,
            refill_interval_seconds=v.refill_interval_seconds,
        )

    if which == "fixed_window":
        v = pr.fixed_window
        return RuleResultFixedWindow(
            conclusion=_conclusion_from_proto(v.conclusion),
            remaining_requests=v.remaining_requests,
            max_requests=v.max_requests,
            reset_at_unix_seconds=v.reset_at_unix_seconds,
            window_seconds=v.window_seconds,
        )

    if which == "sliding_window":
        v = pr.sliding_window
        return RuleResultSlidingWindow(
            conclusion=_conclusion_from_proto(v.conclusion),
            remaining_requests=v.remaining_requests,
            max_requests=v.max_requests,
            reset_at_unix_seconds=v.reset_at_unix_seconds,
            interval_seconds=v.interval_seconds,
        )

    if which == "prompt_injection":
        v = pr.prompt_injection
        return RuleResultPromptInjection(
            conclusion=_conclusion_from_proto(v.conclusion),
        )

    if which == "local_sensitive_info":
        v = pr.local_sensitive_info
        return RuleResultSensitiveInfo(
            conclusion=_conclusion_from_proto(v.conclusion),
            detected_entity_types=tuple(v.detected_entity_types),
        )

    if which == "local_custom":
        v = pr.local_custom
        return RuleResultCustom(
            conclusion=_conclusion_from_proto(v.conclusion),
            data=dict(v.data),
        )

    if which == "error":
        v = pr.error
        return RuleResultError(
            message=v.message or "Unknown error",
            code=v.code or "UNKNOWN",
        )

    if which == "not_run":
        return RuleResultNotRun()

    return RuleResultUnknown()


_MODE_MAP = {
    "LIVE": pb.GUARD_RULE_MODE_LIVE,
    "DRY_RUN": pb.GUARD_RULE_MODE_DRY_RUN,
}


def rule_to_proto(
    rule: RuleWithInput,
    local_results: dict[str, LocalSensitiveInfoResult | LocalSensitiveInfoError]
    | None = None,
) -> pb.GuardRuleSubmission:
    """Convert a ``*WithInput`` to a proto ``GuardRuleSubmission``.

    Maps the SDK rule's config/input data into the proto message structure,
    preserving identity fields (``_config_id``, ``_input_id``) and mode.

    For ``SensitiveInfoWithInput`` rules, the raw text is hashed
    (SHA-256) before being placed on the wire.  Pre-computed local
    evaluation results are attached from *local_results*.

    Rate-limit keys are SHA-256 hashed client-side so the raw key never
    leaves the SDK.

    Raises:
        ArcjetError: If the rule cannot be encoded into protobuf (e.g.
            negative config values that violate uint32 constraints).
    """
    try:
        guard_rule = _rule_body_to_proto(rule, local_results)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ArcjetError(
            f"Failed to encode rule {type(rule).__name__}: {exc}"
        ) from exc
    mode = _MODE_MAP.get(rule.mode, pb.GUARD_RULE_MODE_LIVE)

    try:
        return pb.GuardRuleSubmission(
            config_id=rule._config_id,
            input_id=rule._input_id,
            label=rule.label or "",
            metadata=dict(rule.metadata) if rule.metadata else {},
            rule=guard_rule,
            mode=mode,
        )
    except (ValueError, TypeError, OverflowError) as exc:
        raise ArcjetError(f"Failed to encode rule submission: {exc}") from exc


def _rule_body_to_proto(
    rule: RuleWithInput,
    local_results: dict[str, LocalSensitiveInfoResult | LocalSensitiveInfoError]
    | None = None,
) -> pb.GuardRule:
    """Map a rule to a proto ``GuardRule``."""
    if isinstance(rule, TokenBucketWithInput):
        return pb.GuardRule(
            token_bucket=pb.RuleTokenBucket(
                config_refill_rate=rule.config.refill_rate,
                config_interval_seconds=rule.config.interval_seconds,
                config_max_tokens=rule.config.max_tokens,
                config_bucket=rule.config_bucket,
                input_key_hash=rule.key_hash,
                input_requested=rule.requested,
            ),
        )

    if isinstance(rule, FixedWindowWithInput):
        return pb.GuardRule(
            fixed_window=pb.RuleFixedWindow(
                config_max_requests=rule.config.max_requests,
                config_window_seconds=rule.config.window_seconds,
                config_bucket=rule.config_bucket,
                input_key_hash=rule.key_hash,
                input_requested=rule.requested,
            ),
        )

    if isinstance(rule, SlidingWindowWithInput):
        return pb.GuardRule(
            sliding_window=pb.RuleSlidingWindow(
                config_max_requests=rule.config.max_requests,
                config_interval_seconds=rule.config.interval_seconds,
                config_bucket=rule.config_bucket,
                input_key_hash=rule.key_hash,
                input_requested=rule.requested,
            ),
        )

    if isinstance(rule, PromptInjectionWithInput):
        return pb.GuardRule(
            detect_prompt_injection=pb.RuleDetectPromptInjection(
                input_text=rule.text,
            ),
        )

    if isinstance(rule, SensitiveInfoWithInput):
        text_hash = hash_text(rule.text)
        local_si = pb.RuleLocalSensitiveInfo(
            input_text_hash=text_hash,
        )
        if rule.config.allow:
            local_si.config_entities_allow.CopyFrom(
                pb.EntityList(entities=list(rule.config.allow))
            )
        elif rule.config.deny:
            local_si.config_entities_deny.CopyFrom(
                pb.EntityList(entities=list(rule.config.deny))
            )
        local_result = local_results.get(rule._input_id) if local_results else None
        if isinstance(local_result, LocalSensitiveInfoResult):
            local_si.result_computed.CopyFrom(
                pb.ResultLocalSensitiveInfo(
                    conclusion=(
                        pb.GUARD_CONCLUSION_DENY
                        if local_result.conclusion == "DENY"
                        else pb.GUARD_CONCLUSION_ALLOW
                    ),
                    detected=len(local_result.detected_entity_types) > 0,
                    detected_entity_types=local_result.detected_entity_types,
                )
            )
            local_si.result_duration_ms = local_result.elapsed_ms
        elif isinstance(local_result, LocalSensitiveInfoError):
            local_si.result_error.CopyFrom(
                pb.ResultError(
                    message=local_result.message,
                    code=local_result.code,
                )
            )
        else:
            local_si.result_not_run.CopyFrom(pb.ResultNotRun())
        return pb.GuardRule(local_sensitive_info=local_si)

    if isinstance(rule, LocalCustomWithInput):
        local_cu = pb.RuleLocalCustom(
            config_data=dict(rule.config_data),
            input_data=dict(rule.input_data),
        )
        if rule.evaluate_result is not None:
            local_cu.result_computed.CopyFrom(
                pb.ResultLocalCustom(
                    conclusion=(
                        pb.GUARD_CONCLUSION_DENY
                        if rule.evaluate_result.conclusion == "DENY"
                        else pb.GUARD_CONCLUSION_ALLOW
                    ),
                    data=dict(rule.evaluate_result.data),
                )
            )
            local_cu.result_duration_ms = rule.evaluate_duration_ms
        elif rule.evaluate_error is not None:
            local_cu.result_error.CopyFrom(
                pb.ResultError(
                    message=rule.evaluate_error,
                    code="EVALUATE_ERROR",
                )
            )
        else:
            local_cu.result_not_run.CopyFrom(pb.ResultNotRun())
        return pb.GuardRule(local_custom=local_cu)

    raise ValueError(f"Unknown rule type: {type(rule).__name__}")


def decision_from_proto(
    response: pb.GuardResponse,
) -> Decision:
    """Convert a proto ``GuardResponse`` to the SDK ``Decision``.

    Each proto ``GuardRuleResult`` carries its own ``config_id`` and
    ``input_id`` so Layer 3 lookups (``rule.result(decision)``) can
    correlate results back to submitted rules.

    The server now sends a ``GuardReason`` enum on the ``GuardDecision``
    using fixed priority (SensitiveInfo > RateLimit > PromptInjection >
    Custom).  If the server sends ``GUARD_REASON_UNSPECIFIED``, the SDK
    falls back to deriving the reason from the first DENY result.

    Response-level ``errors`` (recoverable validation diagnostics) are
    logged but do not affect the decision.
    """
    # Log recoverable server-side validation errors if present.
    has_response_errors = len(response.errors) > 0
    for err in response.errors:
        logger.warning(
            "arcjet guard server diagnostic: [%s] %s",
            err.code,
            err.message,
            extra={"event": "guard_server_diagnostic"},
        )

    proto = response.decision
    if not proto or not proto.id:
        # No decision in response — synthesize an ALLOW with error.
        error = RuleResultError(
            message="No decision in response",
            code="NO_DECISION",
        )
        return Decision(
            conclusion="ALLOW",
            id="",
            results=(error,),
            reason="ERROR",
            _internal_results=(
                InternalResult(result=error, config_id="", input_id=""),
            ),
        )

    internal_results: list[InternalResult] = []
    for pr in proto.rule_results:
        result = _result_from_proto(pr)
        internal_results.append(
            InternalResult(
                result=result,
                config_id=pr.config_id,
                input_id=pr.input_id,
            )
        )

    results = tuple(ir.result for ir in internal_results)
    conclusion = _conclusion_from_proto(proto.conclusion)

    # Use the server-computed reason (priority-based).  Fall back to
    # client-side derivation only when the server sends UNSPECIFIED.
    reason = _reason_from_proto(proto.reason)
    if reason == "UNKNOWN":
        # Fallback: derive from the first DENY result's oneof case.
        for pr in proto.rule_results:
            which = pr.WhichOneof("result")
            if which and which not in ("error", "not_run"):
                sub = getattr(pr, which, None)
                if sub and hasattr(sub, "conclusion"):
                    if _conclusion_from_proto(sub.conclusion) == "DENY":
                        reason = _reason_from_oneof(which)
                        break

    return Decision(
        conclusion=conclusion,
        id=proto.id,
        results=results,
        reason=reason,
        _internal_results=tuple(internal_results),
        _has_response_errors=has_response_errors,
    )

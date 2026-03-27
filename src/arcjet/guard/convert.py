"""Proto <-> SDK conversion functions for ``arcjet.guard``.

This module converts between the generated protobuf types and the public SDK
types defined in ``types.py``.  Callers should never import this module
directly.
"""

from __future__ import annotations

from typing import Sequence

from arcjet.guard.proto.decide.v2 import decide_pb2 as pb

from ._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    evaluate_sensitive_info_locally,
    hash_text,
)
from .rules import (
    CustomWithInput,
    FixedWindowWithInput,
    PromptInjectionWithInput,
    RuleWithInput,
    SensitiveInfoWithInput,
    SlidingWindowWithInput,
    TokenBucketWithInput,
)
from .types import (
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
    """Map a proto result's oneof field name to a broad SDK ``Reason``."""
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
            reset_seconds=v.reset_seconds,
            refill_rate=v.refill_rate,
            refill_interval_seconds=v.refill_interval_seconds,
        )

    if which == "fixed_window":
        v = pr.fixed_window
        return RuleResultFixedWindow(
            conclusion=_conclusion_from_proto(v.conclusion),
            remaining_requests=v.remaining_requests,
            max_requests=v.max_requests,
            reset_seconds=v.reset_seconds,
            window_seconds=v.window_seconds,
        )

    if which == "sliding_window":
        v = pr.sliding_window
        return RuleResultSlidingWindow(
            conclusion=_conclusion_from_proto(v.conclusion),
            remaining_requests=v.remaining_requests,
            max_requests=v.max_requests,
            reset_seconds=v.reset_seconds,
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


def rule_to_proto(rule: RuleWithInput) -> pb.GuardRuleSubmission:
    """Convert a ``*WithInput`` to a proto ``GuardRuleSubmission``.

    Maps the SDK rule's config/input data into the proto message structure,
    preserving identity fields (``config_id``, ``input_id``) and mode.

    For ``SensitiveInfoWithInput`` rules, this also runs the WASM
    evaluation locally and attaches the result.  The raw text is hashed
    (SHA-256) before being placed on the wire.
    """
    guard_rule = _rule_body_to_proto(rule)
    mode = _MODE_MAP.get(rule.mode, pb.GUARD_RULE_MODE_LIVE)

    return pb.GuardRuleSubmission(
        config_id=rule.config_id,
        input_id=rule.input_id,
        label=rule.label or "",
        metadata=dict(rule.metadata) if rule.metadata else {},
        rule=guard_rule,
        mode=mode,
    )


def _rule_body_to_proto(rule: RuleWithInput) -> pb.GuardRule:
    """Map a rule to a proto ``GuardRule``."""
    if isinstance(rule, TokenBucketWithInput):
        return pb.GuardRule(
            token_bucket=pb.RuleTokenBucket(
                config_refill_rate=rule.config.refill_rate,
                config_interval_seconds=rule.config.interval_seconds,
                config_max_tokens=rule.config.max_tokens,
                input_key=rule.key,
                input_requested=rule.requested,
            ),
        )

    if isinstance(rule, FixedWindowWithInput):
        return pb.GuardRule(
            fixed_window=pb.RuleFixedWindow(
                config_max_requests=rule.config.max_requests,
                config_window_seconds=rule.config.window_seconds,
                input_key=rule.key,
                input_requested=rule.requested,
            ),
        )

    if isinstance(rule, SlidingWindowWithInput):
        return pb.GuardRule(
            sliding_window=pb.RuleSlidingWindow(
                config_max_requests=rule.config.max_requests,
                config_interval_seconds=rule.config.interval_seconds,
                input_key=rule.key,
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
        local_result = evaluate_sensitive_info_locally(rule)
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

    if isinstance(rule, CustomWithInput):
        local_custom = pb.RuleLocalCustom(
            config_data=dict(rule.config.data),
            input_data=dict(rule.data),
        )
        if rule.conclusion is not None:
            local_custom.result_computed.CopyFrom(
                pb.ResultLocalCustom(
                    conclusion=(
                        pb.GUARD_CONCLUSION_DENY
                        if rule.conclusion == "DENY"
                        else pb.GUARD_CONCLUSION_ALLOW
                    ),
                    data=dict(rule.result_data) if rule.result_data else {},
                )
            )
            if rule.elapsed_ms is not None:
                local_custom.result_duration_ms = rule.elapsed_ms
        else:
            local_custom.result_not_run.CopyFrom(pb.ResultNotRun())
        return pb.GuardRule(local_custom=local_custom)

    raise ValueError(f"Unknown rule type: {type(rule).__name__}")


def decision_from_proto(
    response: pb.GuardResponse,
    rules: Sequence[RuleWithInput],
) -> Decision:
    """Convert a proto ``GuardResponse`` to the SDK ``Decision``.

    Correlates proto results back to SDK rule instances using
    ``config_id`` and ``input_id``.
    """
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

    # Derive reason from the first DENY result's oneof case.
    reason: Reason = "UNKNOWN"
    for pr in proto.rule_results:
        which = pr.WhichOneof("result")
        if which and which not in ("error", "not_run"):
            # Check if this result was a DENY
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
    )

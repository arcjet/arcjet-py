"""Rule builders and types for the Arcjet Python SDK.

This module defines the user-facing rule specs you configure on the client and
converts them into the protobuf messages consumed by the Decide API. Use the
builder functions for a concise, IDE-friendly experience and to get validation
errors early.

Quick examples
--------------

Shield common sensitive endpoints:

    from arcjet.rules import shield, Mode
    rules = [
        shield(mode=Mode.LIVE),
    ]

Detect bots with allow/deny lists:

    from arcjet.rules import detect_bot, BotCategory
    rules = [
        detect_bot(
            allow=(BotCategory.GOOGLE, "OPENAI_CRAWLER_SEARCH"),
        )
    ]

Rate limiting (token bucket):

    from arcjet.rules import token_bucket
    rules = [
        token_bucket(refill_rate=10, interval=60, capacity=20),
    ]
    # When using token buckets, pass `requested` to charge tokens per request:
    #   decision = await aj.protect(req, requested=1)

Email validation:

    from arcjet.rules import validate_email, EmailType
    rules = [
        validate_email(deny=(EmailType.DISPOSABLE, EmailType.INVALID))
    ]
    # When configured, pass `email=...` to `protect()`:
    #   decision = await aj.protect(req, email="alice@example.com")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Tuple, Iterable, Union
from enum import Enum

from proto.decide.v1alpha1 import decide_pb2

from ._enums import _mode_to_proto, Mode


class RuleSpec:
    """User-facing rule definition.

    Subclasses encapsulate validation and `to_proto()` conversion to the
    Decide API format. Prefer using the factory functions such as `shield()` or
    `token_bucket()` instead of constructing subclasses directly, as they
    provide clearer error messages and defaults.
    """

    def to_proto(self) -> decide_pb2.Rule:
        raise NotImplementedError

    def get_characteristics(self) -> tuple[str, ...]:
        """Return characteristics for cache key derivation.

        Defaults to empty; subclasses may define a `characteristics` field.
        """
        ch = getattr(self, "characteristics", ())
        if not isinstance(ch, tuple):
            try:
                ch = tuple(ch)  # best effort
            except Exception:
                return ()
        out: list[str] = []
        for c in ch:
            if isinstance(c, str) and c:
                out.append(c)
        return tuple(out)


@dataclass(frozen=True, slots=True)
class Shield(RuleSpec):
    """Block or monitor access to sensitive areas.

    Prefer using `shield(...)` helper
    """

    mode: Mode
    characteristics: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("Shield.mode must be a Mode enum")
        # characteristics are strings; enforce tuple[str, ...]
        if not isinstance(self.characteristics, tuple):
            raise TypeError("Shield.characteristics must be a tuple of strings")
        for c in self.characteristics:
            if not isinstance(c, str):
                raise TypeError("Shield.characteristics entries must be strings")

    def to_proto(self) -> decide_pb2.Rule:
        sr = decide_pb2.ShieldRule(mode=_mode_to_proto(self.mode))
        sr.characteristics.extend(self.characteristics)
        return decide_pb2.Rule(shield=sr)


class BotCategory(str, Enum):
    """Known bot categories you can allow or deny.

    You can also pass arbitrary bot names as strings to `detect_bot(...)`.

    See https://docs.arcjet.com/bot-protection/identifying-bots for the full
    list.
    """

    ACADEMIC = "CATEGORY:ACADEMIC"
    ADVERTISING = "CATEGORY:ADVERTISING"
    AI = "CATEGORY:AI"
    AMAZON = "CATEGORY:AMAZON"
    ARCHIVE = "CATEGORY:ARCHIVE"
    FEEDFETCHER = "CATEGORY:FEEDFETCHER"
    GOOGLE = "CATEGORY:GOOGLE"
    META = "CATEGORY:META"
    MICROSOFT = "CATEGORY:MICROSOFT"
    MONITOR = "CATEGORY:MONITOR"
    OPTIMIZER = "CATEGORY:OPTIMIZER"
    PREVIEW = "CATEGORY:PREVIEW"
    PROGRAMMATIC = "CATEGORY:PROGRAMMATIC"
    SEARCH_ENGINE = "CATEGORY:SEARCH_ENGINE"
    SLACK = "CATEGORY:SLACK"
    SOCIAL = "CATEGORY:SOCIAL"
    TOOL = "CATEGORY:TOOL"
    UNKNOWN = "CATEGORY:UNKNOWN"
    VERCEL = "CATEGORY:VERCEL"
    YAHOO = "CATEGORY:YAHOO"


def _bot_category_to_proto(value: Union[BotCategory, str]) -> str:
    if isinstance(value, BotCategory):
        return str(value.value)
    v = str(value)
    return v


# A bot specifier can be a known category or an arbitrary bot name string
BotSpecifier = Union[BotCategory, str]


@dataclass(frozen=True, slots=True)
class BotDetection(RuleSpec):
    """Detects bot traffic with allow/deny lists.

    Prefer using `detect_bot(...)` helper.
    """

    mode: Mode
    allow: tuple[BotSpecifier, ...] = ()
    deny: tuple[BotSpecifier, ...] = ()
    characteristics: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("BotDetection.mode must be a Mode enum")
        for seq, name in ((self.allow, "allow"), (self.deny, "deny")):
            if not isinstance(seq, tuple):
                raise TypeError(
                    f"BotDetection.{name} must be a tuple of BotCategory or str"
                )
            for item in seq:
                if not (isinstance(item, BotCategory) or isinstance(item, str)):
                    raise TypeError(
                        f"BotDetection.{name} entries must be BotCategory or str"
                    )
                if isinstance(item, str) and item == "":
                    raise ValueError(
                        f"BotDetection.{name} entries cannot be empty strings"
                    )
        if not isinstance(self.characteristics, tuple):
            raise TypeError("BotDetection.characteristics must be a tuple of strings")
        for c in self.characteristics:
            if not isinstance(c, str):
                raise TypeError("BotDetection.characteristics entries must be strings")

    def to_proto(self) -> decide_pb2.Rule:
        br = decide_pb2.BotV2Rule(mode=_mode_to_proto(self.mode))
        br.allow.extend([_bot_category_to_proto(a) for a in self.allow])
        br.deny.extend([_bot_category_to_proto(d) for d in self.deny])
        return decide_pb2.Rule(bot_v2=br)


class RateLimitAlgorithm(Enum):
    """Internal enum mapping to Decide API algorithms.

    You normally do not set this directly—use the provided helpers:
    `token_bucket`, `fixed_window`, or `sliding_window`.
    """

    TOKEN_BUCKET = "TOKEN_BUCKET"
    FIXED_WINDOW = "FIXED_WINDOW"
    SLIDING_WINDOW = "SLIDING_WINDOW"


def _rate_limit_algorithm_to_proto(alg: RateLimitAlgorithm) -> int:
    if alg is RateLimitAlgorithm.TOKEN_BUCKET:
        return decide_pb2.RATE_LIMIT_ALGORITHM_TOKEN_BUCKET
    if alg is RateLimitAlgorithm.FIXED_WINDOW:
        return decide_pb2.RATE_LIMIT_ALGORITHM_FIXED_WINDOW
    if alg is RateLimitAlgorithm.SLIDING_WINDOW:
        return decide_pb2.RATE_LIMIT_ALGORITHM_SLIDING_WINDOW
    raise ValueError("Unsupported rate limit algorithm")


@dataclass(frozen=True, slots=True)
class TokenBucket(RuleSpec):
    """Token bucket rate limiting.

    Prefer using `token_bucket(...)` helper.
    """

    mode: Mode
    refill_rate: int
    interval: int
    capacity: int
    characteristics: tuple[str, ...] = ()
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("TokenBucket.mode must be a Mode enum")
        for name, val in (
            ("refill_rate", self.refill_rate),
            ("interval", self.interval),
            ("capacity", self.capacity),
        ):
            if not isinstance(val, int) or val <= 0:
                raise ValueError(f"TokenBucket.{name} must be a positive integer")
        if not isinstance(self.algorithm, RateLimitAlgorithm):
            raise TypeError("TokenBucket.algorithm must be a RateLimitAlgorithm enum")
        if not isinstance(self.characteristics, tuple):
            raise TypeError("TokenBucket.characteristics must be a tuple of strings")
        for c in self.characteristics:
            if not isinstance(c, str):
                raise TypeError("TokenBucket.characteristics entries must be strings")

    def to_proto(self) -> decide_pb2.Rule:
        rr = decide_pb2.RateLimitRule(
            mode=_mode_to_proto(self.mode),
            algorithm=_rate_limit_algorithm_to_proto(self.algorithm),
            refill_rate=int(self.refill_rate),
            interval=int(self.interval),
            capacity=int(self.capacity),
        )
        rr.characteristics.extend(self.characteristics)
        return decide_pb2.Rule(rate_limit=rr)


@dataclass(frozen=True, slots=True)
class FixedWindow(RuleSpec):
    """Fixed window rate limiting.

    Prefer using `fixed_window(...)` helper.
    """

    mode: Mode
    max: int
    window_in_seconds: int
    characteristics: tuple[str, ...] = ()
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.FIXED_WINDOW

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("FixedWindow.mode must be a Mode enum")
        for name, val in (
            ("max", self.max),
            ("window_in_seconds", self.window_in_seconds),
        ):
            if not isinstance(val, int) or val <= 0:
                raise ValueError(f"FixedWindow.{name} must be a positive integer")
        if not isinstance(self.algorithm, RateLimitAlgorithm):
            raise TypeError("FixedWindow.algorithm must be a RateLimitAlgorithm enum")
        if self.algorithm is not RateLimitAlgorithm.FIXED_WINDOW:
            raise ValueError("FixedWindow.algorithm must be FIXED_WINDOW")
        if not isinstance(self.characteristics, tuple):
            raise TypeError("FixedWindow.characteristics must be a tuple of strings")
        for c in self.characteristics:
            if not isinstance(c, str):
                raise TypeError("FixedWindow.characteristics entries must be strings")

    def to_proto(self) -> decide_pb2.Rule:
        rr = decide_pb2.RateLimitRule(
            mode=_mode_to_proto(self.mode),
            algorithm=_rate_limit_algorithm_to_proto(self.algorithm),
            max=int(self.max),
            window_in_seconds=int(self.window_in_seconds),
        )
        rr.characteristics.extend(self.characteristics)
        return decide_pb2.Rule(rate_limit=rr)


@dataclass(frozen=True, slots=True)
class SlidingWindow(RuleSpec):
    """Sliding window rate limiting.

    Prefer using `sliding_window(...)` helper.
    """

    mode: Mode
    max: int
    interval: int
    characteristics: tuple[str, ...] = ()
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("SlidingWindow.mode must be a Mode enum")
        for name, val in (("max", self.max), ("interval", self.interval)):
            if not isinstance(val, int) or val <= 0:
                raise ValueError(f"SlidingWindow.{name} must be a positive integer")
        if not isinstance(self.algorithm, RateLimitAlgorithm):
            raise TypeError("SlidingWindow.algorithm must be a RateLimitAlgorithm enum")
        if self.algorithm is not RateLimitAlgorithm.SLIDING_WINDOW:
            raise ValueError("SlidingWindow.algorithm must be SLIDING_WINDOW")
        if not isinstance(self.characteristics, tuple):
            raise TypeError("SlidingWindow.characteristics must be a tuple of strings")
        for c in self.characteristics:
            if not isinstance(c, str):
                raise TypeError("SlidingWindow.characteristics entries must be strings")

    def to_proto(self) -> decide_pb2.Rule:
        rr = decide_pb2.RateLimitRule(
            mode=_mode_to_proto(self.mode),
            algorithm=_rate_limit_algorithm_to_proto(self.algorithm),
            max=int(self.max),
            interval=int(self.interval),
        )
        rr.characteristics.extend(self.characteristics)
        return decide_pb2.Rule(rate_limit=rr)


class EmailType(str, Enum):
    """Email classifier types used by the email validation rule."""

    DISPOSABLE = "DISPOSABLE"
    FREE = "FREE"
    NO_MX_RECORDS = "NO_MX_RECORDS"
    NO_GRAVATAR = "NO_GRAVATAR"
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class EmailValidation(RuleSpec):
    """Validate email addresses using multiple signals.

    Prefer using `validate_email(...)` helper.
    """

    mode: Mode
    deny: tuple[EmailType, ...] = ()
    allow: tuple[EmailType, ...] = ()
    require_top_level_domain: bool = True
    allow_domain_literal: bool = False
    characteristics: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("EmailValidation.mode must be a Mode enum")
        for seq, name in ((self.allow, "allow"), (self.deny, "deny")):
            if not isinstance(seq, tuple):
                raise TypeError(f"EmailValidation.{name} must be a tuple of EmailType")
            for item in seq:
                if not isinstance(item, EmailType):
                    raise TypeError(
                        f"EmailValidation.{name} entries must be EmailType enums"
                    )
        if not isinstance(self.characteristics, tuple):
            raise TypeError(
                "EmailValidation.characteristics must be a tuple of strings"
            )
        for c in self.characteristics:
            if not isinstance(c, str):
                raise TypeError(
                    "EmailValidation.characteristics entries must be strings"
                )

    def to_proto(self) -> decide_pb2.Rule:
        er = decide_pb2.EmailRule(
            mode=_mode_to_proto(self.mode),
            require_top_level_domain=bool(self.require_top_level_domain),
            allow_domain_literal=bool(self.allow_domain_literal),
        )
        er.allow.extend([_email_type_to_proto(t.value) for t in self.allow])
        er.deny.extend([_email_type_to_proto(t.value) for t in self.deny])
        # Do not set version explicitly; server will use the latest
        return decide_pb2.Rule(email=er)


def _email_type_to_proto(value: str) -> int:
    v = (value or "").upper()
    mapping = {
        "DISPOSABLE": decide_pb2.EMAIL_TYPE_DISPOSABLE,
        "FREE": decide_pb2.EMAIL_TYPE_FREE,
        "NO_MX_RECORDS": decide_pb2.EMAIL_TYPE_NO_MX_RECORDS,
        "NO_GRAVATAR": decide_pb2.EMAIL_TYPE_NO_GRAVATAR,
        "INVALID": decide_pb2.EMAIL_TYPE_INVALID,
    }
    if v.startswith("EMAIL_TYPE_"):
        # Allow power users to pass enum names directly
        v2 = v
        for k in mapping:
            if v2 == f"EMAIL_TYPE_{k}":
                return mapping[k]
    if v in mapping:
        return mapping[v]
    raise ValueError(
        f"Unknown email type: {value!r}. Expected one of {sorted(mapping)}"
    )


def _coerce_mode(mode: Union[str, Mode]) -> Mode:
    if isinstance(mode, Mode):
        return mode
    m = str(mode).upper()
    if m in ("LIVE", "DRY_RUN", "DRYRUN", "DRY-RUN"):
        return Mode.LIVE if m == "LIVE" else Mode.DRY_RUN
    raise ValueError(f"Unknown mode: {mode!r}")


def shield(
    *, mode: Union[str, Mode] = Mode.LIVE, characteristics: Sequence[str] = ()
) -> Shield:
    """Construct a `Shield` rule.

    Example:
        rules = [shield(mode=Mode.LIVE)]
    """
    return Shield(mode=_coerce_mode(mode), characteristics=tuple(characteristics))


def _coerce_bot_categories(
    items: Iterable[Union[str, BotCategory]],
) -> Tuple[BotSpecifier, ...]:
    out: list[BotSpecifier] = []
    for it in items:
        if isinstance(it, BotCategory):
            out.append(it)
            continue
        v = str(it)
        for bc in BotCategory:
            if bc.value == v or bc.name == v.upper():
                out.append(bc)
                break
        else:
            # Allow arbitrary bot names as strings (e.g., "OPENAI_CRAWLER_SEARCH")
            out.append(v)
    return tuple(out)


def detect_bot(
    *,
    mode: Union[str, Mode] = Mode.LIVE,
    allow: Sequence[Union[str, BotCategory]] = (),
    deny: Sequence[Union[str, BotCategory]] = (),
) -> BotDetection:
    """Construct a `BotDetection` rule.

    Examples:
        detect_bot(allow=(BotCategory.GOOGLE, "OPENAI_CRAWLER_SEARCH"))
        detect_bot(deny=("OPENAI_CRAWLER",))
    """
    return BotDetection(
        mode=_coerce_mode(mode),
        allow=_coerce_bot_categories(allow),
        deny=_coerce_bot_categories(deny),
    )


def token_bucket(
    *,
    mode: Union[str, Mode] = Mode.LIVE,
    refill_rate: int,
    interval: int,
    capacity: int,
    characteristics: Sequence[str] = (),
) -> TokenBucket:
    """Construct a `TokenBucket` rate limit rule.

    Example:
        token_bucket(refill_rate=10, interval=60, capacity=20)
    """
    # Basic validation before constructing dataclass for clearer errors
    for name, val in (
        ("refill_rate", refill_rate),
        ("interval", interval),
        ("capacity", capacity),
    ):
        if not isinstance(val, int) or val <= 0:
            raise ValueError(f"token_bucket: {name} must be a positive integer")
    return TokenBucket(
        mode=_coerce_mode(mode),
        refill_rate=refill_rate,
        interval=interval,
        capacity=capacity,
        characteristics=tuple(characteristics),
        algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
    )


def fixed_window(
    *,
    mode: Union[str, Mode] = Mode.LIVE,
    max: int,
    window: int,
    characteristics: Sequence[str] = (),
) -> FixedWindow:
    """Construct a `FixedWindow` rate limit rule.

    Example:
        fixed_window(max=100, window=60)
    """
    if not isinstance(max, int) or max <= 0:
        raise ValueError("fixed_window: max must be a positive integer")
    if not isinstance(window, int) or window <= 0:
        raise ValueError("fixed_window: window must be a positive integer (seconds)")
    return FixedWindow(
        mode=_coerce_mode(mode),
        max=max,
        window_in_seconds=window,
        characteristics=tuple(characteristics),
        algorithm=RateLimitAlgorithm.FIXED_WINDOW,
    )


def sliding_window(
    *,
    mode: Union[str, Mode] = Mode.LIVE,
    max: int,
    interval: int,
    characteristics: Sequence[str] = (),
) -> SlidingWindow:
    """Construct a `SlidingWindow` rate limit rule.

    Example:
        sliding_window(max=100, interval=60)
    """
    if not isinstance(max, int) or max <= 0:
        raise ValueError("sliding_window: max must be a positive integer")
    if not isinstance(interval, int) or interval <= 0:
        raise ValueError(
            "sliding_window: interval must be a positive integer (seconds)"
        )
    return SlidingWindow(
        mode=_coerce_mode(mode),
        max=max,
        interval=interval,
        characteristics=tuple(characteristics),
        algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
    )


def _coerce_email_types(
    items: Iterable[Union[str, EmailType]],
) -> Tuple[EmailType, ...]:
    out: list[EmailType] = []
    for it in items:
        if isinstance(it, EmailType):
            out.append(it)
        else:
            v = str(it).upper()
            try:
                out.append(EmailType[v])
            except KeyError:
                try:
                    out.append(EmailType(v))
                except Exception:
                    raise ValueError(f"Unknown email type: {it!r}") from None
    return tuple(out)


def validate_email(
    *,
    mode: Union[str, Mode] = Mode.LIVE,
    deny: Sequence[Union[str, EmailType]] = (
        EmailType.DISPOSABLE,
        EmailType.INVALID,
        EmailType.NO_MX_RECORDS,
    ),
    allow: Sequence[Union[str, EmailType]] = (),
    require_top_level_domain: bool = True,
    allow_domain_literal: bool = False,
) -> EmailValidation:
    """Validate & verify email addresses.

    Examples:
        validate_email(deny=(EmailType.DISPOSABLE, EmailType.INVALID))

    When this rule is configured, pass `email=...` to `aj.protect(...)`.
    """
    return EmailValidation(
        mode=_coerce_mode(mode),
        deny=_coerce_email_types(deny),
        allow=_coerce_email_types(allow),
        require_top_level_domain=require_top_level_domain,
        allow_domain_literal=allow_domain_literal,
    )

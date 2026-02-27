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
from enum import Enum
from typing import Iterable, Sequence, Tuple, Union

from arcjet.proto.decide.v1alpha1 import decide_pb2

from ._enums import Mode, _mode_to_proto


class RuleSpec:
    """Base class for Arcjet rule definitions.

    Do not instantiate this class directly. Use the provided factory functions
    — ``shield()``, ``detect_bot()``, ``token_bucket()``, ``fixed_window()``,
    ``sliding_window()``, and ``validate_email()`` — to create rule instances,
    then pass them in the ``rules`` list of ``arcjet()`` / ``arcjet_sync()``.
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
    """Shield WAF rule configuration.

    Prefer the ``shield()`` factory function over constructing this directly.
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


@dataclass(frozen=True, slots=True)
class PromptInjectionDetection(RuleSpec):
    """Prompt injection detection rule configuration.

    Prefer the ``detect_prompt_injection()`` factory function over constructing this directly.
    """

    mode: Mode
    threshold: float = 0.5

    def __post_init__(self):
        if not isinstance(self.mode, Mode):
            raise TypeError("PromptInjectionDetection.mode must be a Mode enum")
        if not isinstance(self.threshold, (int, float)):
            raise TypeError("PromptInjectionDetection.threshold must be a number")
        threshold = float(self.threshold)
        if not (0.0 <= threshold <= 1.0):
            raise ValueError(
                f"PromptInjectionDetection.threshold must be between 0.0 and 1.0, got {threshold}"
            )

    def to_proto(self) -> decide_pb2.Rule:
        pidr = decide_pb2.PromptInjectionDetectionRule(
            mode=_mode_to_proto(self.mode),
            threshold=float(self.threshold),
        )
        return decide_pb2.Rule(prompt_injection_detection=pidr)


class BotCategory(str, Enum):
    """Known bot categories for use with ``detect_bot()``.

    Pass category values in the ``allow`` or ``deny`` lists of ``detect_bot()``
    to match entire families of bots at once. You can also mix these with
    individual bot-name strings (e.g. ``"GOOGLE_CRAWLER"``).

    See https://docs.arcjet.com/bot-protection/identifying-bots for the
    complete list of categories and named bots.

    The identifiers on the bot list are generated from a collection of known
    bots at https://github.com/arcjet/well-known-bots which includes details of
    their owner and any variations.

    If a bot is detected but cannot be identified as a known bot, it will be
    labeled as ``UNKNOWN_BOT``. This is separate from the ``CATEGORY:UNKNOWN``
    category, which is for bots that cannot be classified into any category but
    can still be identified as a specific bot.

    If you configure an allow rule and do not include ``UNKNOWN_BOT``, then
    detected bots that cannot be identified will be blocked. This is the
    default behavior to protect against new and rapidly evolving bots.

    Example::

        from arcjet import detect_bot, BotCategory, Mode

        rules = [
            detect_bot(
                mode=Mode.LIVE,
                # Allow search engines, uptime monitors, and CURL; block all other bots.
                allow=[
                    BotCategory.SEARCH_ENGINE,
                    BotCategory.MONITOR,
                    "CURL",
                ],
            )
        ]
    """

    ACADEMIC = "CATEGORY:ACADEMIC"
    """Scrape data for research purposes."""

    ADVERTISING = "CATEGORY:ADVERTISING"
    """Advertising and ad-verification bots."""

    AI = "CATEGORY:AI"
    """AI training and data-collection bots."""

    AMAZON = "CATEGORY:AMAZON"
    """Amazon-operated bots (e.g. Alexa)."""

    ARCHIVE = "CATEGORY:ARCHIVE"
    """Web archiving bots (e.g. Internet Archive / Wayback Machine)."""

    FEEDFETCHER = "CATEGORY:FEEDFETCHER"
    """RSS/Atom feed readers."""

    GOOGLE = "CATEGORY:GOOGLE"
    """Google-operated bots (e.g. Googlebot)."""

    META = "CATEGORY:META"
    """Meta/Facebook-operated bots."""

    MICROSOFT = "CATEGORY:MICROSOFT"
    """Microsoft-operated bots (e.g. Bingbot)."""

    MONITOR = "CATEGORY:MONITOR"
    """Uptime-monitoring and health-check services."""

    OPTIMIZER = "CATEGORY:OPTIMIZER"
    """Page-speed and SEO optimization crawlers."""

    PREVIEW = "CATEGORY:PREVIEW"
    """Link-preview bots (e.g. Slack, Discord, Twitter card fetchers)."""

    PROGRAMMATIC = "CATEGORY:PROGRAMMATIC"
    """Headless browsers and programmatic HTTP clients."""

    SEARCH_ENGINE = "CATEGORY:SEARCH_ENGINE"
    """Search-engine indexers (e.g. Google, Bing, DuckDuckGo)."""

    SLACK = "CATEGORY:SLACK"
    """Slack-operated bots."""

    SOCIAL = "CATEGORY:SOCIAL"
    """Social-media crawlers."""

    TOOL = "CATEGORY:TOOL"
    """Developer tools and CLI utilities."""

    UNKNOWN = "CATEGORY:UNKNOWN"
    """Bots that are detected but cannot be classified into another category."""

    VERCEL = "CATEGORY:VERCEL"
    """Vercel-operated bots."""

    YAHOO = "CATEGORY:YAHOO"
    """Yahoo-operated bots."""


def _bot_category_to_proto(value: Union[BotCategory, str]) -> str:
    if isinstance(value, BotCategory):
        return str(value.value)
    v = str(value)
    return v


# A bot specifier can be a known category or an arbitrary bot name string
BotSpecifier = Union[BotCategory, str]


@dataclass(frozen=True, slots=True)
class BotDetection(RuleSpec):
    """Bot detection rule configuration.

    Prefer the ``detect_bot()`` factory function over constructing this directly.
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


def _rate_limit_algorithm_to_proto(
    alg: RateLimitAlgorithm,
) -> decide_pb2.RateLimitAlgorithm:
    if alg is RateLimitAlgorithm.TOKEN_BUCKET:
        return decide_pb2.RATE_LIMIT_ALGORITHM_TOKEN_BUCKET
    if alg is RateLimitAlgorithm.FIXED_WINDOW:
        return decide_pb2.RATE_LIMIT_ALGORITHM_FIXED_WINDOW
    if alg is RateLimitAlgorithm.SLIDING_WINDOW:
        return decide_pb2.RATE_LIMIT_ALGORITHM_SLIDING_WINDOW
    raise ValueError("Unsupported rate limit algorithm")


@dataclass(frozen=True, slots=True)
class TokenBucket(RuleSpec):
    """Token bucket rate limiting rule configuration.

    Prefer the ``token_bucket()`` factory function over constructing this directly.
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
    """Fixed window rate limiting rule configuration.

    Prefer the ``fixed_window()`` factory function over constructing this directly.
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
    """Sliding window rate limiting rule configuration.

    Prefer the ``sliding_window()`` factory function over constructing this directly.
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
    """Email address classifier types used by ``validate_email()``.

    Pass these values in the ``allow`` or ``deny`` lists of
    ``validate_email()`` to filter email addresses by type.

    Example::

        from arcjet import validate_email, EmailType, Mode

        rules = [
            validate_email(
                mode=Mode.LIVE,
                deny=[EmailType.DISPOSABLE, EmailType.INVALID],
            )
        ]
    """

    DISPOSABLE = "DISPOSABLE"
    """Addresses from temporary or throw-away email providers."""

    FREE = "FREE"
    """Addresses from free email providers (e.g. Gmail, Yahoo Mail)."""

    NO_MX_RECORDS = "NO_MX_RECORDS"
    """Domains with no valid MX DNS records — mail cannot be delivered."""

    NO_GRAVATAR = "NO_GRAVATAR"
    """Addresses with no associated Gravatar profile."""

    INVALID = "INVALID"
    """Addresses that fail syntax or format validation."""


@dataclass(frozen=True, slots=True)
class EmailValidation(RuleSpec):
    """Email validation rule configuration.

    Prefer the ``validate_email()`` factory function over constructing this directly.
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


def _email_type_to_proto(value: str) -> decide_pb2.EmailType:
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
    """Protect your app against common attacks such as SQL injection, XSS, and CSRF.

    Shield analyzes each request server-side and blocks those that match known
    attack patterns. It requires no additional configuration beyond setting the
    enforcement mode.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        characteristics: Request attributes used to fingerprint the client
            (e.g. ``["ip.src"]``). Defaults to IP address.

    Returns:
        A ``Shield`` rule to include in the ``rules`` list of ``arcjet()``.

    Example::

        from arcjet import arcjet, shield, Mode

        aj = arcjet(
            key="ajkey_...",
            rules=[shield(mode=Mode.LIVE)],
        )
    """
    return Shield(mode=_coerce_mode(mode), characteristics=tuple(characteristics))


def detect_prompt_injection(
    *, mode: Union[str, Mode] = Mode.LIVE, threshold: float = 0.5
) -> PromptInjectionDetection:
    """Detect prompt injection attacks in user messages.

    Analyzes messages for prompt injection attempts where users try to override
    or manipulate AI system prompts. Requires passing ``message=`` to
    ``protect()`` when this rule is configured.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        threshold: Detection confidence threshold (0.0 to 1.0). Higher values
            are more conservative. Defaults to ``0.5``.

    Returns:
        A ``PromptInjectionDetection`` rule to include in the ``rules`` list of
        ``arcjet()``.

    Example::

        from arcjet import arcjet, detect_prompt_injection, Mode

        aj = arcjet(
            key="ajkey_...",
            rules=[detect_prompt_injection(mode=Mode.LIVE, threshold=0.9)],
        )

        # In your route handler, pass the user message:
        decision = await aj.protect(request, message=user_input)
        if decision.is_denied():
            # Handle detected prompt injection
            return {"error": "Invalid message"}, 400
    """
    return PromptInjectionDetection(mode=_coerce_mode(mode), threshold=float(threshold))


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
    """Detect and filter automated bot traffic.

    Configure an allowlist or a denylist of bot categories and/or named bots:

    - If ``allow`` is non-empty: only the listed bots are permitted; all other
      bots are denied.
    - If ``deny`` is non-empty: only the listed bots are blocked; all other
      bots are allowed.
    - Both lists accept ``BotCategory`` enum values and arbitrary bot-name
      strings (e.g. ``"CURL"``). See
      https://docs.arcjet.com/bot-protection/identifying-bots for the full
      list of named bots.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        allow: Bots to permit. All other bots are denied. Do not combine
            with ``deny``.
        deny: Bots to block. All other bots are allowed. Do not combine
            with ``allow``.

    Returns:
        A ``BotDetection`` rule to include in the ``rules`` list of
        ``arcjet()``.

    Example::

        from arcjet import detect_bot, BotCategory, Mode

        rules = [
            detect_bot(
                mode=Mode.LIVE,
                # Allow search engines and a specific AI bot; block everything else
                allow=[BotCategory.SEARCH_ENGINE, "CURL"],
            )
        ]
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
    """Rate-limit requests using the token bucket algorithm.

    Each client starts with a full bucket of tokens. Every call to
    ``protect(..., requested=N)`` consumes N tokens. Tokens are replenished at
    ``refill_rate`` per ``interval`` seconds up to ``capacity``. Requests are
    denied when the bucket is empty.

    When this rule is configured, pass ``requested=N`` to ``protect()`` to
    specify how many tokens each request costs (defaults to 1).

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        refill_rate: Number of tokens added to the bucket each interval.
        interval: How often (in seconds) tokens are refilled.
        capacity: Maximum number of tokens the bucket can hold.
        characteristics: Request attributes used to identify the client for
            per-client tracking (e.g. ``["ip.src"]``). Defaults to IP
            address. See https://docs.arcjet.com/fingerprints.

    Returns:
        A ``TokenBucket`` rule to include in the ``rules`` list of
        ``arcjet()``.

    Example::

        from arcjet import token_bucket, Mode

        rules = [
            token_bucket(
                mode=Mode.LIVE,
                refill_rate=5,   # add 5 tokens every 10 seconds
                interval=10,
                capacity=10,     # max 10 tokens in the bucket
            )
        ]
        # Then call protect() with a cost per request:
        # decision = await aj.protect(request, requested=1)
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
    """Rate-limit requests using the fixed window algorithm.

    Counts requests in fixed time windows of ``window`` seconds. Once a client
    reaches ``max`` requests within a window, subsequent requests are denied
    until the window resets. Note that request bursts can occur at window
    boundaries — use ``sliding_window()`` to avoid this.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        max: Maximum number of requests allowed per window.
        window: Window duration in seconds.
        characteristics: Request attributes used to identify the client for
            per-client tracking (e.g. ``["ip.src"]``). Defaults to IP
            address. See https://docs.arcjet.com/fingerprints.

    Returns:
        A ``FixedWindow`` rule to include in the ``rules`` list of
        ``arcjet()``.

    Example::

        from arcjet import fixed_window, Mode

        rules = [fixed_window(mode=Mode.LIVE, max=100, window=60)]
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
    """Rate-limit requests using the sliding window algorithm.

    Counts requests in a rolling time window of ``interval`` seconds. Unlike
    ``fixed_window()``, the window slides continuously which prevents request
    bursts at window boundaries.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        max: Maximum number of requests allowed per window.
        interval: Window duration in seconds.
        characteristics: Request attributes used to identify the client for
            per-client tracking (e.g. ``["ip.src"]``). Defaults to IP
            address. See https://docs.arcjet.com/fingerprints.

    Returns:
        A ``SlidingWindow`` rule to include in the ``rules`` list of
        ``arcjet()``.

    Example::

        from arcjet import sliding_window, Mode

        rules = [sliding_window(mode=Mode.LIVE, max=100, interval=60)]
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
    deny: Sequence[Union[str, EmailType]] = (),
    allow: Sequence[Union[str, EmailType]] = (),
    require_top_level_domain: bool = True,
    allow_domain_literal: bool = False,
) -> EmailValidation:
    """Validate and verify email addresses on signup or form submission.

    Checks the email passed to ``protect(email=...)`` against configurable
    criteria. Use ``deny`` to block specific email types (e.g. disposable
    addresses), or ``allow`` to restrict to only certain types.

    When this rule is configured, you **must** pass ``email=...`` to every
    ``protect()`` call, otherwise an ``ArcjetMisconfiguration`` is raised.

    Args:
        mode: Enforcement mode. ``Mode.LIVE`` blocks matching requests;
            ``Mode.DRY_RUN`` logs matches without blocking. Defaults to
            ``Mode.LIVE``.
        deny: Email types to reject. Common choices: ``EmailType.DISPOSABLE``,
            ``EmailType.INVALID``, ``EmailType.NO_MX_RECORDS``.
        allow: Email types to permit. All other types are rejected.
        require_top_level_domain: Reject addresses without a valid TLD.
            Defaults to ``True``.
        allow_domain_literal: Allow IP-literal domain addresses such as
            ``user@[192.0.2.1]``. Defaults to ``False``.

    Returns:
        An ``EmailValidation`` rule to include in the ``rules`` list of
        ``arcjet()``.

    Example::

        from arcjet import validate_email, EmailType, Mode

        rules = [
            validate_email(
                mode=Mode.LIVE,
                deny=[EmailType.DISPOSABLE, EmailType.INVALID],
            )
        ]
        # Then pass the email address on each protect() call:
        # decision = await aj.protect(request, email="alice@example.com")
    """
    return EmailValidation(
        mode=_coerce_mode(mode),
        deny=_coerce_email_types(deny),
        allow=_coerce_email_types(allow),
        require_top_level_domain=require_top_level_domain,
        allow_domain_literal=allow_domain_literal,
    )

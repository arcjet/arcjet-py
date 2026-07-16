"""Deterministic recognizers that mirror Rampart's redaction layer.

Structured, validatable types (email, URL, IP, phone, SSN, Luhn-valid card
numbers) are handled here with patterns rather than by the model, which is more
reliable for them. Recognizers are pure and synchronous so they stay cheap
relative to model inference.

Ported from ``sensitive-info-rampart/src/recognizers.ts`` in arcjet-js.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass(slots=True)
class DetectedSpan:
    """A detected span of sensitive info.

    Attributes:
        start: Start index (inclusive) into the scanned value.
        end: End index (exclusive) into the scanned value.
        type: Identified sensitive info type (an ``ArcjetSensitiveInfoType``
            string such as ``"EMAIL"``).
    """

    start: int
    end: int
    type: str


# A deterministic recognizer: given the full text, return the spans it matched.
Recognizer = Callable[[str], list[DetectedSpan]]


def luhn(digits: str) -> bool:
    """Validate a candidate card number with the Luhn checksum.

    Args:
        digits: String of digits (separators already removed).

    Returns:
        Whether the checksum is valid.
    """
    total = 0
    double = False
    for ch in reversed(digits):
        value = ord(ch) - 48
        if double:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        double = not double
    return total % 10 == 0


def _match_all(value: str, pattern: re.Pattern[str], type: str) -> list[DetectedSpan]:
    """Run a regex over ``value`` and map each match to a :class:`DetectedSpan`."""
    spans: list[DetectedSpan] = []
    for match in pattern.finditer(value):
        spans.append(DetectedSpan(start=match.start(), end=match.end(), type=type))
    return spans


# Patterns are compiled once at import so repeated detection is cheap. The
# ``re.ASCII`` flag keeps ``\d``/``\b`` ASCII-only, matching JavaScript's default
# regex semantics.
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.ASCII)
_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')]+", re.IGNORECASE | re.ASCII)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    re.ASCII,
)
# Full IPv6 (eight groups) or any of the ``::`` zero-compression forms. The
# alternatives all require either eight groups or a ``::``, so ordinary
# colon-separated text such as a clock time (``12:34:56``) does not match.
# Bounded by non-hex/non-colon so we don't match inside a longer token.
_IPV6 = re.compile(
    r"(?<![:.\w])(?:"
    r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,7}:|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|"
    r"(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|"
    r"[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|"
    r":(?::[A-Fa-f0-9]{1,4}){1,7}"
    r")(?![:.\w])",
    re.ASCII,
)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b", re.ASCII)
# Candidate card numbers: 13–19 digits, optionally split by spaces or dashes.
_CREDIT_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b", re.ASCII)

_CARD_SEP = re.compile(r"[ -]")

# A phone-number *candidate*: a maximal run of the characters a phone number is
# made of (digits, the separators the validator understands, parentheses, and a
# leading ``+``). Candidates are validated by ``is_phone_number`` below — which
# enforces the real structure — so this pattern only needs to bracket the run.
_PHONE_CANDIDATE = re.compile(r"[+(]?\d[\d\s()./+-]*", re.ASCII)

# Punctuation the greedy URL pattern can absorb from surrounding prose (e.g. the
# period ending a sentence or a comma in a list). Trimmed from the right edge so
# the span covers only the URL itself.
_URL_TRAILING = ".,;:!?)]}'\""


def email_recognizer(value: str) -> list[DetectedSpan]:
    """Email address recognizer."""
    return _match_all(value, _EMAIL, "EMAIL")


def url_recognizer(value: str) -> list[DetectedSpan]:
    """URL recognizer.

    The pattern is greedy, so trailing prose punctuation is trimmed from each
    match to keep the span on the URL itself.
    """
    result: list[DetectedSpan] = []
    for span in _match_all(value, _URL, "URL"):
        end = span.end
        while end > span.start and value[end - 1] in _URL_TRAILING:
            end -= 1
        if end > span.start:
            result.append(DetectedSpan(start=span.start, end=end, type="URL"))
    return result


def ip_address_recognizer(value: str) -> list[DetectedSpan]:
    """IPv4 and IPv6 address recognizer."""
    return [
        *_match_all(value, _IPV4, "IP_ADDRESS"),
        *_match_all(value, _IPV6, "IP_ADDRESS"),
    ]


def ssn_recognizer(value: str) -> list[DetectedSpan]:
    """US Social Security Number recognizer (dashed form)."""
    return _match_all(value, _SSN, "SSN")


# --- Phone number validation --------------------------------------------------
# Ported from ``arcjet-analyze/parsers/src/parsers/phone_number.rs`` so the
# Rampart backend validates phone numbers exactly as the default (WASM) backend
# does. A candidate must parse *completely* as either a structured phone number
# (an international/trunk ``+``/``0`` prefix, or a NANP start — a bracketed area
# code or a dot/dash-suffixed exchange) followed by 1–5 digit groups, or as a
# bare 10-digit NANP number ``NXXNXXXXXX``. This rejects bare digit runs (order
# numbers, SKUs), short codes, and IP addresses that a digit-count heuristic
# would misclassify.
#
# Each parser takes ``(text, pos)`` and returns the index after what it consumed,
# or ``None`` on failure — mirroring nom's ``(remainder, output)`` result.

_SECTION_SEP = frozenset("- /.")


def _digit(c: str) -> bool:
    return "0" <= c <= "9"


def _nanp_n(c: str) -> bool:
    # NANP area/exchange codes start with 2–9, never 0 or 1.
    return "2" <= c <= "9"


def _take_max1(
    text: str, pos: int, maxn: int, pred: Callable[[str], bool]
) -> int | None:
    """Consume 1..``maxn`` chars matching ``pred``; ``None`` if none match."""
    end = pos
    while end < len(text) and end - pos < maxn and pred(text[end]):
        end += 1
    return end if end > pos else None


def _take_and_verify(
    text: str, pos: int, length: int, pred: Callable[[str], bool]
) -> int | None:
    """Consume exactly ``length`` chars, all matching ``pred``; else ``None``."""
    if pos + length > len(text):
        return None
    if all(pred(text[k]) for k in range(pos, pos + length)):
        return pos + length
    return None


def _limited_digits(text: str, pos: int, minn: int, maxn: int) -> int | None:
    """Consume a maximal digit run and require its length in ``[minn, maxn]``."""
    end = pos
    while end < len(text) and _digit(text[end]):
        end += 1
    return end if minn <= end - pos <= maxn else None


def _section_sep(text: str, pos: int) -> int | None:
    if pos < len(text) and text[pos] in _SECTION_SEP:
        return pos + 1
    return None


def _trunk_or_international(text: str, pos: int) -> int | None:
    # ('0' | '+') then 1–4 digits.
    if pos < len(text) and text[pos] in ("0", "+"):
        return _take_max1(text, pos + 1, 4, _digit)
    return None


def _bracket_start(text: str, pos: int) -> int | None:
    # '(' 2–3 digits ')'
    if pos >= len(text) or text[pos] != "(":
        return None
    end = _limited_digits(text, pos + 1, 2, 3)
    if end is None or end >= len(text) or text[end] != ")":
        return None
    return end + 1


def _nxx_section(text: str, pos: int) -> int | None:
    # NANP NXX: leading digit 2–9, then two more digits.
    end = _take_and_verify(text, pos, 1, _nanp_n)
    return _take_and_verify(text, end, 2, _digit) if end is not None else None


def _dot_or_dash_start(text: str, pos: int) -> int | None:
    # An NXX section, then a '.' or '-', where the following digit/separator run
    # holds exactly one more separator (so IP-like ``255.255.255.255`` is not a
    # start). Only the ``NXX`` + separator is consumed; the rest is peeked.
    end = _nxx_section(text, pos)
    if end is None or end >= len(text) or text[end] not in (".", "-"):
        return None
    after = end + 1
    run = after
    while run < len(text) and (_digit(text[run]) or text[run] in (".", "-")):
        run += 1
    if sum(1 for c in text[after:run] if c in (".", "-")) != 1:
        return None
    return after


def _local_start(text: str, pos: int) -> int | None:
    return _bracket_start(text, pos) or _dot_or_dash_start(text, pos)


def _full_phone_start(text: str, pos: int) -> int | None:
    end = _trunk_or_international(text, pos)
    if end is not None:
        # Optionally followed by a separator + local start; if that combination
        # does not fully match, keep just the prefix (nom ``opt`` backtracks).
        sep = _section_sep(text, end)
        if sep is not None:
            local = _local_start(text, sep)
            if local is not None:
                return local
        return end
    return _local_start(text, pos)


def _generic_chunk(text: str, pos: int) -> int | None:
    # Optional leading separator, 1–10 digits, optional trailing separator.
    start = _section_sep(text, pos) or pos
    end = _limited_digits(text, start, 1, 10)
    if end is None:
        return None
    return _section_sep(text, end) or end


def _parse_phone_number(text: str, pos: int) -> int | None:
    end = _full_phone_start(text, pos)
    if end is None:
        return None
    end = _generic_chunk(text, end)
    if end is None:
        return None
    # Up to four further groups.
    for _ in range(4):
        nxt = _generic_chunk(text, end)
        if nxt is None:
            break
        end = nxt
    return end


def _is_full_nanp(candidate: str) -> bool:
    # A bare 10-digit NANP number: NXX NXX XXXX with no separators.
    end = _nxx_section(candidate, 0)
    if end is None:
        return False
    end = _nxx_section(candidate, end)
    if end is None:
        return False
    end = _take_and_verify(candidate, end, 4, _digit)
    return end == len(candidate)


def is_phone_number(candidate: str) -> bool:
    """Whether ``candidate`` is a valid phone number (whole-string match).

    Ported from ``is_phone_number`` in arcjet-analyze so the Rampart backend and
    the default (WASM) backend agree on what counts as a phone number.
    """
    end = _parse_phone_number(candidate, 0)
    if end == len(candidate):
        return True
    return _is_full_nanp(candidate)


def phone_recognizer(value: str) -> list[DetectedSpan]:
    """Phone number recognizer.

    Finds candidate runs and keeps only those that validate as a phone number
    via :func:`is_phone_number`, matching the default backend's rules.
    """
    result: list[DetectedSpan] = []
    for match in _PHONE_CANDIDATE.finditer(value):
        start, end = match.start(), match.end()
        # Trim to a tight span: drop leading chars that cannot start a number
        # and trailing separators/whitespace the greedy run absorbed.
        while start < end and value[start] not in "0123456789+(":
            start += 1
        while end > start and value[end - 1] not in "0123456789)":
            end -= 1
        if start < end and is_phone_number(value[start:end]):
            result.append(DetectedSpan(start=start, end=end, type="PHONE_NUMBER"))
    return result


def credit_card_recognizer(value: str) -> list[DetectedSpan]:
    """Credit/debit card recognizer, validated with the Luhn checksum."""
    spans = _match_all(value, _CREDIT_CARD, "CREDIT_CARD_NUMBER")
    result: list[DetectedSpan] = []
    for span in spans:
        digits = _CARD_SEP.sub("", value[span.start : span.end])
        if 13 <= len(digits) <= 19 and luhn(digits):
            result.append(span)
    return result


# The default set of deterministic recognizers, ordered most-specific first.
# Overlap resolution happens later in the backend (longer spans win; equal-length
# ties keep the earlier-listed recognizer), so this order only breaks ties — for
# example a Luhn-valid card over the looser phone matcher on the same text.
default_recognizers: tuple[Recognizer, ...] = (
    credit_card_recognizer,
    ssn_recognizer,
    email_recognizer,
    url_recognizer,
    ip_address_recognizer,
    phone_recognizer,
)


def run_recognizers(
    value: str,
    recognizers: Sequence[Recognizer] = default_recognizers,
) -> list[DetectedSpan]:
    """Run a list of recognizers over ``value`` and collect every span.

    Args:
        value: Text to scan.
        recognizers: Recognizers to run (default: :data:`default_recognizers`).

    Returns:
        All matched spans, in recognizer order.
    """
    spans: list[DetectedSpan] = []
    for recognizer in recognizers:
        spans.extend(recognizer(value))
    return spans

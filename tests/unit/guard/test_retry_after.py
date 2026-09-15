"""The one rule every Arcjet SDK follows for a rate-limit retry hint.

The hint says when the call would actually be permitted, so only rules that
denied are considered and the latest of their resets wins. Reporting the
earliest — or the first in submission order — invites a retry that the longer
rule denies again.
"""

from __future__ import annotations

import time

from guard_doubles import make_deny_decision

from arcjet.guard._retry_after import MAX_RETRY_AFTER_SECONDS, retry_after_seconds
from arcjet.guard._types import Conclusion, RuleResultTokenBucket


def _bucket(
    conclusion: Conclusion, reset_at_unix_seconds: int
) -> RuleResultTokenBucket:
    return RuleResultTokenBucket(
        conclusion=conclusion,
        reset_at_unix_seconds=reset_at_unix_seconds,
    )


def _about(actual, expected) -> bool:
    """Wall clock moves between building the decision and reading the result."""
    return actual is not None and abs(actual - expected) <= 1


class TestSeveralRateLimitRulesOnOneDenial:
    def test_a_rule_that_allowed_does_not_supply_the_hint(self) -> None:
        now = int(time.time())
        decision = make_deny_decision(
            results=(
                _bucket("ALLOW", now + 5),
                _bucket("DENY", now + 300),
            ),
        )

        assert _about(retry_after_seconds(decision), 300)

    def test_a_rule_that_allowed_is_ignored_even_when_its_reset_is_later(self) -> None:
        """The case that actually proves the conclusion filter.

        With the allowing rule's reset *earlier*, taking the latest reset
        yields the right answer whether or not the filter is there. Only an
        allowing rule with a later reset distinguishes them.
        """
        now = int(time.time())
        decision = make_deny_decision(
            results=(
                _bucket("ALLOW", now + 900),
                _bucket("DENY", now + 60),
            ),
        )

        assert _about(retry_after_seconds(decision), 60)

    def test_the_latest_reset_among_denying_rules_is_reported(self) -> None:
        now = int(time.time())
        decision = make_deny_decision(
            results=(
                _bucket("DENY", now + 60),
                _bucket("DENY", now + 600),
            ),
        )

        assert _about(retry_after_seconds(decision), 600)

    def test_a_zero_reset_is_an_omitted_field_not_a_reset_in_1970(self) -> None:
        decision = make_deny_decision(results=(_bucket("DENY", 0),))

        assert retry_after_seconds(decision) is None

    def test_the_hint_is_clamped_to_24_hours(self) -> None:
        now = int(time.time())
        decision = make_deny_decision(results=(_bucket("DENY", now + 48 * 60 * 60),))

        assert retry_after_seconds(decision) == MAX_RETRY_AFTER_SECONDS
        assert MAX_RETRY_AFTER_SECONDS == 24 * 60 * 60

    def test_no_denying_rule_means_no_hint(self) -> None:
        now = int(time.time())
        decision = make_deny_decision(results=(_bucket("ALLOW", now + 5),))

        assert retry_after_seconds(decision) is None

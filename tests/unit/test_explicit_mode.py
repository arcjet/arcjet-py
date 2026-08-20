from __future__ import annotations

import pytest


@pytest.mark.parametrize(
    "factory,kwargs",
    [
        ("shield", {}),
        ("detect_bot", {"allow": ["CURL"]}),
        ("token_bucket", {"refill_rate": 1, "interval": 1, "capacity": 1}),
        ("fixed_window", {"max": 1, "window": 1}),
        ("sliding_window", {"max": 1, "interval": 1}),
        ("validate_email", {"deny": ["INVALID"]}),
        ("detect_prompt_injection", {}),
        ("detect_sensitive_info", {"deny": ["EMAIL"]}),
        ("filter_request", {"deny": ["ip.src == 1"]}),
    ],
)
def test_http_factory_requires_mode(mock_protobuf_modules, factory, kwargs):
    import arcjet._rules as rules

    fn = getattr(rules, factory)
    with pytest.raises(TypeError, match="mode"):
        fn(**kwargs)

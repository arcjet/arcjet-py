"""Tests for match-filters export.

Ported from Rust tests in arcjet/arcjet-analyze/filter/src/lib.rs
and JS tests in arcjet-js/analyze/test/analyze.test.ts.
"""

from __future__ import annotations

import json

from arcjet_analyze import AnalyzeComponent, Err, FilterResult, ImportCallbacks, Ok

REQUEST = json.dumps({"ip": "127.0.0.1"})

FULL_REQUEST = json.dumps(
    {
        "ip": "127.0.0.1",
        "host": "example.com",
        "method": "GET",
        "path": "/bot-protection/quick-start",
        "headers": {
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/138.0.0.0 Safari/537.36"
            ),
        },
        "cookies": "NEXT_LOCALE=en-US; notion_locale=en-US/autodetect",
        "query": "?q=alpha&source=hp&uact=5&sclient=gws-wiz",
    }
)


class TestMatchFiltersBasic:
    """Core allow/deny semantics."""

    def test_ok_no_expressions(self, component: AnalyzeComponent) -> None:
        result = component.match_filters("{}", "{}", [], True)
        assert isinstance(result, Ok)
        assert isinstance(result.value, FilterResult)
        assert result.value.matched_expressions == []
        assert result.value.undetermined_expressions == []

    def test_allow_if_match_no_expressions(self, component: AnalyzeComponent) -> None:
        result = component.match_filters("{}", "{}", [], True)
        assert isinstance(result, Ok)
        assert result.value.allowed is False

    def test_deny_if_match_no_expressions(self, component: AnalyzeComponent) -> None:
        result = component.match_filters("{}", "{}", [], False)
        assert isinstance(result, Ok)
        assert result.value.allowed is True

    def test_multiple_sequential_calls(self, component: AnalyzeComponent) -> None:
        """Fresh Store per call — multiple calls must work."""
        r1 = component.match_filters("{}", "{}", [], True)
        r2 = component.match_filters("{}", "{}", [], False)
        r3 = component.match_filters("{}", "{}", [], True)
        assert isinstance(r1, Ok)
        assert isinstance(r2, Ok)
        assert isinstance(r3, Ok)

    def test_allow_if_match_with_ip_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(REQUEST, "{}", ["ip.src == 127.0.0.1"], True)
        assert isinstance(result, Ok)
        assert result.value.allowed is True
        assert result.value.matched_expressions == ["ip.src == 127.0.0.1"]
        assert result.value.undetermined_expressions == []

    def test_allow_if_match_no_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(REQUEST, "{}", ["ip.src == 127.0.0.2"], True)
        assert isinstance(result, Ok)
        assert result.value.allowed is False
        assert result.value.matched_expressions == []

    def test_deny_if_match_with_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(REQUEST, "{}", ["ip.src == 127.0.0.1"], False)
        assert isinstance(result, Ok)
        assert result.value.allowed is False
        assert result.value.matched_expressions == ["ip.src == 127.0.0.1"]

    def test_deny_if_match_no_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(REQUEST, "{}", ["ip.src == 127.0.0.2"], False)
        assert isinstance(result, Ok)
        assert result.value.allowed is True
        assert result.value.matched_expressions == []


class TestMatchFiltersFields:
    """Test each expression field type from the Rust filter tests."""

    def test_ip_src_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ["ip.src == 127.0.0.1"], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ["ip.src == 127.0.0.1"]

    def test_ip_src_no_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ["ip.src == 192.168.1.1"], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

    def test_http_host_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.host == "example.com"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ['http.host == "example.com"']

    def test_http_host_no_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.host == "example.org"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

    def test_http_request_method_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.method == "GET"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ['http.request.method == "GET"']

    def test_http_request_method_no_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.method == "POST"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

    def test_http_request_uri_path_regex_match(
        self, component: AnalyzeComponent
    ) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.uri.path ~ "/quick-start"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == [
            'http.request.uri.path ~ "/quick-start"'
        ]

    def test_http_request_uri_path_regex_no_match(
        self, component: AnalyzeComponent
    ) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.uri.path ~ "/concepts"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

    def test_http_request_headers_regex_match(
        self, component: AnalyzeComponent
    ) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.headers["user-agent"] ~ "Chrome"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == [
            'http.request.headers["user-agent"] ~ "Chrome"'
        ]

    def test_http_request_headers_regex_no_match(
        self, component: AnalyzeComponent
    ) -> None:
        result = component.match_filters(
            FULL_REQUEST,
            "{}",
            ['http.request.headers["user-agent"] ~ "Firefox"'],
            False,
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

    def test_http_request_cookie_regex_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.cookie["NEXT_LOCALE"] ~ "en-"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == [
            'http.request.cookie["NEXT_LOCALE"] ~ "en-"'
        ]

    def test_http_request_cookie_regex_no_match(
        self, component: AnalyzeComponent
    ) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.cookie["NEXT_LOCALE"] ~ "de-"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

    def test_http_request_uri_args_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.uri.args["q"] == "alpha"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == [
            'http.request.uri.args["q"] == "alpha"'
        ]

    def test_http_request_uri_args_no_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.request.uri.args["q"] == "bravo"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []


class TestMatchFiltersFunctions:
    """Test built-in functions: len(), lower(), upper()."""

    def test_len_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ["len(http.request.method) == 3"], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ["len(http.request.method) == 3"]

    def test_lower_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['lower(http.request.method) == "get"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == [
            'lower(http.request.method) == "get"'
        ]

    def test_upper_match(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(
            FULL_REQUEST, "{}", ['upper(http.host) == "EXAMPLE.COM"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ['upper(http.host) == "EXAMPLE.COM"']

    def test_lower_ascii_only(self, component: AnalyzeComponent) -> None:
        """lower() is ASCII-only — non-ASCII chars are not case-folded."""
        req = json.dumps(
            {
                "ip": "127.0.0.1",
                "host": "example.com",
                "method": "GET",
                "path": "/",
                "headers": {
                    "x-upper": "\u0412\u0418\u041a\u0418\u041f\u0415\u0414\u0418\u042e"
                },  # ВИКИПЕДИЮ (Cyrillic uppercase)
            }
        )
        # ASCII lower() does not fold Cyrillic, so lowercase comparison fails
        result = component.match_filters(
            req,
            "{}",
            [
                'lower(http.request.headers["x-upper"]) == "\u0432\u0438\u043a\u0438\u043f\u0435\u0434\u0438\u044e"'
            ],  # википедию
            False,
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []

        # But comparing with the original uppercase value matches
        result2 = component.match_filters(
            req,
            "{}",
            [
                'lower(http.request.headers["x-upper"]) == "\u0412\u0418\u041a\u0418\u041f\u0415\u0414\u0418\u042e"'
            ],
            False,
        )
        assert isinstance(result2, Ok)
        assert len(result2.value.matched_expressions) == 1


class TestMatchFiltersOptionalFields:
    """Test ip.src.* fields that depend on ip_lookup callback."""

    def test_ip_src_country_undetermined_without_lookup(
        self, component: AnalyzeComponent
    ) -> None:
        """Without ip_lookup, geo-IP fields are undetermined."""
        result = component.match_filters(
            FULL_REQUEST, "{}", ['ip.src.country == "US"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []
        assert result.value.undetermined_expressions == ['ip.src.country == "US"']

    def test_ip_src_country_match_with_lookup(self, wasm_path: str) -> None:
        """With ip_lookup returning country=US, expression matches."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(
                ip_lookup=lambda _ip: json.dumps({"country": "US"})
            ),
        )
        result = ac.match_filters(FULL_REQUEST, "{}", ['ip.src.country == "US"'], False)
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ['ip.src.country == "US"']

    def test_ip_src_country_no_match_with_lookup(self, wasm_path: str) -> None:
        """With ip_lookup returning country=US, different country doesn't match."""
        ac = AnalyzeComponent(
            wasm_path,
            callbacks=ImportCallbacks(
                ip_lookup=lambda _ip: json.dumps({"country": "US"})
            ),
        )
        result = ac.match_filters(FULL_REQUEST, "{}", ['ip.src.country == "CA"'], False)
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == []
        assert result.value.undetermined_expressions == []


class TestMatchFiltersErrors:
    """Error cases from the Rust filter tests."""

    def test_undetermined_expressions(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(REQUEST, "{}", ["ip.src.vpn"], False)
        assert isinstance(result, Ok)
        assert result.value.undetermined_expressions == ["ip.src.vpn"]

    def test_syntax_error_expression(self, component: AnalyzeComponent) -> None:
        result = component.match_filters(REQUEST, "{}", ["\U0001f44d"], False)
        assert isinstance(result, Err)
        assert "Filter parsing error" in result.value

    def test_unknown_field(self, component: AnalyzeComponent) -> None:
        """Unknown identifier returns Err with parse error."""
        result = component.match_filters(
            FULL_REQUEST, "{}", ["http.request.blob == 1"], False
        )
        assert isinstance(result, Err)
        assert "unknown identifier" in result.value

    def test_unknown_function(self, component: AnalyzeComponent) -> None:
        """Unknown function returns Err with parse error."""
        result = component.match_filters(
            FULL_REQUEST, "{}", ["blob(http.request) == 1"], False
        )
        assert isinstance(result, Err)
        assert "unknown identifier" in result.value

    def test_invalid_comparison(self, component: AnalyzeComponent) -> None:
        """Type mismatch (string field vs integer literal) returns Err."""
        result = component.match_filters(FULL_REQUEST, "{}", ["http.host == 1"], False)
        assert isinstance(result, Err)
        assert "Filter parsing error" in result.value


class TestMatchFiltersLimits:
    """Expression count and byte size limits."""

    def test_10_expressions_ok(self, component: AnalyzeComponent) -> None:
        exprs = [f"ip.src == 127.0.0.{i}" for i in range(10)]
        result = component.match_filters(
            json.dumps({"ip": "127.0.0.127"}), "{}", exprs, False
        )
        assert isinstance(result, Ok)
        assert result.value.allowed is True
        assert result.value.matched_expressions == []

    def test_11_expressions_fails(self, component: AnalyzeComponent) -> None:
        exprs = [f"ip.src == 127.0.0.{i}" for i in range(11)]
        result = component.match_filters(
            json.dumps({"ip": "127.0.0.127"}), "{}", exprs, False
        )
        assert isinstance(result, Err)
        assert "10" in result.value

    def test_1024_bytes_expression_ok(self, component: AnalyzeComponent) -> None:
        expr = 'http.host eq "' + "a" * 1009 + '"'
        assert len(expr.encode()) == 1024
        result = component.match_filters(REQUEST, "{}", [expr], False)
        assert isinstance(result, Ok)

    def test_1025_bytes_expression_fails(self, component: AnalyzeComponent) -> None:
        expr = 'http.host eq "' + "a" * 1010 + '"'
        assert len(expr.encode()) == 1025
        result = component.match_filters(
            json.dumps({"ip": "127.0.0.127"}), "{}", [expr], False
        )
        assert isinstance(result, Err)
        assert "1024" in result.value


class TestMatchFiltersMultipleExpressions:
    """Multiple expressions in a single call."""

    def test_multiple_expressions_mixed(self, component: AnalyzeComponent) -> None:
        """Some expressions match, some don't, some are undetermined."""
        result = component.match_filters(
            FULL_REQUEST,
            "{}",
            [
                "ip.src == 127.0.0.1",
                'http.host == "other.com"',
                'ip.src.country == "US"',
            ],
            False,
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ["ip.src == 127.0.0.1"]
        assert result.value.undetermined_expressions == ['ip.src.country == "US"']

    def test_eq_operator_alias(self, component: AnalyzeComponent) -> None:
        """'eq' is an alias for '=='."""
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.host eq "example.com"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ['http.host eq "example.com"']

    def test_ne_operator(self, component: AnalyzeComponent) -> None:
        """'!=' / 'ne' inequality operator."""
        result = component.match_filters(
            FULL_REQUEST, "{}", ['http.host != "other.com"'], False
        )
        assert isinstance(result, Ok)
        assert result.value.matched_expressions == ['http.host != "other.com"']

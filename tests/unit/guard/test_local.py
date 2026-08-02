"""Unit tests for arcjet.guard._local — hash_text, WASM evaluation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from arcjet.guard import LocalDetectSensitiveInfo
from arcjet.guard._local import (
    LocalSensitiveInfoError,
    LocalSensitiveInfoResult,
    evaluate_sensitive_info_locally,
    hash_text,
)


class TestHashText:
    def test_returns_sha256_hex(self) -> None:
        import hashlib

        text = "hello world"
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert hash_text(text) == expected

    def test_different_inputs_different_hashes(self) -> None:
        assert hash_text("foo") != hash_text("bar")

    def test_same_input_same_hash(self) -> None:
        assert hash_text("test") == hash_text("test")


class TestLocalSensitiveInfoEvaluation:
    """Test WASM-based local sensitive info evaluation."""

    def test_returns_none_when_wasm_unavailable(self) -> None:
        rule = LocalDetectSensitiveInfo()
        inp = rule("my email is test@example.com")
        with patch("arcjet._local._get_component", return_value=None):
            result = evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        assert result is None

    def test_returns_none_for_empty_text(self) -> None:
        rule = LocalDetectSensitiveInfo()
        inp = rule("")
        with patch("arcjet._local._get_component", return_value=MagicMock()):
            result = evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        assert result is None

    def test_returns_error_on_wasm_exception(self) -> None:
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.side_effect = RuntimeError("boom")
        rule = LocalDetectSensitiveInfo()
        inp = rule("test text")
        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        assert isinstance(result, LocalSensitiveInfoError)
        assert result.code == "SENSITIVE_INFO_ERROR"
        # The message reports only the exception type, not str(exc) ("boom"),
        # since it is sent upstream and could otherwise carry scanned PII.
        assert result.message == "sensitive info backend error: RuntimeError"
        assert "boom" not in result.message

    def test_allow_result_without_detections(self) -> None:
        from arcjet._analyze import SensitiveInfoResult

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )
        rule = LocalDetectSensitiveInfo()
        inp = rule("no sensitive info here")
        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        assert isinstance(result, LocalSensitiveInfoResult)
        assert result.conclusion == "ALLOW"
        assert result.detected_entity_types == []

    def test_deny_result_with_detections(self) -> None:
        from arcjet._analyze import (
            DetectedSensitiveInfoEntity,
            SensitiveInfoEntityEmail,
            SensitiveInfoResult,
        )

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[],
            denied=[
                DetectedSensitiveInfoEntity(
                    start=12,
                    end=28,
                    identified_type=SensitiveInfoEntityEmail(),
                )
            ],
        )
        rule = LocalDetectSensitiveInfo()
        inp = rule("my email is test@example.com")
        with patch("arcjet._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        assert isinstance(result, LocalSensitiveInfoResult)
        assert result.conclusion == "DENY"
        assert "EMAIL" in result.detected_entity_types

    def test_passes_allow_config_to_wasm(self) -> None:
        from arcjet._analyze import SensitiveInfoEntitiesAllow, SensitiveInfoResult

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )
        rule = LocalDetectSensitiveInfo(allow=["EMAIL"])
        inp = rule("test")
        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        call_args = mock_component.detect_sensitive_info.call_args
        config = call_args[0][1]
        assert isinstance(config.entities, SensitiveInfoEntitiesAllow)

    def test_passes_deny_config_to_wasm(self) -> None:
        from arcjet._analyze import SensitiveInfoEntitiesDeny, SensitiveInfoResult

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )
        rule = LocalDetectSensitiveInfo(deny=["CREDIT_CARD_NUMBER"])
        inp = rule("test")
        with patch("arcjet._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(
                inp.text, allow=inp.config.allow, deny=inp.config.deny
            )
        call_args = mock_component.detect_sensitive_info.call_args
        config = call_args[0][1]
        assert isinstance(config.entities, SensitiveInfoEntitiesDeny)


class TestSensitiveInfoBackendOption:
    """A provided backend replaces the WASM engine (JS PR #6141)."""

    def test_uses_provided_backend_without_wasm(self) -> None:
        from arcjet._analyze import (
            DetectedSensitiveInfoEntity,
            SensitiveInfoEntityCustom,
            SensitiveInfoResult,
        )

        class Stub:
            def __init__(self) -> None:
                self.calls = 0

            def detect(self, context, value, entities, options=None):
                self.calls += 1
                return SensitiveInfoResult(
                    allowed=[],
                    denied=[
                        DetectedSensitiveInfoEntity(
                            start=0,
                            end=4,
                            identified_type=SensitiveInfoEntityCustom(
                                value="GIVEN_NAME"
                            ),
                        )
                    ],
                )

        stub = Stub()
        rule = LocalDetectSensitiveInfo(deny=["GIVEN_NAME"], backend=stub)
        inp = rule("Alex Rivera")
        # No WASM component available: a provided backend must still be used.
        with patch("arcjet._local._get_component", return_value=None):
            result = evaluate_sensitive_info_locally(
                inp.text,
                allow=inp.config.allow,
                deny=inp.config.deny,
                backend=inp.config.backend,
            )
        assert stub.calls == 1
        assert isinstance(result, LocalSensitiveInfoResult)
        assert result.conclusion == "DENY"
        assert result.detected_entity_types == ["GIVEN_NAME"]

    def test_backend_error_returns_sensitive_info_error(self) -> None:
        class Boom:
            def detect(self, *a, **k):
                raise RuntimeError("kaboom")

        rule = LocalDetectSensitiveInfo(deny=["GIVEN_NAME"], backend=Boom())
        inp = rule("Alex")
        result = evaluate_sensitive_info_locally(
            inp.text,
            allow=inp.config.allow,
            deny=inp.config.deny,
            backend=inp.config.backend,
        )
        assert isinstance(result, LocalSensitiveInfoError)
        assert result.code == "SENSITIVE_INFO_ERROR"

    def test_malformed_backend_output_returns_sensitive_info_error(self) -> None:
        # A backend returning something that is not a SensitiveInfoResult must
        # fail closed to a LocalSensitiveInfoError rather than crash request
        # handling when the result shape is read.
        class Malformed:
            def detect(self, *a, **k):
                return object()

        rule = LocalDetectSensitiveInfo(
            deny=["GIVEN_NAME"],
            backend=Malformed(),  # pyright: ignore[reportArgumentType]
        )
        inp = rule("Alex")
        result = evaluate_sensitive_info_locally(
            inp.text,
            allow=inp.config.allow,
            deny=inp.config.deny,
            backend=inp.config.backend,
        )
        assert isinstance(result, LocalSensitiveInfoError)
        assert result.code == "SENSITIVE_INFO_ERROR"

    def test_unknown_returned_types_dropped(self) -> None:
        from arcjet._analyze import (
            DetectedSensitiveInfoEntity,
            SensitiveInfoEntityCustom,
            SensitiveInfoResult,
        )

        class Stub:
            def detect(self, context, value, entities, options=None):
                return SensitiveInfoResult(
                    allowed=[],
                    denied=[
                        DetectedSensitiveInfoEntity(
                            start=0,
                            end=4,
                            identified_type=SensitiveInfoEntityCustom(value="BOGUS"),
                        )
                    ],
                )

        rule = LocalDetectSensitiveInfo(deny=["GIVEN_NAME"], backend=Stub())
        inp = rule("Alex")
        result = evaluate_sensitive_info_locally(
            inp.text,
            allow=inp.config.allow,
            deny=inp.config.deny,
            backend=inp.config.backend,
        )
        # Unknown returned type is dropped → no denied types → ALLOW.
        assert isinstance(result, LocalSensitiveInfoResult)
        assert result.detected_entity_types == []
        assert result.conclusion == "ALLOW"

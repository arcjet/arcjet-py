"""Unit tests for arcjet.guard._local — hash_text, WASM evaluation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from arcjet.guard import local_detect_sensitive_info
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
        rule = local_detect_sensitive_info()
        inp = rule("my email is test@example.com")
        with patch("arcjet.guard._local._get_component", return_value=None):
            result = evaluate_sensitive_info_locally(inp)
        assert result is None

    def test_returns_none_for_empty_text(self) -> None:
        rule = local_detect_sensitive_info()
        inp = rule("")
        with patch("arcjet.guard._local._get_component", return_value=MagicMock()):
            result = evaluate_sensitive_info_locally(inp)
        assert result is None

    def test_returns_error_on_wasm_exception(self) -> None:
        mock_component = MagicMock()
        mock_component.detect_sensitive_info.side_effect = RuntimeError("boom")
        rule = local_detect_sensitive_info()
        inp = rule("test text")
        with patch("arcjet.guard._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(inp)
        assert isinstance(result, LocalSensitiveInfoError)
        assert result.code == "WASM_ERROR"
        assert "boom" in result.message

    def test_allow_result_without_detections(self) -> None:
        from arcjet._analyze import SensitiveInfoResult

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )
        rule = local_detect_sensitive_info()
        inp = rule("no sensitive info here")
        with patch("arcjet.guard._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(inp)
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
        rule = local_detect_sensitive_info()
        inp = rule("my email is test@example.com")
        with patch("arcjet.guard._local._get_component", return_value=mock_component):
            result = evaluate_sensitive_info_locally(inp)
        assert isinstance(result, LocalSensitiveInfoResult)
        assert result.conclusion == "DENY"
        assert "EMAIL" in result.detected_entity_types

    def test_passes_allow_config_to_wasm(self) -> None:
        from arcjet._analyze import SensitiveInfoEntitiesAllow, SensitiveInfoResult

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )
        rule = local_detect_sensitive_info(allow=["EMAIL"])
        inp = rule("test")
        with patch("arcjet.guard._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(inp)
        call_args = mock_component.detect_sensitive_info.call_args
        config = call_args[0][1]
        assert isinstance(config.entities, SensitiveInfoEntitiesAllow)

    def test_passes_deny_config_to_wasm(self) -> None:
        from arcjet._analyze import SensitiveInfoEntitiesDeny, SensitiveInfoResult

        mock_component = MagicMock()
        mock_component.detect_sensitive_info.return_value = SensitiveInfoResult(
            allowed=[], denied=[]
        )
        rule = local_detect_sensitive_info(deny=["CREDIT_CARD_NUMBER"])
        inp = rule("test")
        with patch("arcjet.guard._local._get_component", return_value=mock_component):
            evaluate_sensitive_info_locally(inp)
        call_args = mock_component.detect_sensitive_info.call_args
        config = call_args[0][1]
        assert isinstance(config.entities, SensitiveInfoEntitiesDeny)

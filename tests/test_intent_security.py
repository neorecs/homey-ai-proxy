import pytest

from app.config import AppConfig
from app.intent_router import IntentRouter
from app.security import SecurityError, contains_blocked_keyword, is_flow_allowed, validate_flow_start


@pytest.fixture
def config() -> AppConfig:
    return AppConfig(
        allowed_flows=["AI - Presence test"],
        blocked_keywords=["slot", "alarm uitschakelen"],
        command_map={"test presence": "AI - Presence test"},
    )


def test_command_mapping(config: AppConfig) -> None:
    intent = IntentRouter(config).resolve(" test   presence ")
    assert intent.flow_name == "AI - Presence test"


def test_allowlist_accepts_ai_prefix(config: AppConfig) -> None:
    assert is_flow_allowed("AI - Avondmodus", config)
    validate_flow_start("AI - Avondmodus", config)


def test_blocked_keywords(config: AppConfig) -> None:
    assert contains_blocked_keyword("open het slot", config) == "slot"
    with pytest.raises(SecurityError):
        IntentRouter(config).resolve("alarm uitschakelen")


def test_unknown_command_is_rejected(config: AppConfig) -> None:
    with pytest.raises(SecurityError):
        IntentRouter(config).resolve("zet willekeurige lamp aan")

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_port: int = 8000
    log_level: str = "INFO"
    log_file: str = "/app/logs/homey-ai-proxy.log"
    config_path: str = "/app/config.yaml"
    homey_base_url: str = "http://homey.local"
    homey_token: str = ""
    homey_use_mock: bool = True
    homey_transport: Literal["local"] = "local"
    homey_auth_mode: Literal["static_token", "oauth2_session"] = "static_token"
    homey_oauth_client_id: str = ""
    homey_oauth_client_secret: str = ""
    homey_oauth_refresh_token: str = ""
    homey_oauth_access_token: str = ""
    homey_max_requests_per_minute: int = 5
    cache_ttl_seconds: int = 60
    command_debounce_seconds: int = 10
    homey_retry_attempts: int = 3
    homey_retry_base_delay_seconds: float = 0.5
    openai_enabled: bool = False
    openai_api_key: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


class AppConfig(BaseSettings):
    allowed_flows: list[str] = Field(default_factory=list)
    blocked_keywords: list[str] = Field(default_factory=list)
    command_map: dict[str, str] = Field(default_factory=dict)


def _load_yaml(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        fallback = Path("config.yaml.example")
        if fallback.exists():
            config_path = fallback
        else:
            return {}

    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Config file {config_path} must contain a YAML object")
        return data


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_app_config() -> AppConfig:
    settings = get_settings()
    return AppConfig(**_load_yaml(settings.config_path))

from app.config import AppConfig


AI_FLOW_PREFIX = "AI -"


class SecurityError(ValueError):
    pass


def normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def contains_blocked_keyword(text: str, config: AppConfig) -> str | None:
    normalized = normalize_text(text)
    for keyword in config.blocked_keywords:
        if normalize_text(keyword) in normalized:
            return keyword
    return None


def is_flow_allowed(flow_name: str, config: AppConfig) -> bool:
    return flow_name in config.allowed_flows or flow_name.startswith(AI_FLOW_PREFIX)


def validate_command_text(command: str, config: AppConfig) -> None:
    blocked = contains_blocked_keyword(command, config)
    if blocked:
        raise SecurityError(f"Command blocked by keyword: {blocked}")


def validate_flow_start(flow_name: str, config: AppConfig) -> None:
    blocked = contains_blocked_keyword(flow_name, config)
    if blocked:
        raise SecurityError(f"Flow blocked by keyword: {blocked}")
    if not is_flow_allowed(flow_name, config):
        raise SecurityError("Flow is not on the allowlist and does not start with 'AI -'")

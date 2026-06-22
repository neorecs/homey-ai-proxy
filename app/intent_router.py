from dataclasses import dataclass

from app.config import AppConfig
from app.security import SecurityError, normalize_text, validate_command_text, validate_flow_start


@dataclass(frozen=True)
class Intent:
    name: str
    flow_name: str


class IntentRouter:
    def __init__(self, config: AppConfig):
        self.config = config
        self._normalized_map = {
            normalize_text(command): flow_name for command, flow_name in config.command_map.items()
        }

    def resolve(self, command: str) -> Intent:
        validate_command_text(command, self.config)
        normalized = normalize_text(command)
        flow_name = self._normalized_map.get(normalized)
        if not flow_name:
            raise SecurityError("Command is not mapped to a safe intent")
        validate_flow_start(flow_name, self.config)
        return Intent(name=normalized, flow_name=flow_name)

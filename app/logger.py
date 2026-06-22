import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import Settings


SENSITIVE_MARKERS = ("token", "api_key", "authorization", "secret")


class SecretFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for marker in SENSITIVE_MARKERS:
            if marker in message.lower():
                record.msg = "[redacted sensitive log message]"
                record.args = ()
                break
        return True


def configure_logging(settings: Settings) -> None:
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())
    root.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.addFilter(SecretFilter())
    root.addHandler(console)

    log_path = Path(settings.log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        log_path = Path("logs/homey-ai-proxy.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SecretFilter())
    root.addHandler(file_handler)

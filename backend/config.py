"""
Backend settings loaded from environment variables (12-factor style).

Secrets such as API keys MUST come from the environment (.env file locally,
a secret manager in production) — never hard-code real secrets in source.
The development defaults below exist only so the demo runs out of the box;
the backend logs a loud warning when they are in use.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

log = logging.getLogger("ids.config")

DEV_KEYS = {
    "IDS_ADMIN_KEY": "admin-dev-key-change-me",
    "IDS_ANALYST_KEY": "analyst-dev-key-change-me",
    "IDS_SENSOR_KEY": "sensor-dev-key-change-me",
}


def _bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(
        os.getenv("IDS_DB_PATH", PROJECT_ROOT / "data" / "ids.db")))
    admin_key: str = field(default_factory=lambda: os.getenv("IDS_ADMIN_KEY", DEV_KEYS["IDS_ADMIN_KEY"]))
    analyst_key: str = field(default_factory=lambda: os.getenv("IDS_ANALYST_KEY", DEV_KEYS["IDS_ANALYST_KEY"]))
    sensor_key: str = field(default_factory=lambda: os.getenv("IDS_SENSOR_KEY", DEV_KEYS["IDS_SENSOR_KEY"]))
    ml_enabled: bool = field(default_factory=lambda: _bool("IDS_ML_ENABLED", True))
    cors_origins: list = field(default_factory=lambda: [
        o.strip() for o in os.getenv(
            "IDS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if o.strip()])
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.getenv("IDS_RATE_LIMIT_PER_MINUTE", "1200")))
    siem_export_enabled: bool = field(default_factory=lambda: _bool("IDS_SIEM_EXPORT_ENABLED", True))
    siem_export_path: Path = field(default_factory=lambda: Path(
        os.getenv("IDS_SIEM_EXPORT_PATH", PROJECT_ROOT / "logs" / "siem_alerts.jsonl")))
    correlation_window_seconds: int = field(default_factory=lambda: int(os.getenv("IDS_CORRELATION_WINDOW", "60")))

    def using_dev_keys(self) -> bool:
        return DEV_KEYS["IDS_ADMIN_KEY"] == self.admin_key or \
            DEV_KEYS["IDS_ANALYST_KEY"] == self.analyst_key or \
            DEV_KEYS["IDS_SENSOR_KEY"] == self.sensor_key

    def warn_if_insecure(self):
        if self.using_dev_keys():
            log.warning("Using DEVELOPMENT API keys. Set IDS_ADMIN_KEY / IDS_ANALYST_KEY / "
                        "IDS_SENSOR_KEY in .env before exposing this service anywhere.")

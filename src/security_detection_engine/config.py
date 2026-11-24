from enum import StrEnum
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings(BaseSettings):
    """Конфигурация приложения.

    Значения могут переопределяться переменными окружения с префиксом SDE_,
    например: SDE_LOG_LEVEL=DEBUG.
    """

    model_config = SettingsConfigDict(env_prefix="SDE_")

    app_name: str = "security-detection-engine"
    version: str = "0.1.0"
    log_level: LogLevel = LogLevel.INFO
    database_url: str | None = None
    rules_directory: Path = Path(__file__).resolve().parent / "rules"


def get_settings() -> Settings:
    return Settings()

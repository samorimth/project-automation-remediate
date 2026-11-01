"""Configuração por ambiente. Segredos ficam fora do código-fonte."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "remediation-lab"
    app_version: str = "0.1.0"
    environment: str = "lab"
    database_url: str = "sqlite:///./data/remediation.db"
    lab_api_key: str = ""
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()

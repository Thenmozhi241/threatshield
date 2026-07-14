"""
Centralized application configuration.

All settings are loaded from environment variables (or a `.env` file at the
project root). See `.env.example` for the full list of supported variables.
"""
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Application ---
    app_name: str = "ThreatShield"
    app_env: str = "development"
    debug: bool = True
    secret_key: str = "change-this-to-a-long-random-secret-key"
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # --- Database ---
    database_url: str = "sqlite:///./threatshield.db"

    # --- CORS ---
    allowed_origins: str = "http://localhost:8000"

    # --- Email ---
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "alerts@threatshield.local"
    email_alerts_enabled: bool = False

    # --- Telegram ---
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_alerts_enabled: bool = False

    # --- Slack ---
    slack_webhook_url: str = ""
    slack_alerts_enabled: bool = False

    # --- Scheduler ---
    scan_interval_hours: int = 24
    scheduler_enabled: bool = True

    # --- AbuseIPDB (optional; free API key from abuseipdb.com) ---
    abuseipdb_api_key: str = ""

    # --- Rate limiting ---
    rate_limit_per_minute: int = 60

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (loaded once per process)."""
    return Settings()


settings = get_settings()

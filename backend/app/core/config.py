"""
PhishGuard SOC - Core Configuration
Loads settings from environment variables / .env file.
"""
import os
import json
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    # App
    APP_NAME: str = "PhishGuard SOC"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "INSECURE_DEFAULT_CHANGE_ME"

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./phishguard.db"

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480

    # Files
    MAX_FILE_SIZE_MB: int = 25
    UPLOAD_DIR: str = "./uploads"
    REPORTS_DIR: str = "./reports"

    # ClamAV
    CLAMAV_ENABLED: bool = False
    CLAMAV_HOST: str = "localhost"
    CLAMAV_PORT: int = 3310

    # YARA
    YARA_RULES_DIR: str = "./rules"

    # Demo credentials
    DEMO_ADMIN_USERNAME: str = "admin"
    DEMO_ADMIN_PASSWORD: str = "Admin@123"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Threat Intelligence
    VT_API_KEY: str = ""
    ANYRUN_API_KEY: str = ""

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [v]
        return v

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


def ensure_dirs():
    """Create required directories if they don't exist."""
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.YARA_RULES_DIR, exist_ok=True)
"""
Bayora Shield - Configuration Settings
Environment-based configuration. Never store secrets directly in source code.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # API Server
    CONTROL_PLANE_HOST: str = "0.0.0.0"
    CONTROL_PLANE_PORT: int = 8000

    # JWT Authentication
    JWT_SECRET_KEY: str = "insecure_dev_jwt_secret_change_in_production_bayora_32_bytes_min"
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "bayora-shield"
    JWT_AUDIENCE: str = "bayora-api"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # PostgreSQL / Database
    # Defaults to SQLite async in development/testing if DATABASE_URL not pointed to Postgres
    DATABASE_URL: str = "sqlite+aiosqlite:///./bayora_shield.db"

    # Cryptography / Audit
    ED25519_PRIVATE_KEY_PATH: str = "/etc/bayora/keys/audit_ed25519.key"
    ED25519_PUBLIC_KEY_PATH: str = "/etc/bayora/keys/audit_ed25519.pub"

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

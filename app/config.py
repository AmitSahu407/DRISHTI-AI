from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List

class Settings(BaseSettings):
    app_name: str = "Dhristi AI"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"
    secret_key: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    algorithm: str = "HS256"
    database_url: str = "postgresql+psycopg://dhristi:dhristi@db:5432/dhristi"
    redis_url: str = "redis://redis:6379/0"
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    rate_limit_per_minute: int = 120
    bootstrap_admin_email: str = "admin@dhristi.local"
    bootstrap_admin_password: str = "ChangeThisPassword123!"
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def allowed_origins(self) -> List[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

settings = Settings()

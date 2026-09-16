from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TEMIS_LAB_",
        env_file=".env",
        env_file_encoding="utf-8"
        )

    database_url: str = "postgresql+asyncpg://temis_lab@127.0.0.1:55439/temis_sso_lab"
    redis_url: str = "redis://127.0.0.1:56389/0"
    private_key_path: Path = Path("var/keys/access-private.pem")
    public_key_path: Path = Path("var/keys/access-public.pem")
    status_service_key: str = "local-learning-status-key"
    service_name: str = "TEMIS SSO Lab"
    debug: bool = False

    google_client_id: str
    google_client_secret: str


settings = Settings()

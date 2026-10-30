from pathlib import Path
from urllib.parse import urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TEMIS_LAB_", env_file=".env", env_file_encoding="utf-8"
    )

    database_url: str = "postgresql+asyncpg://temis_lab@127.0.0.1:55439/temis_sso_lab"
    redis_url: str = "redis://127.0.0.1:56389/0"
    private_key_path: Path = Path("var/keys/access-private.pem")
    public_key_path: Path = Path("var/keys/access-public.pem")
    status_service_key: str = "local-learning-status-key"
    service_name: str = "TEMIS SSO Lab"
    debug: bool = False

    google_client_id: str = ""
    google_client_secret: str = ""

    naver_client_id: str = ""
    naver_client_secret: str = ""

    kakao_rest_api_key: str = ""
    kakao_client_secret: str = ""

    google_redirect_uri: str = "http://localhost:8000/oauth/google/callback"
    naver_redirect_uri: str = "http://localhost:8000/oauth/naver/callback"
    kakao_redirect_uri: str = "http://localhost:8000/oauth/kakao/callback"
    oauth_cookie_secure: bool = False

    @field_validator("google_redirect_uri", "naver_redirect_uri", "kakao_redirect_uri")
    @classmethod
    def validate_callback(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "Callback must be an absolute HTTP(S) URL without credentials, query or fragment"
            )
        if url.scheme != "https" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Non-loopback callbacks require HTTPS")
        return value


settings = Settings()

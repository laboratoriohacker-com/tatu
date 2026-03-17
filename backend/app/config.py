from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "TATU_"}

    database_url: str = "sqlite+aiosqlite:///./tatu.db"
    secret_key: str
    cors_origins: list[str] = ["http://localhost:5173"]
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # Admin bootstrap
    admin_email: str = ""

    # SMTP
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    smtp_from: str = "noreply@tatu.local"


settings = Settings()

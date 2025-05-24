from pathlib import Path
from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict

base_dir = Path(__file__).resolve().parent


class Environment(str, Enum):
    development = "development"
    production = "production"


class Config(BaseSettings):
    """Config class for the application"""
    postgres_user: str
    postgres_password: str
    postgres_host: str
    postgres_port: int = 5432
    postgres_db: str

    # Default admin token
    admin_token: str
    tasker_token: str

    environment: str = Environment.development

    docs_url: str | None = "/docs"
    redoc_url: str | None = "/redoc"
    openapi_url: str | None = "/openapi.json"

    logger_level: str = "INFO"
    logger_name: str = "backend_logger"

    resource_checks_file: Path = base_dir / "data" / "check_templates" / "service_checks.json"
    projects_dir: Path = base_dir / "data" / "projects"
    attachment_dir: Path = base_dir / "data" / "attachments"
    max_file_upload_size: int = 500_000_000
    default_chunk_size: int = 1024

    model_config = SettingsConfigDict(env_file="../.env")

    def configure(self):
        if self.environment == Environment.development:
            self.logger_level = "DEBUG"
        elif self.environment == Environment.production:
            self.logger_level = "INFO"
            self.docs_url = None
            self.redoc_url = None
            self.openapi_url = None


config = Config()
config.configure()
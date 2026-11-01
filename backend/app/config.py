from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory for the project (workspace root is 2 levels up from backend/app)
BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    APP_NAME: str = "NO ENTRY"
    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    SECRET_KEY: str = "no-entry-super-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    DATABASE_URL: str = "sqlite:///./data/no_entry.db"

    AUTOPILOT_ENABLED: bool = True
    EVENT_INTERVAL_MIN: float = 1.0
    EVENT_INTERVAL_MAX: float = 3.5

    # Directory paths
    DATA_DIR: Path = BASE_DIR / "data"
    FRONTEND_DIR: Path = BASE_DIR / "frontend"
    TEMPLATES_DIR: Path = BASE_DIR / "frontend" / "templates"
    STATIC_DIR: Path = BASE_DIR / "frontend" / "static"
    SCENARIOS_DIR: Path = BASE_DIR / "backend" / "app" / "sim" / "scenarios"
    RULES_DIR: Path = BASE_DIR / "backend" / "app" / "rules" / "samples"

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

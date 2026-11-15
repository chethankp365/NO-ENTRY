from pathlib import Path
from typing import Any, List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base directory for the project (workspace root is 2 levels up from backend/app)
BASE_DIR = Path(__file__).resolve().parent.parent.parent

_STRING_DEFAULTS = {
    "APP_NAME": "NO ENTRY",
    "APP_ENV": "development",
    "HOST": "0.0.0.0",
    "SECRET_KEY": "no-entry-super-secret-key-change-in-production",
    "JWT_ALGORITHM": "HS256",
    "DATABASE_URL": "sqlite:///./data/no_entry.db",
    "AI_PROVIDER_PRIORITY": "groq,gemini,openrouter",
}

_NUMERIC_DEFAULTS = {
    "PORT": 8000,
    "ACCESS_TOKEN_EXPIRE_MINUTES": 1440,
    "EVENT_INTERVAL_MIN": 1.0,
    "EVENT_INTERVAL_MAX": 3.5,
    "AI_REQUEST_TIMEOUT_SEC": 20.0,
    "AI_MAX_RETRIES": 1,
    "GHOST_RATE_LIMIT_PER_HOUR": 20,
    "GHOST_VOICE_RATE_LIMIT_PER_HOUR": 30,
    "GHOST_MAX_INPUT_CHARS": 1000,
}


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

    # Multi-provider Ghost AI Mentor configuration (secrets stay empty by default)
    GEMINI_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""
    DEEPGRAM_API_KEY: str = ""
    HF_TOKEN: str = ""

    # Optional model overrides (empty = provider-managed / dynamically discovered)
    GEMINI_MODEL: str = ""
    GROQ_MODEL: str = ""
    OPENROUTER_MODEL: str = ""
    HF_MODEL: str = ""

    DEEPGRAM_STT_MODEL: str = ""
    DEEPGRAM_TTS_MODEL: str = ""

    AI_PROVIDER_PRIORITY: str = "groq,gemini,openrouter"
    AI_REQUEST_TIMEOUT_SEC: float = 20.0
    AI_MAX_RETRIES: int = 1

    GHOST_RATE_LIMIT_PER_HOUR: int = 20
    GHOST_VOICE_RATE_LIMIT_PER_HOUR: int = 30
    GHOST_MAX_INPUT_CHARS: int = 1000

    @field_validator(*_STRING_DEFAULTS.keys(), mode="before")
    @classmethod
    def _fallback_blank_strings(cls, v: Any, info) -> Any:
        if v is None or (isinstance(v, str) and not v.strip()):
            return _STRING_DEFAULTS[info.field_name]
        return v

    @field_validator(*_NUMERIC_DEFAULTS.keys(), mode="before")
    @classmethod
    def _fallback_blank_numbers(cls, v: Any, info) -> Any:
        if v is None or (isinstance(v, str) and not v.strip()):
            return _NUMERIC_DEFAULTS[info.field_name]
        return v

    # Directory paths
    DATA_DIR: Path = BASE_DIR / "data"
    FRONTEND_DIR: Path = BASE_DIR / "frontend"
    TEMPLATES_DIR: Path = BASE_DIR / "frontend" / "templates"
    STATIC_DIR: Path = BASE_DIR / "frontend" / "static"
    SCENARIOS_DIR: Path = BASE_DIR / "backend" / "app" / "sim" / "scenarios"
    RULES_DIR: Path = BASE_DIR / "backend" / "app" / "rules" / "samples"
    MISSIONS_DIR: Path = BASE_DIR / "backend" / "app" / "missions" / "data"

    model_config = SettingsConfigDict(
        env_file=[str(BASE_DIR / ".env"), str(BASE_DIR / "backend" / ".env")],
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def provider_priority_list(self) -> List[str]:
        parts = [p.strip().lower() for p in (self.AI_PROVIDER_PRIORITY or "").split(",")]
        seen = []
        for p in parts:
            if p in ("groq", "gemini", "openrouter") and p not in seen:
                seen.append(p)
        return seen or ["groq", "gemini", "openrouter"]


settings = Settings()

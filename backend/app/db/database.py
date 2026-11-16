from pathlib import Path
from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy import text
from backend.app.config import settings


def normalize_database_url(raw_url: str) -> str:
    """Normalize PostgreSQL URLs to use psycopg v3 driver while preserving SQLite defaults."""
    url = (raw_url or "").strip() or "sqlite:///./data/no_entry.db"
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


DATABASE_URL_NORMALIZED = normalize_database_url(settings.DATABASE_URL)

# Ensure data directory exists for local SQLite and runtime artifacts
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

# Connect args needed for SQLite concurrency; pool_pre_ping for PostgreSQL
is_sqlite = DATABASE_URL_NORMALIZED.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}
engine_kwargs = {"echo": False, "connect_args": connect_args}
if not is_sqlite:
    engine_kwargs["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL_NORMALIZED, **engine_kwargs)


def _ensure_sqlite_columns():
    """Idempotently add newly added User and MissionProgress columns on existing SQLite DBs."""
    if not DATABASE_URL_NORMALIZED.startswith("sqlite"):
        return

    migrations = {
        "user": {
            "ethics_accepted": "BOOLEAN DEFAULT 0",
            "ethics_accepted_at": "DATETIME",
            "streak_days": "INTEGER DEFAULT 3",
            "last_active_date": "TEXT",
            "full_name": "TEXT",
            "email": "TEXT",
            "is_verified": "BOOLEAN DEFAULT 1",
            "verification_token": "TEXT",
            "reset_token": "TEXT",
            "reset_token_expires_at": "DATETIME",
        },
        "missionprogress": {
            "stage": "TEXT DEFAULT 'briefing'",
            "mode": "TEXT DEFAULT 'guided'",
            "track": "TEXT DEFAULT 'purple'",
            "status": "TEXT DEFAULT 'NEW'",
            "current_step_idx": "INTEGER DEFAULT 0",
            "completed_steps_json": "TEXT DEFAULT '[]'",
            "hints_used": "INTEGER DEFAULT 0",
            "hints_unlocked_json": "TEXT DEFAULT '{}'",
            "xp_earned": "INTEGER DEFAULT 0",
            "xp_spent": "INTEGER DEFAULT 0",
            "flag_captured": "BOOLEAN DEFAULT 0",
            "rule_passed": "BOOLEAN DEFAULT 0",
            "rule_yaml": "TEXT",
            "selected_mitre_id": "TEXT",
            "fix_applied": "BOOLEAN DEFAULT 0",
            "fix_choice_id": "TEXT",
            "verified_blocked": "BOOLEAN DEFAULT 0",
            "quiz_passed": "BOOLEAN DEFAULT 0",
            "quiz_score": "INTEGER DEFAULT 0",
            "started_at": "DATETIME",
            "attacker_done_at": "DATETIME",
            "detected_at": "DATETIME",
            "fixed_at": "DATETIME",
            "completed_at": "DATETIME",
            "logs_json": "TEXT DEFAULT '[]'",
        },
    }

    with engine.begin() as conn:
        for table_name, columns in migrations.items():
            rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
            if not rows:
                continue
            existing = {r[1] for r in rows}
            for col_name, col_def in columns.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}"))


def init_db():
    SQLModel.metadata.create_all(engine)
    _ensure_sqlite_columns()

def get_session():
    with Session(engine) as session:
        yield session

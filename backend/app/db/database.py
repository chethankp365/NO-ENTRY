from pathlib import Path
from sqlmodel import SQLModel, create_engine, Session
from backend.app.config import settings

# Ensure data directory exists
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

# Connect args needed for SQLite concurrency
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args=connect_args
)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

import asyncio
import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine, Session

# Add workspace root to sys.path so backend.app is importable
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

# Set test environment
os.environ["APP_ENV"] = "test"
os.environ["AUTOPILOT_ENABLED"] = "false" # Keep test deterministic
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from backend.app.main import app
from backend.app.db.database import get_session
from backend.app.sim.engine import sim_engine

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

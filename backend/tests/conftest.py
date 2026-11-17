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
os.environ["ALLOW_PROCESS_EMULATION"] = "true"

from backend.app.main import app
from backend.app.db.database import get_session
from backend.app.sim.engine import sim_engine


def drain_terminal_until_prompt(websocket):
    """Consume the complete Academy terminal banner and return once its shell prompt is ready."""
    messages = []
    while True:
        message = websocket.receive_json()
        if message.get("type") != "output":
            raise AssertionError(f"Unexpected terminal startup message: {message!r}")
        messages.append(message)
        if "operator@noentry" in message.get("data", "") and "$ " in message.get("data", ""):
            return messages


def execute_terminal_command(websocket, command):
    """Collect all streamed command output and its exit status before the next prompt."""
    websocket.send_json({"type": "command", "command": command})
    output = []
    while True:
        message = websocket.receive_json()
        if message.get("type") == "exit_status":
            exit_code = message["code"]
            break
        if message.get("type") != "output":
            raise AssertionError(f"Unexpected terminal command message: {message!r}")
        output.append(message.get("data", ""))

    prompt = websocket.receive_json()
    if prompt.get("type") != "output":
        raise AssertionError(f"Unexpected terminal prompt message: {prompt!r}")
    output_text = "".join(output)
    if exit_code != 0:
        raise AssertionError(f"Terminal command exited with status {exit_code}: {output_text}")
    return {"data": output_text, "exit_status": exit_code}


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

import backend.app.db.models  # Ensure tables are registered in SQLModel.metadata
from sqlalchemy.pool import StaticPool

@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
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

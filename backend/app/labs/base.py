"""
Base interfaces and data structures for NO ENTRY Practical Lab Runners.
"""

import hashlib
import hmac
import os
import secrets
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, AsyncIterator, Dict, Optional
from pydantic import BaseModel, Field

INTERNAL_LAB_SECRET = os.getenv("NOENTRY_INTERNAL_SECRET", "noentry-internal-auth-seal-key-991204")


def generate_trusted_session_signature(
    session_id: str, operator_id: str, expires_at: int, secret: Optional[str] = None
) -> str:
    """Generate an authoritative cryptographic HMAC signature for lab communications."""
    sec = secret or INTERNAL_LAB_SECRET
    msg = f"{session_id}:{operator_id}:{expires_at}".encode("utf-8")
    return hmac.new(sec.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_trusted_session_signature(
    session_id: str, operator_id: str, expires_at: int, signature: str, secret: Optional[str] = None
) -> bool:
    """Verify cryptographic HMAC signature and ensure timestamp is unexpired."""
    if not signature or not session_id or not operator_id:
        return False
    now_ts = int(time.time())
    if expires_at < now_ts:
        return False
    expected = generate_trusted_session_signature(session_id, operator_id, expires_at, secret)
    return hmac.compare_digest(expected, signature)


class DockerStatus(str, Enum):
    DOCKER_AVAILABLE = "DOCKER_AVAILABLE"
    DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
    DOCKER_STARTING = "DOCKER_STARTING"
    LAB_BUILD_FAILED = "LAB_BUILD_FAILED"
    LAB_START_FAILED = "LAB_START_FAILED"


class DockerRuntimeError(Exception):
    def __init__(self, status: DockerStatus, message: str, guidance: str = ""):
        super().__init__(message)
        self.status = status
        self.message = message
        self.guidance = guidance


class LabSessionInfo(BaseModel):
    session_id: str
    room_id: str
    operator_id: str
    runner_mode: str  # "docker" | "emulated"
    docker_available: bool = False
    docker_status: DockerStatus = DockerStatus.DOCKER_AVAILABLE
    status: str = "STARTING"  # STARTING | RUNNING | STOPPED | EXPIRED | ERROR
    target_url: str
    target_ip: str = "10.10.14.90"
    target_port: int = 8089
    network_id: Optional[str] = None
    attacker_container_id: Optional[str] = None
    target_container_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=60))
    error_message: Optional[str] = None
    guidance: Optional[str] = None
    session_nonce: str = Field(default_factory=lambda: secrets.token_hex(8))
    recorded_actions: Dict[str, Any] = Field(default_factory=dict)

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def generate_verification_token(self, action: str) -> str:
        """Generate an unforgeable, session-bound HMAC verification token for a practical action."""
        msg = f"{self.session_id}:{self.operator_id}:{action.lower()}".encode("utf-8")
        key = self.session_nonce.encode("utf-8")
        digest = hmac.new(key, msg, hashlib.sha256).hexdigest()[:16].upper()
        clean_act = action.replace("action_", "").replace("_verified", "").upper()
        return f"VERIFIED-{clean_act}-{digest}"

    def verify_token(self, action: str, token: str) -> bool:
        """Verify that a given token is the exact HMAC token for this session and action."""
        if not token:
            return False
        expected = self.generate_verification_token(action)
        return hmac.compare_digest(expected.strip().upper(), token.strip().upper())

    def record_action(self, action: str, details: Optional[Dict[str, Any]] = None) -> str:
        act_key = action.lower()
        token = self.generate_verification_token(act_key)
        act_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "token": token,
            "details": details or {},
        }
        self.recorded_actions[act_key] = act_data
        if action != act_key:
            self.recorded_actions[action] = act_data
        return token

    def has_action(self, action: str) -> bool:
        return action.lower() in self.recorded_actions or action in self.recorded_actions

    def get_action_token(self, action: str) -> Optional[str]:
        act = self.recorded_actions.get(action.lower()) or self.recorded_actions.get(action)
        return act.get("token") if act else None

    def client_dict(self) -> Dict[str, Any]:
        remaining_seconds = max(0, int((self.expires_at - datetime.utcnow()).total_seconds()))
        return {
            "session_id": self.session_id,
            "room_id": self.room_id,
            "status": self.status,
            "runner_mode": self.runner_mode,
            "docker_available": self.docker_available,
            "docker_status": self.docker_status.value if isinstance(self.docker_status, DockerStatus) else str(self.docker_status),
            "target_url": self.target_url,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "remaining_seconds": remaining_seconds,
            "expires_at": self.expires_at.isoformat(),
            "error_message": self.error_message,
            "guidance": self.guidance,
        }


class LabRunner(ABC):
    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the runner runtime (e.g. Docker daemon) is present and usable."""
        pass

    @abstractmethod
    async def start_session(
        self, session_id: str, room_id: str, operator_id: str
    ) -> LabSessionInfo:
        """Spin up isolated target and attacker environments."""
        pass

    @abstractmethod
    async def stop_session(self, session_id: str) -> bool:
        """Tear down and destroy isolated resources."""
        pass

    @abstractmethod
    async def reset_session(self, session_id: str) -> LabSessionInfo:
        """Reset target database and state to clean initial condition."""
        pass

    @abstractmethod
    async def execute_command(self, session_id: str, command: str) -> str:
        """Execute a command in the attacker container or shell environment."""
        pass


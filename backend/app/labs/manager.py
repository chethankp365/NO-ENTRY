"""
Lab Session Lifecycle Coordinator for NO ENTRY Academy.
Manages session creation, ownership, Docker detection, fallback selection,
automatic expiration, and database record synchronization.
"""

import asyncio
import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from sqlmodel import Session, select

from backend.app.db.models import LabSessionRecord, User
from backend.app.labs.base import DockerRuntimeError, DockerStatus, LabRunner, LabSessionInfo
from backend.app.labs.docker_runner import DockerLabRunner
from backend.app.labs.process_runner import ProcessLabRunner


class LabSessionManager:
    def __init__(self):
        self._docker_runner = DockerLabRunner()
        self._process_runner = ProcessLabRunner()
        self._active_sessions: Dict[str, LabSessionInfo] = {}

    def get_docker_status(self) -> Tuple[DockerStatus, str, str]:
        """Query Docker daemon status directly."""
        return self._docker_runner.check_docker_status()

    def is_docker_available(self) -> bool:
        """Dynamically verify if Docker daemon is responsive."""
        return self._docker_runner.is_available()

    def _get_runner(self, allow_emulation: bool = False) -> LabRunner:
        d_status, d_msg, d_guidance = self.get_docker_status()
        if d_status == DockerStatus.DOCKER_AVAILABLE:
            return self._docker_runner

        allow_env = os.getenv("ALLOW_PROCESS_EMULATION", "false").lower() in ("true", "1")
        if allow_emulation or allow_env:
            return self._process_runner

        raise DockerRuntimeError(d_status, d_msg, d_guidance)

    async def start_lab(
        self,
        db_session: Session,
        user: User,
        room_id: str,
        allow_emulation: bool = False,
    ) -> LabSessionInfo:
        # Check if user already has an active, non-expired session for this room
        existing_info = self.get_user_session(user.operator_id, room_id)
        if existing_info and not existing_info.is_expired() and existing_info.status == "RUNNING":
            return existing_info

        # Clean up any stale session for this user/room
        await self.stop_lab(db_session, user.operator_id, room_id)

        session_id = f"lab_{user.operator_id}_{room_id}_{uuid.uuid4().hex[:6]}"
        runner = self._get_runner(allow_emulation=allow_emulation)

        info = await runner.start_session(session_id, room_id, user.operator_id)
        self._active_sessions[session_id] = info

        # Persist session record
        db_record = LabSessionRecord(
            session_id=session_id,
            user_id=user.id or 1,
            operator_id=user.operator_id,
            room_id=room_id,
            status=info.status,
            target_url=info.target_url,
            target_ip=info.target_ip,
            target_port=info.target_port,
            runner_mode=info.runner_mode,
            docker_available=info.docker_available,
            network_id=info.network_id,
            attacker_container_id=info.attacker_container_id,
            target_container_id=info.target_container_id,
            created_at=info.created_at,
            expires_at=info.expires_at,
        )
        db_session.add(db_record)
        db_session.commit()

        return info

    async def stop_lab(
        self,
        db_session: Session,
        operator_id: str,
        room_id: str,
    ) -> bool:
        session_info = self.get_user_session(operator_id, room_id)
        if not session_info:
            return False

        session_info.status = "STOPPED"
        runner = self._docker_runner if session_info.runner_mode == "docker" else self._process_runner
        await runner.stop_session(session_info.session_id)
        self._active_sessions.pop(session_info.session_id, None)

        # Update database record
        record = db_session.exec(
            select(LabSessionRecord).where(
                LabSessionRecord.session_id == session_info.session_id
            )
        ).first()
        if record:
            record.status = "STOPPED"
            db_session.add(record)
            db_session.commit()

        return True

    async def reset_lab(
        self,
        db_session: Session,
        operator_id: str,
        room_id: str,
    ) -> LabSessionInfo:
        session_info = self.get_user_session(operator_id, room_id)
        if not session_info:
            user = db_session.exec(
                select(User).where(User.operator_id == operator_id)
            ).first() or User(username=operator_id, operator_id=operator_id, hashed_password="")
            return await self.start_lab(db_session, user, room_id)

        runner = self._docker_runner if session_info.runner_mode == "docker" else self._process_runner
        info = await runner.reset_session(session_info.session_id)
        return info

    def get_user_session(
        self, operator_id: str, room_id: str
    ) -> Optional[LabSessionInfo]:
        for s in list(self._active_sessions.values()):
            if s.operator_id == operator_id and s.room_id == room_id:
                if s.is_expired():
                    s.status = "EXPIRED"
                return s
        # Also check underlying runners for sessions started directly by tests/runners
        for runner in (self._process_runner, self._docker_runner):
            sess_dict = getattr(runner, "_active_sessions", None) or getattr(runner, "_sessions", None)
            if sess_dict:
                for s in list(sess_dict.values()):
                    if s.operator_id == operator_id and s.room_id == room_id:
                        if s.is_expired():
                            s.status = "EXPIRED"
                        return s
        return None

    def record_action(
        self, operator_id: str, room_id: str, action: str, details: Optional[Dict[str, Any]] = None
    ) -> bool:
        s = self.get_user_session(operator_id, room_id)
        if s and s.status == "RUNNING" and not s.is_expired():
            s.record_action(action, details)
            return True
        return False

    def get_session_by_id(self, session_id: str) -> Optional[LabSessionInfo]:
        return self._active_sessions.get(session_id)

    async def execute_in_session(
        self, session_id: str, operator_id: str, command: str
    ) -> str:
        info = self.get_session_by_id(session_id)
        if not info:
            return "[-] Error: Session not found.\n"
        if info.operator_id != operator_id:
            return "[-] Permission denied: You do not own this lab session.\n"
        if info.is_expired():
            return "[-] Error: Lab session has expired. Please restart the lab.\n"

        runner = self._docker_runner if info.runner_mode == "docker" else self._process_runner
        return await runner.execute_command(session_id, command)


lab_manager = LabSessionManager()

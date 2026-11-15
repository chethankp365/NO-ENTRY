"""
Academy Service Layer for NO ENTRY.
Orchestrates track summaries, room details, user progression, and XP rewards.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlmodel import Session, select

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomDefinition, RoomStatus, TrackEnum
from backend.app.db.models import RoomProgress, TaskProgress, User


class AcademyService:
    def get_tracks_summary(self, session: Session, operator_id: str) -> Dict[str, Any]:
        track_counts = curriculum_registry.get_track_counts()
        user_rooms = session.exec(
            select(RoomProgress).where(RoomProgress.operator_id == operator_id)
        ).all()

        completed_by_track = {t.value: 0 for t in TrackEnum}
        in_progress_by_track = {t.value: 0 for t in TrackEnum}
        total_xp_earned = 0

        for up in user_rooms:
            total_xp_earned += up.xp_earned
            if up.status == "COMPLETED":
                completed_by_track[up.track] = completed_by_track.get(up.track, 0) + 1
            elif up.status == "IN_PROGRESS":
                in_progress_by_track[up.track] = in_progress_by_track.get(up.track, 0) + 1

        tracks_data = []
        for t in TrackEnum:
            k = t.value
            tracks_data.append({
                "track": k,
                "title": f"{k.upper()} TEAM ACADEMY" if k != "detection" else "DETECTION ENGINEERING",
                "total_rooms": track_counts[k]["total"],
                "implemented_rooms": track_counts[k]["implemented"],
                "planned_rooms": track_counts[k]["planned"],
                "completed_rooms": completed_by_track.get(k, 0),
                "in_progress_rooms": in_progress_by_track.get(k, 0),
            })

        return {
            "total_rooms": 80,
            "total_implemented": sum(c["implemented"] for c in track_counts.values()),
            "total_completed": sum(completed_by_track.values()),
            "total_xp_earned": total_xp_earned,
            "tracks": tracks_data,
        }

    def list_rooms_for_user(
        self,
        session: Session,
        operator_id: str,
        track: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        track_enum = TrackEnum(track) if track and track in [t.value for t in TrackEnum] else None
        rooms = curriculum_registry.list_rooms(track_enum)

        user_progress_map = {
            rp.room_id: rp
            for rp in session.exec(
                select(RoomProgress).where(RoomProgress.operator_id == operator_id)
            ).all()
        }

        results = []
        for r in rooms:
            item = r.client_summary()
            up = user_progress_map.get(r.room_id)
            if up:
                item["user_status"] = up.status
                item["user_xp"] = up.xp_earned
                completed_tasks = json.loads(up.completed_tasks_json or "[]")
                item["completed_tasks_count"] = len(completed_tasks)
            else:
                item["user_status"] = "NOT_STARTED"
                item["user_xp"] = 0
                item["completed_tasks_count"] = 0
            results.append(item)

        return results

    def get_room_detail_for_user(
        self,
        session: Session,
        operator_id: str,
        room_id: str,
    ) -> Optional[Dict[str, Any]]:
        room = curriculum_registry.get_room(room_id)
        if not room:
            return None

        data = room.client_detail()

        room_prog = session.exec(
            select(RoomProgress).where(
                RoomProgress.operator_id == operator_id,
                RoomProgress.room_id == room_id,
            )
        ).first()

        completed_tasks = []
        if room_prog:
            data["user_status"] = room_prog.status
            data["user_xp"] = room_prog.xp_earned
            completed_tasks = json.loads(room_prog.completed_tasks_json or "[]")
            data["completed_tasks"] = completed_tasks
        else:
            data["user_status"] = "NOT_STARTED"
            data["user_xp"] = 0
            data["completed_tasks"] = []

        # Annotate each task with completion status
        task_progresses = {
            tp.task_id: tp
            for tp in session.exec(
                select(TaskProgress).where(
                    TaskProgress.operator_id == operator_id,
                    TaskProgress.room_id == room_id,
                )
            ).all()
        }

        for t in data["tasks"]:
            tp = task_progresses.get(t["task_id"])
            if tp:
                t["is_completed"] = tp.completed
                t["attempts"] = tp.attempts
                t["earned_xp"] = tp.earned_xp
            else:
                t["is_completed"] = False
                t["attempts"] = 0
                t["earned_xp"] = 0

        return data

    def start_room(self, session: Session, user: User, room_id: str) -> Dict[str, Any]:
        room = curriculum_registry.get_room(room_id)
        if not room:
            raise ValueError(f"Room '{room_id}' not found.")

        room_prog = session.exec(
            select(RoomProgress).where(
                RoomProgress.operator_id == user.operator_id,
                RoomProgress.room_id == room_id,
            )
        ).first()

        if not room_prog:
            room_prog = RoomProgress(
                user_id=user.id or 1,
                operator_id=user.operator_id,
                room_id=room_id,
                track=room.track.value,
                status="IN_PROGRESS",
                current_task_id=room.tasks[0].task_id if room.tasks else None,
                started_at=datetime.utcnow(),
            )
            session.add(room_prog)
            session.commit()
            session.refresh(room_prog)

        return {
            "room_id": room_id,
            "status": room_prog.status,
            "started_at": room_prog.started_at.isoformat() if room_prog.started_at else None,
            "xp_earned": room_prog.xp_earned,
        }


academy_service = AcademyService()


from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    operator_id: str = Field(default="op-0x7f3a", index=True)
    hashed_password: str
    role: str = Field(default="operator") # operator, admin, analyst
    xp: int = Field(default=1240)
    rank: str = Field(default="SCRIPT RUNNER")
    ethics_accepted: bool = Field(default=False)
    ethics_accepted_at: Optional[datetime] = Field(default=None)
    streak_days: int = Field(default=3)
    last_active_date: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class MissionProgress(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    mission_id: str = Field(index=True)
    step: int = Field(default=1)
    completed: bool = Field(default=False)
    score: int = Field(default=0)
    stage: str = Field(default="briefing")
    mode: str = Field(default="guided")
    track: str = Field(default="purple")
    status: str = Field(default="NEW")
    current_step_idx: int = Field(default=0)
    completed_steps_json: str = Field(default="[]")
    hints_used: int = Field(default=0)
    hints_unlocked_json: str = Field(default="{}")
    xp_earned: int = Field(default=0)
    xp_spent: int = Field(default=0)
    flag_captured: bool = Field(default=False)
    rule_passed: bool = Field(default=False)
    rule_yaml: Optional[str] = Field(default=None)
    selected_mitre_id: Optional[str] = Field(default=None)
    fix_applied: bool = Field(default=False)
    fix_choice_id: Optional[str] = Field(default=None)
    verified_blocked: bool = Field(default=False)
    quiz_passed: bool = Field(default=False)
    quiz_score: int = Field(default=0)
    started_at: Optional[datetime] = Field(default=None)
    attacker_done_at: Optional[datetime] = Field(default=None)
    detected_at: Optional[datetime] = Field(default=None)
    fixed_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    logs_json: str = Field(default="[]")
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class Badge(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    badge_key: str = Field(index=True) # e.g. first_blood, rule_writer, honeytoken_catch
    badge_name: str
    description: str
    unlocked_at: datetime = Field(default_factory=datetime.utcnow)

class Report(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    report_type: str # incident, pentest, assessment
    data_json: str # JSON string containing details, timeline, metrics
    created_at: datetime = Field(default_factory=datetime.utcnow)

class EventLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    event_id: str = Field(index=True) # UUID or evt-id
    time: str # "12:04:11"
    technique_id: str = Field(index=True) # T1110
    event: str
    source_ip: str
    target_host: str
    state: str # DETECTED, BLOCKED, ALERT, ISOLATED
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    module: str # Watch, Trap, Reflex, Intel, Red, Shield
    breach: bool = Field(default=False)
    raw_data_json: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class GhostRateLimit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    operator_id: str = Field(index=True)
    operation: str = Field(default="chat", index=True)  # chat, voice_stt, voice_tts
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class RoomProgress(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    operator_id: str = Field(default="op-0x7f3a", index=True)
    room_id: str = Field(index=True)
    track: str = Field(default="red")
    status: str = Field(default="NOT_STARTED")  # NOT_STARTED | IN_PROGRESS | COMPLETED
    current_task_id: Optional[str] = Field(default=None)
    completed_tasks_json: str = Field(default="[]")
    xp_earned: int = Field(default=0)
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TaskProgress(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    operator_id: str = Field(default="op-0x7f3a", index=True)
    room_id: str = Field(index=True)
    task_id: str = Field(index=True)
    completed: bool = Field(default=False)
    attempts: int = Field(default=0)
    earned_xp: int = Field(default=0)
    completed_at: Optional[datetime] = Field(default=None)


class LabSessionRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(index=True, unique=True)
    user_id: int = Field(index=True)
    operator_id: str = Field(default="op-0x7f3a", index=True)
    room_id: str = Field(index=True)
    status: str = Field(default="STARTING")  # STARTING | RUNNING | STOPPED | EXPIRED | ERROR
    target_url: Optional[str] = Field(default=None)
    target_ip: Optional[str] = Field(default="10.10.14.90")
    target_port: Optional[int] = Field(default=8089)
    runner_mode: str = Field(default="emulated")  # docker | emulated
    docker_available: bool = Field(default=False)
    network_id: Optional[str] = Field(default=None)
    attacker_container_id: Optional[str] = Field(default=None)
    target_container_id: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=datetime.utcnow)


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
    created_at: datetime = Field(default_factory=datetime.utcnow)

class MissionProgress(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    mission_id: str = Field(index=True)
    step: int = Field(default=1)
    completed: bool = Field(default=False)
    score: int = Field(default=0)
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

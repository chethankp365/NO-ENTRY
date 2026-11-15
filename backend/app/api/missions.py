"""
REST API router for NO ENTRY Missions, Learning Gamification, and Ethics Gate.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session

from backend.app.db.database import get_session
from backend.app.db.models import User
from backend.app.api.auth import resolve_operator
from backend.app.sim.engine import sim_engine
from backend.app.missions.ethics import (
    EthicsAcceptRequest,
    evaluate_ethics_submission,
    get_ethics_payload,
)
from backend.app.missions.gamification import get_leaderboard_rows
from backend.app.missions.engine import (
    GLOSSARY_ITEMS,
    apply_mission_fix,
    execute_command,
    generate_mission_logs,
    get_user_full_progress,
    grade_mission_quiz,
    list_missions_for_user,
    reset_mission_progress,
    serialize_mission_detail,
    start_mission,
    submit_flag,
    test_mission_rule,
    unlock_hint,
    verify_mission_fix,
)

missions_router = APIRouter(prefix="/api", tags=["missions"])


class MissionStartRequest(BaseModel):
    mode: str = "guided"
    track: str = "purple"


class MissionCommandRequest(BaseModel):
    command: str
    step_idx: Optional[int] = None


class MissionHintRequest(BaseModel):
    level: int = 1
    step_idx: Optional[int] = None


class MissionFlagRequest(BaseModel):
    flag: str


class MissionRuleTestRequest(BaseModel):
    rule_yaml: str
    selected_mitre_id: Optional[str] = None


class MissionFixRequest(BaseModel):
    option_id: Optional[str] = None
    code_patch: Optional[str] = None


class MissionQuizRequest(BaseModel):
    answers: List[int]


@missions_router.get("/missions")
def api_list_missions(
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return list_missions_for_user(session, user)


@missions_router.get("/missions/{mission_id}")
def api_get_mission(
    mission_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return serialize_mission_detail(session, user, mission_id)


@missions_router.post("/missions/{mission_id}/start")
def api_start_mission(
    mission_id: str,
    req: Optional[MissionStartRequest] = None,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    mode = req.mode if req else "guided"
    track = req.track if req else "purple"
    return start_mission(session, user, mission_id, mode=mode, track=track)


@missions_router.post("/missions/{mission_id}/command")
async def api_mission_command(
    mission_id: str,
    req: MissionCommandRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return await execute_command(
        session=session,
        user=user,
        mission_id=mission_id,
        command=req.command,
        step_idx=req.step_idx,
        sim_engine=sim_engine,
    )


@missions_router.post("/missions/{mission_id}/hint")
def api_mission_hint(
    mission_id: str,
    req: MissionHintRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return unlock_hint(session, user, mission_id, level=req.level, step_idx=req.step_idx)


@missions_router.post("/missions/{mission_id}/flag")
def api_mission_flag(
    mission_id: str,
    req: MissionFlagRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return submit_flag(session, user, mission_id, req.flag)


@missions_router.post("/missions/{mission_id}/logs")
def api_mission_logs(
    mission_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return generate_mission_logs(session, user, mission_id)


@missions_router.post("/missions/{mission_id}/rule/test")
def api_mission_rule_test(
    mission_id: str,
    req: MissionRuleTestRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return test_mission_rule(
        session=session,
        user=user,
        mission_id=mission_id,
        rule_yaml=req.rule_yaml,
        selected_mitre_id=req.selected_mitre_id,
    )


@missions_router.post("/missions/{mission_id}/fix")
def api_mission_fix(
    mission_id: str,
    req: MissionFixRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return apply_mission_fix(
        session=session,
        user=user,
        mission_id=mission_id,
        option_id=req.option_id,
        code_patch=req.code_patch,
    )


@missions_router.post("/missions/{mission_id}/verify")
def api_mission_verify(
    mission_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return verify_mission_fix(session, user, mission_id)


@missions_router.post("/missions/{mission_id}/quiz")
def api_mission_quiz(
    mission_id: str,
    req: MissionQuizRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return grade_mission_quiz(session, user, mission_id, answers=req.answers)


@missions_router.post("/missions/{mission_id}/reset")
def api_mission_reset(
    mission_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return reset_mission_progress(session, user, mission_id)


@missions_router.get("/leaderboard")
def api_leaderboard(
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return {
        "entries": get_leaderboard_rows(session, user),
        "current_operator_id": user.operator_id,
    }


@missions_router.get("/me/progress")
def api_me_progress(
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return get_user_full_progress(session, user)


@missions_router.get("/ethics")
def api_get_ethics(
    user: User = Depends(resolve_operator),
):
    return get_ethics_payload(user)


@missions_router.post("/ethics/accept")
def api_accept_ethics(
    req: EthicsAcceptRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    return evaluate_ethics_submission(session, user, req)


@missions_router.get("/learn/glossary")
def api_learn_glossary():
    return {"items": GLOSSARY_ITEMS}


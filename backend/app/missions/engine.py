"""
Mission State Machine, Shell Matcher, Log Generator, Sigma Grader,
Fix Verifier, and Debrief Metrics Engine for NO ENTRY.
"""

from datetime import datetime
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from fastapi import HTTPException
from sqlmodel import Session, select

from backend.app.db.models import MissionProgress, User
from backend.app.rules.engine import RuleEngine
from backend.app.shell.parser import shell_parser
from backend.app.missions.models import (
    MISSION_STAGES,
    MissionDefinition,
    MissionLogEntry,
    MissionStep,
)
from backend.app.missions.loader import list_missions, get_mission
from backend.app.missions.gamification import (
    award_xp,
    compute_rank_info,
    get_user_badges_view,
    grant_badge,
    touch_streak,
)


HINT_COSTS: Dict[int, int] = {1: 25, 2: 50, 3: 100}

GLOSSARY_ITEMS: List[Dict[str, str]] = [
    {
        "tool": "nmap",
        "category": "RECONNAISSANCE",
        "syntax": "nmap -sV <target_ip>",
        "description": "Probe open TCP ports and fingerprint running server versions across hosts in 10.0.0.0/16.",
        "example": "nmap -sV 10.0.1.10",
    },
    {
        "tool": "sqlmap",
        "category": "EXPLOITATION",
        "syntax": "sqlmap -u \"<url>\" --batch",
        "description": "Automatically test dynamic GET/POST parameters for error-based, boolean, and UNION SQL injection.",
        "example": "sqlmap -u \"http://10.0.1.10/api/v1/search?q=test\" --batch",
    },
    {
        "tool": "hydra",
        "category": "CREDENTIAL ACCESS",
        "syntax": "hydra -l <user> -P <wordlist> ssh://<target_ip>",
        "description": "Execute parallel dictionary/password spraying checks against SSH or management login gateways.",
        "example": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1",
    },
    {
        "tool": "Wazuh Queries",
        "category": "DETECTION HUNTING",
        "syntax": "<field>:<value> AND <field>:<value>",
        "description": "Search normalized SIEM telemetry by source IP, target host, MITRE technique ID, or disposition state.",
        "example": "target.host: web01 AND event: sqli",
    },
    {
        "tool": "Sigma Basics",
        "category": "RULE ENGINEERING",
        "syntax": "selection:\n  uri|contains:\n    - \"union select\"\ncondition: selection",
        "description": "Vendor-agnostic YAML rule schema supporting |contains, |startswith, |endswith, |regex, and `not filter` exclusions.",
        "example": "condition: selection and not filter",
    },
]


def _json_load(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def get_or_create_progress(session: Session, user: User, mission_id: str) -> MissionProgress:
    progress = session.exec(
        select(MissionProgress).where(
            MissionProgress.user_id == user.id,
            MissionProgress.mission_id == mission_id,
        )
    ).first()
    if progress:
        return progress

    progress = MissionProgress(
        user_id=user.id,
        mission_id=mission_id,
        stage="briefing",
        status="NEW",
        step=1,
        current_step_idx=0,
    )
    session.add(progress)
    session.commit()
    session.refresh(progress)
    return progress


def _compute_metrics(progress: MissionProgress) -> Dict[str, Optional[float]]:
    ttd: Optional[float] = None
    ttf: Optional[float] = None

    baseline_attack = progress.attacker_done_at or progress.started_at
    if baseline_attack and progress.detected_at:
        diff = (progress.detected_at - baseline_attack).total_seconds()
        ttd = round(max(0.5, diff), 1)

    baseline_fix = progress.detected_at or baseline_attack
    if baseline_fix and progress.fixed_at:
        diff = (progress.fixed_at - baseline_fix).total_seconds()
        ttf = round(max(0.5, diff), 1)

    elapsed: Optional[float] = None
    if progress.started_at:
        end_ref = progress.completed_at or datetime.utcnow()
        elapsed = round(max(0.0, (end_ref - progress.started_at).total_seconds()), 1)

    return {
        "time_to_detect_sec": ttd,
        "time_to_fix_sec": ttf,
        "elapsed_sec": elapsed,
    }


def _stage_percent(progress: MissionProgress, mission: MissionDefinition) -> int:
    if progress.completed:
        return 100
    if not mission.playable:
        return 100 if progress.completed else 0
    if progress.stage not in MISSION_STAGES:
        return 0
    idx = MISSION_STAGES.index(progress.stage)
    return int(round((idx / (len(MISSION_STAGES) - 1)) * 100))


def serialize_progress(progress: MissionProgress, mission: MissionDefinition) -> Dict[str, Any]:
    completed_steps = _json_load(progress.completed_steps_json, [])
    hints_unlocked = _json_load(progress.hints_unlocked_json, {})
    metrics = _compute_metrics(progress)
    return {
        "mission_id": mission.id,
        "stage": progress.stage,
        "stage_index": MISSION_STAGES.index(progress.stage) + 1 if progress.stage in MISSION_STAGES else 1,
        "stages": MISSION_STAGES,
        "mode": progress.mode,
        "track": progress.track,
        "status": "DONE" if progress.completed else progress.status,
        "completed": bool(progress.completed),
        "current_step_idx": progress.current_step_idx,
        "completed_steps": completed_steps,
        "hints_used": progress.hints_used,
        "hints_unlocked": hints_unlocked,
        "xp_earned": progress.xp_earned,
        "xp_spent": progress.xp_spent,
        "flag_captured": bool(progress.flag_captured),
        "rule_passed": bool(progress.rule_passed),
        "fix_applied": bool(progress.fix_applied),
        "verified_blocked": bool(progress.verified_blocked),
        "quiz_passed": bool(progress.quiz_passed),
        "quiz_score": progress.quiz_score,
        "progress_pct": _stage_percent(progress, mission),
        **metrics,
    }


def list_missions_for_user(session: Session, user: User) -> Dict[str, Any]:
    missions = list_missions()
    progress_rows = session.exec(
        select(MissionProgress).where(MissionProgress.user_id == user.id)
    ).all()
    progress_map = {p.mission_id: p for p in progress_rows}

    cards = []
    cleared_count = 0
    for m in missions:
        p = progress_map.get(m.id)
        is_done = bool(p and p.completed)
        if is_done:
            cleared_count += 1
        status = "DONE" if is_done else (p.status if p else "NEW")
        if not user.ethics_accepted and m.playable and status == "NEW":
            display_status = "LOCKED"
        else:
            display_status = status

        cards.append({
            "id": m.id,
            "order": m.order,
            "title": m.title,
            "subtitle": m.subtitle,
            "description": m.description,
            "track": m.track,
            "difficulty": m.difficulty,
            "mitre_ids": m.mitre_ids,
            "xp_reward": m.xp_reward,
            "playable": m.playable,
            "target_host": m.target_host,
            "target_ip": m.target_ip,
            "has_shop_widget": m.has_shop_widget,
            "status": display_status,
            "raw_status": status,
            "stage": p.stage if p else "briefing",
            "completed": is_done,
            "progress_pct": _stage_percent(p, m) if p else 0,
        })

    total = len(missions)
    cleared_pct = int(round((cleared_count / total) * 100)) if total else 0
    return {
        "missions": cards,
        "cleared_count": cleared_count,
        "total_count": total,
        "cleared_pct": cleared_pct,
        "ethics_accepted": bool(user.ethics_accepted),
        "user": compute_rank_info(user.xp),
    }


def serialize_mission_detail(session: Session, user: User, mission_id: str) -> Dict[str, Any]:
    mission = get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail=f"Mission '{mission_id}' not found.")

    progress = get_or_create_progress(session, user, mission_id)
    hints_unlocked = _json_load(progress.hints_unlocked_json, {})
    completed_steps = set(_json_load(progress.completed_steps_json, []))

    safe_steps = []
    for idx, step in enumerate(mission.steps):
        unlocked_levels = hints_unlocked.get(str(idx), {})
        safe_steps.append({
            "id": step.id,
            "order": step.order,
            "title": step.title,
            "goal": step.goal,
            "tool": step.tool,
            "mitre_id": step.mitre_id,
            "sample_hint_command": step.sample_command if progress.mode == "guided" else None,
            "completed": step.id in completed_steps,
            "unlocked_hints": unlocked_levels,
            "hint_costs": HINT_COSTS,
        })

    safe_rule = None
    if mission.rule_challenge:
        safe_rule = {
            "prompt": mission.rule_challenge.prompt,
            "mitre_choices": mission.rule_challenge.mitre_choices,
            "template_yaml": progress.rule_yaml or mission.rule_challenge.template_yaml,
            "required_min_hits": mission.rule_challenge.required_min_hits,
            "max_false_positives": mission.rule_challenge.max_false_positives,
        }

    safe_fix = None
    if mission.fix:
        safe_fix = {
            "prompt": mission.fix.prompt,
            "language": mission.fix.language,
            "vulnerable_code": mission.fix.vulnerable_code,
            "options": [
                {
                    "id": opt.id,
                    "label": opt.label,
                    "code_snippet": opt.code_snippet,
                }
                for opt in mission.fix.options
            ],
            "supports_custom_patch": bool(mission.fix.accepted_patch_patterns),
        }

    safe_quiz = [
        {
            "id": q.id,
            "question": q.question,
            "options": q.options,
        }
        for q in mission.quiz
    ]

    return {
        "mission": {
            "id": mission.id,
            "order": mission.order,
            "title": mission.title,
            "subtitle": mission.subtitle,
            "description": mission.description,
            "track": mission.track,
            "difficulty": mission.difficulty,
            "mitre_ids": mission.mitre_ids,
            "xp_reward": mission.xp_reward,
            "playable": mission.playable,
            "has_shop_widget": mission.has_shop_widget,
            "target_host": mission.target_host,
            "target_ip": mission.target_ip,
            "story": mission.story,
            "scope": mission.scope,
            "briefing_lines": mission.briefing_lines,
            "cinematic_walkthrough": [c.model_dump() for c in mission.cinematic_walkthrough],
            "steps": safe_steps,
            "rule_challenge": safe_rule,
            "fix": safe_fix,
            "verify_preview": {
                "attack_command": mission.verify.attack_command if mission.verify else "",
                "waf_control": mission.verify.waf_control if mission.verify else "",
            } if mission.verify else None,
            "debrief": mission.debrief.model_dump() if mission.debrief else None,
            "quiz": safe_quiz,
        },
        "progress": serialize_progress(progress, mission),
        "ethics_accepted": bool(user.ethics_accepted),
        "user": {
            "operator_id": user.operator_id,
            "streak_days": user.streak_days,
            **compute_rank_info(user.xp),
        },
        "logs": _collect_public_logs(progress, mission),
    }


def _require_mission(mission_id: str) -> MissionDefinition:
    mission = get_mission(mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail=f"Mission '{mission_id}' not found.")
    return mission


def _require_ethics(user: User, mission: MissionDefinition, track: str = "purple"):
    if not user.ethics_accepted and (mission.playable or track in ("attacker", "purple")):
        raise HTTPException(
            status_code=403,
            detail="Ethics gate required. Complete the mandatory ethics module on /docs before launching attack missions.",
        )


def _format_log_dict(entry: MissionLogEntry, index: int) -> Dict[str, Any]:
    return {
        "index": index,
        "timestamp": entry.timestamp or datetime.utcnow().strftime("%H:%M:%S"),
        "source": entry.source,
        "technique_id": entry.technique_id,
        "source_ip": entry.source_ip,
        "target_host": entry.target_host,
        "raw_line": entry.raw_line,
        "structured": {k: v for k, v in entry.structured.items() if k != "benign"},
    }


def _seed_all_attack_logs(mission: MissionDefinition) -> List[Dict[str, Any]]:
    seeded = []
    now_str = datetime.utcnow().strftime("%H:%M:%S")
    for step in mission.steps:
        for entry in step.generated_logs:
            item = entry.model_dump()
            item["timestamp"] = now_str
            seeded.append(item)
    return seeded


def _collect_public_logs(progress: MissionProgress, mission: MissionDefinition) -> List[Dict[str, Any]]:
    stored = _json_load(progress.logs_json, [])
    entries: List[MissionLogEntry] = [MissionLogEntry(**item) for item in stored]
    if mission.rule_challenge:
        entries.extend(mission.rule_challenge.benign_baseline_logs)
    return [_format_log_dict(e, idx) for idx, e in enumerate(entries)]


def start_mission(
    session: Session,
    user: User,
    mission_id: str,
    mode: str = "guided",
    track: str = "purple",
) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    safe_mode = mode if mode in ("guided", "challenge", "free_play") else "guided"
    safe_track = track if track in ("attacker", "defender", "purple") else "purple"
    _require_ethics(user, mission, safe_track)

    progress = get_or_create_progress(session, user, mission_id)
    now = datetime.utcnow()
    if not progress.started_at:
        progress.started_at = now

    progress.mode = safe_mode
    progress.track = safe_track
    progress.status = "DONE" if progress.completed else "IN_PROGRESS"

    if not mission.playable:
        progress.stage = "briefing" if not progress.completed else "debrief"
    elif safe_track == "defender" and not progress.rule_passed:
        if not _json_load(progress.logs_json, []):
            progress.logs_json = json.dumps(_seed_all_attack_logs(mission))
        progress.attacker_done_at = progress.attacker_done_at or now
        progress.flag_captured = True
        progress.stage = "defender"
    elif progress.stage == "briefing":
        progress.stage = "attacker"
        progress.current_step_idx = 0

    progress.updated_at = now
    session.add(progress)
    session.commit()
    session.refresh(progress)

    return {
        "status": "started",
        "mission_id": mission.id,
        "playable": mission.playable,
        "cinematic_walkthrough": [c.model_dump() for c in mission.cinematic_walkthrough],
        "progress": serialize_progress(progress, mission),
        "logs": _collect_public_logs(progress, mission),
    }


async def execute_command(
    session: Session,
    user: User,
    mission_id: str,
    command: str,
    step_idx: Optional[int] = None,
    sim_engine: Any = None,
) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    _require_ethics(user, mission, "attacker")

    if not mission.playable:
        raise HTTPException(status_code=400, detail="Cinematic walkthrough missions do not use interactive commands.")

    cmd = (command or "").strip()
    if not cmd:
        return {"matched": False, "step_completed": False, "output_lines": []}

    progress = get_or_create_progress(session, user, mission_id)
    if not progress.started_at:
        progress.started_at = datetime.utcnow()
    if progress.stage == "briefing":
        progress.stage = "attacker"
    progress.status = "DONE" if progress.completed else "IN_PROGRESS"

    completed_steps: List[str] = _json_load(progress.completed_steps_json, [])
    target_idx = (
        step_idx
        if (progress.mode == "free_play" and step_idx is not None and 0 <= step_idx < len(mission.steps))
        else min(progress.current_step_idx, len(mission.steps) - 1)
    )
    active_step: MissionStep = mission.steps[target_idx]

    matched = any(re.search(pat, cmd, re.IGNORECASE) for pat in active_step.accepted_patterns)

    if matched:
        if active_step.id not in completed_steps:
            completed_steps.append(active_step.id)

        logs_list = _json_load(progress.logs_json, [])
        now_str = datetime.utcnow().strftime("%H:%M:%S")
        existing_raws = {item.get("raw_line") for item in logs_list}
        for log_entry in active_step.generated_logs:
            payload = log_entry.model_dump()
            payload["timestamp"] = now_str
            if payload["raw_line"] not in existing_raws:
                logs_list.append(payload)
                existing_raws.add(payload["raw_line"])

        # Advance to next incomplete step
        next_idx = len(mission.steps)
        for i, st in enumerate(mission.steps):
            if st.id not in completed_steps:
                next_idx = i
                break

        all_steps_done = len(completed_steps) >= len(mission.steps)
        progress.completed_steps_json = json.dumps(completed_steps)
        progress.logs_json = json.dumps(logs_list)
        progress.current_step_idx = len(mission.steps) - 1 if all_steps_done else next_idx
        progress.step = progress.current_step_idx + 1

        if all_steps_done:
            progress.attacker_done_at = progress.attacker_done_at or datetime.utcnow()
            if progress.stage == "attacker":
                progress.stage = "flag"

        progress.updated_at = datetime.utcnow()
        session.add(progress)
        session.commit()
        session.refresh(progress)

        if sim_engine and active_step.sim_event:
            try:
                await sim_engine.emit_event(active_step.sim_event)
            except Exception:
                pass

        return {
            "matched": True,
            "step_completed": True,
            "completed_step_id": active_step.id,
            "mitre_id": active_step.mitre_id,
            "all_steps_done": all_steps_done,
            "output_lines": active_step.expected_output,
            "shop_response": active_step.shop_response,
            "progress": serialize_progress(progress, mission),
        }

    # Unmatched input: provide realistic normal output for shop or shell exploration
    session.add(progress)
    session.commit()

    if cmd.lower().startswith("shop:search"):
        query_term = cmd.split(" ", 1)[1] if " " in cmd else ""
        return {
            "matched": False,
            "step_completed": False,
            "output_lines": [
                f"[VOLTGEAR SHOP] Search query '{query_term}' returned 2 normal catalog items (Mechanical Keyboard RGB, USB-C Hub).",
                f"[HINT] {active_step.wrong_command_hint}",
            ],
            "shop_response": {
                "mode": "search",
                "leaked_rows": [
                    {"id": "101", "name": "Mechanical Keyboard RGB", "detail": "$89.00 // In Stock"},
                    {"id": "104", "name": "USB-C Dock Pro", "detail": "$34.00 // In Stock"},
                ],
                "note": "Normal query executed safely. Try SQLi syntax like `' UNION SELECT 1,username,password_hash FROM admin_users--`.",
            },
            "progress": serialize_progress(progress, mission),
        }

    if cmd.lower().startswith("shop:login"):
        return {
            "matched": False,
            "step_completed": False,
            "output_lines": [
                "[VOLTGEAR LOGIN] Authentication failed: invalid username or password.",
                f"[HINT] {active_step.wrong_command_hint}",
            ],
            "shop_response": {
                "mode": "login",
                "authenticated": False,
                "note": "Normal login rejected. Try SQLi bypass syntax (`admin' OR '1'='1`).",
            },
            "progress": serialize_progress(progress, mission),
        }

    known_prefix = cmd.split()[0].lower()
    if known_prefix in ("help", "?", "clear", "whoami", "id", "ls", "dir", "cat", "pwd", "uname", "status", "scope", "nmap", "sqlmap", "hydra"):
        out = shell_parser.parse_command(cmd)
        if known_prefix not in ("help", "?", "clear", "whoami", "id", "ls", "dir", "cat", "pwd", "uname", "status", "scope"):
            out.append(f"[*] Guidance: {active_step.wrong_command_hint}")
    else:
        out = [
            f"[!] '{cmd}' did not satisfy Step {active_step.order} ({active_step.title}).",
            f"[*] Guidance: {active_step.wrong_command_hint}",
        ]

    return {
        "matched": False,
        "step_completed": False,
        "output_lines": out,
        "hint": active_step.wrong_command_hint,
        "progress": serialize_progress(progress, mission),
    }


def unlock_hint(
    session: Session,
    user: User,
    mission_id: str,
    level: int,
    step_idx: Optional[int] = None,
) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    if level not in HINT_COSTS:
        raise HTTPException(status_code=400, detail="Hint level must be 1 (nudge), 2 (direction), or 3 (answer).")
    if not mission.steps:
        raise HTTPException(status_code=400, detail="This mission does not define interactive step hints.")

    progress = get_or_create_progress(session, user, mission_id)
    target_idx = progress.current_step_idx if step_idx is None else step_idx
    if target_idx < 0 or target_idx >= len(mission.steps):
        target_idx = 0

    step = mission.steps[target_idx]
    hint_text = step.hints[level - 1]
    unlocked_map: Dict[str, Dict[str, str]] = _json_load(progress.hints_unlocked_json, {})
    step_key = str(target_idx)
    lvl_key = str(level)

    if unlocked_map.get(step_key, {}).get(lvl_key):
        return {
            "level": level,
            "step_idx": target_idx,
            "hint_text": hint_text,
            "xp_cost": 0,
            "already_unlocked": True,
            "remaining_xp": user.xp,
            "hints_used": progress.hints_used,
            "progress": serialize_progress(progress, mission),
        }

    cost = HINT_COSTS[level]
    unlocked_map.setdefault(step_key, {})[lvl_key] = hint_text
    progress.hints_unlocked_json = json.dumps(unlocked_map)
    progress.hints_used += 1
    progress.xp_spent += cost
    progress.updated_at = datetime.utcnow()

    xp_res = award_xp(session, user, -cost)
    session.add(progress)
    session.commit()
    session.refresh(progress)

    return {
        "level": level,
        "step_idx": target_idx,
        "hint_text": hint_text,
        "xp_cost": cost,
        "already_unlocked": False,
        "remaining_xp": xp_res["xp"],
        "hints_used": progress.hints_used,
        "progress": serialize_progress(progress, mission),
    }


def submit_flag(session: Session, user: User, mission_id: str, flag_value: str) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    _require_ethics(user, mission, "attacker")
    if not mission.playable:
        raise HTTPException(status_code=400, detail="Cinematic missions do not use flag capture.")

    progress = get_or_create_progress(session, user, mission_id)
    submitted = (flag_value or "").strip()
    if submitted != mission.flag.strip():
        return {
            "correct": False,
            "message": "ACCESS DENIED: Invalid flag. Inspect the command output from your final attack step for NOENTRY{...}.",
            "progress": serialize_progress(progress, mission),
        }

    newly_unlocked = []
    xp_awarded = 0
    if not progress.flag_captured:
        progress.flag_captured = True
        progress.attacker_done_at = progress.attacker_done_at or datetime.utcnow()
        badge = grant_badge(session, user, "first_blood")
        if badge:
            newly_unlocked.append(badge)
        xp_res = award_xp(session, user, 100)
        xp_awarded = 100
        newly_unlocked.extend(xp_res["newly_unlocked_badges"])

    if progress.track == "attacker":
        progress.stage = "debrief"
        progress.completed = True
        progress.status = "DONE"
        progress.completed_at = progress.completed_at or datetime.utcnow()
    elif progress.stage in ("briefing", "attacker", "flag"):
        progress.stage = "side_switch"

    progress.updated_at = datetime.utcnow()
    session.add(progress)
    session.commit()
    session.refresh(progress)

    return {
        "correct": True,
        "flag_captured": True,
        "trigger_side_switch": progress.track != "attacker",
        "xp_awarded": xp_awarded,
        "remaining_xp": user.xp,
        "newly_unlocked_badges": newly_unlocked,
        "message": "FLAG CAPTURED! Switching sides to Blue Team defense...",
        "progress": serialize_progress(progress, mission),
    }


def generate_mission_logs(session: Session, user: User, mission_id: str) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    progress = get_or_create_progress(session, user, mission_id)

    stored = _json_load(progress.logs_json, [])
    if not stored and mission.steps:
        stored = _seed_all_attack_logs(mission)
        progress.logs_json = json.dumps(stored)

    if progress.stage in ("flag", "side_switch"):
        progress.stage = "defender"

    progress.updated_at = datetime.utcnow()
    session.add(progress)
    session.commit()
    session.refresh(progress)

    public_logs = _collect_public_logs(progress, mission)
    return {
        "mission_id": mission.id,
        "logs": public_logs,
        "total_logs": len(public_logs),
        "progress": serialize_progress(progress, mission),
    }


def test_mission_rule(
    session: Session,
    user: User,
    mission_id: str,
    rule_yaml: str,
    selected_mitre_id: Optional[str] = None,
) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    if not mission.rule_challenge:
        raise HTTPException(status_code=400, detail="Mission does not include a rule-authoring phase.")

    progress = get_or_create_progress(session, user, mission_id)
    stored = _json_load(progress.logs_json, [])
    if not stored and mission.steps:
        stored = _seed_all_attack_logs(mission)
        progress.logs_json = json.dumps(stored)

    eval_entries: List[MissionLogEntry] = [MissionLogEntry(**item) for item in stored]
    eval_entries.extend(mission.rule_challenge.benign_baseline_logs)
    tp_indices = [idx for idx, entry in enumerate(eval_entries) if entry.is_true_positive]

    if "REPLACE_WITH_" in (rule_yaml or ""):
        return {
            "valid_yaml": True,
            "rule_fires": False,
            "mitre_correct": False,
            "passed": False,
            "matched_count": 0,
            "matched_indices": [],
            "matched_lines": [],
            "false_positives_count": 0,
            "false_positive_lines": [],
            "total_evaluated": len(eval_entries),
            "grade": "INCOMPLETE TEMPLATE",
            "message": "Replace all REPLACE_WITH_* placeholders in the Sigma YAML template before testing.",
            "newly_unlocked_badges": [],
            "progress": serialize_progress(progress, mission),
        }

    try:
        parsed_rule = RuleEngine.parse_rule_yaml(rule_yaml)
    except Exception as exc:
        return {
            "valid_yaml": False,
            "rule_fires": False,
            "mitre_correct": False,
            "passed": False,
            "matched_count": 0,
            "matched_indices": [],
            "matched_lines": [],
            "false_positives_count": 0,
            "false_positive_lines": [],
            "total_evaluated": len(eval_entries),
            "grade": "YAML SYNTAX ERROR",
            "message": f"Invalid YAML rule: {exc}",
            "newly_unlocked_badges": [],
            "progress": serialize_progress(progress, mission),
        }

    if not parsed_rule.detection or not isinstance(parsed_rule.detection, dict):
        return {
            "valid_yaml": False,
            "rule_fires": False,
            "mitre_correct": False,
            "passed": False,
            "matched_count": 0,
            "matched_indices": [],
            "matched_lines": [],
            "false_positives_count": 0,
            "false_positive_lines": [],
            "total_evaluated": len(eval_entries),
            "grade": "MISSING DETECTION BLOCK",
            "message": "Sigma rule must include a valid `detection:` mapping.",
            "newly_unlocked_badges": [],
            "progress": serialize_progress(progress, mission),
        }

    structured_corpus = [e.structured for e in eval_entries]
    result = RuleEngine.evaluate_rule(parsed_rule, structured_corpus, expected_matches=tp_indices)

    matched_indices = [idx for idx, s in enumerate(structured_corpus) if s in result.matched_lines]
    fp_indices = [idx for idx in matched_indices if idx not in tp_indices]
    fp_raw_lines = [eval_entries[i].raw_line for i in fp_indices]

    chosen_mitre = (selected_mitre_id or mission.rule_challenge.expected_mitre_id).strip().upper()
    mitre_correct = chosen_mitre == mission.rule_challenge.expected_mitre_id.upper()
    rule_fires = result.count >= mission.rule_challenge.required_min_hits
    fp_ok = len(fp_indices) <= mission.rule_challenge.max_false_positives
    passed = rule_fires and fp_ok and mitre_correct

    newly_unlocked = []
    if passed:
        grade = "PASS (A)"
        msg = f"rule fires: yes ({result.count} hits) / false positives: {len(fp_indices)}"
        progress.rule_passed = True
        progress.rule_yaml = rule_yaml
        progress.selected_mitre_id = chosen_mitre
        progress.detected_at = progress.detected_at or datetime.utcnow()
        if progress.stage in ("briefing", "attacker", "flag", "side_switch", "defender"):
            progress.stage = "fix"
        b = grant_badge(session, user, "rule_writer")
        if b:
            newly_unlocked.append(b)
    elif not mitre_correct:
        grade = "WRONG MITRE TECHNIQUE"
        msg = f"Selected technique {chosen_mitre} does not match the observed attack telemetry ({mission.rule_challenge.expected_mitre_id})."
    elif len(fp_indices) > mission.rule_challenge.max_false_positives:
        grade = "FALSE POSITIVES DETECTED"
        msg = f"rule fires: {'yes' if rule_fires else 'no'} / false positives: {len(fp_indices)} (rule matched benign traffic!)"
    else:
        grade = "INSUFFICIENT COVERAGE"
        msg = f"rule fires: no ({result.count}/{mission.rule_challenge.required_min_hits} required attack logs matched) / false positives: {len(fp_indices)}"

    progress.updated_at = datetime.utcnow()
    session.add(progress)
    session.commit()
    session.refresh(progress)

    return {
        "valid_yaml": True,
        "rule_fires": rule_fires,
        "mitre_correct": mitre_correct,
        "expected_mitre_id": mission.rule_challenge.expected_mitre_id,
        "passed": passed,
        "matched_count": result.count,
        "matched_indices": matched_indices,
        "matched_lines": [eval_entries[i].raw_line for i in matched_indices],
        "false_positives_count": len(fp_indices),
        "false_positive_lines": fp_raw_lines,
        "total_evaluated": len(eval_entries),
        "grade": grade,
        "message": msg,
        "newly_unlocked_badges": newly_unlocked,
        "progress": serialize_progress(progress, mission),
    }


def apply_mission_fix(
    session: Session,
    user: User,
    mission_id: str,
    option_id: Optional[str] = None,
    code_patch: Optional[str] = None,
) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    if not mission.fix:
        raise HTTPException(status_code=400, detail="Mission does not define a remediation step.")

    progress = get_or_create_progress(session, user, mission_id)
    applied = False
    explanation = "Select a remediation option or supply a parameterized code fix."
    choice_key = option_id or "custom_patch"

    if option_id:
        selected = next((o for o in mission.fix.options if o.id == option_id), None)
        if not selected:
            raise HTTPException(status_code=404, detail=f"Fix option '{option_id}' not found.")
        applied = selected.is_correct
        explanation = selected.explanation
    elif code_patch is not None:
        patch_text = code_patch.strip()
        applied = any(
            re.search(pat, patch_text, re.DOTALL | re.IGNORECASE)
            for pat in mission.fix.accepted_patch_patterns
        )
        explanation = (
            mission.fix.patch_explanation
            if applied
            else "Submitted snippet still relies on unsafe interpolation or omits the required defensive parameter."
        )

    if applied:
        progress.fix_applied = True
        progress.fix_choice_id = choice_key
        progress.fixed_at = progress.fixed_at or datetime.utcnow()
        if progress.stage in ("briefing", "attacker", "flag", "side_switch", "defender", "fix"):
            progress.stage = "verify"
        progress.updated_at = datetime.utcnow()
        session.add(progress)
        session.commit()
        session.refresh(progress)

    return {
        "applied": applied,
        "option_id": option_id,
        "explanation": explanation,
        "progress": serialize_progress(progress, mission),
    }


def verify_mission_fix(session: Session, user: User, mission_id: str) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    progress = get_or_create_progress(session, user, mission_id)

    if mission.playable and not progress.fix_applied and progress.mode != "free_play":
        return {
            "blocked": False,
            "message": "Apply the remediation patch in Stage 6 (Fix) before verifying defense.",
            "progress": serialize_progress(progress, mission),
        }

    now = datetime.utcnow()
    progress.verified_blocked = True
    progress.stage = "debrief"
    progress.completed = True
    progress.status = "DONE"
    progress.completed_at = progress.completed_at or now
    progress.updated_at = now

    newly_unlocked: List[Dict[str, str]] = []
    xp_awarded = 0
    old_rank = compute_rank_info(user.xp)["rank"]

    if progress.xp_earned == 0:
        multiplier = 1.25 if progress.mode == "challenge" else 1.0
        xp_awarded = int(round(mission.xp_reward * multiplier))
        progress.xp_earned = xp_awarded
        progress.score = xp_awarded
        xp_res = award_xp(session, user, xp_awarded)
        newly_unlocked.extend(xp_res["newly_unlocked_badges"])

    if mission.id == "insider":
        hb = grant_badge(session, user, "honeytoken_catch")
        if hb:
            newly_unlocked.append(hb)

    streak_days = touch_streak(user)
    session.add(user)
    session.add(progress)
    session.commit()
    session.refresh(progress)

    rank_info = compute_rank_info(user.xp)
    return {
        "blocked": True,
        "status_banner": "ATTACK NEUTRALISED",
        "attack_command": mission.verify.attack_command if mission.verify else "",
        "blocked_output": mission.verify.blocked_output if mission.verify else ["[BLOCKED] Walkthrough complete."],
        "blocked_log_line": mission.verify.blocked_log_line if mission.verify else "",
        "waf_control": mission.verify.waf_control if mission.verify else "Reflex SOAR Containment",
        "explanation": mission.verify.explanation if mission.verify else "",
        "xp_awarded": xp_awarded,
        "old_rank": old_rank,
        "new_rank": rank_info["rank"],
        "rank_up": rank_info["rank"] != old_rank,
        "streak_days": streak_days,
        "newly_unlocked_badges": newly_unlocked,
        "debrief": mission.debrief.model_dump() if mission.debrief else None,
        "progress": serialize_progress(progress, mission),
        "user": rank_info,
    }


def grade_mission_quiz(
    session: Session,
    user: User,
    mission_id: str,
    answers: List[int],
) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    if not mission.quiz:
        raise HTTPException(status_code=400, detail="This mission does not define a debrief quiz.")
    if len(answers) != len(mission.quiz):
        raise HTTPException(status_code=400, detail=f"Expected exactly {len(mission.quiz)} quiz answers.")

    progress = get_or_create_progress(session, user, mission_id)
    results = []
    score = 0
    for q, chosen in zip(mission.quiz, answers):
        ok = chosen == q.correct_index
        if ok:
            score += 1
        results.append({
            "id": q.id,
            "correct": ok,
            "correct_index": q.correct_index,
            "chosen_index": chosen,
            "explanation": q.explanation,
        })

    passed = score >= 3
    old_rank = compute_rank_info(user.xp)["rank"]
    newly_unlocked: List[Dict[str, str]] = []
    quiz_bonus_xp = 0

    if passed and not progress.quiz_passed:
        quiz_bonus_xp = 100
        xp_res = award_xp(session, user, quiz_bonus_xp)
        newly_unlocked.extend(xp_res["newly_unlocked_badges"])
        progress.xp_earned += quiz_bonus_xp

    progress.quiz_score = max(progress.quiz_score, score)
    progress.quiz_passed = progress.quiz_passed or passed
    progress.stage = "debrief"
    progress.updated_at = datetime.utcnow()

    session.add(progress)
    session.commit()
    session.refresh(progress)

    rank_info = compute_rank_info(user.xp)
    return {
        "score": score,
        "total": len(mission.quiz),
        "passed": passed,
        "results": results,
        "xp_awarded": quiz_bonus_xp,
        "old_rank": old_rank,
        "new_rank": rank_info["rank"],
        "rank_up": rank_info["rank"] != old_rank,
        "newly_unlocked_badges": newly_unlocked,
        "debrief": mission.debrief.model_dump() if mission.debrief else None,
        "progress": serialize_progress(progress, mission),
        "user": rank_info,
    }


def reset_mission_progress(session: Session, user: User, mission_id: str) -> Dict[str, Any]:
    mission = _require_mission(mission_id)
    progress = get_or_create_progress(session, user, mission_id)

    progress.stage = "briefing"
    progress.status = "NEW"
    progress.step = 1
    progress.current_step_idx = 0
    progress.completed_steps_json = "[]"
    progress.flag_captured = False
    progress.rule_passed = False
    progress.rule_yaml = None
    progress.selected_mitre_id = None
    progress.fix_applied = False
    progress.fix_choice_id = None
    progress.verified_blocked = False
    progress.quiz_passed = False
    progress.quiz_score = 0
    progress.completed = False
    progress.started_at = None
    progress.attacker_done_at = None
    progress.detected_at = None
    progress.fixed_at = None
    progress.completed_at = None
    progress.logs_json = "[]"
    progress.updated_at = datetime.utcnow()

    session.add(progress)
    session.commit()
    session.refresh(progress)

    return {
        "status": "reset",
        "message": f"Snapshot restored for '{mission.title}'. Lab environment is clean.",
        "progress": serialize_progress(progress, mission),
    }


def get_user_full_progress(session: Session, user: User) -> Dict[str, Any]:
    missions_summary = list_missions_for_user(session, user)
    badges = get_user_badges_view(session, user)
    rank_info = compute_rank_info(user.xp)

    return {
        "user": {
            "operator_id": user.operator_id,
            "username": user.username,
            "streak_days": user.streak_days,
            "ethics_accepted": bool(user.ethics_accepted),
            "ethics_accepted_at": user.ethics_accepted_at.isoformat() if user.ethics_accepted_at else None,
            **rank_info,
        },
        "stats": {
            "missions_cleared": missions_summary["cleared_count"],
            "total_missions": missions_summary["total_count"],
            "cleared_pct": missions_summary["cleared_pct"],
            "badges_unlocked": sum(1 for b in badges if b["unlocked"]),
            "badges_total": len(badges),
        },
        "badges": badges,
        "missions": missions_summary["missions"],
    }


"""
GHOST AI Cybersecurity Mentor Service.
Collects isolated lab context (mission state, steps, logs, Sigma evaluation), applies prompt-injection
safety, checks DB rate limits, routes across LLM providers via AIOrchestrator, and gracefully degrades
to mission YAML scripted hints/explanations whenever keys are missing, upstream fails, or rate limit hits.
"""

from datetime import datetime, timedelta
import json
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
import yaml
from sqlmodel import Session, select

from backend.app.config import settings
from backend.app.db.models import GhostRateLimit, MissionProgress, User
from backend.app.missions.loader import get_mission, list_missions
from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomDefinition
from backend.app.missions.models import MissionDefinition
from backend.app.rules.engine import RuleEngine
from backend.app.sim.engine import sim_engine
from backend.app.ai.intent import intent_classifier
from backend.app.ai.orchestrator import AllProvidersUnavailableError, orchestrator
from backend.app.ai.safety import (
    GHOST_SYSTEM_INSTRUCTIONS,
    MAX_RULE_CHARS,
    build_rejection_response,
    detect_prompt_injection,
    format_untrusted_lines,
    neutralize_untrusted_text,
    scrub_secrets,
    validate_learner_input,
)

ACTION_DEFAULT_PROMPTS = {
    "hint": "Give me a concise nudge for my current step without spoiling the final command or flag unless requested.",
    "explain_log": "Explain the security telemetry log line(s) shown in my current lab context in clear beginner-friendly terms.",
    "why_it_worked": "Explain why this attack succeeded on the vulnerable system and how our mitigation blocks it.",
    "review_rule": "Review my Sigma detection rule and the actual rule test results. Tell me what hits, what causes false positives, and how to fix it.",
}

OFFLINE_BADGE = "Ghost offline: scripted hints"


def _count_recent_requests(session: Session, operator_id: str, operation: str, window_hours: int = 1) -> int:
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    rows = session.exec(
        select(GhostRateLimit).where(
            GhostRateLimit.operator_id == operator_id,
            GhostRateLimit.operation == operation,
            GhostRateLimit.created_at >= cutoff,
        )
    ).all()
    return len(rows)


def record_rate_limit_hit(session: Session, operator_id: str, operation: str) -> None:
    session.add(GhostRateLimit(operator_id=operator_id, operation=operation))
    session.commit()


def check_rate_limit(session: Session, operator_id: str, operation: str) -> Tuple[bool, int, int]:
    """Return `(allowed, used_count, limit)` for operator in the rolling 1-hour window."""
    limit = (
        int(settings.GHOST_RATE_LIMIT_PER_HOUR or 20)
        if operation == "chat"
        else int(settings.GHOST_VOICE_RATE_LIMIT_PER_HOUR or 30)
    )
    used = _count_recent_requests(session, operator_id, operation)
    return (used < limit, used, limit)


def _evaluate_sigma_rule_for_context(
    mission: Optional[MissionDefinition],
    progress: Optional[MissionProgress],
    rule_yaml: Optional[str],
    selected_mitre_id: Optional[str],
    client_test_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compute real backend Sigma rule evaluation against the active mission telemetry
    so REVIEW MY RULE always operates on true backend grading data.
    """
    effective_yaml = (rule_yaml or (progress.rule_yaml if progress else "") or "").strip()
    if not effective_yaml and mission and mission.rule_challenge:
        effective_yaml = mission.rule_challenge.template_yaml

    if not mission or not mission.rule_challenge:
        return client_test_result or {"available": False, "note": "No Sigma rule challenge active on this screen."}

    if not effective_yaml:
        return {"available": False, "passed": False, "grade": "NO RULE PROVIDED", "message": "Rule editor is empty."}

    try:
        parsed = yaml.safe_load(effective_yaml)
    except Exception as exc:
        return {
            "available": True,
            "valid_yaml": False,
            "passed": False,
            "grade": "YAML SYNTAX ERROR",
            "message": f"Invalid YAML syntax: {str(exc)[:140]}",
            "matched_count": 0,
            "false_positives_count": 0,
        }

    if not isinstance(parsed, dict) or not isinstance(parsed.get("detection"), dict):
        return {
            "available": True,
            "valid_yaml": True,
            "passed": False,
            "grade": "MISSING DETECTION BLOCK",
            "message": "Sigma rule must include a `detection:` dictionary with `selection` and `condition`.",
            "matched_count": 0,
            "false_positives_count": 0,
        }

    # Build the exact evaluation corpus (attack logs + benign baseline)
    from backend.app.missions.models import MissionLogEntry

    eval_entries: List[MissionLogEntry] = []
    if progress and progress.logs_json:
        try:
            for item in json.loads(progress.logs_json):
                eval_entries.append(MissionLogEntry(**item))
        except Exception:
            pass
    if not eval_entries:
        for step in mission.steps:
            eval_entries.extend(step.generated_logs)

    tp_indices = {i for i, e in enumerate(eval_entries) if e.is_true_positive}
    eval_entries.extend(mission.rule_challenge.benign_baseline_logs)

    corpus = [e.structured for e in eval_entries]
    rule_obj = RuleEngine.parse_rule_yaml(effective_yaml)
    res = RuleEngine.evaluate_rule(rule_obj, corpus, expected_matches=list(tp_indices))
    matched_idx = [i for i, s in enumerate(corpus) if s in res.matched_lines]
    fp_idx = [i for i in matched_idx if i not in tp_indices]
    tp_hits = len([i for i in matched_idx if i in tp_indices])

    chosen_mitre = (
        selected_mitre_id
        or (progress.selected_mitre_id if progress else None)
        or mission.rule_challenge.expected_mitre_id
    ).strip().upper()
    mitre_ok = chosen_mitre == mission.rule_challenge.expected_mitre_id.upper()
    rule_fires = tp_hits >= mission.rule_challenge.required_min_hits
    fp_ok = len(fp_idx) <= mission.rule_challenge.max_false_positives
    passed = rule_fires and fp_ok and mitre_ok

    return {
        "available": True,
        "valid_yaml": True,
        "passed": passed,
        "rule_fires": rule_fires,
        "tp_hits": tp_hits,
        "matched_count": res.count,
        "required_min_hits": mission.rule_challenge.required_min_hits,
        "false_positives_count": len(fp_idx),
        "false_positive_samples": [eval_entries[i].raw_line for i in fp_idx[:2]],
        "selected_mitre_id": chosen_mitre,
        "expected_mitre_id": mission.rule_challenge.expected_mitre_id,
        "mitre_correct": mitre_ok,
        "grade": (
            "PASS (A)"
            if passed
            else "WRONG MITRE"
            if not mitre_ok
            else "FALSE POSITIVES"
            if not fp_ok
            else "INSUFFICIENT COVERAGE"
        ),
    }


def _load_mission_context(
    session: Session,
    user: User,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    mission_id = (payload.get("mission_id") or payload.get("room_id") or "").strip() or None
    mission: Optional[MissionDefinition] = get_mission(mission_id) if mission_id else None
    room: Optional[RoomDefinition] = curriculum_registry.get_room(mission_id) if mission_id and not mission else None
    progress: Optional[MissionProgress] = None
    academy_context: Optional[Dict[str, Any]] = None
    if mission:
        progress = session.exec(
            select(MissionProgress).where(
                MissionProgress.user_id == user.id,
                MissionProgress.mission_id == mission.id,
            )
        ).first()

    stage = (payload.get("stage") or (progress.stage if progress else "") or "").strip()
    step_idx = progress.current_step_idx if progress else 0
    current_step = None
    if mission and mission.steps:
        clamped_idx = max(0, min(step_idx, len(mission.steps) - 1))
        current_step = mission.steps[clamped_idx]
    if room:
        from backend.app.academy.service import academy_service
        from backend.app.labs.manager import lab_manager

        room_detail = academy_service.get_room_detail_for_user(session, user.operator_id, room.room_id)
        room_tasks = room_detail["tasks"] if room_detail else []
        current_task = next(
            (item for item in room_tasks if not item.get("is_completed")),
            room_tasks[-1] if room_tasks else None,
        )
        lab_session = lab_manager.get_user_session(user.operator_id, room.room_id)
        active_lab = (
            lab_session
            if lab_session and lab_session.status == "RUNNING" and lab_session.runner_mode == "docker"
            else None
        )
        lab_status = (
            "EMULATED"
            if lab_session and lab_session.status == "RUNNING" and lab_session.runner_mode != "docker"
            else lab_session.status if lab_session else "STOPPED"
        )
        task_hint = next(
            (task.hint for task in room.tasks if current_task and task.task_id == current_task["task_id"]),
            None,
        )
        target_reference = active_lab.target_ip if active_lab else "<target-ip>"
        task_context = dict(current_task) if current_task else None
        if task_context:
            for key in ("instructions", "hint"):
                if isinstance(task_context.get(key), str):
                    task_context[key] = task_context[key].replace("10.10.14.90", target_reference)
        if task_hint:
            task_hint = task_hint.replace("10.10.14.90", target_reference)
        academy_context = {
            "task": task_context,
            "task_hint": task_hint,
            "completed_tasks": [item["task_id"] for item in room_tasks if item.get("is_completed")],
            "lab_status": lab_status,
            "target_ip": active_lab.target_ip if active_lab else None,
            "target_port": active_lab.target_port if active_lab else None,
            "required_tools": room.required_practical_skills,
            "assessment_criteria": room.assessment_criteria,
        }

    # Collect simulated logs (caller selection -> DB mission logs -> step generated logs -> recent SOC stream)
    logs: List[str] = [str(l) for l in (payload.get("logs") or []) if str(l).strip()]
    if not logs and progress and progress.logs_json:
        try:
            logs = [item.get("raw_line", "") for item in json.loads(progress.logs_json) if item.get("raw_line")]
        except Exception:
            logs = []
    if not logs and mission and mission.steps:
        for s in mission.steps:
            logs.extend([lg.raw_line for lg in s.generated_logs])
    if not logs:
        recent_evts = list(getattr(sim_engine, "recent_events", []) or [])[-6:]
        logs = [
            f"[{e.get('time') if isinstance(e, dict) else getattr(e, 'time', '')}] "
            f"{e.get('technique_id') if isinstance(e, dict) else getattr(e, 'technique_id', '')} "
            f"host={e.get('target_host') if isinstance(e, dict) else getattr(e, 'target_host', '')} "
            f"ip={e.get('source_ip') if isinstance(e, dict) else getattr(e, 'source_ip', '')} -> "
            f"{e.get('event') if isinstance(e, dict) else getattr(e, 'event', '')}"
            for e in recent_evts
        ]

    rule_yaml = (payload.get("rule_yaml") or (progress.rule_yaml if progress else "") or "").strip()
    if rule_yaml:
        rule_yaml = rule_yaml[:MAX_RULE_CHARS]

    rule_eval = _evaluate_sigma_rule_for_context(
        mission=mission,
        progress=progress,
        rule_yaml=rule_yaml,
        selected_mitre_id=payload.get("selected_mitre_id"),
        client_test_result=payload.get("rule_test_result"),
    )

    return {
        "mission": mission,
        "room": room,
        "academy_context": academy_context,
        "progress": progress,
        "stage": stage or "command_center",
        "screen": (payload.get("screen") or ("academy" if room else "")).strip(),
        "current_step": current_step,
        "logs": logs[:10],
        "terminal_output": [str(t) for t in (payload.get("terminal_output") or [])][-10:],
        "rule_yaml": rule_yaml,
        "rule_eval": rule_eval,
    }


def _build_user_prompt(
    message: str,
    action: str,
    intent: str,
    ctx: Dict[str, Any],
) -> str:
    mission: Optional[MissionDefinition] = ctx["mission"]
    room: Optional[RoomDefinition] = ctx["room"]
    academy: Optional[Dict[str, Any]] = ctx.get("academy_context")
    step = ctx["current_step"]
    rule_eval = ctx["rule_eval"]

    mission_header = (
        f"{mission.id} ({mission.title}) | Stage: {ctx['stage']} | Target: {mission.target_host} ({mission.target_ip}) | Scope: {mission.scope}"
        if mission
        else f"Command Center / Lab Screen: {ctx['screen'] or ctx['stage']} | Scope: Isolated 10.0.0.0/16 cyber range"
    )

    step_block = "(No active mission step)"
    hints_block = "(None)"
    if step:
        step_block = f"Step {step.order}: {step.title} | Tool: {step.tool} | MITRE: {step.mitre_id} | Goal: {step.goal}"
        # Provide nudge and direction hints ONLY (avoid spoiling full answer automatically)
        safe_hints = step.hints[:2] if action != "answer" else step.hints
        hints_block = " / ".join(safe_hints)

    academy_block = "(No academy room active)"
    if room and academy:
        active_task = academy["task"]
        task_block = (
            f"{active_task['title']}: {active_task['instructions']} "
            f"Completed: {active_task.get('is_completed', False)}. "
            f"Task hint: {academy['task_hint'] or '(none supplied)'}"
            if active_task
            else "No curriculum tasks are defined."
        )
        academy_block = (
            f"Room: {room.title} ({room.room_id}) | Track: {room.track.value} | "
            f"Lab: {academy['lab_status']} | Actual target: "
            f"{academy['target_ip']}:{academy['target_port']}"
            if academy["target_ip"]
            else f"Room: {room.title} ({room.room_id}) | Lab: STOPPED | No target address is assigned."
        ) + f"\nTask: {task_block}\nTools: {', '.join(academy['required_tools']) or '(none listed)'}"
    academy_block = neutralize_untrusted_text(academy_block, max_len=2200)

    rule_block = neutralize_untrusted_text(ctx["rule_yaml"] or "(none submitted yet)", max_len=1500)
    rule_eval_block = json.dumps(rule_eval, ensure_ascii=True)
    term_block = format_untrusted_lines(ctx["terminal_output"], limit=8)
    logs_block = format_untrusted_lines(ctx["logs"], limit=6)
    learner_text = neutralize_untrusted_text(message, max_len=1000)

    return f"""ACTION: {action} | CLASSIFIED_INTENT: {intent}
MISSION_CONTEXT: {mission_header}
CURRENT_STEP: {step_block}
MISSION_NUDGE_HINTS: {hints_block}
ACADEMY_ROOM_CONTEXT: {academy_block}
BACKEND_RULE_EVALUATION: {rule_eval_block}

<UNTRUSTED_TELEMETRY>
TERMINAL_OUTPUT:
{term_block}

SECURITY_LOGS:
{logs_block}

LEARNER_SIGMA_RULE:
{rule_block}
</UNTRUSTED_TELEMETRY>

<UNTRUSTED_LEARNER_INPUT>
{learner_text}
</UNTRUSTED_LEARNER_INPUT>"""


def build_scripted_response(action: str, intent: str, message: str, ctx: Dict[str, Any]) -> str:
    """Produce honest, YAML-backed offline guidance when LLMs are unconfigured/unavailable/rate-limited."""
    mission: Optional[MissionDefinition] = ctx["mission"]
    step = ctx["current_step"]
    stage = ctx["stage"]
    effective = action if action in ("hint", "explain_log", "why_it_worked", "review_rule") else intent

    if effective == "review_rule" and ctx["rule_eval"].get("available"):
        reval = ctx["rule_eval"]
        if not reval.get("valid_yaml", True):
            return f"[SCRIPTED REVIEW] YAML error: {reval.get('message')} Fix indentation (2 spaces, no tabs) before testing again."
        if reval.get("passed"):
            return (
                f"[SCRIPTED REVIEW] Grade {reval['grade']}: rule matches {reval['matched_count']} attack events with "
                "0 false positives and the correct MITRE ID. Ready to advance to Stage 6 (Fix)."
            )
        notes = [
            f"[SCRIPTED REVIEW] Grade {reval.get('grade')}:",
            f"- Attack hits: {reval.get('tp_hits', 0)}/{reval.get('required_min_hits', 1)} required.",
            f"- False positives on benign traffic: {reval.get('false_positives_count', 0)}.",
        ]
        if not reval.get("mitre_correct", True):
            notes.append(f"- Select MITRE {reval.get('expected_mitre_id')} instead of {reval.get('selected_mitre_id')}.")
        elif reval.get("false_positives_count", 0) > 0:
            notes.append("- Add a `filter` exclusion (`condition: selection and not filter`) so routine baseline requests stay ignored.")
        else:
            notes.append("- Inspect the exact URI/message tokens in your attack logs and replace placeholder substrings.")
        return " ".join(notes)

    if effective == "why_it_worked" and mission and mission.debrief:
        return f"[SCRIPTED DEBRIEF] Why it worked: {mission.debrief.why_it_worked} How it stops: {mission.debrief.how_it_was_stopped}"

    if effective == "explain_log":
        logs = ctx["logs"]
        sample = logs[-1] if logs else "No log lines selected yet."
        mitre = ", ".join(mission.mitre_ids) if mission else "T1190 / T1110"
        return (
            f"[SCRIPTED LOG ANALYSIS] Latest telemetry (`{mitre}`): `{sample[:160]}`. "
            "Check the source IP (`185.220.x.x` external vs `10.0.x.x` internal), targeted path/account, and response status to spot anomalous activity."
        )

    if step:
        nudge = step.hints[0] if step.hints else step.goal
        return f"[SCRIPTED HINT // {mission.title if mission else ''} Step {step.order} ({step.tool})] {nudge}"

    if mission and mission.debrief:
        return f"[SCRIPTED BRIEFING // {mission.title}] {mission.story[:220]}"

    room: Optional[RoomDefinition] = ctx.get("room")
    academy: Optional[Dict[str, Any]] = ctx.get("academy_context")
    if room and academy:
        task = academy["task"]
        if task:
            if not academy["target_ip"]:
                return (
                    f"[SCRIPTED ACADEMY MENTOR // {room.title}] Start the lab to receive a real target address. "
                    f"Your current task is “{task['title']}”: {task['instructions']}"
                )
            hint = academy["task_hint"] or "Use the task instructions to plan your investigation."
            return (
                f"[SCRIPTED ACADEMY MENTOR // {room.title}] Current task: {task['title']}. "
                f"{task['instructions']} Tools: {', '.join(academy['required_tools']) or 'see room instructions'}. "
                f"Task guidance: {hint}"
            )
    if room and room.concept:
        if effective == "hint":
            task_hint = room.tasks[0].hint if room.tasks and room.tasks[0].hint else "Inspect how the application concatenates parameters into dynamic queries."
            return f"[SCRIPTED ACADEMY MENTOR // {room.title}] {task_hint}"
        return (
            f"[SCRIPTED ACADEMY MENTOR // {room.title}] {room.concept.technical_definition[:220]} "
            f"Analogy: {room.concept.simple_analogy[:180]}"
        )

    # Command Center / general screen fallback
    available = ", ".join(m.id for m in list_missions()[:3])
    return (
        f"[SCRIPTED SOC MENTOR] You are on `{ctx['screen'] or stage}` inside the isolated 10.0.0.0/16 range. "
        f"Check live SIEM logs on Watch, deploy playbooks on Reflex, or train attack->defend missions ({available}) on /missions."
    )


class GhostMentorService:
    def get_status(self, session: Session, operator_id: str) -> Dict[str, Any]:
        orch = orchestrator.get_status()
        allowed_chat, used_chat, limit_chat = check_rate_limit(session, operator_id, "chat")
        allowed_voice, used_voice, limit_voice = check_rate_limit(session, operator_id, "voice_stt")
        return {
            "ai_online": orch["ai_online"],
            "status_label": (
                f"Ghost online ({orch['priority'][0].upper()})"
                if orch["ai_online"]
                else OFFLINE_BADGE
            ),
            "offline_badge": OFFLINE_BADGE,
            "priority": orch["priority"],
            "providers": orch["providers"],
            "voice": voice_status_summary(),
            "intent": intent_classifier.get_status(),
            "local_inference": orch["local_inference"],
            "rate_limit": {
                "chat_limit_per_hour": limit_chat,
                "chat_used": used_chat,
                "chat_remaining": max(0, limit_chat - used_chat),
                "chat_limited": not allowed_chat,
                "voice_limit_per_hour": limit_voice,
                "voice_remaining": max(0, limit_voice - used_voice),
            },
        }

    async def stream_mentor_reply(
        self,
        session: Session,
        user: User,
        payload: Dict[str, Any],
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Yields structured event dicts (`meta`, `token`, `done`) cleanly without ever exposing secrets.
        Falls back to mission YAML scripted hints on missing keys, provider failure, timeout, or rate limit.
        """
        action = (payload.get("action") or "auto").strip().lower()
        raw_message = payload.get("message") or ""
        allow_empty = action in ACTION_DEFAULT_PROMPTS

        validated_msg = validate_learner_input(raw_message, allow_empty=allow_empty)
        if not validated_msg and allow_empty:
            validated_msg = ACTION_DEFAULT_PROMPTS[action]

        ctx = _load_mission_context(session, user, payload)
        mission_title = ctx["mission"].title if ctx["mission"] else "NO ENTRY Range"

        # 1. Prompt-injection / out-of-scope check
        injection_reason = detect_prompt_injection(validated_msg)
        if injection_reason:
            rejection = build_rejection_response(mission_title)
            yield {
                "type": "meta",
                "provider": "safety_guard",
                "model": "policy-filter",
                "ai_generated": False,
                "intent": "blocked",
                "status_label": "Safety guard active",
                "rate_limited": False,
            }
            yield {"type": "token", "text": rejection}
            yield {
                "type": "done",
                "provider": "safety_guard",
                "model": "policy-filter",
                "ai_generated": False,
                "intent": "blocked",
                "full_text": rejection,
                "status_label": "Safety guard active",
                "rate_limited": False,
            }
            return

        # 2. Optional intent classification (explicit quick actions stay authoritative)
        resolved_intent, intent_source = await intent_classifier.classify(
            validated_msg, explicit_action=action, stage=ctx["stage"]
        )

        # 3. Rate limiting check (20 requests / hour per user)
        allowed, used, limit = check_rate_limit(session, user.operator_id, "chat")
        if not allowed:
            scripted = build_scripted_response(action, resolved_intent, validated_msg, ctx)
            msg_with_note = f"[RATE LIMIT {used}/{limit}/hr] {scripted}"
            yield {
                "type": "meta",
                "provider": "scripted",
                "model": "mission-yaml-fallback",
                "ai_generated": False,
                "intent": resolved_intent,
                "intent_source": intent_source,
                "status_label": OFFLINE_BADGE,
                "rate_limited": True,
                "remaining": 0,
                "fallback_reason": "rate_limit_exceeded",
            }
            yield {"type": "token", "text": msg_with_note}
            yield {
                "type": "done",
                "provider": "scripted",
                "model": "mission-yaml-fallback",
                "ai_generated": False,
                "intent": resolved_intent,
                "full_text": msg_with_note,
                "status_label": OFFLINE_BADGE,
                "rate_limited": True,
                "remaining": 0,
                "fallback_reason": "rate_limit_exceeded",
            }
            return

        # Record chat usage in DB
        record_rate_limit_hit(session, user.operator_id, "chat")
        remaining = max(0, limit - (used + 1))

        # 4. Stream via multi-provider orchestrator, falling back cleanly if unavailable/failing
        user_prompt = _build_user_prompt(validated_msg, action, resolved_intent, ctx)
        full_chunks: List[str] = []
        active_provider: Optional[str] = None
        active_model: Optional[str] = None
        meta_sent = False

        try:
            async for prov, model, token in orchestrator.stream_with_fallback(
                system_prompt=GHOST_SYSTEM_INSTRUCTIONS,
                user_prompt=user_prompt,
            ):
                safe_tok = scrub_secrets(token)
                if not meta_sent:
                    active_provider = prov
                    active_model = model
                    meta_sent = True
                    yield {
                        "type": "meta",
                        "provider": prov,
                        "model": model,
                        "ai_generated": True,
                        "intent": resolved_intent,
                        "intent_source": intent_source,
                        "status_label": f"Ghost online ({prov.upper()} // {model})",
                        "rate_limited": False,
                        "remaining": remaining,
                    }
                full_chunks.append(safe_tok)
                yield {"type": "token", "text": safe_tok}

            if meta_sent:
                yield {
                    "type": "done",
                    "provider": active_provider,
                    "model": active_model,
                    "ai_generated": True,
                    "intent": resolved_intent,
                    "full_text": "".join(full_chunks),
                    "status_label": f"Ghost online ({active_provider.upper()} // {active_model})",
                    "rate_limited": False,
                    "remaining": remaining,
                }
                return
        except AllProvidersUnavailableError as exc:
            fallback_reason = scrub_secrets(exc.reason)
        except Exception as exc:
            fallback_reason = scrub_secrets(str(exc))

        # 5. Deterministic scripted fallback (clearly flagged, never faked as LLM)
        scripted_text = build_scripted_response(action, resolved_intent, validated_msg, ctx)
        yield {
            "type": "meta",
            "provider": "scripted",
            "model": "mission-yaml-fallback",
            "ai_generated": False,
            "intent": resolved_intent,
            "intent_source": intent_source,
            "status_label": OFFLINE_BADGE,
            "rate_limited": False,
            "remaining": remaining,
            "fallback_reason": fallback_reason,
        }
        yield {"type": "token", "text": scripted_text}
        yield {
            "type": "done",
            "provider": "scripted",
            "model": "mission-yaml-fallback",
            "ai_generated": False,
            "intent": resolved_intent,
            "full_text": scripted_text,
            "status_label": OFFLINE_BADGE,
            "rate_limited": False,
            "remaining": remaining,
            "fallback_reason": fallback_reason,
        }


def voice_status_summary() -> Dict[str, Any]:
    from backend.app.ai.voice import voice_service
    return voice_service.get_status()


ghost_service = GhostMentorService()

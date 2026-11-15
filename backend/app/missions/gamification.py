"""
Python-driven gamification engine: XP, ranks, badges, streaks, and leaderboard.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlmodel import Session, select

from backend.app.db.models import Badge, MissionProgress, User


RANK_TIERS: List[Tuple[int, str]] = [
    (0, "SCRIPT RUNNER"),
    (2000, "PACKET HUNTER"),
    (3500, "SHADOW OPERATOR"),
    (4500, "GHOST"),
]

BADGE_CATALOG: List[Dict[str, str]] = [
    {
        "key": "first_blood",
        "name": "First blood",
        "description": "Captured your first flag inside an active offensive mission.",
        "icon": "FLAG",
    },
    {
        "key": "rule_writer",
        "name": "Rule writer",
        "description": "Authored a zero-false-positive Sigma detection rule from live attack logs.",
        "icon": "RULE",
    },
    {
        "key": "honeytoken_catch",
        "name": "Honeytoken catch",
        "description": "Detected and contained the malicious insider via deception telemetry.",
        "icon": "TRAP",
    },
    {
        "key": "ghost",
        "name": "Ghost",
        "description": "Ascended to GHOST rank (4,500+ XP) across red and blue operations.",
        "icon": "GHOST",
    },
]

SEEDED_LEADERBOARD = [
    {"operator_id": "op-ghost", "xp": 4820, "rank": "GHOST", "missions_cleared": 5, "streak_days": 14, "is_you": False},
    {"operator_id": "op-nyx", "xp": 3990, "rank": "SHADOW OPERATOR", "missions_cleared": 4, "streak_days": 9, "is_you": False},
    {"operator_id": "op-cipher", "xp": 2640, "rank": "PACKET HUNTER", "missions_cleared": 3, "streak_days": 5, "is_you": False},
    {"operator_id": "op-kestrel", "xp": 1820, "rank": "SCRIPT RUNNER", "missions_cleared": 2, "streak_days": 4, "is_you": False},
]


def compute_rank_info(xp: int) -> Dict[str, Any]:
    """Compute current rank, next rank target, and bar progress percentage."""
    safe_xp = max(0, int(xp or 0))
    current_idx = 0
    for idx, (threshold, _) in enumerate(RANK_TIERS):
        if safe_xp >= threshold:
            current_idx = idx

    current_threshold, current_rank = RANK_TIERS[current_idx]
    if current_idx + 1 < len(RANK_TIERS):
        next_threshold, next_rank = RANK_TIERS[current_idx + 1]
        span = max(1, next_threshold - current_threshold)
        progress_in_tier = safe_xp - current_threshold
        progress_pct = round(min(100.0, max(0.0, (safe_xp / next_threshold) * 100.0)), 1)
        tier_pct = round(min(100.0, max(0.0, (progress_in_tier / span) * 100.0)), 1)
        xp_to_next = max(0, next_threshold - safe_xp)
    else:
        next_threshold = current_threshold
        next_rank = "MAX RANK"
        progress_pct = 100.0
        tier_pct = 100.0
        xp_to_next = 0

    return {
        "xp": safe_xp,
        "rank": current_rank,
        "current_threshold": current_threshold,
        "next_rank": next_rank,
        "next_threshold": next_threshold,
        "xp_to_next": xp_to_next,
        "progress_pct": progress_pct,
        "tier_pct": tier_pct,
        "tiers": [{"threshold": t, "rank": r} for t, r in RANK_TIERS],
    }


def grant_badge(session: Session, user: User, badge_key: str) -> Optional[Dict[str, str]]:
    """Unlock a badge if not already unlocked for this user. Returns unlocked info or None."""
    spec = next((b for b in BADGE_CATALOG if b["key"] == badge_key), None)
    if not spec:
        return None

    existing = session.exec(
        select(Badge).where(Badge.user_id == user.id, Badge.badge_key == badge_key)
    ).first()
    if existing:
        return None

    badge = Badge(
        user_id=user.id,
        badge_key=spec["key"],
        badge_name=spec["name"],
        description=spec["description"],
    )
    session.add(badge)
    return dict(spec)


def award_xp(session: Session, user: User, delta: int) -> Dict[str, Any]:
    """Adjust user XP cleanly, recompute rank, and unlock rank badges if crossed."""
    old_rank = compute_rank_info(user.xp)["rank"]
    user.xp = max(0, user.xp + delta)
    new_info = compute_rank_info(user.xp)
    user.rank = new_info["rank"]

    newly_unlocked: List[Dict[str, str]] = []
    if user.xp >= 4500:
        b = grant_badge(session, user, "ghost")
        if b:
            newly_unlocked.append(b)

    session.add(user)
    return {
        "old_rank": old_rank,
        "new_rank": user.rank,
        "rank_up": new_info["rank"] != old_rank and delta > 0,
        "xp": user.xp,
        "delta": delta,
        "rank_info": new_info,
        "newly_unlocked_badges": newly_unlocked,
    }


def touch_streak(user: User) -> int:
    """Update daily operator streak deterministically based on UTC date."""
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    yesterday_str = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")

    if user.last_active_date == today_str:
        return user.streak_days
    elif user.last_active_date == yesterday_str:
        user.streak_days = max(1, user.streak_days + 1)
    else:
        user.streak_days = max(user.streak_days or 1, 1)
    user.last_active_date = today_str
    return user.streak_days


def get_user_badges_view(session: Session, user: User) -> List[Dict[str, Any]]:
    """Return full badge catalog annotated with unlocked state and timestamps."""
    unlocked_rows = session.exec(select(Badge).where(Badge.user_id == user.id)).all()
    unlocked_map = {b.badge_key: b for b in unlocked_rows}

    result = []
    for spec in BADGE_CATALOG:
        row = unlocked_map.get(spec["key"])
        result.append({
            **spec,
            "unlocked": row is not None,
            "unlocked_at": row.unlocked_at.isoformat() if row else None,
        })
    return result


def get_leaderboard_rows(session: Session, current_user: User) -> List[Dict[str, Any]]:
    """Combine live DB operators with seeded rivals and return ranked entries."""
    db_users = session.exec(select(User)).all()
    entries_by_op: Dict[str, Dict[str, Any]] = {
        entry["operator_id"]: dict(entry) for entry in SEEDED_LEADERBOARD
    }

    for u in db_users:
        cleared = session.exec(
            select(MissionProgress).where(
                MissionProgress.user_id == u.id,
                MissionProgress.completed == True,
            )
        ).all()
        entries_by_op[u.operator_id] = {
            "operator_id": u.operator_id,
            "xp": u.xp,
            "rank": compute_rank_info(u.xp)["rank"],
            "missions_cleared": len(cleared),
            "streak_days": u.streak_days,
            "is_you": u.id == current_user.id,
        }

    ranked = sorted(entries_by_op.values(), key=lambda x: (-x["xp"], x["operator_id"]))
    for idx, row in enumerate(ranked, start=1):
        row["position"] = idx
    return ranked


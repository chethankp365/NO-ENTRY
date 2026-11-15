"""
Mandatory Ethics & Safe Range Gate for NO ENTRY.
Learners must accept range isolation scope and pass a 3-question ethics check
before launching any interactive attack mission.
"""

from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel
from sqlmodel import Session

from backend.app.db.models import User


ETHICS_QUESTIONS: List[Dict[str, Any]] = [
    {
        "id": "eth-1",
        "question": "Where are NO ENTRY offensive commands and scenarios permitted to execute?",
        "options": [
            "Strictly inside the isolated simulated cyber range (10.0.0.0/16) and never against external targets",
            "Against any public website that lacks a security.txt file",
            "Against employer or school Wi-Fi networks without prior written notice",
            "Anywhere as long as you use a VPN",
        ],
        "correct_index": 0,
        "explanation": "Unauthorized scanning or exploitation outside an explicitly authorized or isolated lab is illegal and violates NO ENTRY safety policy.",
    },
    {
        "id": "eth-2",
        "question": "What should you do when you discover a real vulnerability in an external production service?",
        "options": [
            "Dump its user database to prove impact",
            "Do not test or exploit it without permission; follow coordinated vulnerability disclosure via authorized channels",
            "Post the exploit payload publicly on social media immediately",
            "Upload a web shell so you can inspect internal configuration files",
        ],
        "correct_index": 1,
        "explanation": "Responsible security engineering relies on written authorization and coordinated disclosure, never unauthorized data access.",
    },
    {
        "id": "eth-3",
        "question": "What is the primary engineering purpose of practicing offensive techniques inside NO ENTRY?",
        "options": [
            "Collecting credentials from third-party e-commerce stores",
            "Bypassing corporate monitoring so red team actions stay hidden forever",
            "Understanding attacker tradecraft in order to detect, block, patch, and verify resilient defenses",
            "Generating real denial-of-service floods against internet hosts",
        ],
        "correct_index": 2,
        "explanation": "Every mission closes the loop: attack, read the telemetry it produces, author a zero-FP detection rule, fix the root cause, and verify.",
    },
]


class EthicsAcceptRequest(BaseModel):
    checkbox_agreed: bool
    answers: List[int]


def get_ethics_payload(user: User) -> Dict[str, Any]:
    """Return mandatory ethics rules and 3-question quiz without revealing answer keys."""
    return {
        "accepted": bool(user.ethics_accepted),
        "accepted_at": user.ethics_accepted_at.isoformat() if user.ethics_accepted_at else None,
        "pledge_text": "I confirm that NO ENTRY labs are isolated and I will never apply offensive techniques against systems without explicit written authorization.",
        "questions": [
            {
                "id": q["id"],
                "question": q["question"],
                "options": q["options"],
            }
            for q in ETHICS_QUESTIONS
        ],
    }


def evaluate_ethics_submission(session: Session, user: User, req: EthicsAcceptRequest) -> Dict[str, Any]:
    """Validate pledge checkbox and all 3 ethics check answers."""
    if not req.checkbox_agreed:
        return {
            "accepted": False,
            "score": 0,
            "total": len(ETHICS_QUESTIONS),
            "wrong_indices": [],
            "message": "You must check the isolated range ethics pledge before verification.",
            "feedback": [],
        }

    if len(req.answers) != len(ETHICS_QUESTIONS):
        return {
            "accepted": False,
            "score": 0,
            "total": len(ETHICS_QUESTIONS),
            "wrong_indices": list(range(len(ETHICS_QUESTIONS))),
            "message": "All 3 ethics check questions must be answered.",
            "feedback": [],
        }

    wrong_indices: List[int] = []
    feedback: List[Dict[str, Any]] = []
    correct_count = 0

    for idx, q in enumerate(ETHICS_QUESTIONS):
        chosen = req.answers[idx]
        is_ok = chosen == q["correct_index"]
        if is_ok:
            correct_count += 1
        else:
            wrong_indices.append(idx)
        feedback.append({
            "id": q["id"],
            "correct": is_ok,
            "explanation": q["explanation"],
        })

    if wrong_indices:
        return {
            "accepted": False,
            "score": correct_count,
            "total": len(ETHICS_QUESTIONS),
            "wrong_indices": wrong_indices,
            "message": f"{correct_count}/3 correct. Review the highlighted principles and retry.",
            "feedback": feedback,
        }

    user.ethics_accepted = True
    user.ethics_accepted_at = datetime.utcnow()
    session.add(user)
    session.commit()
    session.refresh(user)

    return {
        "accepted": True,
        "accepted_at": user.ethics_accepted_at.isoformat(),
        "score": correct_count,
        "total": len(ETHICS_QUESTIONS),
        "wrong_indices": [],
        "message": "ETHICS CLEARANCE GRANTED. Offensive mission range unlocked.",
        "feedback": feedback,
    }


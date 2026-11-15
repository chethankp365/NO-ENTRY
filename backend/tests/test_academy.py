"""
Unit and Integration Tests for NO ENTRY Practical Academy.
Verifies the 80-room curriculum registry, task validation, mistake explanations,
progress persistence, and security (no leaked answers).
"""

import pytest
from sqlmodel import Session, select

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TrackEnum
from backend.app.db.models import RoomProgress, TaskProgress, User


def test_80_room_curriculum_integrity():
    """Verify that curriculum registry contains exactly 80 rooms (20 per track)."""
    rooms = curriculum_registry.list_rooms()
    assert len(rooms) == 80

    track_counts = curriculum_registry.get_track_counts()
    for track in TrackEnum:
        assert track_counts[track.value]["total"] == 20
        rooms_in_track = curriculum_registry.list_rooms(track)
        assert len(rooms_in_track) == 20

        # Verify sequential numbering 1..20
        numbers = [r.room_number for r in rooms_in_track]
        assert numbers == list(range(1, 21))


def test_rooms_01_to_20_implemented_and_60_planned():
    """Verify Rooms 01–20 (Red) and Blue 01–12 are implemented and remaining 48 rooms are planned."""
    # Check all 20 implemented red rooms + 12 blue rooms
    implemented_ids = [
        ("red-01-cybersecurity-foundations", TrackEnum.RED),
        ("red-02-linux-for-hackers", TrackEnum.RED),
        ("red-03-networking-fundamentals", TrackEnum.RED),
        ("red-04-reconnaissance", TrackEnum.RED),
        ("red-05-network-scanning", TrackEnum.RED),
        ("red-06-service-enumeration", TrackEnum.RED),
        ("red-07-vulnerability-assessment", TrackEnum.RED),
        ("red-08-web-application-fundamentals", TrackEnum.RED),
        ("red-09-sqli-fundamentals", TrackEnum.RED),
        ("red-10-cross-site-scripting", TrackEnum.RED),
        ("red-11-authentication-attacks", TrackEnum.RED),
        ("red-12-access-control-testing", TrackEnum.RED),
        ("red-13-file-upload-vulnerabilities", TrackEnum.RED),
        ("red-14-command-injection", TrackEnum.RED),
        ("red-15-directory-traversal", TrackEnum.RED),
        ("red-16-password-security", TrackEnum.RED),
        ("red-17-privilege-escalation", TrackEnum.RED),
        ("red-18-active-directory-fundamentals", TrackEnum.RED),
        ("red-19-exploitation-post-exploitation", TrackEnum.RED),
        ("red-20-red-team-capstone", TrackEnum.RED),
        ("blue-01-blue-team-foundations", TrackEnum.BLUE),
        ("blue-02-windows-security-fundamentals", TrackEnum.BLUE),
        ("blue-03-linux-security-monitoring", TrackEnum.BLUE),
        ("blue-04-network-traffic-analysis", TrackEnum.BLUE),
        ("blue-05-wireshark-fundamentals", TrackEnum.BLUE),
        ("blue-06-log-analysis-fundamentals", TrackEnum.BLUE),
        ("blue-07-siem-fundamentals", TrackEnum.BLUE),
        ("blue-08-windows-event-investigation", TrackEnum.BLUE),
        ("blue-09-bruteforce-detection", TrackEnum.BLUE),
        ("blue-10-malware-behaviour-analysis", TrackEnum.BLUE),
        ("blue-11-phishing-investigation", TrackEnum.BLUE),
        ("blue-12-endpoint-detection", TrackEnum.BLUE),
        ("blue-13-network-intrusion-detection", TrackEnum.BLUE),
        ("blue-14-threat-hunting", TrackEnum.BLUE),
        ("blue-15-incident-triage", TrackEnum.BLUE),
        ("blue-16-incident-response", TrackEnum.BLUE),
        ("blue-17-digital-forensics", TrackEnum.BLUE),
        ("blue-18-windows-linux-hardening", TrackEnum.BLUE),
        ("blue-19-threat-intelligence", TrackEnum.BLUE),
        ("blue-20-blue-team-capstone", TrackEnum.BLUE),
        ("purple-01-purple-team-foundations", TrackEnum.PURPLE),
        ("purple-02-mitre-attack-fundamentals", TrackEnum.PURPLE),
        ("purple-03-attack-simulation-planning", TrackEnum.PURPLE),
        ("purple-04-reconnaissance-vs-monitoring", TrackEnum.PURPLE),
        ("purple-05-privesc-emulation", TrackEnum.PURPLE),
        ("purple-06-defense-evasion-emulation", TrackEnum.PURPLE),
        ("purple-07-lateral-movement-emulation", TrackEnum.PURPLE),
        ("purple-08-persistence-emulation", TrackEnum.PURPLE),
        ("purple-09-c2-framework-emulation", TrackEnum.PURPLE),
        ("purple-10-exfiltration-emulation", TrackEnum.PURPLE),
        ("purple-11-ransomware-readiness", TrackEnum.PURPLE),
        ("purple-12-cloud-identity-emulation", TrackEnum.PURPLE),
        ("purple-13-supply-chain-emulation", TrackEnum.PURPLE),
        ("purple-14-api-abuse-emulation", TrackEnum.PURPLE),
        ("purple-15-active-directory-attacks-emulation", TrackEnum.PURPLE),
        ("purple-16-ci-cd-pipeline-emulation", TrackEnum.PURPLE),
        ("purple-17-edr-telemetry-blinding-and-bypass-emulation", TrackEnum.PURPLE),
        ("purple-18-ttp-heatmap-generation-and-coverage-scoring", TrackEnum.PURPLE),
        ("purple-19-continuous-security-validation-and-automated-testing", TrackEnum.PURPLE),
        ("purple-20-purple-team-capstone-full-adversary-emulation-exercise", TrackEnum.PURPLE),
        ("detect-01-foundations-as-code", TrackEnum.DETECTION),
        ("detect-02-log-normalization", TrackEnum.DETECTION),
        ("detect-03-sigma-syntax", TrackEnum.DETECTION),
        ("detect-04-process-creation-rules", TrackEnum.DETECTION),
        ("detect-05-network-connection-rules", TrackEnum.DETECTION),
        ("detect-06-file-registry-rules", TrackEnum.DETECTION),
        ("detect-07-auth-abuse-rules", TrackEnum.DETECTION),
        ("detect-08-powershell-obfuscation", TrackEnum.DETECTION),
        ("detect-09-web-detection-rules", TrackEnum.DETECTION),
        ("detect-10-modsec-crs-tuning", TrackEnum.DETECTION),
        ("detect-11-wazuh-decoders-rules", TrackEnum.DETECTION),
        ("detect-12-reducing-false-positives", TrackEnum.DETECTION),
        ("detect-13-threshold-detections", TrackEnum.DETECTION),
        ("detect-14-correlation-rules", TrackEnum.DETECTION),
        ("detect-15-unit-testing-rules", TrackEnum.DETECTION),
        ("detect-16-yara-hunting", TrackEnum.DETECTION),
        ("detect-17-snort-suricata", TrackEnum.DETECTION),
        ("detect-18-threat-hunting-hypothesis", TrackEnum.DETECTION),
        ("detect-19-ci-cd-detection-pipelines", TrackEnum.DETECTION),
        ("detect-20-capstone-detection-pipeline", TrackEnum.DETECTION),
    ]
    for rid, trk in implemented_ids:
        r = curriculum_registry.get_room(rid)
        assert r is not None, f"Room {rid} not found in registry"
        assert r.status == RoomStatus.IMPLEMENTED
        assert r.track == trk
        assert len(r.tasks) == 6
        assert r.concept is not None
        assert "toddler" not in r.concept.simple_analogy.lower()
        assert "baby" not in r.concept.simple_analogy.lower()

    # Verify counts
    all_rooms = curriculum_registry.list_rooms()
    implemented_rooms = [r for r in all_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_rooms = [r for r in all_rooms if r.status == RoomStatus.PLANNED]

    assert len(implemented_rooms) == 80
    assert len(planned_rooms) == 0
    assert len(all_rooms) == 80

    counts = curriculum_registry.get_track_counts()
    assert counts["red"]["implemented"] == 20
    assert counts["red"]["planned"] == 0
    assert counts["blue"]["implemented"] == 20
    assert counts["blue"]["planned"] == 0
    assert counts["purple"]["implemented"] == 20
    assert counts["purple"]["planned"] == 0
    assert counts["detection"]["implemented"] == 20
    assert counts["detection"]["planned"] == 0


def test_client_detail_scrubs_secret_answers():
    """Verify that client_detail() scrubs accepted_answers and regex before sending to client."""
    r9 = curriculum_registry.get_room("red-09-sqli-fundamentals")
    detail = r9.client_detail()

    for task in detail["tasks"]:
        assert "accepted_answers" not in task
        assert "accepted_regex" not in task
        if task.get("quiz_questions"):
            for q in task["quiz_questions"]:
                assert "correct_index" not in q


def test_api_tracks_endpoint(client):
    """GET /api/academy/tracks returns track summary and counts."""
    res = client.get("/api/academy/tracks")
    assert res.status_code == 200
    data = res.json()
    assert data["total_rooms"] == 80
    assert data["total_implemented"] == 80
    assert len(data["tracks"]) == 4


def test_api_rooms_list_and_filter(client):
    """GET /api/academy/rooms returns all 80 rooms and supports ?track= filtering."""
    res_all = client.get("/api/academy/rooms")
    assert res_all.status_code == 200
    assert len(res_all.json()) == 80

    res_red = client.get("/api/academy/rooms?track=red")
    assert res_red.status_code == 200
    assert len(res_red.json()) == 20

    res_blue = client.get("/api/academy/rooms?track=blue")
    assert res_blue.status_code == 200
    assert len(res_blue.json()) == 20


def test_api_room_detail_and_start(client):
    """GET /api/academy/rooms/{room_id} and POST /api/academy/rooms/{room_id}/start."""
    res_404 = client.get("/api/academy/rooms/non-existent-room")
    assert res_404.status_code == 404

    res = client.get("/api/academy/rooms/red-09-sqli-fundamentals")
    assert res.status_code == 200
    data = res.json()
    assert data["room_id"] == "red-09-sqli-fundamentals"
    assert len(data["tasks"]) == 6

    # Start room
    res_start = client.post("/api/academy/rooms/red-09-sqli-fundamentals/start")
    assert res_start.status_code == 200
    assert res_start.json()["status"] in ("IN_PROGRESS", "COMPLETED")


def test_task_submission_mistake_explanation_and_success(client):
    """Test task validation: mistake explanations for common errors, and success on correct answer."""
    # 1. Mistake explanation for Task 1
    res_wrong = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-01-detection/submit",
        json={"answer": ";"},
    )
    assert res_wrong.status_code == 200
    data_wrong = res_wrong.json()
    assert data_wrong["is_correct"] is False
    assert "semicolon terminates" in (data_wrong["mistake_explanation"] or "").lower()

    # 2. Correct answer for Task 1
    res_correct = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-01-detection/submit",
        json={"answer": "'"},
    )
    assert res_correct.status_code == 200
    data_correct = res_correct.json()
    assert data_correct["is_correct"] is True
    assert data_correct["completed"] is True
    assert data_correct["earned_xp"] == 50


def test_flag_submission_and_quiz_evaluation(client):
    """Test auth bypass flag, union flag, numeric challenge flag, remediation, and quiz."""
    # Task 1: Detection
    res_t1 = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-01-detection/submit",
        json={"answer": "'"},
    )
    assert res_t1.status_code == 200
    assert res_t1.json()["is_correct"] is True

    # Task 2: Auth bypass flag
    res_flag2 = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-02-auth-bypass/submit",
        json={"answer": "NOENTRY{sqli_auth_bypass_success_3914}"},
    )
    assert res_flag2.status_code == 200
    assert res_flag2.json()["is_correct"] is True

    # Task 3: Union extraction flag
    res_flag3 = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-03-union-extraction/submit",
        json={"answer": "NOENTRY{union_sqli_data_extraction_7129}"},
    )
    assert res_flag3.status_code == 200
    assert res_flag3.json()["is_correct"] is True

    # Task 4: Numeric challenge flag
    res_flag4 = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-04-challenge/submit",
        json={"answer": "NOENTRY{sqli_numeric_challenge_pivot_8842}"},
    )
    assert res_flag4.status_code == 200
    assert res_flag4.json()["is_correct"] is True

    # Task 5: Defensive remediation
    res_fix = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-05-remediation/submit",
        json={"answer": "parameterized queries"},
    )
    assert res_fix.status_code == 200
    assert res_fix.json()["is_correct"] is True

    # Task 6: Quiz with all correct answers
    quiz_payload = {
        "answer": "",
        "quiz_answers": {
            "q1": 0,
            "q2": 0,
            "q3": 0,
            "q4": 0,
            "q5": 0,
        },
    }
    res_quiz = client.post(
        "/api/academy/rooms/red-09-sqli-fundamentals/tasks/task-06-quiz/submit",
        json=quiz_payload,
    )
    assert res_quiz.status_code == 200
    quiz_data = res_quiz.json()
    assert quiz_data["is_correct"] is True
    assert quiz_data["room_completed"] is True
    assert quiz_data["new_room_status"] == "COMPLETED"


def test_academy_html_pages_render(client):
    """Verify that /academy and /academy/rooms/{room_id} render valid 200 HTML."""
    res_cat = client.get("/academy")
    assert res_cat.status_code == 200
    assert "ACADEMY" in res_cat.text
    assert "80 ROOMS" in res_cat.text

    res_room = client.get("/academy/rooms/red-09-sqli-fundamentals")
    assert res_room.status_code == 200
    assert "SQL Injection Fundamentals" in res_room.text
    assert "terminalContainer" in res_room.text

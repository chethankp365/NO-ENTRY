"""
Comprehensive Backend Test Suite for NO ENTRY Prompt 7 (Missions + Learning Layer).
Tests YAML validation, mandatory ethics gate, gamification, Sigma rule grading,
and complete end-to-end automated playthroughs including The Hacked Shop.
"""

import pytest
from backend.app.missions.loader import list_missions, get_mission, reload_missions
from backend.app.missions.models import MissionLogEntry
from backend.app.rules.engine import RuleEngine


def _register_operator(client, operator_id="op-learner-1"):
    resp = client.post("/api/auth/login", json={
        "operator_id": operator_id,
        "passphrase": "range-test-passphrase",
    })
    assert resp.status_code == 200
    return resp.json()


def _pass_ethics(client):
    ethics_get = client.get("/api/ethics")
    assert ethics_get.status_code == 200
    assert ethics_get.json()["accepted"] is False

    # Wrong answers must fail validation cleanly
    bad = client.post("/api/ethics/accept", json={
        "checkbox_agreed": True,
        "answers": [1, 0, 0],
    })
    assert bad.status_code == 200
    assert bad.json()["accepted"] is False
    assert len(bad.json()["wrong_indices"]) == 3

    # Correct 3-question check + checkbox unlocks range
    good = client.post("/api/ethics/accept", json={
        "checkbox_agreed": True,
        "answers": [0, 1, 2],
    })
    assert good.status_code == 200
    assert good.json()["accepted"] is True
    assert good.json()["score"] == 3


def test_five_mission_yamls_valid_and_rules_zero_fp():
    reload_missions()
    missions = list_missions()
    assert [m.id for m in missions] == [
        "ransomware",
        "web-breach",
        "insider",
        "credential",
        "exfiltration",
    ]
    playable = [m for m in missions if m.playable]
    cinematic = [m for m in missions if not m.playable]
    assert len(playable) == 3
    assert len(cinematic) == 2

    # Every playable mission's reference Sigma rule must detect attack logs with zero FPs
    for m in playable:
        entries: list[MissionLogEntry] = []
        for step in m.steps:
            entries.extend(step.generated_logs)
        entries.extend(m.rule_challenge.benign_baseline_logs)

        tp_indices = [i for i, e in enumerate(entries) if e.is_true_positive]
        structured_logs = [e.structured for e in entries]
        rule = RuleEngine.parse_rule_yaml(m.rule_challenge.reference_solution_yaml)
        res = RuleEngine.evaluate_rule(rule, structured_logs, expected_matches=tp_indices)
        assert res.count >= m.rule_challenge.required_min_hits, f"{m.id} rule missed TP logs"
        assert len(res.false_positives) == 0, f"{m.id} reference rule had FPs: {res.false_positives}"


def test_ethics_gate_blocks_attack_missions_with_403_until_accepted(client):
    _register_operator(client, "op-ethics-test")

    # Attack mission start & command must return 403 prior to ethics clearance
    start_denied = client.post("/api/missions/web-breach/start", json={"mode": "guided", "track": "purple"})
    assert start_denied.status_code == 403

    cmd_denied = client.post("/api/missions/web-breach/command", json={"command": "nmap -sV 10.0.1.10"})
    assert cmd_denied.status_code == 403

    # Unchecked box rejected
    unchecked = client.post("/api/ethics/accept", json={"checkbox_agreed": False, "answers": [0, 1, 2]})
    assert unchecked.status_code == 200
    assert unchecked.json()["accepted"] is False

    # Passing check unlocks attack missions
    _pass_ethics(client)
    start_ok = client.post("/api/missions/web-breach/start", json={"mode": "guided", "track": "purple"})
    assert start_ok.status_code == 200
    assert start_ok.json()["progress"]["stage"] == "attacker"


def test_full_playthrough_the_hacked_shop_start_to_debrief(client):
    """Complete automated end-to-end playthrough of The Hacked Shop (web-breach)."""
    op = _register_operator(client, "op-shop-runner")
    assert op["xp"] == 1240
    assert op["rank"] == "SCRIPT RUNNER"

    _pass_ethics(client)

    # Catalog & mission detail load without leaking secrets
    catalog = client.get("/api/missions").json()
    assert catalog["total_count"] == 5
    assert catalog["cleared_count"] == 0
    detail = client.get("/api/missions/web-breach").json()
    assert detail["mission"]["has_shop_widget"] is True
    assert "NOENTRY{" not in str(detail["mission"])

    # 1. Start (Briefing -> Attacker)
    st = client.post("/api/missions/web-breach/start", json={"mode": "guided", "track": "purple"}).json()
    assert st["progress"]["stage"] == "attacker"

    # Wrong command gives helpful hint without advancing step
    wrong_cmd = client.post("/api/missions/web-breach/command", json={"command": "whoami"}).json()
    assert wrong_cmd["matched"] is False
    assert wrong_cmd["step_completed"] is False

    # Step 1: nmap web01
    s1 = client.post("/api/missions/web-breach/command", json={"command": "nmap -sV 10.0.1.10"}).json()
    assert s1["matched"] is True
    assert s1["completed_step_id"] == "recon-web01"
    assert s1["progress"]["current_step_idx"] == 1

    # Hint deduction (-25 XP), repeat same hint is free
    h1 = client.post("/api/missions/web-breach/hint", json={"level": 1}).json()
    assert h1["xp_cost"] == 25
    assert h1["remaining_xp"] == 1215
    assert h1["hints_used"] == 1
    h1_repeat = client.post("/api/missions/web-breach/hint", json={"level": 1}).json()
    assert h1_repeat["xp_cost"] == 0
    assert h1_repeat["remaining_xp"] == 1215

    # Step 2: SQLi via VoltGear mock shop search
    s2 = client.post("/api/missions/web-breach/command", json={
        "command": "shop:search ' UNION SELECT 1,username,password_hash FROM admin_users--"
    }).json()
    assert s2["matched"] is True
    assert s2["completed_step_id"] == "sqli-probe"
    assert s2["shop_response"]["mode"] == "search"

    # Step 3: Upload webshell via curl
    s3 = client.post("/api/missions/web-breach/command", json={
        "command": "curl -X POST http://10.0.1.10/admin/upload -F \"file=@c99.php\""
    }).json()
    assert s3["matched"] is True
    assert s3["completed_step_id"] == "webshell-upload"

    # Step 4: Execute webshell to get flag
    s4 = client.post("/api/missions/web-breach/command", json={
        "command": "curl \"http://10.0.1.10/uploads/c99.php?cmd=cat+/var/www/flag.txt\""
    }).json()
    assert s4["matched"] is True
    assert s4["all_steps_done"] is True
    assert s4["progress"]["stage"] == "flag"
    assert any("NOENTRY{sqli_t0_sh3ll_v0ltg3ar_w4f}" in line for line in s4["output_lines"])

    # 3. Flag Capture: wrong flag rejected, right flag unlocks first_blood & side_switch
    bad_flag = client.post("/api/missions/web-breach/flag", json={"flag": "NOENTRY{wrong}"}).json()
    assert bad_flag["correct"] is False

    good_flag = client.post("/api/missions/web-breach/flag", json={
        "flag": "NOENTRY{sqli_t0_sh3ll_v0ltg3ar_w4f}"
    }).json()
    assert good_flag["correct"] is True
    assert good_flag["trigger_side_switch"] is True
    assert good_flag["progress"]["stage"] == "side_switch"
    assert any(b["key"] == "first_blood" for b in good_flag["newly_unlocked_badges"])

    # 4->5. Generate logs created by learner's attack
    logs_resp = client.post("/api/missions/web-breach/logs").json()
    assert logs_resp["total_logs"] >= 6
    assert logs_resp["progress"]["stage"] == "defender"

    # Overly broad Sigma rule produces false positives against benign traffic
    broad_yaml = """
title: Broad Rule
detection:
  selection:
    uri|contains: "/"
  condition: selection
"""
    broad_res = client.post("/api/missions/web-breach/rule/test", json={
        "rule_yaml": broad_yaml,
        "selected_mitre_id": "T1190",
    }).json()
    assert broad_res["passed"] is False
    assert broad_res["false_positives_count"] > 0

    # Wrong MITRE technique fails even with valid rule
    mission_def = get_mission("web-breach")
    wrong_mitre = client.post("/api/missions/web-breach/rule/test", json={
        "rule_yaml": mission_def.rule_challenge.reference_solution_yaml,
        "selected_mitre_id": "T1110",
    }).json()
    assert wrong_mitre["passed"] is False
    assert wrong_mitre["mitre_correct"] is False

    # Passing Sigma rule + right MITRE (T1190) -> 0 FPs, rule_writer badge, stage=fix
    pass_rule = client.post("/api/missions/web-breach/rule/test", json={
        "rule_yaml": mission_def.rule_challenge.reference_solution_yaml,
        "selected_mitre_id": "T1190",
    }).json()
    assert pass_rule["passed"] is True
    assert pass_rule["rule_fires"] is True
    assert pass_rule["false_positives_count"] == 0
    assert pass_rule["progress"]["stage"] == "fix"
    assert any(b["key"] == "rule_writer" for b in pass_rule["newly_unlocked_badges"])

    # 6. Fix: wrong choice explains why; custom parameterized code or correct choice succeeds
    bad_fix = client.post("/api/missions/web-breach/fix", json={"option_id": "opt-client-only"}).json()
    assert bad_fix["applied"] is False
    assert "JavaScript" in bad_fix["explanation"]

    good_fix = client.post("/api/missions/web-breach/fix", json={
        "code_patch": "cursor.execute('SELECT id, name FROM products WHERE name LIKE %s', (f'%{q}%',))"
    }).json()
    assert good_fix["applied"] is True
    assert good_fix["progress"]["stage"] == "verify"

    # 7. Verify: attack blocked + XP awarded + debrief unlocked
    verify_res = client.post("/api/missions/web-breach/verify").json()
    assert verify_res["blocked"] is True
    assert verify_res["status_banner"] == "ATTACK NEUTRALISED"
    assert verify_res["xp_awarded"] == 500
    assert verify_res["progress"]["stage"] == "debrief"
    assert verify_res["progress"]["completed"] is True
    assert verify_res["progress"]["time_to_detect_sec"] is not None
    assert verify_res["progress"]["time_to_fix_sec"] is not None

    # 8. Quiz & Debrief
    quiz_res = client.post("/api/missions/web-breach/quiz", json={"answers": [1, 1, 1, 1, 2]}).json()
    assert quiz_res["score"] == 5
    assert quiz_res["passed"] is True
    assert quiz_res["xp_awarded"] == 100
    assert "VoltGear" in quiz_res["debrief"]["why_it_worked"]

    # Gamification endpoints reflect progress & leaderboard
    me_prog = client.get("/api/me/progress").json()
    assert me_prog["stats"]["missions_cleared"] == 1
    assert me_prog["stats"]["cleared_pct"] == 20
    # 1240 - 25 (hint) + 100 (flag) + 500 (verify) + 100 (quiz) = 1915 XP
    assert me_prog["user"]["xp"] == 1915
    assert me_prog["user"]["rank"] == "SCRIPT RUNNER"

    lb = client.get("/api/leaderboard").json()
    you_rows = [r for r in lb["entries"] if r["is_you"]]
    assert len(you_rows) == 1
    assert you_rows[0]["xp"] == 1915

    # Glossary cheat-sheet
    glossary = client.get("/api/learn/glossary").json()
    assert any(item["tool"] == "sqlmap" for item in glossary["items"])

    # Snapshot Reset
    reset_res = client.post("/api/missions/web-breach/reset").json()
    assert reset_res["status"] == "reset"
    assert reset_res["progress"]["stage"] == "briefing"
    assert reset_res["progress"]["completed"] is False


def test_rank_up_and_insider_honeytoken_badge(client):
    _register_operator(client, "op-insider-hunter")
    _pass_ethics(client)

    # Play Silent Insider in defender track (jumps straight to defender with logs seeded)
    start_res = client.post("/api/missions/insider/start", json={
        "mode": "challenge",
        "track": "defender",
    }).json()
    assert start_res["progress"]["stage"] == "defender"
    assert len(start_res["logs"]) >= 4

    insider_def = get_mission("insider")
    rule_res = client.post("/api/missions/insider/rule/test", json={
        "rule_yaml": insider_def.rule_challenge.reference_solution_yaml,
        "selected_mitre_id": "T1078",
    }).json()
    assert rule_res["passed"] is True

    fix_res = client.post("/api/missions/insider/fix", json={"option_id": "opt-disable-ad"}).json()
    assert fix_res["applied"] is True

    # Verify in challenge mode awards 700 * 1.25 = 875 XP -> crosses 2000 threshold -> PACKET HUNTER!
    verify_res = client.post("/api/missions/insider/verify").json()
    assert verify_res["blocked"] is True
    assert verify_res["xp_awarded"] == 875
    assert verify_res["old_rank"] == "SCRIPT RUNNER"
    assert verify_res["new_rank"] == "PACKET HUNTER"
    assert verify_res["rank_up"] is True
    assert any(b["key"] == "honeytoken_catch" for b in verify_res["newly_unlocked_badges"])


def test_learning_html_routes_render(client):
    r_missions = client.get("/missions")
    assert r_missions.status_code == 200
    assert "/static/js/screens/missions.js" in r_missions.text

    r_player = client.get("/missions/web-breach")
    assert r_player.status_code == 200
    assert 'data-mission-id="web-breach"' in r_player.text
    assert "/static/js/screens/missionPlayer.js" in r_player.text

    r_learn = client.get("/learn")
    assert r_learn.status_code == 200
    assert "/static/js/screens/learn.js" in r_learn.text

    r_docs = client.get("/docs")
    assert r_docs.status_code == 200
    assert "/static/js/screens/docs.js" in r_docs.text


def test_cinematic_walkthrough_and_credential_sigma_filter(client):
    _register_operator(client, "op-cinematic-tester")
    _pass_ethics(client)

    # Non-playable cinematic mission: start + verify completes walkthrough + rewards XP
    cine_start = client.post("/api/missions/ransomware/start", json={"mode": "guided", "track": "purple"})
    assert cine_start.status_code == 200
    cine_data = cine_start.json()
    assert cine_data["playable"] is False
    assert len(cine_data["cinematic_walkthrough"]) >= 4

    cine_done = client.post("/api/missions/ransomware/verify").json()
    assert cine_done["blocked"] is True
    assert cine_done["progress"]["completed"] is True
    assert cine_done["xp_awarded"] == 300

    # Credential mission defender track: excluding internal scanner 10.0.3.15 eliminates false positives
    cred_start = client.post("/api/missions/credential/start", json={"mode": "guided", "track": "defender"})
    assert cred_start.status_code == 200
    assert cred_start.json()["progress"]["stage"] == "defender"

    naive_rule = """
title: SSH Brute Force Without Exclusion
detection:
  selection:
    service: ssh
    message|contains:
      - "failed password"
  condition: selection
"""
    naive_res = client.post("/api/missions/credential/rule/test", json={
        "rule_yaml": naive_rule,
        "selected_mitre_id": "T1110",
    }).json()
    assert naive_res["passed"] is False
    assert naive_res["false_positives_count"] >= 1

    cred_def = get_mission("credential")
    filtered_res = client.post("/api/missions/credential/rule/test", json={
        "rule_yaml": cred_def.rule_challenge.reference_solution_yaml,
        "selected_mitre_id": "T1110",
    }).json()
    assert filtered_res["passed"] is True
    assert filtered_res["false_positives_count"] == 0


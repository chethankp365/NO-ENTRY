"""
Task and Flag Validation Engine for NO ENTRY Academy.
Validates exact answers, regex patterns, parameterized query fixes, and quizzes.
Provides constructive mistake explanations without exposing flags.
"""

import json
import re
from datetime import datetime
from typing import Dict, Optional, Tuple
from sqlmodel import Session, select

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import (
    RoomDefinition,
    TaskDefinition,
    TaskSubmission,
    TaskSubmissionResult,
    TaskType,
)
from backend.app.db.models import RoomProgress, TaskProgress, User


PRACTICAL_CHALLENGE_ACTIONS: Dict[str, str] = {
    # Blue Room 01
    "task-04-incident-triage-classification": "soc_triage_verified",
    "task-05-evidence-timeline-challenge": "soc_timeline_verified",
    # Blue Room 02
    "task-04-windows-privilege-audit-challenge": "win_privilege_audited",
    "task-05-windows-remediation-hardening": "win_audit_remediation_verified",
    "task-05-incident-remediation-challenge": "win_audit_remediation_verified",
    # Blue Room 03
    "task-04-threat-actor-attribution-challenge": "linux_attribution_verified",
    "task-05-linux-hardening-remediation": "linux_incident_verified",
    "task-05-incident-investigation-challenge": "linux_incident_verified",
    # Blue Room 04
    "task-05-pcap-stream-forensic-challenge": "traffic_investigation_verified",
    "task-05-incident-containment-challenge": "traffic_investigation_verified",
    # Blue Room 05
    "task-05-wireshark-challenge": "wireshark_challenge_verified",
    "task-05-wireshark-pcap-challenge": "wireshark_challenge_verified",
    # Blue Room 06
    "task-05-log-analysis-challenge": "log_analysis_challenge_verified",
    "task-05-multi-source-log-correlation-challenge": "log_analysis_challenge_verified",
    # Blue Room 07
    "task-04-siem-custom-rule-deployment": "siem_rule_deployed",
    "task-05-siem-incident-prioritization-challenge": "siem_challenge_verified",
    "task-05-siem-incident-escalation-challenge": "siem_challenge_verified",
    # Blue Room 08
    "task-05-windows-event-investigation-challenge": "win_event_challenge_verified",
    "task-05-multi-event-correlation-challenge": "win_event_challenge_verified",
    # Blue Room 09
    "task-04-siem-threshold-rule-deployment": "bruteforce_rule_deployed",
    "task-05-bruteforce-challenge": "bruteforce_challenge_verified",
    "task-05-bruteforce-correlation-challenge": "bruteforce_challenge_verified",
    # Blue Room 10
    "task-04-yara-rule-syntax-validation": "malware_yara_validated",
    "task-05-malware-challenge": "malware_challenge_verified",
    "task-05-malware-yara-rule-challenge": "malware_challenge_verified",
    # Blue Room 11
    "task-04-phishing-triage-submission": "phishing_triage_verified",
    "task-05-phishing-challenge": "phishing_challenge_verified",
    "task-05-phishing-triage-remediation-challenge": "phishing_challenge_verified",
    # Blue Room 12
    "task-04-edr-rule-deployment": "endpoint_rule_deployed",
    "task-05-endpoint-challenge": "endpoint_challenge_verified",
    "task-05-edr-threat-hunting-containment-challenge": "endpoint_challenge_verified",
    # Blue Room 13
    "task-04-snort-rule-deployment": "nids_rule_deployed",
    "task-05-intrusion-correlation-challenge": "nids_challenge_verified",
    # Blue Room 14
    "task-04-sigma-query-authoring": "hunt_query_deployed",
    "task-05-threat-hunting-challenge": "hunt_challenge_verified",
    # Blue Room 15
    "task-04-formal-triage-classification": "triage_alert_classified",
    "task-05-incident-escalation-challenge": "triage_challenge_verified",
    # Blue Room 16
    "task-03-rapid-containment-execution": "response_containment_enforced",
    "task-04-threat-eradication-execution": "response_eradication_complete",
    "task-05-incident-response-challenge": "response_challenge_verified",
    # Blue Room 17
    "task-04-timeline-reconstruction": "forensics_timeline_confirmed",
    "task-05-digital-forensics-challenge": "forensics_challenge_verified",
    # Blue Room 18
    "task-04-apply-linux-hardening": "linux_hardening_enforced",
    "task-05-hardening-verification-challenge": "hardening_challenge_verified",
    # Blue Room 19
    "task-04-indicator-correlation-enrichment": "intel_correlation_confirmed",
    "task-05-threat-intel-challenge": "intel_challenge_verified",
    # Blue Room 20
    "task-01-capstone-stage1-detection": "capstone_stage1_verified",
    "task-02-capstone-stage2-threat-hunting": "capstone_stage2_verified",
    "task-03-capstone-stage3-forensic-preservation": "capstone_stage3_verified",
    "task-04-capstone-stage4-intelligence-triage": "capstone_stage4_verified",
    "task-05-capstone-stage5-containment-recovery": "capstone_stage5_verified",
    "task-06-capstone-final-report-assessment": "capstone_final_verified",
    # Purple Room 01
    "task-04-telemetry-mapping": "purple_telemetry_mapped",
    "task-05-purple-foundations-challenge": "purple_foundations_approved",
    # Purple Room 02
    "task-04-attck-evidence-mapping": "attck_evidence_mapped",
    "task-05-attck-mapping-challenge": "attck_lifecycle_complete",
    # Purple Room 03
    "task-04-register-simulation-step": "simulation_step_registered",
    "task-05-simulation-planning-challenge": "simulation_plan_approved",
    # Purple Room 04
    "task-04-recon-telemetry-correlation": "recon_correlation_confirmed",
    "task-05-recon-monitoring-challenge": "recon_monitoring_validated",
    # Purple Room 05
    "task-04-uac-emulation-telemetry": "privesc_emulated",
    "task-05-privesc-detection-challenge": "privesc_detection_validated",
    # Purple Room 06
    "task-04-process-injection-emulation": "injection_emulated",
    "task-05-defense-evasion-challenge": "defense_evasion_detection_validated",
    # Purple Room 07
    "task-04-wmi-lateral-emulation": "lateral_emulated",
    "task-05-lateral-movement-challenge": "lateral_movement_detection_validated",
    # Purple Room 08
    "task-04-scheduled-task-emulation": "persistence_emulated",
    "task-05-persistence-remediation-challenge": "persistence_remediation_validated",
    # Purple Room 09
    "task-04-c2-beacon-emulation": "c2_beacon_emulated",
    "task-05-c2-detection-challenge": "c2_detection_validated",
    # Purple Room 10
    "task-04-exfil-emulation": "exfil_emulated",
    "task-05-exfil-challenge": "exfil_detection_validated",
    # Purple Room 11
    "task-04-ransomware-emulation": "ransomware_emulated",
    "task-05-ransomware-challenge": "ransomware_readiness_validated",
    # Purple Room 12
    "task-04-cloud-iam-emulation": "cloud_iam_emulated",
    "task-05-cloud-detection-challenge": "cloud_identity_detection_validated",
    # Purple Room 13
    "task-04-supply-chain-emulation": "supply_chain_emulated",
    "task-05-supply-chain-challenge": "supply_chain_detection_validated",
    # Purple Room 14
    "task-04-bola-emulation": "bola_emulated",
    "task-05-api-detection-challenge": "api_abuse_detection_validated",
    # Purple Room 15
    "task-04-kerberoasting-emulation": "kerberoasting_emulated",
    "task-05-ad-detection-challenge": "ad_attack_detection_validated",
    # Purple Room 16
    "task-04-cicd-emulation": "cicd_pipeline_emulated",
    "task-05-cicd-detection-challenge": "cicd_pipeline_detection_validated",
    # Purple Room 17
    "task-04-edr-bypass-emulation": "edr_bypass_emulated",
    "task-05-edr-bypass-challenge": "edr_bypass_detection_validated",
    # Purple Room 18
    "task-04-heatmap-emulation": "heatmap_emulated",
    "task-05-heatmap-challenge": "heatmap_coverage_validated",
    # Purple Room 19
    "task-04-continuous-validation-emulation": "continuous_validation_emulated",
    "task-05-continuous-validation-challenge": "continuous_validation_detection_validated",
    # Purple Room 20
    "task-04-capstone-emulation": "purple_capstone_emulated",
    "task-05-capstone-challenge": "purple_capstone_detection_validated",
    # Detection Room 01
    "task-04-dac-pipeline-emulation": "detection_foundations_verified",
    "task-05-dac-challenge": "detection_foundations_validated",
    # Detection Room 02
    "task-04-normalization-emulation": "log_normalization_verified",
    "task-05-normalization-challenge": "log_normalization_validated",
    # Detection Room 03
    "task-04-sigma-syntax-emulation": "sigma_syntax_verified",
    "task-05-sigma-syntax-challenge": "sigma_syntax_validated",
    # Detection Room 04
    "task-04-process-creation-emulation": "process_creation_verified",
    "task-05-process-creation-challenge": "process_creation_validated",
    # Detection Room 05
    "task-04-network-connection-emulation": "network_connection_verified",
    "task-05-network-connection-challenge": "network_connection_validated",
    # Detection Room 06
    "task-04-file-registry-emulation": "file_registry_verified",
    "task-05-file-registry-challenge": "file_registry_validated",
    # Detection Room 07
    "task-04-auth-abuse-emulation": "auth_abuse_verified",
    "task-05-auth-abuse-challenge": "auth_abuse_validated",
    # Detection Room 08
    "task-04-powershell-emulation": "powershell_obfuscation_verified",
    "task-05-powershell-challenge": "powershell_obfuscation_validated",
    # Detection Room 09
    "task-04-web-detection-emulation": "web_detection_verified",
    "task-05-web-detection-challenge": "web_detection_validated",
    # Detection Room 10
    "task-04-modsec-crs-emulation": "modsec_crs_verified",
    "task-05-modsec-crs-challenge": "modsec_crs_validated",
    # Detection Room 11
    "task-04-wazuh-decoders-emulation": "wazuh_rules_verified",
    "task-05-wazuh-decoders-challenge": "wazuh_rules_validated",
    # Detection Room 12
    "task-04-false-positive-emulation": "false_positive_tuning_verified",
    "task-05-false-positive-challenge": "false_positive_tuning_validated",
    # Detection Room 13
    "task-04-threshold-emulation": "threshold_detection_verified",
    "task-05-threshold-challenge": "threshold_detection_validated",
    # Detection Room 14
    "task-04-correlation-emulation": "correlation_rule_verified",
    "task-05-correlation-challenge": "correlation_rule_validated",
    # Detection Room 15
    "task-04-testing-unit-emulation": "detection_unit_test_verified",
    "task-05-testing-unit-challenge": "detection_unit_test_validated",
    # Detection Room 16
    "task-04-yara-hunting-emulation": "yara_hunting_verified",
    "task-05-yara-hunting-challenge": "yara_hunting_validated",
    # Detection Room 17
    "task-04-snort-suricata-emulation": "suricata_signature_verified",
    "task-05-snort-suricata-challenge": "suricata_signature_validated",
    # Detection Room 18
    "task-04-threat-hunting-hypothesis-emulation": "threat_hunt_hypothesis_verified",
    "task-05-threat-hunting-hypothesis-challenge": "threat_hunt_hypothesis_validated",
    # Detection Room 19
    "task-04-detection-pipeline-emulation": "detection_pipeline_verified",
    "task-05-detection-pipeline-challenge": "detection_pipeline_validated",
    # Detection Room 20
    "task-04-capstone-pipeline-emulation": "capstone_pipeline_verified",
    "task-05-capstone-pipeline-challenge": "capstone_pipeline_validated",
}


class TaskValidator:
    def validate_submission(
        self,
        session: Session,
        user: User,
        room_id: str,
        task_id: str,
        submission: TaskSubmission,
    ) -> TaskSubmissionResult:
        room = curriculum_registry.get_room(room_id)
        if not room:
            return TaskSubmissionResult(
                task_id=task_id,
                completed=False,
                is_correct=False,
                feedback=f"Room '{room_id}' not found.",
            )

        task = next((t for t in room.tasks if t.task_id == task_id), None)
        if not task:
            return TaskSubmissionResult(
                task_id=task_id,
                completed=False,
                is_correct=False,
                feedback=f"Task '{task_id}' not found in room '{room_id}'.",
            )

        # Retrieve or initialize task progress
        task_prog = session.exec(
            select(TaskProgress).where(
                TaskProgress.operator_id == user.operator_id,
                TaskProgress.room_id == room_id,
                TaskProgress.task_id == task_id,
            )
        ).first()

        if not task_prog:
            task_prog = TaskProgress(
                user_id=user.id or 1,
                operator_id=user.operator_id,
                room_id=room_id,
                task_id=task_id,
                completed=False,
                attempts=0,
                earned_xp=0,
            )
            session.add(task_prog)

        task_prog.attempts += 1

        # If already completed, return existing success state
        if task_prog.completed:
            return TaskSubmissionResult(
                task_id=task_id,
                completed=True,
                is_correct=True,
                feedback="Task previously completed. Good work!",
                earned_xp=task_prog.earned_xp,
                attempts=task_prog.attempts,
                total_user_xp=user.xp,
            )

        # Check if practical challenge requires verified lab action
        dynamic_token = None
        if task_id in PRACTICAL_CHALLENGE_ACTIONS:
            from backend.app.labs.manager import lab_manager
            session_info = lab_manager.get_user_session(user.operator_id, room_id)
            if not session_info or session_info.status != "RUNNING" or session_info.is_expired():
                session.add(task_prog)
                session.commit()
                return TaskSubmissionResult(
                    task_id=task_id,
                    completed=False,
                    is_correct=False,
                    feedback="Investigation required: You must start and run the practical lab session before submitting findings.",
                    mistake_explanation="Practical challenge tasks require an active running lab container session.",
                    earned_xp=0,
                    attempts=task_prog.attempts,
                    total_user_xp=user.xp,
                )

            required_action = PRACTICAL_CHALLENGE_ACTIONS[task_id]
            if not session_info.has_action(required_action):
                session.add(task_prog)
                session.commit()
                return TaskSubmissionResult(
                    task_id=task_id,
                    completed=False,
                    is_correct=False,
                    feedback="Investigation incomplete: The required challenge action has not been verified in your running lab environment.",
                    mistake_explanation="You must execute the investigation tools and submit your findings to the lab target to earn the verification token.",
                    earned_xp=0,
                    attempts=task_prog.attempts,
                    total_user_xp=user.xp,
                )
            dynamic_token = session_info.get_action_token(required_action)

        # Evaluate correctness
        is_correct, feedback, mistake_explanation = self._evaluate_task(task, submission, dynamic_token=dynamic_token)

        earned_xp = 0
        if is_correct:
            task_prog.completed = True
            task_prog.completed_at = datetime.utcnow()
            task_prog.earned_xp = task.xp_reward
            earned_xp = task.xp_reward

            # Update User XP
            user.xp += earned_xp
            session.add(user)

        session.add(task_prog)
        session.commit()

        # Update room progress and check for room completion
        room_completed, room_status = self._sync_room_progress(session, user, room)

        return TaskSubmissionResult(
            task_id=task_id,
            completed=task_prog.completed,
            is_correct=is_correct,
            feedback=feedback,
            mistake_explanation=mistake_explanation,
            earned_xp=earned_xp,
            attempts=task_prog.attempts,
            room_completed=room_completed,
            new_room_status=room_status,
            total_user_xp=user.xp,
        )

    def _evaluate_task(
        self,
        task: TaskDefinition,
        submission: TaskSubmission,
        dynamic_token: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        raw_ans = (submission.answer or "").strip()

        # Dynamic session token check
        if dynamic_token and (raw_ans == dynamic_token or raw_ans.lower() == dynamic_token.lower()):
            return True, "Correct! Task objectives successfully satisfied with verified session token.", None

        # Replay / Cross-user dynamic token rejection
        if raw_ans.startswith("VERIFIED-"):
            return (
                False,
                "Invalid or expired verification token.",
                "Dynamic verification tokens are cryptographically bound to the specific operator and active lab session. Tokens from other sessions or learners cannot be reused.",
            )

        # 1. QUIZ evaluation
        if task.task_type == TaskType.QUIZ:
            user_choices = submission.quiz_answers or {}
            if not task.quiz_questions:
                return False, "Quiz questions are missing from this task.", None
            if len(user_choices) < len(task.quiz_questions):
                return (
                    False,
                    f"Please answer all {len(task.quiz_questions)} quiz questions before submitting.",
                    f"You have answered {len(user_choices)} of {len(task.quiz_questions)} questions.",
                )

            all_correct = True
            incorrect_explanations = []
            for q in task.quiz_questions:
                choice = user_choices.get(q.id)
                if choice is None or int(choice) != q.correct_index:
                    all_correct = False
                    incorrect_explanations.append(f"Q: '{q.question[:45]}...' — {q.explanation}")

            if all_correct:
                return True, f"Excellent! All {len(task.quiz_questions)} questions answered correctly.", None
            return (
                False,
                "One or more answers were incorrect. Review the explanations and retry.",
                " | ".join(incorrect_explanations),
            )

        # 2. EXACT or NORMALIZED MATCH
        normalized_input = raw_ans.strip().lower()
        for valid in task.accepted_answers:
            if normalized_input == valid.strip().lower() or raw_ans == valid.strip():
                return True, "Correct! Task objectives successfully satisfied.", None

        # 3. REGEX MATCH
        if task.accepted_regex and re.search(task.accepted_regex, raw_ans.strip()):
            return True, "Correct! Valid flag pattern submitted.", None

        # 4. Check for known mistake explanations
        for mistake_key, explanation in task.mistake_explanations.items():
            if raw_ans.lower() == mistake_key.lower() or mistake_key.lower() in raw_ans.lower():
                return False, "Incorrect answer. See analysis below:", explanation

        # Feedback for wrong answer
        hint_msg = f" Hint: {task.hint}" if task.hint else ""
        return False, f"Incorrect answer.{hint_msg}", None

    def _sync_room_progress(
        self, session: Session, user: User, room: RoomDefinition
    ) -> Tuple[bool, str]:
        room_prog = session.exec(
            select(RoomProgress).where(
                RoomProgress.operator_id == user.operator_id,
                RoomProgress.room_id == room.room_id,
            )
        ).first()

        if not room_prog:
            room_prog = RoomProgress(
                user_id=user.id or 1,
                operator_id=user.operator_id,
                room_id=room.room_id,
                track=room.track.value,
                status="IN_PROGRESS",
                started_at=datetime.utcnow(),
            )
            session.add(room_prog)

        all_tasks = session.exec(
            select(TaskProgress).where(
                TaskProgress.operator_id == user.operator_id,
                TaskProgress.room_id == room.room_id,
            )
        ).all()

        completed_ids = [t.task_id for t in all_tasks if t.completed]
        room_prog.completed_tasks_json = json.dumps(completed_ids)
        room_prog.xp_earned = sum(t.earned_xp for t in all_tasks)

        # Check if all room tasks are completed
        required_task_ids = {t.task_id for t in room.tasks}
        is_completed = required_task_ids.issubset(set(completed_ids)) and len(required_task_ids) > 0

        if is_completed and room_prog.status != "COMPLETED":
            room_prog.status = "COMPLETED"
            room_prog.completed_at = datetime.utcnow()
        elif room_prog.status != "COMPLETED":
            room_prog.status = "IN_PROGRESS"

        session.add(room_prog)
        session.commit()
        return is_completed, room_prog.status


task_validator = TaskValidator()


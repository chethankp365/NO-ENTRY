"""
NO ENTRY Cybersecurity Academy - Purple Team Track: Rooms 17–20
Canonical Implementation of:
- Room 17: EDR Telemetry Blinding & Bypass Emulation (purple-17-edr-bypass-emulation)
- Room 18: TTP Heatmap Generation & Coverage Scoring (purple-18-ttp-heatmap-generation)
- Room 19: Continuous Security Validation & Automated Testing (purple-19-continuous-security-validation)
- Room 20: Purple Team Capstone: Full Adversary Emulation Exercise (purple-20-capstone-purple-exercise)

Completes the entire 20-room Purple Team curriculum.
Each room provides deep technical concepts, 6 tasks (350 XP per room),
session-bound validation, anti-forgery guards, and 4-question technical quizzes.
"""

from typing import List
from backend.app.academy.models import (
    QuizQuestion,
    RoomConcept,
    RoomDefinition,
    RoomStatus,
    TaskDefinition,
    TaskType,
    TrackEnum,
)


# ============================================================================
# ROOM 17: EDR TELEMETRY BLINDING & BYPASS EMULATION (PORT 8317)
# ============================================================================

ROOM_PURPLE_17_CONCEPT = RoomConcept(
    overview=(
        "Endpoint Detection & Response (EDR) platforms monitor system execution using user-mode API hooking (in ntdll.dll), "
        "the Antimalware Scan Interface (AMSI), and kernel-level event tracing (ETW-TI). Advanced adversaries attempt to "
        "blind defensive sensors by unhooking DLLs in memory, patching `AmsiScanBuffer` return codes, or disabling ETW sessions. "
        "Purple teaming evaluates whether defensive teams maintain visibility through kernel callbacks and behavioral fallbacks "
        "when user-mode sensors are tampered with."
    ),
    simple_analogy=(
        "Imagine a high-security facility monitored by both hallway security guards (user-mode hooks) and ceiling vibration "
        "sensors wired directly to the bedrock foundation (kernel telemetry). If an intruder sprays paint over the guard's "
        "spectacles (patching AMSI in user space), the guard cannot read the intruder's ID badge. A naive security team is blinded; "
        "a mature Purple Team ensures the bedrock vibration sensors still sound an alarm because the physical movement itself "
        "violates policy regardless of the guard's obstructed view."
    ),
    technical_term="EDR User-Mode Hooking, AMSI Memory Patching & ETW-TI Telemetry Blinding",
    technical_definition=(
        "User-mode EDR agents inject monitoring DLLs into newly created processes, overwriting beginning bytes of native API stubs "
        "in `ntdll.dll` (e.g. `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`) with `JMP` instructions directing control flow to EDR inspection routines. "
        "Adversaries bypass these hooks by: 1) Reloading a clean copy of `ntdll.dll` from disk (API unhooking); 2) Patching `amsi.dll!AmsiScanBuffer` "
        "to return `AMSI_RESULT_CLEAN` (0x0); or 3) Disabling Event Tracing for Windows (`EtwEventWrite`). "
        "Robust defense relies on kernel-level Minifilter drivers, Event Tracing for Windows Threat Intelligence (ETW-TI), and "
        "detecting the memory protection modifications (`PAGE_EXECUTE_READWRITE`) required to perform the unhooking."
    ),
    cybersecurity_context=(
        "Adversaries such as APT29 and FIN7 routinely deploy in-memory AMSI patches and direct system calls to evade EDR. "
        "Purple teaming tests whether defensive engineering has deployed rules alerting on memory-patching primitives and fallback "
        "heuristics rather than relying exclusively on user-mode signatures."
    ),
    why_it_matters=(
        "If a defensive organization relies solely on user-mode hooks, any adversary who executes code can manipulate their own "
        "process memory space to blind the defense completely. Validating that kernel-level telemetry alerts on the blinding action "
        "itself turns the evasion technique into a high-confidence tripwire."
    ),
    demonstration=(
        "1. Inspect prepared EDR telemetry events documenting AMSI memory modification attempts.\n"
        "2. Identify the memory protection constant and API function targeted for in-memory byte patching.\n"
        "3. Emulate an AMSI bypass and API unhooking routine against target port 8317.\n"
        "4. Deploy an ETW-TI behavioral correlation rule that detects `AmsiScanBuffer` tampering.\n"
        "5. Complete the validation challenge to confirm fallback detection efficacy."
    ),
    remediation_guide=(
        "Deploy kernel-mode telemetry via ETW-TI (Event Tracing for Windows Threat Intelligence); enforce Arbitrary Code Guard (ACG) "
        "and Code Integrity Guard (CIG) to prevent dynamic unsigned code modification; alert on `VirtualProtect` calls altering `ntdll.dll` "
        "or `amsi.dll` code section permissions to `PAGE_EXECUTE_READWRITE`; and implement behavioral detections on post-bypass activity."
    ),
)

ROOM_PURPLE_17_TASKS = [
    TaskDefinition(
        task_id="task-01-edr-hooking-mechanics",
        order=1,
        title="Understand EDR User-Mode Hooking & AMSI Architecture",
        instructions=(
            "Review the technical overview for endpoint telemetry and EDR evasion.\n\n"
            "In Windows, Microsoft provides an interface that allows applications and scripting engines (PowerShell, WScript, VBA) "
            "to pass in-memory script contents to installed antivirus/EDR software before execution. Adversaries bypass this control "
            "by patching memory bytes in `amsi.dll`.\n\n"
            "What 4-letter acronym designates the Antimalware Scan Interface in Windows?"
        ),
        task_type=TaskType.QUESTION,
        question="What 4-letter acronym represents the Antimalware Scan Interface in Windows?",
        hint="It starts with 'A' and stands for Antimalware Scan Interface.",
        accepted_answers=["AMSI", "amsi", "Antimalware Scan Interface"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-edr-telemetry-analysis",
        order=2,
        title="Analyze AMSI Patching & Memory Telemetry",
        instructions=(
            "Inspect the prepared EDR memory telemetry log on your attacker workstation:\n"
            "`cat /var/log/edr_bypass/amsi_etw_events.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8317/api/edr-bypass/telemetry`\n\n"
            "Identify the specific function name within `amsi.dll` that was patched by the adversary to force an in-memory clean verdict."
        ),
        task_type=TaskType.QUESTION,
        question="What specific exported function in amsi.dll was targeted for in-memory byte patching?",
        hint="Look for the function name starting with 'AmsiScan...' in the telemetry log.",
        accepted_answers=["AmsiScanBuffer", "amsiscanbuffer", "amsi.dll!AmsiScanBuffer"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-edr-mapping",
        order=3,
        title="Map Telemetry Blinding to MITRE ATT&CK",
        instructions=(
            "Adversaries manipulate defensive tools and in-memory sensors to prevent security mechanisms from collecting telemetry.\n\n"
            "Under the Defense Evasion tactic, disabling or modifying defensive tools and their event collection mechanisms "
            "is cataloged under technique T1562.\n\n"
            "Submit the MITRE ATT&CK sub-technique ID for Impair Defenses: Disable or Modify Tools (e.g. T1562.001)."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Impair Defenses: Disable or Modify Tools?",
        hint="The format is T1562.001.",
        accepted_answers=["T1562.001", "t1562.001", "T1562.001 - Disable or Modify Tools"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-edr-bypass-emulation",
        order=4,
        title="Emulate In-Memory AMSI Bypass & API Unhooking",
        instructions=(
            "Execute an in-memory AMSI patch and API unhooking simulation using the EDR bypass tool:\n"
            "`python3 /home/operator/tools/edr_bypass_tool.py --emulate-bypass`\n\n"
            "This command simulates memory permission modification on `AmsiScanBuffer` and evaluates EDR hook integrity.\n"
            "Upon successful execution, the tool will return a verification token.\n"
            "Submit the verification token to validate practical emulation."
        ),
        task_type=TaskType.COMMAND,
        question="Run the EDR bypass emulation tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/edr_bypass_tool.py --emulate-bypass' in the lab terminal.",
        accepted_answers=["EDR_BYPASS_EMULATION_VERIFIED", "AMSI_BYPASS_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-edr-bypass-challenge",
        order=5,
        title="Deploy ETW-TI Fallback Detection & Validate Challenge",
        instructions=(
            "To counter user-mode telemetry blinding, defensive engineers deploy kernel-mode ETW Threat Intelligence (ETW-TI) "
            "monitoring that alerts whenever memory protection is altered to writable executable on security DLLs.\n\n"
            "1. Deploy ETW-TI behavioral correlation rules:\n"
            "`python3 /home/operator/tools/edr_bypass_tool.py --tune-etw`\n\n"
            "2. Complete the validation challenge:\n"
            "`python3 /home/operator/tools/edr_bypass_tool.py --challenge`\n\n"
            "Submit the verification token to confirm that the telemetry blinding attempt triggered a fallback detection alert."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy ETW-TI detection rules, complete the challenge, and submit the verification token.",
        hint="Run '--tune-etw' followed by '--challenge' using the EDR bypass tool.",
        accepted_answers=["EDR_BYPASS_DETECTION_VALIDATED", "ETW_TI_FALLBACK_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-edr-quiz",
        order=6,
        title="Assess Technical Understanding of EDR Bypasses",
        instructions="Complete the 4-question technical assessment on user-mode hooks, AMSI patching, and kernel ETW-TI telemetry.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why can an unprivileged process patch `AmsiScanBuffer` inside its own virtual address space?",
                options=[
                    "Because user processes have write permission over their own virtual address space memory pages",
                    "Because the Windows kernel is disabled during script execution",
                    "Because AMSI is only designed to run inside Linux kernel modules",
                    "Because user processes inherit full domain controller rights by default",
                ],
                correct_index=0,
                explanation="In Windows user mode, a process has sovereignty over its own virtual memory space; it can call `VirtualProtect` to make its loaded code pages writable and patch functions like `AmsiScanBuffer`.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the primary advantage of Event Tracing for Windows Threat Intelligence (ETW-TI) over user-mode hooking?",
                options=[
                    "ETW-TI events are generated directly inside the kernel and cannot be unhooked or tampered with by user-mode processes",
                    "ETW-TI completely replaces the need for any antivirus software or firewalls",
                    "ETW-TI automatically reboots the computer whenever PowerShell opens",
                    "ETW-TI encrypts all files on the hard drive with AES-256",
                ],
                correct_index=0,
                explanation="Kernel-level ETW-TI telemetry originates from the operating system kernel, making it immune to user-mode API unhooking and memory patching.",
            ),
            QuizQuestion(
                id="q3",
                question="How does API unhooking restore native system call functionality in an EDR-monitored process?",
                options=[
                    "By reading the clean `.text` code section of `ntdll.dll` from disk and overwriting the in-memory hooked bytes",
                    "By deleting `ntdll.dll` from the system directory",
                    "By renaming `powershell.exe` to `calc.exe`",
                    "By changing the DNS server IP address",
                ],
                correct_index=0,
                explanation="Unhooking reads the original unmodified native API stubs from `ntdll.dll` on disk and copies them over the hooked in-memory stubs, removing EDR detour jumps.",
            ),
            QuizQuestion(
                id="q4",
                question="Which defensive strategy reliably detects API unhooking and AMSI patching without relying on user-mode hooks?",
                options=[
                    "Alerting on `PAGE_EXECUTE_READWRITE` memory permission modifications on DLL code sections via kernel callbacks",
                    "Disabling all user account passwords across the domain",
                    "Blocking all outbound TCP traffic on port 443",
                    "Configuring web servers to use HTTP instead of HTTPS",
                ],
                correct_index=0,
                explanation="Kernel sensors monitor memory allocation and protection changes; changing an executable code section in `ntdll` or `amsi` to writable triggers a high-fidelity evasion alert.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_17_DEFINITION = RoomDefinition(
    room_id="purple-17-edr-bypass-emulation",
    track=TrackEnum.PURPLE,
    room_number=17,
    title="EDR Telemetry Blinding & Bypass Emulation",
    short_description="Test AMSI bypasses and API unhooking in a controlled lab to evaluate behavioral fallback detections.",
    difficulty="Advanced",
    estimated_duration="75 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_17_CONCEPT,
    tasks=ROOM_PURPLE_17_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8317,
    learning_objectives=[
        "Understand user-mode EDR architecture, API inline hooks, and AMSI script interception.",
        "Inspect telemetry logs documenting in-memory function patching and protection manipulation.",
        "Emulate an AMSI bypass and API unhooking routine in an isolated sandbox target.",
        "Deploy kernel-level ETW-TI fallback detection rules to catch telemetry blinding.",
        "Evaluate defensive resiliency against defense evasion techniques under MITRE ATT&CK T1562.001.",
    ],
    assessment_criteria=[
        "Identify AMSI architecture and targeted functions like AmsiScanBuffer.",
        "Extract memory modification parameters from EDR telemetry events.",
        "Successfully execute EDR bypass emulation using the dedicated CLI tool.",
        "Deploy ETW-TI fallback rules and confirm challenge verification token.",
        "Attain 100% on the EDR bypass technical assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for EDR mechanics and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)


# ============================================================================
# ROOM 18: TTP HEATMAP GENERATION & COVERAGE SCORING (PORT 8318)
# ============================================================================

ROOM_PURPLE_18_CONCEPT = RoomConcept(
    overview=(
        "Adversary emulation exercises generate massive volumes of validation data. To make this data actionable for "
        "defenders, engineers, and executive leadership, Purple Teams synthesize technical test results into visual "
        "TTP (Tactics, Techniques, and Procedures) heatmaps and quantitative detection coverage scores. "
        "Using frameworks such as MITRE ATT&CK Navigator, teams assign coverage scores (Blocked, Detected, Alerted, Visibility Only, "
        "or Zero Coverage), identify systemic blind spots across kill-chain phases, and prioritize defensive engineering investments."
    ),
    simple_analogy=(
        "Think of a building's thermal energy audit during winter. Rather than handing a homeowner an 800-page list of temperatures "
        "for every single brick, an engineer provides an infrared thermal heatmap image. Blue areas indicate well-insulated walls "
        "(strong detections), while bright red and yellow areas immediately highlight drafty windows and unsealed doors "
        "(zero-coverage blind spots). A TTP heatmap gives leadership that exact visual clarity across their entire threat model."
    ),
    technical_term="Adversary Emulation Coverage Scoring & MITRE ATT&CK Navigator Heatmaps",
    technical_definition=(
        "A TTP coverage heatmap is a structured visualization mapping organizational detection and prevention capabilities against "
        "the MITRE ATT&CK enterprise matrix. Techniques are assigned numerical or categorical scores based on empirical testing: "
        "Score 0 (No visibility/log collection); Score 1 (Telemetry logged but no alert); Score 2 (Alert generated but required manual review); "
        "Score 3 (Automated detection & containment). Heatmap JSON layers (such as ATT&CK Navigator layer files) calculate aggregate coverage "
        "percentages across tactics (e.g. Initial Access: 80%, Credential Access: 40%), revealing specific security blind spots."
    ),
    cybersecurity_context=(
        "Executive leadership and SOC managers use ATT&CK heatmaps to justify security budgets, measure quarterly detection improvements, "
        "and track remediation progress after Purple Team engagements. Validating that heatmaps reflect real empirical test results "
        "ensures detection engineering focuses on actual threat exposures rather than hypothetical compliance checkboxes."
    ),
    why_it_matters=(
        "Without standardized coverage scoring, organizations suffer from the 'illusion of security'—assuming that purchasing an EDR "
        "or SIEM grants 100% protection. Generating evidence-backed heatmaps proves exactly where detections exist and where gaps remain."
    ),
    demonstration=(
        "1. Inspect prepared matrix coverage telemetry documenting validation test results across ATT&CK tactics.\n"
        "2. Identify the technique and tactic suffering from zero visibility and unmonitored execution.\n"
        "3. Emulate a coverage scoring calculation and generate a standardized ATT&CK Navigator layer file.\n"
        "4. Deploy a gap-closing overlay policy that updates detection coverage scores across the matrix.\n"
        "5. Complete the validation challenge to confirm heatmap accuracy."
    ),
    remediation_guide=(
        "Ingest adversary emulation outcomes into centralized coverage dashboards; prioritize engineering sprint tasks on techniques "
        "with Score 0 (no logs); configure SIEM data onboarding for missing data sources; and establish quarterly re-testing benchmarks "
        "to verify that remediated techniques maintain active detection status."
    ),
)

ROOM_PURPLE_18_TASKS = [
    TaskDefinition(
        task_id="task-01-heatmap-foundations",
        order=1,
        title="Understand TTP Heatmaps & ATT&CK Navigator",
        instructions=(
            "Review the technical overview for threat coverage scoring and visual heatmaps.\n\n"
            "MITRE provides an open-source web application and JSON layer format widely used by Purple Teams to visualize "
            "technique coverage, assign numerical scores, and compare offensive testing against defensive visibility.\n\n"
            "Identify the standard tool name created by MITRE for generating interactive matrix heatmaps (e.g. ATT&CK ...)."
        ),
        task_type=TaskType.QUESTION,
        question="What is the name of the standard MITRE tool used to generate interactive matrix heatmaps?",
        hint="It is known as the 'ATT&CK Navigator' (or MITRE ATT&CK Navigator).",
        accepted_answers=["ATT&CK Navigator", "att&ck navigator", "MITRE ATT&CK Navigator", "Navigator"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-matrix-coverage-analysis",
        order=2,
        title="Analyze Empirical Matrix Telemetry for Visibility Gaps",
        instructions=(
            "Inspect the prepared ATT&CK coverage matrix telemetry on your attacker workstation:\n"
            "`cat /var/log/heatmap/attck_coverage_matrix.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8318/api/heatmap/telemetry`\n\n"
            "Analyze the coverage scores across the evaluated tactics. Identify the technique ID (e.g. T1003) that is currently "
            "marked with a coverage score of 0 (ZERO_COVERAGE / completely unmonitored)."
        ),
        task_type=TaskType.QUESTION,
        question="Which MITRE ATT&CK technique ID has a coverage score of 0 (ZERO_COVERAGE) in the matrix telemetry?",
        hint="Look for the technique under Credential Access with zero score (e.g. T1003).",
        accepted_answers=["T1003", "t1003", "T1003 - OS Credential Dumping", "T1003.001"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-coverage-metrics",
        order=3,
        title="Understand Scoring Models & Gap Remediation",
        instructions=(
            "In Purple Team scoring models, each technique receives an empirical rating based on testing outcomes.\n\n"
            "When an organization successfully detects and automatically contains an emulated adversary technique, that technique "
            "is scored at the highest level of defensive efficacy.\n\n"
            "What term refers to the quantifiable metric representing the percentage of prioritized threat techniques an organization "
            "can successfully observe or block across the ATT&CK matrix?"
        ),
        task_type=TaskType.QUESTION,
        question="What term refers to the percentage of ATT&CK techniques with active defensive visibility or prevention?",
        hint="It consists of two words starting with 'D' and 'C' (e.g. Detection ...).",
        accepted_answers=["Detection Coverage", "detection coverage", "Coverage Score", "TTP Coverage"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-heatmap-emulation",
        order=4,
        title="Compile Empirical Test Results & Generate Heatmap Layer",
        instructions=(
            "Run the heatmap compilation tool to process test outcomes and generate an ATT&CK Navigator layer:\n"
            "`python3 /home/operator/tools/heatmap_tool.py --emulate-scoring`\n\n"
            "This command aggregates validation logs, computes coverage scores per tactic, and generates a standardized layer.\n"
            "Submit the returned verification token to record task completion."
        ),
        task_type=TaskType.COMMAND,
        question="Run the heatmap tool to generate the coverage layer and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/heatmap_tool.py --emulate-scoring' in the lab terminal.",
        accepted_answers=["HEATMAP_EMULATION_VERIFIED", "ATTACK_NAVIGATOR_LAYER_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-heatmap-challenge",
        order=5,
        title="Deploy Gap-Closing Overlay & Validate Final Posture",
        instructions=(
            "Remediation engineering updates detections for unmonitored techniques, elevating the overall organizational coverage score.\n\n"
            "1. Deploy the detection overlay policy to close identified visibility gaps:\n"
            "`python3 /home/operator/tools/heatmap_tool.py --tune-overlay`\n\n"
            "2. Complete the validation challenge:\n"
            "`python3 /home/operator/tools/heatmap_tool.py --challenge`\n\n"
            "Submit the verification token to confirm that all evaluated techniques meet minimum defensive coverage standards."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy the detection overlay, complete the challenge, and submit the verification token.",
        hint="Run '--tune-overlay' followed by '--challenge' using the heatmap tool.",
        accepted_answers=["HEATMAP_COVERAGE_VALIDATED", "TTP_POSTURE_VERIFIED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-heatmap-quiz",
        order=6,
        title="Assess Technical Understanding of TTP Coverage Heatmaps",
        instructions="Complete the 4-question technical assessment on ATT&CK Navigator layers, coverage scoring, and gap remediation.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary operational purpose of an ATT&CK Navigator heatmap layer?",
                options=[
                    "To visually communicate empirical detection coverage and visibility gaps across tactics to engineers and leadership",
                    "To automatically reformat hard drives on unpatched servers",
                    "To generate random passwords for all domain administrators",
                    "To replace firewalls with social media marketing campaigns",
                ],
                correct_index=0,
                explanation="ATT&CK Navigator layers provide an intuitive, color-coded visual representation of test results, demonstrating where detections are robust and where blind spots exist.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is relying solely on 'total number of SIEM alerts' a flawed metric compared to TTP coverage percentage?",
                options=[
                    "Because high alert volume often indicates noisy, low-fidelity rules rather than broad visibility across the adversary lifecycle",
                    "Because SIEM alerts can only be generated in plaintext ASCII",
                    "Because SIEM platforms are legally prohibited from monitoring Windows endpoints",
                    "Because alerts expire within 10 seconds of creation",
                ],
                correct_index=0,
                explanation="Alert volume is a vanity metric; a million alerts on simple port scans provides zero protection if an adversary executes Kerberoasting or lateral movement with zero visibility.",
            ),
            QuizQuestion(
                id="q3",
                question="In an ATT&CK coverage scoring model, what does a score of 0 typically signify?",
                options=[
                    "Zero visibility: the adversary activity produces no collected telemetry or alerts in defensive platforms",
                    "The technique has been permanently patched in the Windows kernel",
                    "The technique was executed by an automated AI agent",
                    "The target host has been disconnected from electrical power",
                ],
                correct_index=0,
                explanation="A score of 0 indicates complete blindness: the defender does not collect the requisite log sources to observe the technique.",
            ),
            QuizQuestion(
                id="q4",
                question="How should a Purple Team prioritize remediation when presented with a newly compiled TTP heatmap?",
                options=[
                    "Prioritize techniques that are actively leveraged by known threat actors targeting the organization's specific industry",
                    "Randomly select techniques using a dice roll",
                    "Only remediate techniques that do not require any configuration changes",
                    "Ignore all findings until the next annual external penetration test",
                ],
                correct_index=0,
                explanation="Threat-informed defense dictates prioritizing techniques based on adversary intelligence relevant to the organization's sector, threat model, and critical assets.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_18_DEFINITION = RoomDefinition(
    room_id="purple-18-ttp-heatmap-generation",
    track=TrackEnum.PURPLE,
    room_number=18,
    title="TTP Heatmap Generation & Coverage Scoring",
    short_description="Compile attack validation results into interactive ATT&CK Navigator heatmaps for leadership review.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_18_CONCEPT,
    tasks=ROOM_PURPLE_18_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8318,
    learning_objectives=[
        "Master the methodology of synthesizing offensive test data into structured detection coverage models.",
        "Analyze empirical matrix telemetry to identify systemic visibility gaps across ATT&CK tactics.",
        "Generate standardized MITRE ATT&CK Navigator JSON layer files displaying color-coded posture.",
        "Deploy gap-closing remediation policies and verify updated coverage thresholds.",
        "Communicate technical risk effectively using threat-informed defense metrics.",
    ],
    assessment_criteria=[
        "Identify MITRE ATT&CK Navigator capabilities and file formats.",
        "Locate zero-coverage techniques from raw validation telemetry.",
        "Execute heatmap emulation and generate valid Navigator layer data.",
        "Deploy detection overlays and achieve challenge verification token.",
        "Score 100% on the TTP heatmap technical assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for heatmap methodology and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)


# ============================================================================
# ROOM 19: CONTINUOUS SECURITY VALIDATION & AUTOMATED TESTING (PORT 8319)
# ============================================================================

ROOM_PURPLE_19_CONCEPT = RoomConcept(
    overview=(
        "Manual Purple Team exercises are invaluable, but adversary techniques evolve rapidly while enterprise environments "
        "experience continuous configuration drift, software updates, and SIEM parser modifications. Continuous Security Validation (CSV) "
        "transforms Purple Teaming into an automated, recurring discipline. By integrating automated adversary emulation engines "
        "(such as Atomic Red Team or Caldera) into CI/CD pipelines, organizations continuously trigger controlled attack tests, "
        "verify that detection alerts fire as expected, and instantly flag regression when a detection rule breaks."
    ),
    simple_analogy=(
        "Consider automated software testing. Software engineers don't wait 6 months to test if their website's checkout button works; "
        "they write automated unit and integration tests that run on every single code commit. Continuous security validation applies "
        "that exact principle to defense: instead of waiting for an annual penetration test to discover that a Windows update broke "
        "your PowerShell logging, automated tests execute the technique daily and sound an immediate alarm if the alert fails to trigger."
    ),
    technical_term="Continuous Security Validation (CSV), Detection Drift & Automated Emulation Pipelines",
    technical_definition=(
        "Continuous Security Validation (CSV) is the programmatic execution of standardized adversary techniques to validate "
        "defensive controls on an ongoing basis. Automated execution frameworks (e.g. Atomic Red Team invoked via PowerShell/Bash, "
        "MITRE Caldera plugins) execute safe unit tests for specific ATT&CK technique IDs. Telemetry collectors verify whether: "
        "1) The expected endpoint log was generated; 2) The SIEM pipeline parsed the event fields properly; and 3) The detection rule "
        "fired within established Mean Time to Detect (MTTD) thresholds. Failures are treated as regression bugs and tracked in issue queues."
    ),
    cybersecurity_context=(
        "Detection engineering teams manage hundreds of detection rules. A simple parser update in a cloud log shipper or a Windows "
        "Sysmon schema change can silently break a critical rule. CSV guarantees that defensive coverage is verified continuously, "
        "alerting security teams to detection drift before adversaries exploit the gap."
    ),
    why_it_matters=(
        "Security controls degrade over time without anyone noticing. Firewalls get modified during outages, agents crash, and log "
        "formats change. Without automated continuous validation, defenders discover broken detections during a live ransomware incident."
    ),
    demonstration=(
        "1. Inspect continuous validation pipeline run history logs documenting daily recurring emulation passes.\n"
        "2. Identify the specific detection rule and technique that suffered a silent regression failure.\n"
        "3. Emulate an automated regression execution cycle against target port 8319.\n"
        "4. Deploy automated pipeline guardrails that block broken parser updates and restore detection fidelity.\n"
        "5. Complete the validation challenge to certify automated pipeline resiliency."
    ),
    remediation_guide=(
        "Implement detection-as-code pipelines with automated pre-merge testing against synthetic attack logs; schedule automated "
        "daily executions of low-impact atomic tests in staging environments; configure alert regression notifications when a test "
        "fails to trigger an alert; and track Mean Time to Detect (MTTD) trends over time."
    ),
)

ROOM_PURPLE_19_TASKS = [
    TaskDefinition(
        task_id="task-01-continuous-validation-foundations",
        order=1,
        title="Understand Continuous Security Validation (CSV)",
        instructions=(
            "Review the technical overview for automated adversary emulation and regression testing.\n\n"
            "Open-source frameworks like Atomic Red Team provide modular, scripted unit tests mapped to MITRE ATT&CK techniques "
            "designed to be executed automatically in continuous testing pipelines.\n\n"
            "Identify the popular open-source adversary emulation library developed by Red Canary that provides scripted 'atomic' tests."
        ),
        task_type=TaskType.QUESTION,
        question="What open-source library developed by Red Canary provides scripted tests mapped to ATT&CK?",
        hint="It consists of three words: 'Atomic Red Team'.",
        accepted_answers=["Atomic Red Team", "atomic red team", "AtomicRedTeam", "ART"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-pipeline-run-telemetry",
        order=2,
        title="Analyze Pipeline Execution Logs for Detection Drift",
        instructions=(
            "Inspect the continuous validation execution history log on your attacker workstation:\n"
            "`cat /var/log/continuous_validation/pipeline_run_history.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8319/api/continuous-validation/telemetry`\n\n"
            "Identify the technique ID (e.g. T1059.001) that experienced a regression failure where the emulation ran successfully "
            "but the corresponding detection rule failed to generate an alert."
        ),
        task_type=TaskType.QUESTION,
        question="Which technique ID suffered a detection regression failure in the continuous validation history log?",
        hint="Look for the test entry with 'status': 'REGRESSION_DETECTED' (e.g. T1059.001).",
        accepted_answers=["T1059.001", "t1059.001", "T1059.001 - PowerShell", "T1059"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-automation-metrics",
        order=3,
        title="Track Mean Time to Detect (MTTD) & Drift Metrics",
        instructions=(
            "Continuous validation pipelines measure the exact duration between attack initiation and SIEM alert generation.\n\n"
            "What 4-letter operational cybersecurity metric represents the average time elapsed between an adversary executing "
            "an attack technique and the security operations team receiving an actionable detection alert?"
        ),
        task_type=TaskType.QUESTION,
        question="What 4-letter acronym represents the Mean Time to Detect metric in security operations?",
        hint="It stands for Mean Time to Detect (starts with 'M' and ends with 'D').",
        accepted_answers=["MTTD", "mttd", "Mean Time to Detect"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-continuous-validation-emulation",
        order=4,
        title="Execute Automated Adversary Emulation Pipeline",
        instructions=(
            "Trigger a continuous security validation test run using the automated validation tool:\n"
            "`python3 /home/operator/tools/continuous_validation_tool.py --emulate-pipeline`\n\n"
            "This command simulates executing scheduled atomic tests across multiple techniques and evaluates real-time alert latency.\n"
            "Submit the returned verification token to record completion."
        ),
        task_type=TaskType.COMMAND,
        question="Execute the automated validation tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/continuous_validation_tool.py --emulate-pipeline' in the lab terminal.",
        accepted_answers=["CONTINUOUS_VALIDATION_EMULATION_VERIFIED", "AUTOMATED_CSV_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-continuous-validation-challenge",
        order=5,
        title="Deploy Regression Guardrails & Validate Pipeline",
        instructions=(
            "To resolve detection drift, engineers update SIEM field extractors and add regression tripwires to CI pipelines.\n\n"
            "1. Deploy automated regression guardrails and parser corrections:\n"
            "`python3 /home/operator/tools/continuous_validation_tool.py --tune-guardrails`\n\n"
            "2. Complete the validation challenge:\n"
            "`python3 /home/operator/tools/continuous_validation_tool.py --challenge`\n\n"
            "Submit the returned verification token once all continuous tests pass with 100% alert verification."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy regression guardrails, complete the challenge, and submit the verification token.",
        hint="Run '--tune-guardrails' followed by '--challenge' using the continuous validation tool.",
        accepted_answers=["CONTINUOUS_VALIDATION_DETECTION_VALIDATED", "CSV_GUARDRAILS_ARMED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-continuous-val-quiz",
        order=6,
        title="Assess Technical Understanding of Continuous Validation",
        instructions="Complete the 4-question technical assessment on automated emulation, detection drift, and MTTD metrics.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is 'detection drift' in enterprise security environments?",
                options=[
                    "The silent degradation or failure of detection rules over time due to system updates, parser changes, or log schema shifts",
                    "A technique where malware moves laterally across Wi-Fi networks",
                    "A physical security malfunction where server racks shift position",
                    "The process of deleting obsolete employee email accounts",
                ],
                correct_index=0,
                explanation="Detection drift occurs when changes to infrastructure, operating systems, or log shippers silently break the query logic of previously working detection rules.",
            ),
            QuizQuestion(
                id="q2",
                question="How does Continuous Security Validation (CSV) fundamentally differ from an annual penetration test?",
                options=[
                    "CSV executes programmatic, repeatable attack unit tests on a recurring daily or weekly schedule rather than once a year",
                    "CSV requires hiring an external team of 20 consultants for each run",
                    "CSV only tests website favicon images",
                    "CSV permanently disables all defensive firewalls during testing",
                ],
                correct_index=0,
                explanation="CSV automates testing into an ongoing engineering cadence, validating that detections remain functional continuously rather than testing posture at a single point in time.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is automated deconfliction critical when running automated adversary emulation in staging or production?",
                options=[
                    "To ensure SOC analysts can immediately distinguish automated scheduled tests from real unauthorized attacker activity",
                    "To prevent hard drives from running out of disk space",
                    "To allow attackers to read company emails anonymously",
                    "To automatically pay cloud subscription invoices",
                ],
                correct_index=0,
                explanation="Deconfliction logging ties each automated simulation execution to a registered exercise ID so defenders can correlate alarms with test timestamps without triggering false incident responses.",
            ),
            QuizQuestion(
                id="q4",
                question="Which practice best prevents broken detection rules from being deployed to production SIEM systems?",
                options=[
                    "Detection-as-Code with automated CI pipelines testing rules against positive and negative synthetic log corpuses before merge",
                    "Writing all detection rules by hand directly in the live production web portal without peer review",
                    "Disabling all alert notifications during weekends",
                    "Running detection rules only once per calendar year",
                ],
                correct_index=0,
                explanation="Treating detections as software code in Git repositories with automated CI unit tests ensures that syntax errors and query regressions are caught before reaching production.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_19_DEFINITION = RoomDefinition(
    room_id="purple-19-continuous-security-validation",
    track=TrackEnum.PURPLE,
    room_number=19,
    title="Continuous Security Validation & Automated Testing",
    short_description="Deploy automated adversary emulation frameworks (Caldera/Atomic) for daily recurring checks.",
    difficulty="Advanced",
    estimated_duration="60 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_19_CONCEPT,
    tasks=ROOM_PURPLE_19_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8319,
    learning_objectives=[
        "Understand Continuous Security Validation (CSV) principles, detection drift, and automated testing architecture.",
        "Inspect execution history telemetry to identify detection rule regressions and parser breakages.",
        "Execute automated atomic emulation test cycles against isolated targets.",
        "Deploy automated CI/CD guardrails and tripwires to prevent detection query regressions.",
        "Measure and optimize Mean Time to Detect (MTTD) across recurring adversary emulation runs.",
    ],
    assessment_criteria=[
        "Identify automated adversary emulation frameworks including Atomic Red Team.",
        "Locate detection drift and regression failures in pipeline history logs.",
        "Successfully trigger automated emulation via the dedicated CSV tool.",
        "Deploy regression guardrails and achieve challenge verification token.",
        "Score 100% on the continuous validation technical assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for continuous validation concepts and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)


# ============================================================================
# ROOM 20: PURPLE TEAM CAPSTONE: FULL ADVERSARY EMULATION (PORT 8320)
# ============================================================================

ROOM_PURPLE_20_CONCEPT = RoomConcept(
    overview=(
        "The Purple Team Capstone is the comprehensive culmination of the 20-room Purple Team curriculum. "
        "Learners orchestrate an end-to-end adversary emulation exercise modeled on a sophisticated threat actor "
        "(APT29 / Cozy Bear). The exercise requires executing a multi-stage attack lifecycle: initial execution via scripted download cradles, "
        "in-memory telemetry blinding, Active Directory Kerberoasting, lateral movement across internal network segments, "
        "encrypted C2 beaconing, and automated data exfiltration staging. At each phase, learners observe the corresponding defensive telemetry, "
        "identify blind spots, tune enterprise detection rules, and achieve full end-to-end defensive certification."
    ),
    simple_analogy=(
        "Think of a full-scale orchestral symphony. In earlier rooms, you mastered individual instruments—the violin of Reconnaissance, "
        "the trumpet of Privilege Escalation, the drums of Kerberoasting, and the cello of C2 Beaconing. The Capstone brings the entire "
        "orchestra together into a unified performance, conducting both the offensive attack cadence and the defensive acoustic monitoring "
        "in perfect harmony to ensure no discordant note escapes detection."
    ),
    technical_term="Comprehensive Multi-Stage Adversary Emulation & Collaborative Defense Certification",
    technical_definition=(
        "A multi-stage adversary emulation exercise simulates the complete cyber kill chain of a specific threat group (e.g. APT29). "
        "The campaign progresses through distinct tactical phases: 1) Execution (T1059.001); 2) Defense Evasion & Telemetry Blinding (T1562.001); "
        "3) Credential Access via Kerberoasting (T1558.003); 4) Lateral Movement via Remote Services (T1021.002); 5) Command and Control via "
        "encrypted HTTPS beaconing (T1071.001); and 6) Exfiltration of staged archives (T1041). Defensive validation confirms that SIEM correlation "
        "rules link individual low-severity events into a high-confidence enterprise incident, triggering automated host containment."
    ),
    cybersecurity_context=(
        "Enterprise security operations must be capable of detecting and interrupting sophisticated multi-stage intrusions before "
        "adversaries accomplish their objectives. Conducting full-lifecycle Purple Team exercises proves that defensive controls "
        "operate cohesively across endpoint, network, identity, and cloud telemetry layers."
    ),
    why_it_matters=(
        "Individual detection rules often perform well in isolation but fail when an adversary combines subtle, low-noise techniques. "
        "The Capstone verifies cross-stage correlation, ensuring defenders can detect, track, and eradicate an advanced threat across "
        "every phase of an intrusion."
    ),
    demonstration=(
        "1. Inspect multi-stage APT29 campaign telemetry events encompassing all 6 intrusion phases.\n"
        "2. Identify the correlated campaign identifier and critical Kerberoasting and C2 beacons.\n"
        "3. Emulate the full end-to-end adversary campaign against capstone target port 8320.\n"
        "4. Deploy enterprise correlation rules linking initial execution to lateral movement and egress.\n"
        "5. Complete the validation challenge to earn the Purple Team Capstone certification."
    ),
    remediation_guide=(
        "Implement multi-stage SIEM correlation logic that aggregates events across tactics within a rolling time window; "
        "enforce automated host network isolation upon detection of simultaneous credential dumping and external beaconing; "
        "and maintain living adversary emulation playbooks re-tested on a continuous quarterly schedule."
    ),
)

ROOM_PURPLE_20_TASKS = [
    TaskDefinition(
        task_id="task-01-capstone-threat-intel",
        order=1,
        title="Analyze Threat Intelligence for APT29 Emulation",
        instructions=(
            "Review the technical overview for the Purple Team Capstone.\n\n"
            "This capstone exercise models an advanced persistent threat actor known for sophisticated in-memory evasion, "
            "Kerberos ticket attacks, and stealthy HTTPS beaconing, famously attributed to Russian state intelligence (SVR).\n\n"
            "Identify the standard 5-character threat actor designation commonly used by MITRE ATT&CK for Cozy Bear (e.g. APT...)."
        ),
        task_type=TaskType.QUESTION,
        question="What 5-character designation does MITRE ATT&CK assign to the Cozy Bear threat group?",
        hint="It starts with 'APT' followed by a two-digit number (e.g. APT29).",
        accepted_answers=["APT29", "apt29", "APT-29", "Cozy Bear"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-capstone-campaign-telemetry",
        order=2,
        title="Analyze End-to-End Campaign Telemetry Across Tactics",
        instructions=(
            "Inspect the prepared full-campaign exercise telemetry log on your attacker workstation:\n"
            "`cat /var/log/purple_capstone/apt29_exercise_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8320/api/purple-capstone/telemetry`\n\n"
            "Examine the multi-stage campaign events. Identify the unique campaign identifier (e.g. CMP-...) that links all stages "
            "from initial execution to final data egress."
        ),
        task_type=TaskType.QUESTION,
        question="What unique campaign identifier links all stages in the capstone exercise telemetry?",
        hint="Look for the 'campaign_id' attribute in the JSON telemetry (e.g. CMP-2026-APT29).",
        accepted_answers=["CMP-2026-APT29", "cmp-2026-apt29", "CMP-2026-APT29-PROD"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-capstone-attck-correlation",
        order=3,
        title="Map Multi-Stage Campaign Lifecycle to ATT&CK",
        instructions=(
            "A structured adversary emulation exercise follows a coordinated plan across multiple tactics.\n\n"
            "What formal cybersecurity document defines the step-by-step offensive procedures, expected defensive telemetry, "
            "deconfliction criteria, and rollback instructions for an end-to-end exercise?"
        ),
        task_type=TaskType.QUESTION,
        question="What formal document details the offensive procedures, telemetry, and rules for a full exercise?",
        hint="It consists of three words: 'Adversary Emulation Plan'.",
        accepted_answers=["Adversary Emulation Plan", "adversary emulation plan", "Emulation Plan"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-capstone-emulation",
        order=4,
        title="Execute Multi-Stage APT29 Adversary Campaign",
        instructions=(
            "Orchestrate the full multi-stage adversary emulation campaign using the purple capstone tool:\n"
            "`python3 /home/operator/tools/purple_capstone_tool.py --emulate-campaign`\n\n"
            "This command executes all 6 attack stages in sequence: execution, AMSI blinding, Kerberoasting, lateral pivot, "
            "C2 beaconing, and archive exfiltration against the disposable lab target.\n"
            "Submit the returned verification token to record campaign completion."
        ),
        task_type=TaskType.COMMAND,
        question="Run the full adversary campaign emulation and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/purple_capstone_tool.py --emulate-campaign' in the lab terminal.",
        accepted_answers=["PURPLE_CAPSTONE_EMULATION_VERIFIED", "APT29_FULL_CAMPAIGN_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-capstone-challenge",
        order=5,
        title="Deploy Multi-Stage Correlation Rules & Final Certification",
        instructions=(
            "The final capstone challenge requires deploying end-to-end multi-stage correlation logic in the SIEM that correlates "
            "low-severity events across stages into a single critical incident alert.\n\n"
            "1. Deploy the enterprise multi-stage correlation rules:\n"
            "`python3 /home/operator/tools/purple_capstone_tool.py --tune-enterprise-rules`\n\n"
            "2. Complete the validation challenge:\n"
            "`python3 /home/operator/tools/purple_capstone_tool.py --challenge`\n\n"
            "Submit the resulting verification token to achieve official Purple Team Track completion."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy enterprise correlation rules, complete the challenge, and submit the verification token.",
        hint="Run '--tune-enterprise-rules' followed by '--challenge' using the purple capstone tool.",
        accepted_answers=["PURPLE_CAPSTONE_DETECTION_VALIDATED", "PURPLE_TEAM_TRACK_CERTIFIED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-purple-capstone-quiz",
        order=6,
        title="Assess Comprehensive Purple Team Track Knowledge",
        instructions="Complete the 4-question technical assessment covering adversary emulation, telemetry correlation, and purple team methodology.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is multi-stage event correlation vital when detecting sophisticated threat actors like APT29?",
                options=[
                    "Because adversaries use low-noise, individually benign-looking commands across each phase that only reveal their malicious intent when correlated together",
                    "Because SIEM licenses only allow storing one single log event per day",
                    "Because correlation eliminates the need for any endpoint security agents",
                    "Because correlation automatically decrypts all HTTPS web traffic globally",
                ],
                correct_index=0,
                explanation="Advanced adversaries avoid loud, easily detected actions. Correlating sequential actions (e.g. PowerShell launch -> AmsiScanBuffer patch -> Kerberos TGS request -> outbound HTTPS beacon) confirms high-confidence intrusions.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the ultimate goal of a mature Purple Team program?",
                options=[
                    "To establish a continuous feedback loop that continuously validates and improves defensive detection, visibility, and response capabilities",
                    "To determine whether the Red Team or Blue Team is superior in technical skill",
                    "To replace human analysts with fully automated social media bots",
                    "To disable all security monitoring during business hours",
                ],
                correct_index=0,
                explanation="Purple Teaming is fundamentally collaborative: offensive expertise directly empowers defensive engineering to close detection gaps, eliminate blind spots, and accelerate response.",
            ),
            QuizQuestion(
                id="q3",
                question="How does continuous adversary emulation strengthen Zero Trust network architecture?",
                options=[
                    "By empirically proving whether segmentation, identity controls, and lateral movement restrictions successfully block adversary pivot attempts",
                    "By granting every domain user full local administrator access",
                    "By ensuring that passwords never expire under any circumstances",
                    "By removing all TLS certificates from corporate web applications",
                ],
                correct_index=0,
                explanation="Adversary emulation tests Zero Trust policies in practice, verifying that compromised credentials cannot traverse network boundaries or access unauthorized resources.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the most effective post-exercise deliverable produced by a Purple Team engagement?",
                options=[
                    "A prioritized engineering backlog with detection-as-code rules, validated test playbooks, and an updated ATT&CK coverage heatmap",
                    "A 500-page unformatted PDF report containing raw terminal command dumps",
                    "A trophy presented to the team with the fewest software bugs",
                    "An email asking users to create longer passwords",
                ],
                correct_index=0,
                explanation="Actionable engineering artifacts—tested detection rules, repeatable atomic test scripts, and updated coverage heatmaps—directly improve an organization's defensive posture long after the exercise ends.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_20_DEFINITION = RoomDefinition(
    room_id="purple-20-capstone-purple-exercise",
    track=TrackEnum.PURPLE,
    room_number=20,
    title="Purple Team Capstone: Full Adversary Emulation Exercise",
    short_description="Orchestrate an end-to-end Purple Team exercise: emulate APT29 tactics, tune detections, and close security gaps.",
    difficulty="Advanced",
    estimated_duration="90 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_20_CONCEPT,
    tasks=ROOM_PURPLE_20_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8320,
    learning_objectives=[
        "Orchestrate an end-to-end, multi-stage adversary emulation campaign modeled on APT29 tactics.",
        "Inspect cross-stage telemetry spanning execution, defense evasion, credential access, lateral movement, and C2.",
        "Execute a full kill-chain attack emulation using the capstone CLI tool.",
        "Deploy enterprise multi-stage correlation rules to link disparate events into high-confidence incidents.",
        "Attain final certification across the complete 20-room Purple Team curriculum.",
    ],
    assessment_criteria=[
        "Identify APT29 adversary profile and campaign planning requirements.",
        "Locate cross-stage campaign identifiers in full-lifecycle exercise telemetry.",
        "Successfully execute the multi-stage campaign emulation.",
        "Deploy enterprise correlation rules and earn the final capstone validation token.",
        "Attain 100% on the comprehensive Purple Team track assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for capstone threat intel and campaign analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the comprehensive track assessment quiz.",
    ],
)


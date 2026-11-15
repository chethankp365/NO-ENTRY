"""
NO ENTRY Academy - Purple Team Rooms 05-08 Definitions
- Room 05: Emulating Privilege Escalation Techniques (purple-05-privesc-emulation)
- Room 06: Emulating Defense Evasion & Process Injection (purple-06-defense-evasion-emulation)
- Room 07: Emulating Lateral Movement (SMB, WMI, WinRM) (purple-07-lateral-movement-emulation)
- Room 08: Emulating Persistence Mechanisms (purple-08-persistence-emulation)

Authoritative curriculum specifications for Rooms 05-08 in the Purple Team Track.
Includes rich task definitions, accepted answers, mistake explanations, hints,
interactive assessment quizzes, and comprehensive RoomConcepts.
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
# ROOM 05: EMULATING PRIVILEGE ESCALATION TECHNIQUES
# ============================================================================

ROOM_PURPLE_05_CONCEPT = RoomConcept(
    overview=(
        "Privilege Escalation involves adversaries transitioning from a low-integrity security context "
        "to elevated local privileges (Administrator or SYSTEM) to gain full host control. In Purple Teaming, "
        "offensive operators simulate techniques such as User Account Control (UAC) bypasses and token "
        "impersonation while defensive operators monitor event generation in real time. By contrasting "
        "the offensive execution artifacts with defensive event logs (Event ID 4688 and 4672), purple teams "
        "verify whether security controls alert on unauthorized integrity level elevation."
    ),
    simple_analogy=(
        "Think of a secure building where a visitor badge grants access only to the lobby. Privilege escalation "
        "is like swapping that visitor badge for a master keycard to the server vault. A Purple Team test checks "
        "whether the card readers trigger an alarm the instant a visitor badge opens a restricted door."
    ),
    technical_term="Privilege Escalation Emulation & Token Telemetry Correlation",
    technical_definition=(
        "The systematic execution and detection validation of local privilege elevation techniques, specifically "
        "analyzing Windows access token manipulation (SeImpersonatePrivilege), auto-elevating binary hijack (UAC bypass), "
        "and corresponding event log generation across Windows Event IDs 4688, 4672, and Sysmon Event ID 1."
    ),
    cybersecurity_context=(
        "Adversaries arriving on enterprise endpoints rarely start as Domain Admins. They land as low-integrity "
        "service or user accounts and must escalate privileges locally to dump LSASS credentials, disable endpoint "
        "sensors, or establish persistent services. Detecting this privilege boundary crossing is critical to containment."
    ),
    why_it_matters=(
        "If privilege escalation goes undetected, adversaries transition from contained footholds to full local control, "
        "allowing them to disable security agents, tamper with audit trails, and move laterally with elevated credentials."
    ),
    demonstration=(
        "Offensive operators execute a registry-hijacking UAC bypass targeting fodhelper.exe. Defenders immediately inspect "
        "Security Event ID 4688 to correlate the elevation: parent process 'fodhelper.exe' spawning child process 'cmd.exe' "
        "with a High integrity token, triggering an automated SIEM alert for anomalous parent-child execution."
    ),
    remediation_guide=(
        "Configure UAC policy to 'Always Notify' to block silent auto-elevation. Enable command-line auditing and Token "
        "Elevation Type logging in Event ID 4688. Restrict SeImpersonatePrivilege on all service accounts."
    ),
)

ROOM_PURPLE_05_TASKS = [
    TaskDefinition(
        task_id="task-01-privilege-mechanics-token-security",
        order=1,
        title="Access Tokens & Impersonation Privileges",
        instructions=(
            "Access tokens define the security context of a process on Windows, containing its user SID, "
            "group memberships, and privileges. Certain service accounts possess specific privileges that "
            "allow them to impersonate client connections. Exploits such as JuicyPotato and PrintSpoofer "
            "abuse this privilege to intercept local RPC/DCOM tokens and escalate directly to NT AUTHORITY\\SYSTEM.\n\n"
            "Which Windows security privilege is specifically required by local potato-style exploits to "
            "impersonate authenticated client tokens?"
        ),
        task_type=TaskType.QUESTION,
        question="Which Windows privilege is required to impersonate a client token (e.g. in potato exploits)?",
        hint="This privilege is typically assigned to service accounts like LOCAL SERVICE and NETWORK SERVICE.",
        accepted_answers=[
            "SeImpersonatePrivilege",
            "SeImpersonate",
            "SeImpersonatePrivilege (Impersonate a client after authentication)",
            "seimpersonateprivilege",
        ],
        xp_reward=50,
        mistake_explanations={
            "sedebugprivilege": "SeDebugPrivilege allows debugging arbitrary processes, but potato exploits specifically require token impersonation.",
            "setcbprivilege": "SeTcbPrivilege acts as part of the operating system; potato exploits abuse token impersonation.",
        },
    ),
    TaskDefinition(
        task_id="task-02-uac-elevation-telemetry-analysis",
        order=2,
        title="Inspect UAC Bypass Process Telemetry",
        instructions=(
            "When an attacker performs a UAC bypass, they abuse auto-elevating binaries to spawn child processes "
            "at High integrity without triggering a UAC prompt.\n\n"
            "Inspect the prepared elevation audit logs on your attacker workstation at:\n"
            "`cat /var/log/privesc/uac_elevation_events.json`\n\n"
            "Examine the event attributes. What Windows Security Event ID records detailed process creation "
            "events along with token elevation attributes?"
        ),
        task_type=TaskType.QUESTION,
        question="Which Windows Security Event ID records process creation and token elevation attributes?",
        hint="This is the standard Windows Audit Process Creation event.",
        accepted_answers=["4688", "Event ID 4688", "EventID 4688", "4688 (Process Creation)"],
        xp_reward=50,
        mistake_explanations={
            "4624": "Event ID 4624 records successful logons, not process creation.",
            "4672": "Event ID 4672 records special privileges assigned at logon; Event 4688 records process execution with token elevation.",
            "7045": "Event ID 7045 records service installation.",
        },
    ),
    TaskDefinition(
        task_id="task-03-attck-privesc-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: UAC Bypass",
        instructions=(
            "In the MITRE ATT&CK framework, User Account Control bypass techniques belong to the Privilege "
            "Escalation and Defense Evasion tactics.\n\n"
            "Identify the specific MITRE ATT&CK sub-technique ID for Bypass User Account Control."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Bypass User Account Control?",
        hint="Under Technique T1548 (Abuse Elevation Control Mechanism), sub-technique .002 is UAC bypass.",
        accepted_answers=["T1548.002", "t1548.002", "T1548.002 - Bypass User Account Control"],
        xp_reward=60,
        mistake_explanations={
            "t1548": "T1548 is the parent technique (Abuse Elevation Control Mechanism); specify sub-technique .002 for UAC.",
            "t1068": "T1068 is Exploitation for Privilege Escalation, which involves software vulnerabilities rather than elevation control bypass.",
        },
    ),
    TaskDefinition(
        task_id="task-04-uac-emulation-telemetry",
        order=4,
        title="Emulate UAC Bypass & Validate Telemetry",
        instructions=(
            "Now execute an active privilege escalation emulation against the target on port 8305.\n\n"
            "Execute the emulation utility from your workstation:\n"
            "`python3 /home/operator/tools/privesc_emulation_tool.py --emulate-uac`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"technique_id\":\"T1548.002\",\"bypass_vector\":\"fodhelper\",\"target_integrity\":\"High\"}' \\\n"
            "  http://10.10.14.90:8305/api/privesc/emulate`\n\n"
            "The target verifies the UAC bypass simulation and returns an authoritative verification token. "
            "Submit the token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating the UAC bypass.",
        hint="Run privesc_emulation_tool.py with --emulate-uac to capture the verification token.",
        accepted_answers=["PRIVESC_EMULATION_VERIFIED", "PRIVESC_UAC_EMULATION_OK"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-privesc-detection-challenge",
        order=5,
        title="Deploy Detection Rule & Validate Mitigation",
        instructions=(
            "To complete the purple loop, author and submit a behavioral detection rule that flags "
            "auto-elevating binary execution spawning interactive command shells.\n\n"
            "Submit your detection configuration using the tool:\n"
            "`python3 /home/operator/tools/privesc_emulation_tool.py --tune-detection`\n"
            "Followed by the challenge finalization:\n"
            "`python3 /home/operator/tools/privesc_emulation_tool.py --finalize`\n\n"
            "Alternatively, POST your challenge submission:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_PRIVESC_DETECTION\",\"rule_target\":\"fodhelper_child_process\"}' \\\n"
            "  http://10.10.14.90:8305/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming privilege escalation detection.",
        hint="Tune the detection rule first, then finalize the challenge to verify your remediation.",
        accepted_answers=["PRIVESC_DETECTION_VALIDATED", "PRIVESC_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-privesc-quiz",
        order=6,
        title="Privilege Escalation Emulation Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify privilege escalation concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which integrity level is assigned to standard interactive processes launched by non-admin users?",
                options=["Medium Integrity", "Low Integrity", "High Integrity", "SYSTEM Integrity"],
                correct_index=0,
                explanation="Standard interactive Windows user processes run at Medium integrity by default.",
            ),
            QuizQuestion(
                id="q2",
                question="What distinguishing artifact allows defenders to detect fodhelper-based UAC bypasses in Event ID 4688?",
                options=[
                    "fodhelper.exe spawning an unexpected shell like cmd.exe or powershell.exe",
                    "fodhelper.exe opening an unencrypted outbound TCP port 4444",
                    "fodhelper.exe deleting the Security event log",
                    "fodhelper.exe installing a kernel-mode device driver",
                ],
                correct_index=0,
                explanation="Under normal operations, fodhelper.exe does not spawn command interpreters; doing so indicates a registry hijack bypass.",
            ),
            QuizQuestion(
                id="q3",
                question="Which Windows Security event log records 'Special privileges assigned to new logon'?",
                options=["Event ID 4672", "Event ID 4624", "Event ID 4688", "Event ID 1102"],
                correct_index=0,
                explanation="Event ID 4672 is generated whenever an elevated logon is assigned special administrative privileges.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the most effective administrative GPO policy to prevent auto-elevation UAC bypasses?",
                options=[
                    "Set UAC prompt behavior for administrators to 'Prompt for consent on the secure desktop'",
                    "Disable the Windows Event Log service",
                    "Grant SeImpersonatePrivilege to all local accounts",
                    "Delete the C:\\Windows\\System32 directory",
                ],
                correct_index=0,
                explanation="Setting UAC to 'Always Notify / Prompt for consent' forces all elevation requests through consent.exe, blocking silent auto-elevate.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_05_DEFINITION = RoomDefinition(
    room_id="purple-05-privesc-emulation",
    track=TrackEnum.PURPLE,
    room_number=5,
    title="Emulating Privilege Escalation Techniques",
    short_description="Simulate token manipulation, UAC bypasses, and verify security event log correlation.",
    difficulty="Intermediate",
    estimated_duration="55 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_05_CONCEPT,
    tasks=ROOM_PURPLE_05_TASKS,
)


# ============================================================================
# ROOM 06: EMULATING DEFENSE EVASION & PROCESS INJECTION
# ============================================================================

ROOM_PURPLE_06_CONCEPT = RoomConcept(
    overview=(
        "Process Injection allows adversaries to execute malicious code within the memory address space of "
        "a legitimate, trusted process to evade endpoint defenses and blend with normal operational traffic. "
        "Process Hollowing creates a genuine process in a suspended state, unmaps its legitimate code sections, "
        "writes a malicious payload into the vacated memory, adjusts the entry point thread context, and resumes "
        "execution. In Purple Teaming, operators simulate this technique to evaluate whether defensive EDR "
        "and Sysmon sensors catch the cross-process memory manipulation."
    ),
    simple_analogy=(
        "Imagine a courier delivering a standard company van into a garage. Inside, mechanics secretly replace "
        "the original driver and contents while keeping the familiar company logo on the vehicle before sending it "
        "back out into traffic. Process hollowing keeps the legitimate outer process name while replacing the code inside."
    ),
    technical_term="Process Hollowing & Cross-Process Memory Telemetry",
    technical_definition=(
        "A defense evasion technique where an adversary executes malicious code in the address space of a suspended "
        "legitimate executable, analyzed through Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess "
        "with PROCESS_VM_WRITE / PROCESS_VM_OPERATION access masks)."
    ),
    cybersecurity_context=(
        "Standard security controls monitor running process names and network connections. When an adversary injects "
        "code into svchost.exe or explorer.exe, perimeter firewalls and basic task managers treat the outbound network "
        "traffic as benign system communication, concealing the intrusion."
    ),
    why_it_matters=(
        "Without behavioral memory inspection, malicious payloads execute invisible to standard file-integrity scanners. "
        "Empirical purple validation ensures EDR sensors detect cross-process memory handles before execution resumes."
    ),
    demonstration=(
        "Offensive operators launch svchost.exe suspended and allocate executable memory. Defensive operators inspect Sysmon "
        "Event ID 10 to observe an unbacked process requesting PROCESS_VM_WRITE permissions, triggering a high-severity "
        "EDR behavioral heuristic alert."
    ),
    remediation_guide=(
        "Deploy EDR agents configured to monitor Sysmon Event ID 8 and 10 with call trace inspection. Enable Arbitrary Code "
        "Guard (ACG) to block dynamic generation of executable code in unsigned memory pages."
    ),
)

ROOM_PURPLE_06_TASKS = [
    TaskDefinition(
        task_id="task-01-process-injection-mechanics",
        order=1,
        title="Process Hollowing Creation Mechanics",
        instructions=(
            "Process Hollowing begins by launching a legitimate target process in a paused state so that its "
            "executable sections can be modified in memory before any original code executes.\n\n"
            "What core Windows API function is used to create a new process with the `CREATE_SUSPENDED` flag?"
        ),
        task_type=TaskType.QUESTION,
        question="What Windows API function is used to create a new process in a suspended state?",
        hint="This is the primary Win32 function used to spawn processes, taking creation flags as a parameter.",
        accepted_answers=[
            "CreateProcess",
            "CreateProcessA",
            "CreateProcessW",
            "CreateProcess (CREATE_SUSPENDED)",
            "createprocess",
        ],
        xp_reward=50,
        mistake_explanations={
            "openprocess": "OpenProcess opens an existing process handle; it does not spawn a new suspended process.",
            "virtualallocex": "VirtualAllocEx allocates memory inside a process, called after the process is created.",
        },
    ),
    TaskDefinition(
        task_id="task-02-sysmon-injection-telemetry",
        order=2,
        title="Inspect Sysmon Injection Event Telemetry",
        instructions=(
            "Inspect the prepared memory injection telemetry log on your workstation at:\n"
            "`cat /var/log/injection/sysmon_injection_events.json`\n\n"
            "Review the Sysmon Event ID 8 and Event ID 10 records. What is the target image name (executable) "
            "into which the malicious thread was injected?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the target process executable name into which code was injected?",
        hint="Look at the 'TargetImage' field in the Sysmon Event ID 8 / 10 entries.",
        accepted_answers=[
            "svchost.exe",
            "svchost",
            "C:\\Windows\\System32\\svchost.exe",
            "System32\\svchost.exe",
        ],
        xp_reward=50,
        mistake_explanations={
            "payload_runner.exe": "payload_runner.exe is the source process initiating the injection, not the target.",
            "explorer.exe": "Check the log file; in this exercise svchost.exe was targeted.",
        },
    ),
    TaskDefinition(
        task_id="task-03-attck-injection-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Process Hollowing",
        instructions=(
            "Under the Defense Evasion and Privilege Escalation tactics, Process Injection is cataloged "
            "under technique T1055.\n\n"
            "What is the specific MITRE ATT&CK sub-technique ID for Process Hollowing?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Process Hollowing?",
        hint="Look for the .012 sub-technique under T1055 (Process Injection).",
        accepted_answers=["T1055.012", "t1055.012", "T1055.012 - Process Hollowing"],
        xp_reward=60,
        mistake_explanations={
            "t1055": "T1055 is the parent technique (Process Injection); provide the specific sub-technique .012 for Process Hollowing.",
            "t1055.001": "T1055.001 represents Dynamic-link Library Injection; Hollowing is .012.",
        },
    ),
    TaskDefinition(
        task_id="task-04-process-injection-emulation",
        order=4,
        title="Emulate Process Injection & Verify Sysmon Detection",
        instructions=(
            "Perform an active process injection simulation against target port 8306.\n\n"
            "Execute the injection emulation tool from your workstation:\n"
            "`python3 /home/operator/tools/injection_emulation_tool.py --test-injection`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"injection_type\":\"HOLLOWING\",\"target_binary\":\"svchost.exe\",\"memory_protection\":\"PAGE_EXECUTE_READWRITE\"}' \\\n"
            "  http://10.10.14.90:8306/api/injection/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating process injection.",
        hint="Run injection_emulation_tool.py with --test-injection to capture the verification token.",
        accepted_answers=["INJECTION_EMULATION_VERIFIED", "PROCESS_INJECTION_EMULATED_OK", "PROCESS_INJECTION_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-defense-evasion-challenge",
        order=5,
        title="Deploy Behavioral EDR Rule & Complete Challenge",
        instructions=(
            "Close the purple feedback loop by deploying an EDR behavioral detection rule targeting "
            "cross-process thread creations with RWX permissions.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/injection_emulation_tool.py --tune-edr`\n"
            "`python3 /home/operator/tools/injection_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_INJECTION_DEFENSE\",\"rule_id\":\"EDR-INJECT-01\"}' \\\n"
            "  http://10.10.14.90:8306/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming defense evasion detection.",
        hint="Tune the EDR rule first, then finalize the challenge.",
        accepted_answers=["DEFENSE_EVASION_DETECTION_VALIDATED", "INJECTION_DETECTION_APPROVED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-defense-evasion-quiz",
        order=6,
        title="Defense Evasion & Process Injection Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify process injection concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which Sysmon event ID specifically tracks 'CreateRemoteThread' operations between processes?",
                options=["Event ID 8", "Event ID 1", "Event ID 3", "Event ID 11"],
                correct_index=0,
                explanation="Sysmon Event ID 8 is specifically designated for CreateRemoteThread and thread hijacking detection.",
            ),
            QuizQuestion(
                id="q2",
                question="Why do adversaries set allocated memory protection to PAGE_EXECUTE_READWRITE (RWX)?",
                options=[
                    "To write shellcode into the memory buffer and immediately execute it from the same address space",
                    "To compress the executable payload using NTFS compression",
                    "To prevent Windows Defender from accessing the hard drive",
                    "To encrypt the host RAM with BitLocker",
                ],
                correct_index=0,
                explanation="PAGE_EXECUTE_READWRITE grants write access for payload copying and execute permissions for running shellcode.",
            ),
            QuizQuestion(
                id="q3",
                question="What access mask in Sysmon Event ID 10 (ProcessAccess) signifies memory write permissions?",
                options=["PROCESS_VM_WRITE (0x0020)", "PROCESS_TERMINATE (0x0001)", "PROCESS_QUERY_INFORMATION (0x0400)", "SYNCHRONIZE (0x00100000)"],
                correct_index=0,
                explanation="PROCESS_VM_WRITE (0x0020) is required to write into another process's virtual memory space.",
            ),
            QuizQuestion(
                id="q4",
                question="What defensive technique checks whether code executing in a thread originates from a signed on-disk binary rather than unbacked memory?",
                options=[
                    "Memory Call Stack Walking and Unbacked Memory Scanning",
                    "Static SHA-256 file hashing of desktop icons",
                    "Checking the user's password complexity policy",
                    "Disabling DNS resolution on the local router",
                ],
                correct_index=0,
                explanation="Advanced EDR solutions inspect the thread call stack to verify if instruction pointers point to unbacked (non-file-mapped) memory pages.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_06_DEFINITION = RoomDefinition(
    room_id="purple-06-defense-evasion-emulation",
    track=TrackEnum.PURPLE,
    room_number=6,
    title="Emulating Defense Evasion & Process Injection",
    short_description="Test process hollowing, thread execution hijacking, and evaluate EDR behavioral alerts.",
    difficulty="Advanced",
    estimated_duration="65 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_06_CONCEPT,
    tasks=ROOM_PURPLE_06_TASKS,
)


# ============================================================================
# ROOM 07: EMULATING LATERAL MOVEMENT (SMB, WMI, WINRM)
# ============================================================================

ROOM_PURPLE_07_CONCEPT = RoomConcept(
    overview=(
        "Lateral Movement enables an adversary to extend their foothold across an enterprise network "
        "by authenticating to remote hosts using acquired credentials and native administrative interfaces. "
        "Common mechanisms include SMB-based service installation (PsExec), Windows Management Instrumentation "
        "(WMI), and Windows Remote Management (WinRM). Purple Teaming tests the defender's ability to correlate "
        "network logons with remote execution artifacts, uncovering detection gaps between network sensors and host logs."
    ),
    simple_analogy=(
        "If an intruder enters a hotel lobby with a stolen key, lateral movement is like walking down the corridors "
        "and trying the key on every door until finding one that opens. A Purple Team exercise verifies whether "
        "the hallway cameras and room door sensors communicate to spot the unauthorized progression."
    ),
    technical_term="Lateral Movement Emulation & Network Authentication Correlation",
    technical_definition=(
        "The empirical simulation and detection evaluation of remote execution across network boundaries via native "
        "management protocols (SMB, RPC, WMI, WinRM), evaluated through Security Event ID 4624 (Logon Type 3), Event ID 7045 "
        "(Service Creation), and WMI-Activity operational logs."
    ),
    cybersecurity_context=(
        "In modern enterprise Active Directory environments, perimeter breaches are isolated to single workstations "
        "until lateral movement occurs. Adversaries abuse built-in administrative tools (Living off the Land) to move "
        "horizontally to servers holding sensitive data or credentials."
    ),
    why_it_matters=(
        "Stopping an adversary at the initial access workstation prevents enterprise-wide compromise. Purple team "
        "lateral movement testing measures the visibility gap between network segmentation and endpoint detection."
    ),
    demonstration=(
        "Offensive operators launch remote execution via WMI targeting a remote host. Defenders observe Event ID 4624 "
        "(Logon Type 3) followed immediately by 'wmiprvse.exe' spawning 'cmd.exe', generating a high-priority alert for "
        "unauthorized remote administrative execution."
    ),
    remediation_guide=(
        "Enforce host firewalls to block inbound SMB (445) and RPC (135) between workstations. Deploy LAPS to randomize "
        "local admin passwords. Monitor Event ID 7045 for unexpected service creations."
    ),
)

ROOM_PURPLE_07_TASKS = [
    TaskDefinition(
        task_id="task-01-lateral-movement-logon-type",
        order=1,
        title="Windows Network Logon Type Identification",
        instructions=(
            "When an attacker or administrative tool connects to a remote computer via SMB, RPC, or WMI "
            "using valid credentials, Windows Security Event ID 4624 records the authentication.\n\n"
            "What numerical Logon Type is assigned to network logons (such as connecting to a network share "
            "or executing remote RPC calls) in Event ID 4624?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the numerical Logon Type in Event ID 4624 for a Network logon?",
        hint="Interactive desktop logons are Type 2; Remote Desktop (RDP) is Type 10; Network logons are Type...",
        accepted_answers=["3", "Logon Type 3", "Type 3", "3 (Network)"],
        xp_reward=50,
        mistake_explanations={
            "2": "Logon Type 2 represents an Interactive logon (local console keyboard/screen).",
            "10": "Logon Type 10 represents a Remote Interactive (RDP) logon.",
            "5": "Logon Type 5 represents a Service account logon.",
        },
    ),
    TaskDefinition(
        task_id="task-02-psexec-service-telemetry",
        order=2,
        title="Inspect Remote Service Execution Artifacts",
        instructions=(
            "Inspect the lateral movement event logs on your attacker workstation at:\n"
            "`cat /var/log/lateral/remote_exec_events.json`\n\n"
            "The log records System Event ID 7045 (Service Creation). What is the service name installed "
            "during PsExec-style lateral execution in the captured telemetry?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the service name recorded in Event ID 7045 for the PsExec execution?",
        hint="Look at the 'ServiceName' field in the Event ID 7045 record.",
        accepted_answers=["PSEXESVC", "PSEXESVC.exe", "psexesvc", "PSEXESVC service"],
        xp_reward=50,
        mistake_explanations={
            "services.exe": "services.exe is the Service Control Manager process, not the name of the installed service.",
            "cmd.exe": "cmd.exe is the executed payload; the service wrapper name is PSEXESVC.",
        },
    ),
    TaskDefinition(
        task_id="task-03-attck-lateral-movement-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Service Execution",
        instructions=(
            "PsExec relies on the Service Control Manager to install and start an executable service "
            "on a remote host.\n\n"
            "What is the MITRE ATT&CK technique ID for System Services: Service Execution?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique ID for System Services: Service Execution?",
        hint="Under Execution / System Services (T1569), look for the .002 sub-technique.",
        accepted_answers=["T1569.002", "t1569.002", "T1569.002 - Service Execution"],
        xp_reward=60,
        mistake_explanations={
            "t1569": "T1569 is the parent technique (System Services); specify sub-technique .002 for Service Execution.",
            "t1021.002": "T1021.002 is SMB/Windows Admin Shares (used to stage the binary); execution occurs via T1569.002.",
        },
    ),
    TaskDefinition(
        task_id="task-04-wmi-lateral-emulation",
        order=4,
        title="Emulate WMI / SMB Lateral Movement",
        instructions=(
            "Perform an active lateral movement simulation against target port 8307.\n\n"
            "Execute the lateral movement emulation tool from your workstation:\n"
            "`python3 /home/operator/tools/lateral_emulation_tool.py --emulate-wmi`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"protocol\":\"WMI\",\"target_host\":\"10.10.14.90\",\"command\":\"whoami\",\"parent\":\"wmiprvse.exe\"}' \\\n"
            "  http://10.10.14.90:8307/api/lateral/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating lateral movement.",
        hint="Run lateral_emulation_tool.py with --emulate-wmi to capture the verification token.",
        accepted_answers=["LATERAL_EMULATION_VERIFIED", "LATERAL_MOVEMENT_EMULATED_OK", "LATERAL_MOVEMENT_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-lateral-movement-challenge",
        order=5,
        title="Deploy Correlated Lateral Detection Rule",
        instructions=(
            "Complete the exercise by authoring and validating a detection rule that correlates "
            "Logon Type 3 events with immediate child process creation under wmiprvse.exe or PSEXESVC.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/lateral_emulation_tool.py --tune-rule`\n"
            "`python3 /home/operator/tools/lateral_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_LATERAL_DETECTION\",\"rule_name\":\"CORRELATE_LOGON3_REMOTE_EXEC\"}' \\\n"
            "  http://10.10.14.90:8307/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming lateral movement detection.",
        hint="Tune the lateral detection rule first, then finalize the challenge.",
        accepted_answers=["LATERAL_MOVEMENT_DETECTION_VALIDATED", "LATERAL_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-lateral-movement-quiz",
        order=6,
        title="Lateral Movement Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify lateral movement concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which administrative share is conventionally targeted by PsExec to upload its service binary?",
                options=["ADMIN$", "NETLOGON", "SYSVOL", "PRINT$"],
                correct_index=0,
                explanation="ADMIN$ maps to C:\\Windows and is the default staging share used by PsExec.",
            ),
            QuizQuestion(
                id="q2",
                question="Which parent process is spawned when remote commands are executed via WMI Win32_Process.Create?",
                options=["wmiprvse.exe", "svchost.exe", "lsass.exe", "explorer.exe"],
                correct_index=0,
                explanation="WMI-created processes are spawned directly under the WMI Provider Host (wmiprvse.exe).",
            ),
            QuizQuestion(
                id="q3",
                question="Which TCP port is used by default for unencrypted Windows Remote Management (WinRM)?",
                options=["5985", "445", "135", "3389"],
                correct_index=0,
                explanation="WinRM uses HTTP port 5985 for unencrypted traffic and HTTPS port 5986 for encrypted sessions.",
            ),
            QuizQuestion(
                id="q4",
                question="What security solution prevents lateral movement using shared local administrator passwords across multiple workstations?",
                options=[
                    "Microsoft LAPS (Local Administrator Password Solution)",
                    "Disabling Windows Defender Antivirus",
                    "Opening TCP port 445 on the edge firewall",
                    "Installing an unmanaged Wi-Fi access point",
                ],
                correct_index=0,
                explanation="LAPS automatically rotates and randomizes the local administrator password on every computer, eliminating single-credential lateral movement.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_07_DEFINITION = RoomDefinition(
    room_id="purple-07-lateral-movement-emulation",
    track=TrackEnum.PURPLE,
    room_number=7,
    title="Emulating Lateral Movement (SMB, WMI, WinRM)",
    short_description="Emulate remote execution via PsExec and WMI, identifying detection blind spots across network segments.",
    difficulty="Intermediate",
    estimated_duration="60 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_07_CONCEPT,
    tasks=ROOM_PURPLE_07_TASKS,
)


# ============================================================================
# ROOM 08: EMULATING PERSISTENCE MECHANISMS
# ============================================================================

ROOM_PURPLE_08_CONCEPT = RoomConcept(
    overview=(
        "Persistence consists of techniques adversaries use to maintain their foothold across restarts, "
        "changed credentials, and other interruptions. In Windows environments, attackers frequently abuse "
        "Scheduled Tasks, Registry Run Keys, and Services to trigger payload execution automatically. "
        "Purple Teaming evaluates whether detection engineering catches the moment persistence is installed, "
        "measures detection latency, and ensures that clean rollback procedures restore systems to baseline "
        "without leaving lingering test backdoors."
    ),
    simple_analogy=(
        "Installing persistence is like planting a spare key in a combination lockbox under the porch so that "
        "even if the front door lock is changed, the occupant can get back in. A Purple Team test checks whether "
        "the motion detector spots the person mounting the lockbox, and ensures the lockbox is removed when testing ends."
    ),
    technical_term="Persistence Mechanism Emulation & Automated Eradication Hygiene",
    technical_definition=(
        "The empirical testing of endpoint persistence installations (Windows Scheduled Tasks, Registry Run Keys, Services), "
        "measuring detection alert latency via Security Event ID 4698, and validating automated eradication hygiene."
    ),
    cybersecurity_context=(
        "Security incident response teams frequently eradicate initial access footholds (e.g. killing a malicious process) "
        "only for the adversary to regain access minutes later via a dormant scheduled task. Validating persistence detection "
        "guarantees that remediation actions are comprehensive."
    ),
    why_it_matters=(
        "Persistent footholds allow adversaries to withstand reboots and network isolation. Automated detection of Event "
        "ID 4698 coupled with rapid eradication reduces attacker dwell time from months to minutes."
    ),
    demonstration=(
        "Offensive operators register a disguised scheduled task executing a staging payload. Defenders observe Event ID "
        "4698 containing suspicious script parameters in <Actions><Exec><Command>, triggering an automated SOAR playbook "
        "that deletes the task and isolates the host."
    ),
    remediation_guide=(
        "Enable 'Audit Other Object Access Events' in GPO to guarantee Event ID 4698 logging. Deploy WDAC/AppLocker "
        "to prevent unauthorized scripts from running via tasks. Audit Scheduled Tasks enterprise-wide."
    ),
)

ROOM_PURPLE_08_TASKS = [
    TaskDefinition(
        task_id="task-01-persistence-event-id",
        order=1,
        title="Scheduled Task Security Event Identification",
        instructions=(
            "Windows Task Scheduler provides comprehensive auditing when Advanced Audit Policy is configured "
            "for 'Audit Other Object Access Events'.\n\n"
            "What Windows Security Event ID is generated specifically when a new Scheduled Task is created?"
        ),
        task_type=TaskType.QUESTION,
        question="What Windows Security Event ID records the creation of a new Scheduled Task?",
        hint="This event is logged in the Security log and contains the full task XML specification.",
        accepted_answers=["4698", "Event ID 4698", "EventID 4698", "4698 (A scheduled task was created)"],
        xp_reward=50,
        mistake_explanations={
            "4697": "Event ID 4697 records a service being installed, not a scheduled task.",
            "7045": "Event ID 7045 is logged in the System log for service creation.",
            "4702": "Event ID 4702 records an update to an existing scheduled task.",
        },
    ),
    TaskDefinition(
        task_id="task-02-scheduled-task-telemetry",
        order=2,
        title="Inspect Scheduled Task Telemetry",
        instructions=(
            "Inspect the persistence event logs on your attacker workstation at:\n"
            "`cat /var/log/persistence/scheduled_task_events.json`\n\n"
            "Examine the Event ID 4698 record. What is the Task Name assigned to the malicious scheduled task "
            "designed to mimic a Windows maintenance routine?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the Task Name assigned to the scheduled task in the event telemetry?",
        hint="Look for the 'TaskName' field inside the Event ID 4698 entry.",
        accepted_answers=[
            "SecurityTelemetryUpdate",
            "\\Microsoft\\Windows\\Maintenance\\SecurityTelemetryUpdate",
            "SecurityTelemetryUpdate.job",
            "\\SecurityTelemetryUpdate",
        ],
        xp_reward=50,
        mistake_explanations={
            "powershell.exe": "powershell.exe is the executable action, not the Task Name.",
            "maintenance": "Check the full task path in the log; the task name is SecurityTelemetryUpdate.",
        },
    ),
    TaskDefinition(
        task_id="task-03-attck-scheduled-task-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Scheduled Task",
        instructions=(
            "Scheduled Task abuse is one of the most prevalent persistence techniques cataloged in MITRE ATT&CK "
            "under the Persistence, Privilege Escalation, and Execution tactics.\n\n"
            "What is the MITRE ATT&CK technique ID for Scheduled Task / Job: Scheduled Task?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique ID for Scheduled Task?",
        hint="Under T1053 (Scheduled Task/Job), .005 specifically designates Windows Scheduled Tasks.",
        accepted_answers=["T1053.005", "t1053.005", "T1053.005 - Scheduled Task"],
        xp_reward=60,
        mistake_explanations={
            "t1053": "T1053 is the parent technique (Scheduled Task/Job); specify sub-technique .005 for Scheduled Task.",
            "t1053.003": "T1053.003 is Linux cron; Windows Scheduled Tasks is .005.",
        },
    ),
    TaskDefinition(
        task_id="task-04-scheduled-task-emulation",
        order=4,
        title="Emulate Scheduled Task Persistence",
        instructions=(
            "Perform an active scheduled task persistence simulation against target port 8308.\n\n"
            "Execute the persistence emulation tool from your workstation:\n"
            "`python3 /home/operator/tools/persistence_emulation_tool.py --emulate-task`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"task_name\":\"SecurityTelemetryUpdate\",\"action_path\":\"C:\\\\Windows\\\\Temp\\\\updater.ps1\",\"trigger\":\"ONLOGON\"}' \\\n"
            "  http://10.10.14.90:8308/api/persistence/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating scheduled task persistence.",
        hint="Run persistence_emulation_tool.py with --emulate-task to capture the verification token.",
        accepted_answers=["PERSISTENCE_EMULATION_VERIFIED", "PERSISTENCE_TASK_EMULATED_OK"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-persistence-remediation-challenge",
        order=5,
        title="Enforce Automated Eradication & Challenge Verification",
        instructions=(
            "A core rule of Purple Teaming is zero lingering test artifacts. Execute automated rollback "
            "to delete the persistent scheduled task and verify system restoration.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/persistence_emulation_tool.py --remediate`\n"
            "`python3 /home/operator/tools/persistence_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_PERSISTENCE_REMEDIATION\",\"task_deleted\":true,\"remediation_action\":\"REVOKE_AND_PURGE\"}' \\\n"
            "  http://10.10.14.90:8308/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming persistence eradication.",
        hint="Execute the remediation cleanup first, then finalize the challenge.",
        accepted_answers=["PERSISTENCE_REMEDIATION_VALIDATED", "PERSISTENCE_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-persistence-quiz",
        order=6,
        title="Persistence Emulation & Remediation Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify persistence concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which Windows command-line utility is standardly used to manage and query scheduled tasks?",
                options=["schtasks.exe", "sc.exe", "netstat.exe", "reg.exe"],
                correct_index=0,
                explanation="schtasks.exe is the native Windows command-line tool for creating, modifying, and querying scheduled tasks.",
            ),
            QuizQuestion(
                id="q2",
                question="In Windows Security Event ID 4698, what section of the event XML details the binary or script executed by the task?",
                options=["<Actions><Exec><Command>", "<Triggers><BootTrigger>", "<Principals><UserId>", "<Settings><IdleSettings>"],
                correct_index=0,
                explanation="The <Actions><Exec><Command> XML element specifies the exact executable path and arguments launched by the task.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is automated remediation verification an essential part of Purple Team exercise hygiene?",
                options=[
                    "To ensure simulation artifacts and backdoors are not left active on corporate production endpoints",
                    "To speed up the internet bandwidth on the host",
                    "To grant full domain admin rights to all users",
                    "To reset the system clock to GMT",
                ],
                correct_index=0,
                explanation="Leaving test backdoors or scheduled tasks behind poses severe security risks; purple teams must guarantee clean rollback.",
            ),
            QuizQuestion(
                id="q4",
                question="Which registry key path is most commonly abused for user-level persistence executed on logon?",
                options=[
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                    "HKCR\\.txt",
                    "HKLM\\SAM\\SAM",
                ],
                correct_index=0,
                explanation="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run executes binaries in the user's context upon every interactive logon.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_08_DEFINITION = RoomDefinition(
    room_id="purple-08-persistence-emulation",
    track=TrackEnum.PURPLE,
    room_number=8,
    title="Emulating Persistence Mechanisms",
    short_description="Install persistence via scheduled tasks, registry run keys, and services; verify detection and remediation.",
    difficulty="Intermediate",
    estimated_duration="55 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_08_CONCEPT,
    tasks=ROOM_PURPLE_08_TASKS,
)

/**
 * NO ENTRY Academy Room Workspace
 * Cinematic, hands-on cybersecurity training room interface.
 * Connects concept theory, interactive tasks, lab session controls,
 * simulated/Docker target services, xterm.js terminal, and audio-visual feedback.
 */

import { sound } from '../core/sound.js';

let currentRoom = null;
let currentLabSession = null;
let terminal = null;
let termFitAddon = null;
let termSocket = null;
let timerInterval = null;
let currentInputLine = '';

const containerEl = document.querySelector('.workspace-container');
const roomId = containerEl ? containerEl.dataset.roomId : null;

export async function initRoomWorkspace() {
  if (!roomId) return;

  setupConceptToggle();
  setupLabButtons();
  setupModalControls();

  await loadRoomData();
  await checkLabStatus();
  initTerminal();
  setupQuickCommands();
  setupEvidenceDrawer();
}

// ---------------------------------------------------------------------------
// MODALS SETUP (Briefing, Mission Accomplished, Evidence Drawer)
// ---------------------------------------------------------------------------

function setupModalControls() {
  // 1. Mission Briefing Modal
  const btnOpenBriefing = document.getElementById('btnOpenBriefing');
  const btnCommence = document.getElementById('btnCommenceMission');
  const briefingModal = document.getElementById('missionBriefingModal');

  if (btnOpenBriefing && briefingModal) {
    btnOpenBriefing.addEventListener('click', () => {
      sound.keyClick();
      briefingModal.style.display = 'flex';
    });
  }

  if (btnCommence && briefingModal) {
    btnCommence.addEventListener('click', () => {
      sound.bootHum();
      briefingModal.style.display = 'none';
      sessionStorage.setItem(`briefing_seen_${roomId}`, 'true');
    });
  }

  // 2. Mission Accomplished Modal
  const accomplishedModal = document.getElementById('missionAccomplishedModal');
  const btnReview = document.getElementById('btnReviewWorkspace');

  if (btnReview && accomplishedModal) {
    btnReview.addEventListener('click', () => {
      sound.keyClick();
      accomplishedModal.style.display = 'none';
    });
  }

  // 3. Evidence Drawer
  const btnOpenEvidence = document.getElementById('btnOpenEvidence');
  const btnCloseEvidence = document.getElementById('btnCloseEvidence');
  const evidenceDrawer = document.getElementById('evidenceDrawerModal');

  if (btnOpenEvidence && evidenceDrawer) {
    btnOpenEvidence.addEventListener('click', () => {
      sound.keyClick();
      evidenceDrawer.style.display = 'flex';
    });
  }

  if (btnCloseEvidence && evidenceDrawer) {
    btnCloseEvidence.addEventListener('click', () => {
      evidenceDrawer.style.display = 'none';
    });
  }

  // Copy Evidence Command
  const btnCopyEvidence = document.getElementById('btnCopyEvidenceCmd');
  if (btnCopyEvidence) {
    btnCopyEvidence.addEventListener('click', () => {
      const filePath = document.getElementById('evidenceFilePath')?.textContent || '';
      const cmd = `cat ${filePath}`;
      navigator.clipboard.writeText(cmd).then(() => {
        const origText = btnCopyEvidence.textContent;
        btnCopyEvidence.textContent = '✓ COPIED';
        sound.alertBlip();
        setTimeout(() => { btnCopyEvidence.textContent = origText; }, 1800);
      }).catch(() => {});
    });
  }
}

function setupConceptToggle() {
  const header = document.getElementById('conceptHeader');
  const content = document.getElementById('conceptContent');
  const icon = document.getElementById('conceptToggleIcon');

  if (header && content) {
    header.addEventListener('click', () => {
      sound.keyClick();
      const isHidden = content.style.display === 'none';
      content.style.display = isHidden ? 'block' : 'none';
      if (icon) icon.innerHTML = isHidden ? '&#9660;' : '&#9654;';
    });
  }
}

// ---------------------------------------------------------------------------
// DATA FETCHING & UI POPULATION
// ---------------------------------------------------------------------------

async function loadRoomData() {
  try {
    const res = await fetch(`/api/academy/rooms/${roomId}`);
    if (!res.ok) {
      console.error(`Error loading room: ${res.statusText}`);
      return;
    }
    currentRoom = await res.json();
    applyTrackTheme();
    renderRoomHeader();
    renderConcept();
    renderTasks();
    populateMissionBriefing();
    updateProgress();

    // Auto-display Mission Briefing on first entry
    if (!sessionStorage.getItem(`briefing_seen_${roomId}`)) {
      setTimeout(() => {
        const briefingModal = document.getElementById('missionBriefingModal');
        if (briefingModal) {
          briefingModal.style.display = 'flex';
          sound.alertBlip();
        }
      }, 350);
    }
  } catch (err) {
    console.error('Failed to load room details:', err);
  }
}

function applyTrackTheme() {
  if (!currentRoom || !containerEl) return;
  const rawTrack = (currentRoom.track || 'blue').toLowerCase();
  const trackTheme = rawTrack.startsWith('detect') ? 'detection' : rawTrack;

  containerEl.classList.remove('theme-red', 'theme-blue', 'theme-purple', 'theme-detection', 'theme-cyan');
  containerEl.classList.add(`theme-${trackTheme}`);
}

function renderRoomHeader() {
  if (!currentRoom) return;

  const trackBreadcrumb = document.getElementById('roomTrackBreadcrumb');
  const numberBreadcrumb = document.getElementById('roomNumberBreadcrumb');
  const titleText = document.getElementById('roomTitleText');
  const diffBadge = document.getElementById('roomDifficultyBadge');
  const durBadge = document.getElementById('roomDurationBadge');
  const xpBadge = document.getElementById('roomXpBadge');
  const trackHudPill = document.getElementById('trackHudPill');

  const rawTrack = (currentRoom.track || 'SECURITY').toUpperCase();
  const roomNum = String(currentRoom.room_number || 1).padStart(2, '0');

  if (trackBreadcrumb) trackBreadcrumb.textContent = `${rawTrack} TRACK`;
  if (numberBreadcrumb) numberBreadcrumb.textContent = `ROOM ${roomNum}`;
  if (titleText) titleText.textContent = currentRoom.title;
  if (diffBadge) diffBadge.textContent = currentRoom.difficulty;
  if (durBadge) durBadge.textContent = currentRoom.estimated_duration;
  if (xpBadge) xpBadge.textContent = `+${currentRoom.total_xp} XP`;

  if (trackHudPill) {
    if (rawTrack.includes('RED')) {
      trackHudPill.textContent = 'RED // ATTACK VECTOR';
    } else if (rawTrack.includes('BLUE')) {
      trackHudPill.textContent = 'BLUE // DEFENSE MATRIX';
    } else if (rawTrack.includes('PURPLE')) {
      trackHudPill.textContent = 'PURPLE // ADVERSARY EMULATION';
    } else if (rawTrack.includes('DETECT')) {
      trackHudPill.textContent = 'DETECTION // ENGINE ACTIVE';
    } else {
      trackHudPill.textContent = `${rawTrack} // ACTIVE`;
    }
  }
}

function populateMissionBriefing() {
  if (!currentRoom) return;

  const rawTrack = (currentRoom.track || 'SECURITY').toUpperCase();
  const roomNum = String(currentRoom.room_number || 1).padStart(2, '0');

  const trackBadge = document.getElementById('briefingTrackBadge');
  const idChip = document.getElementById('briefingIdChip');
  const titleText = document.getElementById('briefingTitleText');
  const descText = document.getElementById('briefingDescText');
  const diffEl = document.getElementById('briefingDifficulty');
  const durEl = document.getElementById('briefingDuration');
  const xpEl = document.getElementById('briefingXp');
  const targetEl = document.getElementById('briefingTarget');
  const objList = document.getElementById('briefingObjectivesList');

  if (trackBadge) trackBadge.textContent = `${rawTrack} TEAM ENGAGEMENT`;
  if (idChip) idChip.textContent = `ROOM ${roomNum}`;
  if (titleText) titleText.textContent = currentRoom.title;
  if (descText) descText.textContent = currentRoom.description || (currentRoom.concept ? currentRoom.concept.why_it_matters : 'Operational parameters initialized.');
  if (diffEl) diffEl.textContent = currentRoom.difficulty;
  if (durEl) durEl.textContent = currentRoom.estimated_duration;
  if (xpEl) xpEl.textContent = `+${currentRoom.total_xp} XP`;
  if (targetEl) targetEl.textContent = currentLabSession ? `${currentLabSession.target_ip}:${currentLabSession.target_port}` : '10.10.14.90';

  if (objList && currentRoom.learning_objectives && currentRoom.learning_objectives.length > 0) {
    objList.innerHTML = currentRoom.learning_objectives.map(obj => `
      <li style="display:flex;align-items:flex-start;gap:8px;margin-bottom:6px;">
        <span style="color:var(--track-accent);font-weight:bold;">▶</span>
        <span>${obj}</span>
      </li>
    `).join('');
  }
}

function renderConcept() {
  if (!currentRoom || !currentRoom.concept) return;
  const c = currentRoom.concept;

  const analogyEl = document.getElementById('conceptAnalogyText');
  const techDefEl = document.getElementById('conceptTechDefText');
  const whyEl = document.getElementById('conceptWhyItMattersText');
  const demoEl = document.getElementById('conceptDemoText');
  const remEl = document.getElementById('conceptRemediationText');

  if (analogyEl) analogyEl.textContent = c.simple_analogy;
  if (techDefEl) techDefEl.textContent = `${c.technical_term} — ${c.technical_definition}`;
  if (whyEl) whyEl.textContent = `${c.why_it_matters} ${c.cybersecurity_context}`;
  if (demoEl) demoEl.textContent = c.demonstration;
  if (remEl) remEl.textContent = c.remediation_guide;
}

function renderTasks() {
  const container = document.getElementById('tasksListContainer');
  if (!container || !currentRoom) return;

  container.innerHTML = '';

  currentRoom.tasks.forEach((task, idx) => {
    const card = document.createElement('div');
    card.className = `task-card ${task.is_completed ? 'completed' : ''}`;
    card.id = `card_${task.task_id}`;

    let inputAreaHtml = '';

    if (task.task_type === 'quiz') {
      const qListHtml = (task.quiz_questions || []).map(q => {
        const optsHtml = q.options.map((opt, optIdx) => `
          <label class="quiz-option">
            <input type="radio" name="quiz_${task.task_id}_${q.id}" value="${optIdx}">
            <span>${opt}</span>
          </label>
        `).join('');

        return `
          <div class="quiz-q-item" data-qid="${q.id}">
            <div class="quiz-q-text">${q.question}</div>
            <div class="quiz-options-group">${optsHtml}</div>
          </div>
        `;
      }).join('');

      inputAreaHtml = `
        <div class="quiz-container">${qListHtml}</div>
        <button class="btn-submit-task" style="margin-top:10px;" data-task-id="${task.task_id}" data-type="quiz">SUBMIT QUIZ ANSWERS</button>
      `;
    } else {
      inputAreaHtml = `
        <div class="task-input-row">
          <input type="text" class="task-input" id="input_${task.task_id}" placeholder="${task.question || 'Enter flag, value, or command...'}" value="${task.is_completed ? '[COMPLETED]' : ''}" ${task.is_completed ? 'disabled' : ''}>
          <button class="btn-submit-task" data-task-id="${task.task_id}" data-type="text" ${task.is_completed ? 'disabled' : ''}>${task.is_completed ? 'SOLVED' : 'SUBMIT'}</button>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="task-header">
        <span class="task-title">[TASK ${idx + 1}] ${task.title}</span>
        <span class="task-xp-pill">+${task.xp_reward} XP</span>
      </div>
      <div class="task-instructions">${task.instructions}</div>
      ${task.hint ? `<div style="font-size:11px;color:#64748b;margin-bottom:8px;"><em>Hint: ${task.hint}</em></div>` : ''}
      ${inputAreaHtml}
      <div class="feedback-box" id="feedback_${task.task_id}"></div>
      <div class="mistake-box" id="mistake_${task.task_id}" style="display:none;"></div>
    `;

    container.appendChild(card);
  });

  // Attach submit listeners
  container.querySelectorAll('.btn-submit-task').forEach(btn => {
    btn.addEventListener('click', () => handleTaskSubmit(btn.dataset.taskId, btn.dataset.type));
  });
}

async function handleTaskSubmit(taskId, type) {
  const task = currentRoom.tasks.find(t => t.task_id === taskId);
  if (!task) return;

  const feedbackBox = document.getElementById(`feedback_${taskId}`);
  const mistakeBox = document.getElementById(`mistake_${taskId}`);
  if (feedbackBox) {
    feedbackBox.style.display = 'none';
    feedbackBox.className = 'feedback-box';
  }
  if (mistakeBox) {
    mistakeBox.style.display = 'none';
  }

  let payload = { answer: '' };

  if (type === 'quiz') {
    const answers = {};
    (task.quiz_questions || []).forEach(q => {
      const checked = document.querySelector(`input[name="quiz_${taskId}_${q.id}"]:checked`);
      if (checked) {
        answers[q.id] = parseInt(checked.value, 10);
      }
    });
    payload.quiz_answers = answers;
  } else {
    const inputEl = document.getElementById(`input_${taskId}`);
    payload.answer = inputEl ? inputEl.value.trim() : '';
  }

  try {
    const res = await fetch(`/api/academy/rooms/${roomId}/tasks/${taskId}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const result = await res.json();

    if (result.is_correct) {
      sound.xpBurst();
      showXpToast(result.earned_xp || task.xp_reward || 50);

      if (feedbackBox) {
        feedbackBox.textContent = `[+] ${result.feedback} (+${result.earned_xp} XP)`;
        feedbackBox.classList.add('success');
      }
      task.is_completed = true;
      const card = document.getElementById(`card_${taskId}`);
      if (card) card.classList.add('completed');

      const submitBtn = document.querySelector(`button[data-task-id="${taskId}"]`);
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'SOLVED';
      }

      updateProgress();

      if (result.room_completed) {
        setTimeout(() => {
          showMissionAccomplishedModal();
        }, 600);
      }
    } else {
      sound.alertBlip();
      if (feedbackBox) {
        feedbackBox.textContent = `[-] ${result.feedback}`;
        feedbackBox.classList.add('error');
      }
      if (result.mistake_explanation && mistakeBox) {
        mistakeBox.innerHTML = `<strong>ANALYSIS:</strong> ${result.mistake_explanation}`;
        mistakeBox.style.display = 'block';
      }
    }
  } catch (err) {
    console.error('Task submission error:', err);
  }
}

function showXpToast(amount) {
  const toast = document.getElementById('xpToastNotification');
  const toastText = document.getElementById('xpToastText');
  if (!toast) return;

  if (toastText) toastText.textContent = `+${amount} XP EARNED`;
  toast.style.display = 'flex';
  toast.classList.add('show');

  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => { toast.style.display = 'none'; }, 300);
  }, 2200);
}

function showMissionAccomplishedModal() {
  sound.victoryChime();
  const modal = document.getElementById('missionAccomplishedModal');
  if (!modal || !currentRoom) return;

  const roomTitleEl = document.getElementById('accomplishedRoomTitle');
  const xpEarnedEl = document.getElementById('accomplishedXpEarned');
  const btnNext = document.getElementById('btnNextRoom');

  if (roomTitleEl) roomTitleEl.textContent = currentRoom.title;
  if (xpEarnedEl) xpEarnedEl.textContent = `+${currentRoom.total_xp} XP`;

  // Compute Next Room URL
  const track = (currentRoom.track || 'red').toLowerCase();
  const num = currentRoom.room_number || 1;
  let nextUrl = '/academy';

  if (num < 20) {
    const nextNum = String(num + 1).padStart(2, '0');
    if (track.startsWith('red')) nextUrl = `/academy/red-${nextNum}`;
    else if (track.startsWith('blue')) nextUrl = `/academy/blue-${nextNum}`;
    else if (track.startsWith('purple')) nextUrl = `/academy/purple-${nextNum}`;
    else if (track.startsWith('detect')) nextUrl = `/academy/detect-${nextNum}`;
  } else {
    // End of track transition
    if (track.startsWith('red')) nextUrl = '/academy/blue-01';
    else if (track.startsWith('blue')) nextUrl = '/academy/purple-01';
    else if (track.startsWith('purple')) nextUrl = '/academy/detect-01';
    else if (track.startsWith('detect')) nextUrl = '/command-center';
  }

  if (btnNext) {
    if (track.startsWith('detect') && num >= 20) {
      btnNext.textContent = 'CLEARANCE COMPLETE // RETURN TO COMMAND CENTER';
    } else {
      btnNext.textContent = 'PROCEED TO NEXT MISSION >>';
    }
    btnNext.onclick = () => {
      window.location.href = nextUrl;
    };
  }

  modal.style.display = 'flex';
}

function updateProgress() {
  if (!currentRoom || !currentRoom.tasks) return;
  const total = currentRoom.tasks.length;
  const completed = currentRoom.tasks.filter(t => t.is_completed).length;
  const pct = total > 0 ? (completed / total) * 100 : 0;

  const bar = document.getElementById('progressBarFill');
  if (bar) bar.style.width = `${pct}%`;

  const statusBadge = document.getElementById('roomStatusBadge');
  if (statusBadge) {
    if (completed === total && total > 0) {
      statusBadge.textContent = 'STATUS: COMPLETED';
      statusBadge.style.color = 'var(--color-green)';
    } else if (completed > 0) {
      statusBadge.textContent = `STATUS: IN PROGRESS (${completed}/${total})`;
      statusBadge.style.color = 'var(--color-yellow)';
    }
  }
}

// ---------------------------------------------------------------------------
// LAB LIFECYCLE CONTROLS
// ---------------------------------------------------------------------------

function setupLabButtons() {
  const btnStart = document.getElementById('btnStartLab');
  const btnReset = document.getElementById('btnResetLab');
  const btnStop = document.getElementById('btnStopLab');

  if (btnStart) btnStart.addEventListener('click', startLabSession);
  if (btnReset) btnReset.addEventListener('click', resetLabSession);
  if (btnStop) btnStop.addEventListener('click', stopLabSession);
}

async function checkLabStatus() {
  try {
    const res = await fetch(`/api/academy/labs/${roomId}/status`);
    if (!res.ok) return;
    const data = await res.json();
    currentLabSession = data;
    updateLabUI();
  } catch (err) {
    console.error('Failed to query lab status:', err);
  }
}

async function startLabSession() {
  const btnStart = document.getElementById('btnStartLab');
  if (btnStart) btnStart.textContent = 'SPAWNING...';
  sound.keyClick();

  try {
    const res = await fetch(`/api/academy/labs/${roomId}/start`, { method: 'POST' });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const detail = errData.detail || {};
      const statusTitle = detail.error || 'DOCKER_ERROR';
      const errMsg = detail.message || 'Failed to start lab session.';
      const guidance = detail.guidance ? `\n\nGUIDANCE: ${detail.guidance}` : '';

      if (terminal) {
        terminal.writeln(`\r\n\x1b[31m[-] [${statusTitle}] ${errMsg}\x1b[0m`);
        if (detail.guidance) {
          terminal.writeln(`\x1b[36m[*] Guidance: ${detail.guidance}\x1b[0m\r\n`);
        }
      }
      return;
    }
    currentLabSession = await res.json();
    sound.bootHum();
    updateLabUI();
    if (terminal) {
      terminal.writeln('\r\n\x1b[32m[+] Lab environment ready! Target online.\x1b[0m\r\n');
    }
    reconnectTerminalWebSocket();
  } catch (err) {
    console.error('Failed to start lab:', err);
  } finally {
    if (btnStart) btnStart.innerHTML = '&#9654; START LAB';
  }
}

async function resetLabSession() {
  sound.keyClick();
  if (!confirm('Are you sure you want to reset the lab database to its initial clean state?')) return;
  try {
    const res = await fetch(`/api/academy/labs/${roomId}/reset`, { method: 'POST' });
    if (res.ok) {
      currentLabSession = await res.json();
      updateLabUI();
      if (terminal) terminal.writeln('\r\n\x1b[33m[!] Target database wiped and re-seeded to initial clean state.\x1b[0m\r\n');
    }
  } catch (err) {
    console.error('Failed to reset lab:', err);
  }
}

async function stopLabSession() {
  sound.keyClick();
  try {
    const res = await fetch(`/api/academy/labs/${roomId}/stop`, { method: 'POST' });
    if (res.ok) {
      currentLabSession = null;
      updateLabUI();
      if (terminal) terminal.writeln('\r\n\x1b[31m[-] Lab session stopped and resources destroyed.\x1b[0m\r\n');
    }
  } catch (err) {
    console.error('Failed to stop lab:', err);
  }
}

function updateLabUI() {
  const targetIpEl = document.getElementById('labTargetIpText');
  const runnerBadge = document.getElementById('labRunnerBadge');
  const timerEl = document.getElementById('labTimerText');
  const webLink = document.getElementById('btnTargetAppWebLink');

  if (currentLabSession && currentLabSession.status === 'RUNNING') {
    if (targetIpEl) targetIpEl.textContent = `${currentLabSession.target_ip}:${currentLabSession.target_port}`;
    if (webLink) {
      if (currentLabSession.runner_mode === 'docker') {
        webLink.style.display = 'none';
      } else {
        webLink.href = currentLabSession.target_url || `http://127.0.0.1:${currentLabSession.target_port}`;
        webLink.style.display = 'inline-flex';
      }
    }

    if (runnerBadge) {
      if (currentLabSession.runner_mode === 'docker') {
        runnerBadge.textContent = 'DOCKER CONTAINER [ISOLATED]';
        runnerBadge.className = 'runner-badge docker';
      } else {
        runnerBadge.textContent = 'PROCESS EMULATION';
        runnerBadge.className = 'runner-badge emulated';
      }
    }

    startTimer(currentLabSession.remaining_seconds || 3600);
  } else {
    if (targetIpEl) targetIpEl.textContent = 'OFFLINE';
    if (timerEl) timerEl.textContent = '--:--';
    if (webLink) webLink.style.display = 'none';
    if (runnerBadge) {
      if (currentLabSession && currentLabSession.docker_status === 'DOCKER_AVAILABLE') {
        runnerBadge.textContent = 'DOCKER READY';
        runnerBadge.className = 'runner-badge docker';
      } else if (currentLabSession && currentLabSession.docker_status) {
        runnerBadge.textContent = currentLabSession.docker_status;
        runnerBadge.className = 'runner-badge emulated';
      } else {
        runnerBadge.textContent = 'STANDBY';
        runnerBadge.className = 'runner-badge';
      }
    }
    if (timerInterval) clearInterval(timerInterval);
  }
}

function startTimer(seconds) {
  if (timerInterval) clearInterval(timerInterval);
  let remaining = seconds;

  const timerEl = document.getElementById('labTimerText');
  timerInterval = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(timerInterval);
      if (timerEl) timerEl.textContent = 'EXPIRED';
      return;
    }
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    if (timerEl) {
      timerEl.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }
  }, 1000);
}

// ---------------------------------------------------------------------------
// EVIDENCE DATASET DRAWER
// ---------------------------------------------------------------------------

function setupEvidenceDrawer() {
  const filePathEl = document.getElementById('evidenceFilePath');
  const contentPre = document.getElementById('evidenceContentPre');
  if (!filePathEl || !contentPre || !currentRoom) return;

  const track = (currentRoom.track || 'blue').toLowerCase();
  const roomNum = currentRoom.room_number || 1;
  const numPadded = String(roomNum).padStart(2, '0');

  let filePath = '';
  let content = '';

  if (track.startsWith('red')) {
    filePath = `/home/operator/targets/room_${numPadded}/recon_telemetry.json`;
    content = JSON.stringify({
      target_host: "10.10.14.90",
      active_ports: [80, 443, 8080 + (roomNum % 25)],
      detected_os: "Linux 6.1.0-custom-hardened",
      service_banners: {
        http: "Apache/2.4.52 (Ubuntu)",
        custom_daemon: "NO_ENTRY_EXPLOIT_TARGET_v1.4"
      },
      vulnerability_indicators: [
        `CWE-${100 + roomNum * 12}: Potential vector detected in input validation`,
        "Session authentication token bypass possible on /api/v1/debug"
      ],
      capture_timestamp: new Date().toISOString()
    }, null, 2);
  } else if (track.startsWith('blue')) {
    filePath = `/var/log/telemetry/incident_capture_${numPadded}.json`;
    content = JSON.stringify({
      incident_id: `INC-2026-${numPadded}`,
      sensor_source: "SOC_EDR_AGENT_PRIMARY",
      event_type: "PROCESS_INJECTION_OR_SUSPICIOUS_EXECUTION",
      severity: "HIGH",
      telemetry: {
        host: "CORP-WKS-042",
        parent_process: "powershell.exe",
        command_line: "-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgA...",
        source_ip: "198.51.100.42",
        destination_ip: "10.10.14.90"
      },
      recommended_action: "ISOLATE_HOST_AND_EXTRACT_MEMORY"
    }, null, 2);
  } else if (track.startsWith('purple')) {
    filePath = `/opt/adversary_emulation/plans/apt_${numPadded}_adversary.yml`;
    content = `# NO ENTRY PURPLE TEAM // ADVERSARY EMULATION PLAN
technique_id: "T1059.00${roomNum % 10}"
tactic: "Execution / Persistence"
adversary_profile: "APT-VOLT-STORM-${numPadded}"
emulation_steps:
  - step: 1
    name: "Foothold Execution"
    command: "curl -s http://10.10.14.90:${8300 + roomNum}/api/emulate/trigger"
    expected_telemetry: "Sysmon EventID 1"
  - step: 2
    name: "Detection Validation"
    endpoint: "http://10.10.14.90:${8300 + roomNum}/api/converge/metrics"
    pass_criteria: "detection_gap_rate == 0.0"`;
  } else {
    filePath = `/etc/detection_rules/detect_${numPadded}_sigma.yml`;
    content = `title: "NO_ENTRY_DETECT_${numPadded}_AnomalousExecution"
status: experimental
description: "Detects anomalous adversary execution pattern in detection engineering lab ${roomNum}"
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/python3'
      - '/bash'
    CommandLine|contains:
      - 'pipeline_tool.py'
      - 'eval_rule'
  condition: selection
level: high
falsepositives:
  - Legitimate security automation pipelines`;
  }

  filePathEl.textContent = filePath;
  contentPre.textContent = content;
}

// ---------------------------------------------------------------------------
// XTERM.JS TERMINAL INTEGRATION & EASTER EGGS
// ---------------------------------------------------------------------------

function initTerminal() {
  const container = document.getElementById('terminalContainer');
  if (!container || !window.Terminal) return;

  terminal = new window.Terminal({
    cursorBlink: true,
    fontFamily: 'var(--font-mono, monospace)',
    fontSize: 12,
    theme: {
      background: '#020408',
      foreground: '#e2e8f0',
      cursor: '#00E5FF',
      black: '#000000',
      red: '#FF1F3D',
      green: '#00FF6A',
      yellow: '#FFE600',
      blue: '#00E5FF',
      magenta: '#A855F7',
      cyan: '#00E5FF',
      white: '#ffffff',
    },
  });

  if (window.FitAddon && window.FitAddon.FitAddon) {
    termFitAddon = new window.FitAddon.FitAddon();
    terminal.loadAddon(termFitAddon);
  }

  terminal.open(container);
  const updateSize = () => {
    if (termFitAddon) {
      termFitAddon.fit();
    } else if (terminal && container) {
      const cols = Math.max(40, Math.floor(container.clientWidth / 7.5));
      const rows = Math.max(15, Math.floor(container.clientHeight / 17));
      terminal.resize(cols, rows);
    }
  };
  setTimeout(updateSize, 100);

  // Buffer user keypresses for Easter Egg interception
  terminal.onData(data => {
    sound.keyClick();

    if (data === '\r' || data === '\n') {
      const trimmed = currentInputLine.trim().toLowerCase();
      currentInputLine = '';

      if (handleEasterEggCommand(trimmed)) {
        return;
      }
    } else if (data === '\u007F' || data === '\b') {
      currentInputLine = currentInputLine.slice(0, -1);
    } else if (data.length === 1 && data >= ' ') {
      currentInputLine += data;
    }

    if (termSocket && termSocket.readyState === WebSocket.OPEN) {
      termSocket.send(JSON.stringify({ type: 'input', data: data }));
    }
  });

  window.addEventListener('resize', updateSize);
  reconnectTerminalWebSocket();
}

function handleEasterEggCommand(cmd) {
  if (!terminal) return false;

  if (cmd === 'matrix') {
    terminal.writeln('\r\n\x1b[32m[INITIALIZING NEURAL MATRIX STREAM...]\x1b[0m');
    sound.alertBlip();
    let count = 0;
    const matrixChars = 'ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ1234567890ABCDEF';
    const interval = setInterval(() => {
      let line = '  ';
      for (let i = 0; i < 48; i++) {
        line += matrixChars[Math.floor(Math.random() * matrixChars.length)];
      }
      terminal.writeln(`\x1b[32m${line}\x1b[0m`);
      count++;
      if (count > 12) {
        clearInterval(interval);
        terminal.writeln('\r\n\x1b[32m[+] "Wake up, Neo... The Matrix has you. Follow the white rabbit, Operator."\x1b[0m\r\noperator@noentry-box:~$ ');
      }
    }, 90);
    return true;
  }

  if (cmd === 'hack_the_planet' || cmd === 'hack-the-planet') {
    sound.victoryChime();
    terminal.writeln('\r\n\x1b[36m[+] "Mess with the best, die like the rest. HACK THE PLANET!" — Zero Cool (1995)\x1b[0m\r\noperator@noentry-box:~$ ');
    return true;
  }

  if (cmd === 'ghost --whoami' || cmd === 'ghost') {
    sound.bootHum();
    terminal.writeln('\r\n\x1b[35m[GHOST COGNITIVE AI SENTINEL // NODE GH-9021-ALPHA]');
    terminal.writeln('  Clearance:   OMNI-RESTRICTED');
    terminal.writeln('  Providers:   Groq / Gemini / OpenRouter / Local Fallback');
    terminal.writeln('  Neural Link: ONLINE // TELEMETRY CONTINUOUSLY INDEXED');
    terminal.writeln('  Message:     "I observe every packet, Operator. Keep hunting."\x1b[0m\r\noperator@noentry-box:~$ ');
    return true;
  }

  if (cmd.startsWith('sudo rm -rf') || cmd === 'sudo su' || cmd === 'sudo') {
    sound.alertBlip();
    terminal.writeln('\r\n\x1b[31m[-] [NO ENTRY KERNEL SECURITY ENFORCER]\r\n    Nice try, Operator. This incident will be reported to Santa Claus and the SOC.\x1b[0m\r\noperator@noentry-box:~$ ');
    return true;
  }

  if (cmd === 'ne --stats' || cmd === 'noentry --stats') {
    sound.xpBurst();
    terminal.writeln('\r\n\x1b[32m=====================================================');
    terminal.writeln('   NO ENTRY CYBERSECURITY TRAINING ACADEMY // STATS');
    terminal.writeln('=====================================================');
    terminal.writeln('   Total Operational Rooms:  80 / 80 (100% Complete)');
    terminal.writeln('   - Red Team:              20 / 20');
    terminal.writeln('   - Blue Team:             20 / 20');
    terminal.writeln('   - Purple Team:           20 / 20');
    terminal.writeln('   - Detection Engineering: 20 / 20');
    terminal.writeln('   Lab Engine:              Zero-Trust Docker Network Bridge');
    terminal.writeln('   AI Supervisor:           GHOST Multi-Provider System');
    terminal.writeln('=====================================================\x1b[0m\r\noperator@noentry-box:~$ ');
    return true;
  }

  return false;
}

function reconnectTerminalWebSocket() {
  if (termSocket) {
    try { termSocket.close(); } catch (_) {}
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/academy/${roomId}/terminal`;

  termSocket = new WebSocket(wsUrl);

  termSocket.onmessage = evt => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'output' && terminal) {
        terminal.write(msg.data);
      }
    } catch (_) {
      if (terminal) terminal.write(evt.data);
    }
  };

  termSocket.onerror = err => {
    console.error('Terminal WebSocket error:', err);
  };
}

// ---------------------------------------------------------------------------
// DYNAMIC QUICK PROBES (ALL 80 ROOMS)
// ---------------------------------------------------------------------------

function setupQuickCommands() {
  const bar = document.getElementById('quickCmdBar');
  if (!bar || !roomId) return;

  const track = (currentRoom ? currentRoom.track : 'red').toLowerCase();
  const roomNum = currentRoom ? currentRoom.room_number : 1;
  const port = currentLabSession ? currentLabSession.target_port : (8080 + roomNum);

  let buttons = getQuickProbes(roomId, track, roomNum, port);

  bar.innerHTML = '<span style="font-family:var(--font-mono);font-size:10px;color:#64748b;align-self:center;">QUICK PROBES:</span>';
  buttons.forEach(b => {
    const btnEl = document.createElement('button');
    btnEl.className = 'btn-quick-cmd';
    btnEl.dataset.cmd = b.cmd;
    btnEl.textContent = b.label;
    bar.appendChild(btnEl);
  });

  bar.querySelectorAll('.btn-quick-cmd').forEach(btn => {
    btn.addEventListener('click', () => {
      sound.keyClick();
      const cmd = btn.dataset.cmd;
      if (!cmd || !terminal) return;
      if (cmd === 'clear') {
        terminal.clear();
        return;
      }
      if (handleEasterEggCommand(cmd)) {
        return;
      }
      if (termSocket && termSocket.readyState === WebSocket.OPEN) {
        termSocket.send(JSON.stringify({ type: 'command', command: cmd }));
      }
    });
  });
}

function getQuickProbes(rId, track, num, port) {
  // Check exact room overrides first
  if (rId.startsWith('blue-01')) {
    return [
      { label: 'curl soc events (:8201)', cmd: 'curl -s http://10.10.14.90:8201/api/soc/events' },
      { label: 'python soc_query.py', cmd: 'python3 /home/operator/tools/soc_query.py' },
      { label: 'curl siem alerts', cmd: 'curl -s http://10.10.14.90:8201/api/soc/alerts' },
      { label: 'curl post triage', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"event_id\":\"EVT-1003\",\"classification\":\"TRUE_POSITIVE\",\"severity\":\"HIGH\"}' http://10.10.14.90:8201/api/soc/triage" },
      { label: 'clear', cmd: 'clear' },
    ];
  }

  if (rId.startsWith('purple-')) {
    return [
      { label: `curl status (:${port})`, cmd: `curl -s http://10.10.14.90:${port}/api/emulate/status` },
      { label: 'python emulate_threat.py', cmd: 'python3 /home/operator/tools/emulate_threat.py' },
      { label: 'curl trigger attack', cmd: `curl -s -X POST http://10.10.14.90:${port}/api/emulate/trigger` },
      { label: 'curl converge metrics', cmd: `curl -s http://10.10.14.90:${port}/api/converge/metrics` },
      { label: 'ghost --whoami', cmd: 'ghost --whoami' },
      { label: 'clear', cmd: 'clear' },
    ];
  }

  if (rId.startsWith('detect-')) {
    return [
      { label: 'python pipeline_tool.py lint', cmd: 'python3 /home/operator/tools/pipeline_tool.py lint' },
      { label: 'python pipeline_tool.py test', cmd: 'python3 /home/operator/tools/pipeline_tool.py test' },
      { label: `curl rules status (:${port})`, cmd: `curl -s http://10.10.14.90:${port}/api/rules/status` },
      { label: 'ne --stats', cmd: 'ne --stats' },
      { label: 'clear', cmd: 'clear' },
    ];
  }

  if (rId.startsWith('red-')) {
    return [
      { label: `curl target (:${port})`, cmd: `curl -s http://10.10.14.90:${port}/` },
      { label: 'whoami && id', cmd: 'whoami && id' },
      { label: 'ls -la /home/operator', cmd: 'ls -la /home/operator/' },
      { label: 'hack_the_planet', cmd: 'hack_the_planet' },
      { label: 'clear', cmd: 'clear' },
    ];
  }

  // Fallback defaults for any other room
  return [
    { label: `curl target (:${port})`, cmd: `curl -s http://10.10.14.90:${port}/` },
    { label: 'ls /home/operator', cmd: 'ls -la /home/operator/' },
    { label: 'ne --stats', cmd: 'ne --stats' },
    { label: 'clear', cmd: 'clear' },
  ];
}

document.addEventListener('DOMContentLoaded', initRoomWorkspace);

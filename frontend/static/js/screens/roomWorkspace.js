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
  setupFullscreenWorkstation();

  await loadRoomData();
  await checkLabStatus();
  initTerminal();
  setupQuickCommands();
  setupEvidenceDrawer();
  initGhostMentor();
  syncFullscreenWorkstationData();

  openFullscreenWorkstation();
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
  const container = document.getElementById('conceptContent');
  if (!container || !currentRoom) return;

  const c = currentRoom.concept || {};
  const title = currentRoom.title || 'Cybersecurity Operation';
  const term = c.technical_term || title;
  const desc = currentRoom.description || currentRoom.short_description || '';

  // 1. What is this? (Plain-English definition avoiding heavy jargon)
  const whatIsThis = c.what_is_this || c.overview || `${term} is a foundational cybersecurity concept focusing on ${c.cybersecurity_context || desc.toLowerCase() || 'evaluating system security posture and eliminating risk'}. In plain English, it describes how computers, services, and software interact with inputs and permissions, and what happens when those interactions are misconfigured or deliberately exploited.`;

  // 2. Everyday Analogy (Relatable real-world non-technical comparison)
  const analogy = c.simple_analogy || `Think of ${term} like a security checkpoint at a private event: if security guards check names on an invitation list but never verify physical ID cards, anyone who whispers a valid guest's name can walk straight inside.`;

  // 3. How it Works (Step-by-step breakdown of mechanics)
  let steps = c.how_it_works || [];
  if (!Array.isArray(steps) || steps.length === 0) {
    if (c.demonstration) {
      steps = [
        'Reconnaissance & Vector Identification: Discover input fields, open network ports, or exposed configurations.',
        'Crafting Interaction: Deliver targeted payloads or query parameters designed to test validation logic.',
        'State Evaluation: Analyze responses, logs, or error codes to confirm vulnerability presence.',
        'Execution & Verification: Confirm unauthorized command execution, data access, or defensive detection.'
      ];
    } else {
      steps = [
        'Target Enumeration: Map services, processes, and network boundaries.',
        'Execution of Technique: Issue commands or trigger automated scenarios.',
        'Telemetry Generation: Audit logs, network packets, or defensive alerts record the activity.',
        'Outcome Verification: Validate defensive efficacy or offensive objective completion.'
      ];
    }
  }

  // 4. Technical Explanation (The actual protocols, code, flags, or configurations)
  const techDef = c.technical_definition ? `${c.technical_term ? c.technical_term + ': ' : ''}${c.technical_definition}` : `${term} operates at the protocol, process, or data layer where boundary conditions are evaluated. It involves inspecting data structures, network packets, or execution privileges.`;

  // 5. Real-World Application & Impact (Why organizations care, CVE examples, breach history)
  const realWorld = c.real_world_application || c.why_it_matters || `${c.cybersecurity_context || ''} Failure to address or detect ${term} has historically resulted in unauthorized privilege escalation, lateral network movement, critical data theft, or major operational disruptions across enterprise networks.`;

  // 6. What to Observe in this Lab (Specific signs, logs, response codes, or flags)
  const observe = c.what_to_observe || 'Observe response payloads, HTTP status codes, command outputs, and audit logs during execution.';

  // 7. Common Mistakes & Gotchas (What beginners do wrong and how to avoid it)
  const mistakes = c.common_mistakes || c.remediation_guide || 'Common pitfalls include forgetting proper escape quotes in shell/SQL commands, targeting the wrong IP or port, missing required flags, or failing to check log files.';

  // 8. Key Takeaway (One-sentence summary to remember)
  const takeaway = c.key_takeaway || `${term} demonstrates that security depends on strict input validation, least-privilege access, and continuous telemetry monitoring.`;

  // Visual Diagram
  const diagramSvg = getConceptDiagramSvg(currentRoom);

  container.innerHTML = `
    <!-- 1. What is this -->
    <div class="concept-section">
      <h4><span class="part-badge">1</span> WHAT IS THIS?</h4>
      <div class="concept-box part-what-is">${whatIsThis}</div>
    </div>

    <!-- 2. Everyday Analogy -->
    <div class="concept-section">
      <h4><span class="part-badge">2</span> EVERYDAY ANALOGY</h4>
      <div class="concept-box part-analogy">${analogy}</div>
    </div>

    <!-- 3. Visual Architecture Diagram -->
    <div class="concept-section">
      <h4><span class="part-badge">3</span> ARCHITECTURAL FLOW DIAGRAM</h4>
      <div class="concept-diagram-wrapper">
        ${diagramSvg}
      </div>
    </div>

    <!-- 4. How it Works -->
    <div class="concept-section">
      <h4><span class="part-badge">4</span> HOW IT WORKS (STEP-BY-STEP)</h4>
      <div class="concept-steps-list">
        ${steps.map((st, i) => `
          <div class="concept-step-item">
            <span class="step-num">${i + 1}</span>
            <span class="step-text">${st}</span>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- 5. Technical Explanation -->
    <div class="concept-section">
      <h4><span class="part-badge">5</span> TECHNICAL EXPLANATION</h4>
      <p style="margin: 4px 0; color: #cbd5e1; font-size: 12.5px;">${techDef}</p>
      ${c.demonstration ? `<div class="code-demo">${c.demonstration}</div>` : ''}
    </div>

    <!-- 6. Real-World Application & Impact -->
    <div class="concept-section">
      <h4><span class="part-badge">6</span> REAL-WORLD APPLICATION &amp; IMPACT</h4>
      <p style="margin: 4px 0; color: #cbd5e1; font-size: 12.5px;">${realWorld}</p>
    </div>

    <!-- 7. What to Observe in this Lab -->
    <div class="concept-section">
      <h4><span class="part-badge">7</span> WHAT TO OBSERVE IN THIS LAB</h4>
      <div class="concept-box part-observe">${observe}</div>
    </div>

    <!-- 8. Common Mistakes & Key Takeaway -->
    <div class="concept-section">
      <h4><span class="part-badge">8</span> COMMON MISTAKES &amp; KEY TAKEAWAY</h4>
      <div class="mistake-box" style="margin-bottom: 8px;">
        <strong>Common Pitfall:</strong> ${mistakes}
      </div>
      <div class="takeaway-pill">
        <span class="takeaway-icon">⚡</span>
        <span><strong>KEY TAKEAWAY:</strong> ${takeaway}</span>
      </div>
    </div>
  `;
}

function getConceptDiagramSvg(room) {
  const rid = (room.room_id || '').toLowerCase();
  const title = (room.title || '').toLowerCase();
  const track = (room.track || '').toLowerCase();

  // 1. SQL Injection Diagram
  if (rid.includes('sql') || title.includes('sql') || title.includes('injection')) {
    return `
      <svg viewBox="0 0 540 100" width="100%" height="100" style="max-width:540px; margin:0 auto; display:block;">
        <defs>
          <linearGradient id="sqliGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#FF1F3D"/>
            <stop offset="100%" stop-color="#00E5FF"/>
          </linearGradient>
        </defs>
        <!-- Box 1: Attacker Input -->
        <rect x="10" y="25" width="120" height="50" rx="4" fill="#0c121e" stroke="#FF1F3D" stroke-width="1.5"/>
        <text x="70" y="45" fill="#FF1F3D" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">USER INPUT</text>
        <text x="70" y="60" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">' OR 1=1--</text>
        <!-- Arrow 1 -->
        <line x1="130" y1="50" x2="180" y2="50" stroke="#FF1F3D" stroke-width="2" marker-end="url(#arrow)"/>
        <!-- Box 2: Vulnerable Web App -->
        <rect x="180" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#00E5FF" stroke-width="1.5"/>
        <text x="255" y="45" fill="#00E5FF" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">VULNERABLE APP</text>
        <text x="255" y="60" fill="#94a3b8" font-size="8.5" font-family="monospace" text-anchor="middle">Unsanitized String Concat</text>
        <!-- Arrow 2 -->
        <line x1="330" y1="50" x2="380" y2="50" stroke="#00E5FF" stroke-width="2"/>
        <!-- Box 3: Database Engine -->
        <rect x="380" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#00FF6A" stroke-width="1.5"/>
        <text x="455" y="45" fill="#00FF6A" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">DATABASE (SQL)</text>
        <text x="455" y="60" fill="#00FF6A" font-size="8.5" font-family="monospace" text-anchor="middle">WHERE 1=1 (TRUE)</text>
      </svg>
    `;
  }

  // 2. Port Scanning / Reconnaissance Diagram
  if (rid.includes('port') || rid.includes('scan') || title.includes('port') || title.includes('nmap') || title.includes('recon')) {
    return `
      <svg viewBox="0 0 540 100" width="100%" height="100" style="max-width:540px; margin:0 auto; display:block;">
        <rect x="10" y="25" width="130" height="50" rx="4" fill="#0c121e" stroke="#00E5FF" stroke-width="1.5"/>
        <text x="75" y="45" fill="#00E5FF" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">ATTACKER HOST</text>
        <text x="75" y="60" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">nmap -sS -p 80,443</text>
        <!-- Flow Lines -->
        <path d="M 140 40 L 390 40" stroke="#00E5FF" stroke-width="1.5" stroke-dasharray="4,2"/>
        <text x="265" y="34" fill="#00E5FF" font-size="9" font-family="monospace" text-anchor="middle">TCP SYN [Port 80] &gt;&gt;</text>
        <path d="M 390 60 L 140 60" stroke="#00FF6A" stroke-width="1.5"/>
        <text x="265" y="73" fill="#00FF6A" font-size="9" font-family="monospace" text-anchor="middle">&lt;&lt; TCP SYN/ACK [PORT OPEN]</text>
        <rect x="390" y="25" width="140" height="50" rx="4" fill="#0c121e" stroke="#00FF6A" stroke-width="1.5"/>
        <text x="460" y="45" fill="#00FF6A" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">TARGET SERVER</text>
        <text x="460" y="60" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">10.10.14.90 (Active)</text>
      </svg>
    `;
  }

  // 3. SUID / Privilege Escalation Diagram
  if (rid.includes('suid') || rid.includes('priv') || title.includes('privilege') || title.includes('suid') || title.includes('escalation')) {
    return `
      <svg viewBox="0 0 540 100" width="100%" height="100" style="max-width:540px; margin:0 auto; display:block;">
        <rect x="10" y="25" width="140" height="50" rx="4" fill="#0c121e" stroke="#FFE600" stroke-width="1.5"/>
        <text x="80" y="45" fill="#FFE600" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">USER PRIVILEGE</text>
        <text x="80" y="60" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">uid=1000 (standard)</text>
        <!-- Arrow 1 -->
        <line x1="150" y1="50" x2="200" y2="50" stroke="#FFE600" stroke-width="2"/>
        <!-- Box 2 -->
        <rect x="200" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#FF1F3D" stroke-width="1.5"/>
        <text x="275" y="45" fill="#FF1F3D" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">SUID BIT BINARY</text>
        <text x="275" y="60" fill="#94a3b8" font-size="8.5" font-family="monospace" text-anchor="middle">chmod u+s / PATH Hijack</text>
        <!-- Arrow 2 -->
        <line x1="350" y1="50" x2="400" y2="50" stroke="#FF1F3D" stroke-width="2"/>
        <!-- Box 3 -->
        <rect x="400" y="25" width="130" height="50" rx="4" fill="#0c121e" stroke="#00FF6A" stroke-width="1.5"/>
        <text x="465" y="45" fill="#00FF6A" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">ROOT PRIVILEGES</text>
        <text x="465" y="60" fill="#00FF6A" font-size="9" font-family="monospace" text-anchor="middle">euid=0 (FULL CONTROL)</text>
      </svg>
    `;
  }

  // 4. SIEM / Sigma / Detection Engineering Diagram
  if (track === 'detection' || track === 'purple' || rid.includes('siem') || title.includes('sigma') || title.includes('detection') || title.includes('rule')) {
    return `
      <svg viewBox="0 0 540 100" width="100%" height="100" style="max-width:540px; margin:0 auto; display:block;">
        <rect x="10" y="25" width="120" height="50" rx="4" fill="#0c121e" stroke="#38bdf8" stroke-width="1.5"/>
        <text x="70" y="45" fill="#38bdf8" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">RAW SENSORS</text>
        <text x="70" y="60" fill="#94a3b8" font-size="8.5" font-family="monospace" text-anchor="middle">Sysmon, Zeek, WAF</text>
        <line x1="130" y1="50" x2="180" y2="50" stroke="#38bdf8" stroke-width="2"/>
        <rect x="180" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#A855F7" stroke-width="1.5"/>
        <text x="255" y="45" fill="#A855F7" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">SIGMA ENGINE</text>
        <text x="255" y="60" fill="#94a3b8" font-size="8.5" font-family="monospace" text-anchor="middle">Pattern &amp; Logic Match</text>
        <line x1="330" y1="50" x2="380" y2="50" stroke="#00FF6A" stroke-width="2"/>
        <rect x="380" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#00FF6A" stroke-width="1.5"/>
        <text x="455" y="45" fill="#00FF6A" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">ALERT &amp; RESPONSE</text>
        <text x="455" y="60" fill="#00FF6A" font-size="8.5" font-family="monospace" text-anchor="middle">Reflex Containment Active</text>
      </svg>
    `;
  }

  // 5. Default Defense-in-Depth Cyber Architecture Diagram
  return `
    <svg viewBox="0 0 540 100" width="100%" height="100" style="max-width:540px; margin:0 auto; display:block;">
      <rect x="10" y="25" width="120" height="50" rx="4" fill="#0c121e" stroke="#FF1F3D" stroke-width="1.5"/>
      <text x="70" y="45" fill="#FF1F3D" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">ATTACK VECTOR</text>
      <text x="70" y="60" fill="#94a3b8" font-size="8.5" font-family="monospace" text-anchor="middle">Inbound Probe</text>
      <line x1="130" y1="50" x2="180" y2="50" stroke="#FF1F3D" stroke-width="2"/>
      <rect x="180" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#00E5FF" stroke-width="1.5"/>
      <text x="255" y="45" fill="#00E5FF" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">ISOLATED LAB</text>
      <text x="255" y="60" fill="#94a3b8" font-size="8.5" font-family="monospace" text-anchor="middle">Zero-Trust Environment</text>
      <line x1="330" y1="50" x2="380" y2="50" stroke="#00FF6A" stroke-width="2"/>
      <rect x="380" y="25" width="150" height="50" rx="4" fill="#0c121e" stroke="#00FF6A" stroke-width="1.5"/>
      <text x="455" y="45" fill="#00FF6A" font-size="10" font-family="monospace" font-weight="bold" text-anchor="middle">EVALUATION</text>
      <text x="455" y="60" fill="#00FF6A" font-size="8.5" font-family="monospace" text-anchor="middle">Objective Accomplished</text>
    </svg>
  `;
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
  syncFullscreenWorkstationData();
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
  currentLabSession = { status: 'STARTING' };
  updateLabUI();

  try {
    const res = await fetch(`/api/academy/labs/${roomId}/start`, { method: 'POST' });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const detail = errData.detail || {};
      const statusTitle = detail.error || 'DOCKER_ERROR';
      const errMsg = detail.message || 'Failed to start lab session.';
      const guidance = detail.guidance ? `\n\nGUIDANCE: ${detail.guidance}` : '';

      currentLabSession = null;
      updateLabUI();
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
      terminal.clear();
    }
    reconnectTerminalWebSocket();
    addLiveActivityLog('INFO', `Target container started: ${currentLabSession.target_ip || '10.10.15.90'}`);
  } catch (err) {
    console.error('Failed to start lab:', err);
    currentLabSession = null;
    updateLabUI();
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
      addLiveActivityLog('WARN', 'Target database wiped & re-seeded');
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
      addLiveActivityLog('WARN', 'Lab session terminated');
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
  const termDot = document.getElementById('termDotIndicator');
  const termBadge = document.getElementById('termStatusBadge');

  if (currentLabSession && currentLabSession.status === 'RUNNING') {
    if (termDot) termDot.classList.add('online');
    if (termBadge) {
      termBadge.textContent = 'ONLINE';
      termBadge.className = 'term-status-badge online';
    }
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
    if (termDot) termDot.classList.remove('online');
    if (termBadge) {
      termBadge.textContent = 'STANDBY';
      termBadge.className = 'term-status-badge standby';
    }
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
  syncFullscreenWorkstationData();
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
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: 13,
    lineHeight: 1.35,
    letterSpacing: 0,
    theme: {
      background: 'transparent',
      foreground: '#e2e8f0',
      cursor: '#00E5FF',
      cursorAccent: '#020408',
      selectionBackground: 'rgba(0, 229, 255, 0.3)',
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

  // Wire terminal toolbar buttons
  const btnClear = document.getElementById('btnTermClear');
  const btnReset = document.getElementById('btnTermReset');
  if (btnClear) {
    btnClear.addEventListener('click', () => {
      sound.keyClick();
      if (terminal) {
        terminal.clear();
        terminal.write('\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ ');
      }
    });
  }
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      sound.keyClick();
      if (terminal) terminal.clear();
      reconnectTerminalWebSocket();
    });
  }

  const updateSize = () => {
    if (termFitAddon) {
      try { termFitAddon.fit(); } catch (_) {}
    } else if (terminal && container) {
      const cols = Math.max(40, Math.floor(container.clientWidth / 7.8));
      const rows = Math.max(15, Math.floor(container.clientHeight / 17.5));
      terminal.resize(cols, rows);
    }
  };
  setTimeout(updateSize, 100);

  // ResizeObserver for zero-lag auto-fit during container changes
  if (window.ResizeObserver) {
    const termObserver = new ResizeObserver(() => {
      updateSize();
    });
    termObserver.observe(container);
  }

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

// ===========================================================================
// CINEMATIC FULL-SCREEN OPERATOR WORKSTATION CONTROLLER (MODE B & FOCUS MODE)
// ===========================================================================

let wsTimerCountdown = 28 * 60 + 47; // 28:47 countdown default matching reference HUD
let wsCountdownInterval = null;

function setupFullscreenWorkstation() {
  const btnMaximize = document.getElementById('btnMaximizeWorkstation');
  const btnExitFs = document.getElementById('btnExitFsLab');
  const btnFsClose = document.getElementById('btnFsClose');
  const btnFsFocus = document.getElementById('btnFsFocus');
  const btnFsRestore = document.getElementById('btnFsRestoreWorkstation');
  const btnFsClear = document.getElementById('btnFsClear');
  const btnFsCopy = document.getElementById('btnFsCopy');
  const btnFsMin = document.getElementById('btnFsMin');
  const btnFsCopyIp = document.getElementById('btnFsCopyIp');
  const btnFsViewDetails = document.getElementById('btnFsViewDetails');
  const btnFsCloseDrawer = document.getElementById('btnFsCloseDrawer');

  // 1. Maximize Button (from normal mode)
  if (btnMaximize) {
    btnMaximize.addEventListener('click', () => {
      openFullscreenWorkstation();
    });
  }

  // 2. Exit Lab Buttons
  if (btnExitFs) {
    btnExitFs.addEventListener('click', () => {
      closeFullscreenWorkstation();
    });
  }
  if (btnFsClose) {
    btnFsClose.addEventListener('click', () => {
      closeFullscreenWorkstation();
    });
  }

  // 3. Global ESC key listener
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const ws = document.getElementById('fullscreenWorkstation');
      if (ws && ws.classList.contains('active')) {
        const drawer = document.getElementById('fsDrawerOverlay');
        if (drawer && drawer.style.display !== 'none') {
          drawer.style.display = 'none';
          return;
        }
        if (ws.classList.contains('terminal-focus-active')) {
          setTerminalFocusMode(false);
          return;
        }
        closeFullscreenWorkstation();
      }
    }
  });

  // 4. Terminal Focus Mode
  if (btnFsFocus) {
    btnFsFocus.addEventListener('click', () => {
      const ws = document.getElementById('fullscreenWorkstation');
      const isFocus = ws.classList.contains('terminal-focus-active');
      setTerminalFocusMode(!isFocus);
    });
  }
  if (btnFsRestore) {
    btnFsRestore.addEventListener('click', () => {
      setTerminalFocusMode(false);
    });
  }

  // 5. Terminal Toolbar Buttons
  if (btnFsClear) {
    btnFsClear.addEventListener('click', () => {
      sound.keyClick();
      if (terminal) {
        terminal.clear();
        writeTerminalBanner();
        terminal.write('\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ ');
      }
      addLiveActivityLog('CMD', 'Terminal screen cleared');
    });
  }

  if (btnFsCopy) {
    btnFsCopy.addEventListener('click', () => {
      sound.keyClick();
      if (terminal && terminal.hasSelection()) {
        const text = terminal.getSelection();
        navigator.clipboard.writeText(text).then(() => {
          addLiveActivityLog('INFO', 'Selection copied to clipboard');
        }).catch(() => {});
      } else {
        addLiveActivityLog('WARN', 'No active terminal selection to copy');
      }
    });
  }

  if (btnFsMin) {
    btnFsMin.addEventListener('click', () => {
      sound.keyClick();
      const ws = document.getElementById('fullscreenWorkstation');
      if (ws.classList.contains('terminal-focus-active')) {
        setTerminalFocusMode(false);
      }
    });
  }

  // 6. Copy Target IP
  if (btnFsCopyIp) {
    btnFsCopyIp.addEventListener('click', () => {
      const ip = (currentLabSession && currentLabSession.target_ip) ? currentLabSession.target_ip : '10.10.15.90';
      navigator.clipboard.writeText(ip).then(() => {
        const prev = btnFsCopyIp.textContent;
        btnFsCopyIp.textContent = '✓';
        sound.alertBlip();
        addLiveActivityLog('INFO', `Copied Target IP: ${ip}`);
        setTimeout(() => { btnFsCopyIp.textContent = prev; }, 1800);
      }).catch(() => {});
    });
  }

  // 7. View Details (opens holographic briefing)
  if (btnFsViewDetails) {
    btnFsViewDetails.addEventListener('click', () => {
      sound.keyClick();
      const briefingModal = document.getElementById('missionBriefingModal');
      if (briefingModal) briefingModal.style.display = 'flex';
    });
  }

  // 7b. Lab Control Buttons (Start / Stop / Reset)
  const btnFsStartLab = document.getElementById('btnFsStartLab');
  const btnFsStopLab = document.getElementById('btnFsStopLab');
  const btnFsResetLab = document.getElementById('btnFsResetLab');

  if (btnFsStartLab) {
    btnFsStartLab.addEventListener('click', async () => {
      await startLabSession();
    });
  }
  if (btnFsStopLab) {
    btnFsStopLab.addEventListener('click', async () => {
      await stopLabSession();
    });
  }
  if (btnFsResetLab) {
    btnFsResetLab.addEventListener('click', async () => {
      await resetLabSession();
    });
  }


  // 9. Left Navigation Rail
  setupLeftRailControls();

  // 10. Quick Commands in Right Panel
  setupWorkstationQuickCommands();

  // 11. Drawer Close
  if (btnFsCloseDrawer) {
    btnFsCloseDrawer.addEventListener('click', () => {
      const drawer = document.getElementById('fsDrawerOverlay');
      if (drawer) drawer.style.display = 'none';
    });
  }

  // 12. Start Countdown Timer
  startWorkstationTimer();
}

function openFullscreenWorkstation() {
  const ws = document.getElementById('fullscreenWorkstation');
  if (!ws) return;

  sound.bootHum();
  ws.style.display = 'flex';
  void ws.offsetWidth; // force reflow
  ws.classList.add('active');

  syncFullscreenWorkstationData();

  setTimeout(() => {
    if (termFitAddon) {
      termFitAddon.fit();
    }
    if (terminal) {
      terminal.focus();
    }
  }, 120);

  addLiveActivityLog('INFO', 'Operator workstation active');
}

function closeFullscreenWorkstation() {
  sound.keyClick();
  window.location.href = '/academy';
}

function setTerminalFocusMode(enable) {
  const ws = document.getElementById('fullscreenWorkstation');
  if (!ws) return;
  sound.keyClick();
  if (enable) {
    ws.classList.add('terminal-focus-active');
    addLiveActivityLog('INFO', 'Terminal Focus Mode engaged (95%+ screen)');
  } else {
    ws.classList.remove('terminal-focus-active');
    addLiveActivityLog('INFO', 'Terminal Focus Mode disengaged');
  }
  setTimeout(() => {
    if (termFitAddon) termFitAddon.fit();
    if (terminal) terminal.focus();
  }, 80);
}

function writeTerminalBanner() {
  if (!terminal) return;
  terminal.writeln('\x1b[38;2;255;31;61m _  _   ____    \x1b[38;2;0;229;255m______ _  _ _____ ______   __\x1b[0m');
  terminal.writeln('\x1b[38;2;255;31;61m| \\| | / __ \\  \x1b[38;2;0;229;255m|  ____| \\| |_   _|  _ \\ \\ / /\x1b[0m');
  terminal.writeln('\x1b[38;2;255;31;61m| .` || |  | | \x1b[38;2;0;229;255m| |__  | .` | | | | |_) \\ V / \x1b[0m');
  terminal.writeln('\x1b[38;2;255;31;61m| |\\ || |  | | \x1b[38;2;0;229;255m|  __| | |\\ | | | |  _ <  | |  \x1b[0m');
  terminal.writeln('\x1b[38;2;255;31;61m|_| \\_| \\____/  \x1b[38;2;0;229;255m|______|_| \\_| |_| |_| \\_\\ |_|  \x1b[0m');
  terminal.writeln('          \x1b[38;2;255;255;255m- CYBERSECURITY ACADEMY -\x1b[0m');
  terminal.writeln('          \x1b[38;2;0;229;255m> Learn • Practice • Defend <\x1b[0m\r\n');
}

function setupLeftRailControls() {
  const btnTerm = document.getElementById('btnFsRailTerm');
  const btnConcept = document.getElementById('btnFsRailConcept');
  const btnEvidence = document.getElementById('btnFsRailEvidence');
  const btnHints = document.getElementById('btnFsRailHints');
  const btnProbes = document.getElementById('btnFsRailProbes');
  const btnGhost = document.getElementById('btnFsRailGhost');
  const btnStartToggle = document.getElementById('btnFsRailStartToggle');
  const btnReset = document.getElementById('btnFsRailReset');

  const railBtns = [btnTerm, btnConcept, btnEvidence, btnHints, btnProbes, btnGhost];
  const setRailActive = (activeBtn) => {
    railBtns.forEach(b => { if (b) b.classList.remove('active'); });
    if (activeBtn) activeBtn.classList.add('active');
  };

  if (btnTerm) {
    btnTerm.addEventListener('click', () => {
      sound.keyClick();
      setRailActive(btnTerm);
      const drawer = document.getElementById('fsDrawerOverlay');
      if (drawer) drawer.style.display = 'none';
      if (terminal) terminal.focus();
    });
  }

  if (btnConcept) {
    btnConcept.addEventListener('click', () => {
      sound.keyClick();
      setRailActive(btnConcept);
      openFsDrawer('concept');
    });
  }

  if (btnEvidence) {
    btnEvidence.addEventListener('click', () => {
      sound.keyClick();
      setRailActive(btnEvidence);
      openFsDrawer('evidence');
    });
  }

  if (btnHints) {
    btnHints.addEventListener('click', () => {
      sound.keyClick();
      setRailActive(btnHints);
      openFsDrawer('hints');
    });
  }

  if (btnProbes) {
    btnProbes.addEventListener('click', () => {
      sound.keyClick();
      setRailActive(btnProbes);
      openFsDrawer('probes');
    });
  }

  if (btnGhost) {
    btnGhost.addEventListener('click', () => {
      sound.keyClick();
      setRailActive(btnGhost);
      openFsDrawer('ghost');
    });
  }

  if (btnStartToggle) {
    btnStartToggle.addEventListener('click', () => {
      sound.keyClick();
      if (currentLabSession && currentLabSession.status === 'RUNNING') {
        stopLabSession();
      } else {
        startLabSession();
      }
    });
  }

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      sound.keyClick();
      resetLabSession();
    });
  }
}

function openFsDrawer(type) {
  const overlay = document.getElementById('fsDrawerOverlay');
  const title = document.getElementById('fsDrawerTitle');
  const body = document.getElementById('fsDrawerBody');
  if (!overlay || !title || !body) return;

  if (type === 'concept') {
    title.textContent = '📖 THEORY & ARCHITECTURAL PRINCIPLES';
    const conceptContainer = document.getElementById('conceptSlideContainer') || document.getElementById('conceptContent');
    if (conceptContainer && conceptContainer.innerHTML.trim().length > 0) {
      body.innerHTML = conceptContainer.innerHTML;
    } else {
      body.innerHTML = `
        <div style="padding:16px;">
          <h3 style="color:#00E5FF;margin-top:0;">${currentRoom ? currentRoom.title : 'Theory Overview'}</h3>
          <p>${currentRoom ? currentRoom.description : 'Load room theory...'}</p>
          <div style="background:#070d18;border-left:3px solid #00E5FF;padding:12px;margin:12px 0;">
            <strong>Track:</strong> ${currentRoom ? currentRoom.track.toUpperCase() : 'CYBER'} | 
            <strong>Difficulty:</strong> ${currentRoom ? currentRoom.difficulty : 'Medium'} | 
            <strong>XP Reward:</strong> +${currentRoom ? currentRoom.xp_reward : 350} XP
          </div>
          <p>Review the primary concepts, target service topologies, and analytical trade-offs before executing mission commands in the terminal.</p>
        </div>`;
    }
  } else if (type === 'evidence') {
    title.textContent = '💾 EVIDENCE & TELEMETRY DATASET INSPECTOR';
    const evPre = document.getElementById('evidenceContentPre');
    const evPath = document.getElementById('evidenceFilePath')?.textContent || '/var/log/detection/evidence.json';
    const content = evPre ? evPre.textContent : 'No telemetry loaded.';
    body.innerHTML = `
      <div style="padding:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;background:#050a14;padding:8px 12px;border:1px solid rgba(0,229,255,0.3);border-radius:4px;margin-bottom:12px;">
          <span style="font-family:var(--font-mono);color:#00E5FF;font-size:11px;">${evPath}</span>
          <button id="btnFsCopyCatCmd" class="term-tool-btn" style="padding:3px 10px;font-size:10px;">📋 COPY CAT CMD</button>
        </div>
        <pre style="background:#020408;border:1px solid rgba(255,255,255,0.1);padding:14px;border-radius:4px;color:#00FF6A;font-family:var(--font-mono);font-size:11px;overflow-x:auto;max-height:55vh;">${escapeHtml(content)}</pre>
      </div>`;
    const copyBtn = document.getElementById('btnFsCopyCatCmd');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(`cat ${evPath}`).then(() => {
          copyBtn.textContent = '✓ COPIED';
          sound.alertBlip();
          setTimeout(() => { copyBtn.textContent = '📋 COPY CAT CMD'; }, 1800);
        }).catch(() => {});
      });
    }
  } else if (type === 'hints') {
    title.textContent = '💡 MISSION TACTICAL HINTS (4 PROGRESSIVE LEVELS)';
    const targetIp = (currentLabSession && currentLabSession.target_ip) ? currentLabSession.target_ip : '10.10.15.90';
    const targetPort = (currentLabSession && currentLabSession.target_port) ? currentLabSession.target_port : 8089;
    const taskTitle = (currentRoom && currentRoom.tasks && currentRoom.tasks[0]) ? currentRoom.tasks[0].title : 'System Analysis';

    body.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:12px;padding:14px;">
        <div style="background:#050a14;border:1px solid rgba(255,230,0,0.3);border-radius:6px;padding:12px;">
          <div style="color:#FFE600;font-weight:800;font-size:11px;font-family:var(--font-mono);margin-bottom:4px;">LEVEL 1: CONCEPTUAL DIRECTION</div>
          <div style="color:#cbd5e1;font-size:11.5px;line-height:1.4;">Objective: ${escapeHtml(taskTitle)}. Focus on understanding how the system behaves under standard operation versus attack conditions. Determine whether anomalous behavior exceeds the baseline threshold.</div>
        </div>

        <div style="background:#050a14;border:1px solid rgba(0,229,255,0.3);border-radius:6px;padding:12px;">
          <div style="color:#00E5FF;font-weight:800;font-size:11px;font-family:var(--font-mono);margin-bottom:4px;">LEVEL 2: TOOL SELECTION & SYNTAX</div>
          <div style="color:#cbd5e1;font-size:11.5px;line-height:1.4;">Recommended Tool: <code>nmap</code> or <code>curl</code>. Probe the target address <code>${targetIp}:${targetPort}</code>. Use <code>-sV</code> to probe daemon versions and <code>-F</code> to scan fast ports.</div>
        </div>

        <div style="background:#050a14;border:1px solid rgba(0,255,106,0.3);border-radius:6px;padding:12px;">
          <div style="color:#00FF6A;font-weight:800;font-size:11px;font-family:var(--font-mono);margin-bottom:4px;">LEVEL 3: ACTIONABLE COMMAND</div>
          <div style="color:#cbd5e1;font-size:11.5px;margin-bottom:8px;">Execute this exact command in the terminal to inspect the target directly:</div>
          <div style="display:flex;align-items:center;justify-content:space-between;background:#020408;border:1px solid #1e293b;padding:8px 12px;border-radius:4px;">
            <code style="color:#00FF6A;font-size:11px;font-family:var(--font-mono);">nmap -sV -F ${targetIp}</code>
            <div style="display:flex;gap:6px;">
              <button class="fs-drawer-probe-btn" data-cmd="nmap -sV -F ${targetIp}" style="padding:4px 10px;font-size:10px;background:rgba(0,255,106,0.15);border:1px solid #00FF6A;color:#00FF6A;border-radius:3px;cursor:pointer;">RUN ▶</button>
              <button class="fs-hint-copy-btn" data-cmd="nmap -sV -F ${targetIp}" style="padding:4px 10px;font-size:10px;background:rgba(0,229,255,0.15);border:1px solid #00E5FF;color:#00E5FF;border-radius:3px;cursor:pointer;">COPY</button>
            </div>
          </div>
        </div>

        <div style="background:#050a14;border:1px solid rgba(168,85,247,0.3);border-radius:6px;padding:12px;">
          <div style="color:#A855F7;font-weight:800;font-size:11px;font-family:var(--font-mono);margin-bottom:4px;">LEVEL 4: RESULT INTERPRETATION & EVIDENCE SUBMISSION</div>
          <div style="color:#cbd5e1;font-size:11.5px;line-height:1.4;">Examine the discovered service versions and open ports. Confirm if service responses reveal vulnerable parameters or flag tokens, then submit your findings in the task validation box.</div>
        </div>
      </div>`;

    body.querySelectorAll('.fs-drawer-probe-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const cmd = btn.dataset.cmd;
        overlay.style.display = 'none';
        executeWorkstationCommand(cmd);
      });
    });
    body.querySelectorAll('.fs-hint-copy-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
          btn.textContent = '✓';
          setTimeout(() => { btn.textContent = 'COPY'; }, 1500);
        });
      });
    });

  } else if (type === 'ghost') {
    title.textContent = '🤖 GHOST AI // STEP-BY-STEP MISSION INSTRUCTOR';
    body.innerHTML = `
      <div style="padding:14px;display:flex;flex-direction:column;gap:14px;">
        <div style="display:flex;align-items:center;gap:12px;background:#050a14;padding:12px;border:1px solid rgba(0,229,255,0.4);border-radius:6px;">
          <div style="font-size:28px;">👻</div>
          <div>
            <div style="font-weight:800;color:#00E5FF;font-size:13px;">GHOST MENTOR // ROOM-AWARE TACTICAL GUIDANCE</div>
            <div style="color:#94a3b8;font-size:11px;">Active Objective: ${escapeHtml(currentRoom ? currentRoom.title : 'Mission Exploration')}</div>
          </div>
        </div>
        <div id="fsGhostGuideContainer" style="display:flex;flex-direction:column;gap:10px;">
          <div style="color:#64748b;font-size:11px;text-align:center;padding:20px;">Fetching structured 6-step guided mission...</div>
        </div>
        <div style="background:#050a14;border:1px solid rgba(0,255,106,0.3);border-radius:6px;padding:12px;margin-top:6px;">
          <div style="color:#00FF6A;font-weight:700;font-size:11px;margin-bottom:6px;">ASK GHOST A QUESTION ABOUT THIS ROOM</div>
          <div style="display:flex;gap:8px;">
            <input type="text" id="fsGhostInput" placeholder="e.g. How do I test the target service? What does the nmap output mean?" style="flex:1;background:#020408;border:1px solid #334155;color:#f8fafc;padding:8px 12px;border-radius:4px;font-size:11px;font-family:var(--font-mono);">
            <button id="btnFsGhostAsk" style="background:rgba(0,255,106,0.2);border:1px solid #00FF6A;color:#00FF6A;padding:8px 14px;border-radius:4px;font-weight:800;font-size:11px;cursor:pointer;">ASK</button>
          </div>
          <div id="fsGhostReply" style="margin-top:10px;font-size:11.5px;color:#cbd5e1;line-height:1.5;display:none;background:#020408;padding:10px;border-radius:4px;border-left:3px solid #00FF6A;"></div>
        </div>
      </div>`;

    fetch(`/api/ghost/room/${roomId}/guide`)
      .then(res => res.json())
      .then(data => {
        const container = document.getElementById('fsGhostGuideContainer');
        if (!container) return;
        if (data.steps && data.steps.length > 0) {
          let html = '';
          data.steps.forEach(s => {
            html += `
              <div style="background:#050a14;border:1px solid rgba(0,229,255,0.2);border-radius:6px;padding:12px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                  <span style="font-weight:800;color:#00E5FF;font-size:11px;font-family:var(--font-mono);">STEP ${s.step}: ${escapeHtml(s.title)}</span>
                  <span style="font-size:10px;color:#64748b;font-family:var(--font-mono);">${escapeHtml(s.tool)}</span>
                </div>
                <div style="color:#cbd5e1;font-size:11px;margin-bottom:8px;">${escapeHtml(s.goal)}</div>
                <div style="display:flex;align-items:center;justify-content:space-between;background:#020408;border:1px solid #1e293b;padding:6px 10px;border-radius:4px;">
                  <code style="color:#00FF6A;font-size:11px;font-family:var(--font-mono);">${escapeHtml(s.command)}</code>
                  <div style="display:flex;gap:6px;">
                    <button class="fs-run-cmd-btn" data-cmd="${escapeHtml(s.command)}" style="padding:3px 8px;font-size:9.5px;background:rgba(0,255,106,0.15);border:1px solid #00FF6A;color:#00FF6A;border-radius:3px;cursor:pointer;">RUN ▶</button>
                    <button class="fs-copy-cmd-btn" data-cmd="${escapeHtml(s.command)}" style="padding:3px 8px;font-size:9.5px;background:rgba(0,229,255,0.15);border:1px solid #00E5FF;color:#00E5FF;border-radius:3px;cursor:pointer;">COPY</button>
                  </div>
                </div>
                <div style="color:#94a3b8;font-size:10.5px;margin-top:6px;line-height:1.4;">${escapeHtml(s.explanation)}</div>
              </div>`;
          });
          container.innerHTML = html;

          container.querySelectorAll('.fs-run-cmd-btn').forEach(btn => {
            btn.addEventListener('click', () => {
              const cmd = btn.dataset.cmd;
              overlay.style.display = 'none';
              executeWorkstationCommand(cmd);
            });
          });
          container.querySelectorAll('.fs-copy-cmd-btn').forEach(btn => {
            btn.addEventListener('click', () => {
              navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
                btn.textContent = '✓';
                setTimeout(() => { btn.textContent = 'COPY'; }, 1500);
              });
            });
          });
        }
      })
      .catch(err => {
        const container = document.getElementById('fsGhostGuideContainer');
        if (container) container.innerHTML = '<div style="color:#ef4444;font-size:11px;padding:12px;">Failed to load dynamic guide. Check backend connection.</div>';
      });

    const btnAsk = document.getElementById('btnFsGhostAsk');
    const inputAsk = document.getElementById('fsGhostInput');
    const replyEl = document.getElementById('fsGhostReply');
    if (btnAsk && inputAsk && replyEl) {
      const doAsk = () => {
        const q = inputAsk.value.trim();
        if (!q) return;
        btnAsk.disabled = true;
        btnAsk.textContent = '...';
        replyEl.style.display = 'block';
        replyEl.innerHTML = '<span style="color:#64748b;">GHOST is analyzing room telemetry and curriculum...</span>';
        fetch(`/api/ghost/room/${roomId}/ask`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ question: q }),
        })
          .then(res => res.json())
          .then(data => {
            replyEl.innerHTML = `<strong>GHOST:</strong> ${escapeHtml(data.answer)}`;
          })
          .catch(err => {
            replyEl.innerHTML = '<span style="color:#ef4444;">Unable to reach GHOST mentor.</span>';
          })
          .finally(() => {
            btnAsk.disabled = false;
            btnAsk.textContent = 'ASK';
          });
      };
      btnAsk.addEventListener('click', doAsk);
      inputAsk.addEventListener('keydown', e => { if (e.key === 'Enter') doAsk(); });
    }
  } else if (type === 'probes') {
    title.textContent = '⚡ QUICK PROBES & TACTICAL INJECTIONS';
    const track = (currentRoom ? currentRoom.track : 'red').toLowerCase();
    const roomNum = currentRoom ? currentRoom.room_number : 1;
    const port = currentLabSession ? currentLabSession.target_port : (8080 + roomNum);
    const probes = getQuickProbes(roomId, track, roomNum, port);
    let probesHtml = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:14px;">';
    probes.forEach(p => {
      probesHtml += `
        <button class="fs-drawer-probe-btn" data-cmd="${escapeHtml(p.cmd)}" style="background:#050a14;border:1px solid #00E5FF;border-radius:4px;color:#00E5FF;font-family:var(--font-mono);font-size:11px;font-weight:700;padding:10px;cursor:pointer;text-align:left;">
          <div style="color:#ffffff;margin-bottom:4px;">${escapeHtml(p.label)}</div>
          <div style="color:#64748b;font-size:9.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">$ ${escapeHtml(p.cmd)}</div>
        </button>`;
    });
    probesHtml += '</div>';
    body.innerHTML = probesHtml;

    body.querySelectorAll('.fs-drawer-probe-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const cmd = btn.dataset.cmd;
        overlay.style.display = 'none';
        executeWorkstationCommand(cmd);
      });
    });
  }

  overlay.style.display = 'flex';
}

function setupWorkstationQuickCommands() {
  const grid = document.getElementById('fsQuickCmdGrid');
  if (!grid) return;
  grid.querySelectorAll('.fs-cmd-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.dataset.cmd;
      executeWorkstationCommand(cmd);
    });
  });
}

function executeWorkstationCommand(cmd) {
  if (!cmd || !terminal) return;
  sound.keyClick();

  if (cmd === 'clear') {
    terminal.clear();
    writeTerminalBanner();
    terminal.write('\x1b[38;2;0;229;255moperator@noentry\x1b[0m:\x1b[34m~\x1b[0m$ ');
    addLiveActivityLog('CMD', 'Executed: clear');
    return;
  }

  if (handleEasterEggCommand(cmd)) {
    addLiveActivityLog('CMD', `Executed easter egg: ${cmd}`);
    return;
  }

  addLiveActivityLog('CMD', `Executed: ${cmd}`);

  if (termSocket && termSocket.readyState === WebSocket.OPEN) {
    terminal.write(cmd + '\r\n');
    termSocket.send(JSON.stringify({ type: 'command', command: cmd }));
  } else {
    terminal.write(cmd + '\r\n');
    reconnectTerminalWebSocket();
    setTimeout(() => {
      if (termSocket && termSocket.readyState === WebSocket.OPEN) {
        termSocket.send(JSON.stringify({ type: 'command', command: cmd }));
      } else {
        terminal.writeln('\r\n\x1b[31m[-] Lab session is not active. Please click \'START LAB\' to launch.\x1b[0m');
        terminal.write('\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ ');
      }
    }, 250);
  }
}
window.executeWorkstationCommand = executeWorkstationCommand;

function addLiveActivityLog(tag, msg) {
  const feed = document.getElementById('fsActivityFeed');
  if (!feed) return;
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const timeStr = `[${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}]`;

  const item = document.createElement('div');
  item.className = 'fs-log-entry';
  item.innerHTML = `
    <span class="fs-log-time">${timeStr}</span>
    <span class="fs-log-tag ${tag.toLowerCase()}">${tag}</span>
    <span class="fs-log-msg">${escapeHtml(msg)}</span>
  `;
  feed.appendChild(item);
  feed.scrollTop = feed.scrollHeight;
}

function startWorkstationTimer(seconds) {
  if (seconds !== undefined) {
    wsTimerCountdown = seconds;
  }
  if (wsCountdownInterval) clearInterval(wsCountdownInterval);
  wsCountdownInterval = setInterval(() => {
    if (wsTimerCountdown > 0) {
      wsTimerCountdown--;
      const m = Math.floor(wsTimerCountdown / 60);
      const s = wsTimerCountdown % 60;
      const timerVal = document.getElementById('fsTimerVal');
      if (timerVal) {
        timerVal.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
      }
    } else {
      if (wsCountdownInterval) clearInterval(wsCountdownInterval);
      const timerVal = document.getElementById('fsTimerVal');
      if (timerVal) timerVal.textContent = 'EXPIRED';
    }
  }, 1000);
}

function syncFullscreenWorkstationData() {
  if (!currentRoom) return;

  // Header & Info
  const roomNum = currentRoom.room_number || 13;
  const badge = document.getElementById('fsRoomBadge');
  const title = document.getElementById('fsRoomTitle');
  const xp = document.getElementById('fsXpText');
  const desc = document.getElementById('fsBriefingDesc');
  const chipTrack = document.getElementById('fsChipTrack');
  const chipDiff = document.getElementById('fsChipDiff');
  const chipDuration = document.getElementById('fsChipDuration');
  const chipXp = document.getElementById('fsChipXp');

  if (badge) badge.textContent = `ROOM ${roomNum}`;
  if (title) title.textContent = (currentRoom.title || '').toUpperCase();
  if (xp) xp.textContent = `XP ${currentRoom.xp_reward || 350}`;
  if (desc) desc.textContent = currentRoom.description || 'Profile system behavior and set effective thresholds to detect anomalous activity.';
  if (chipTrack) chipTrack.textContent = `🛡️ ${(currentRoom.track || 'Red').toUpperCase()} TEAM`;
  if (chipDiff) chipDiff.textContent = `📶 ${currentRoom.difficulty || 'Medium'}`;
  if (chipDuration) chipDuration.textContent = `⏱ ~ ${currentRoom.estimated_minutes || 30} min`;
  if (chipXp) chipXp.textContent = `★ ${currentRoom.xp_reward || 350} XP`;

  // Lab Intel Authoritative State
  const isRunning = currentLabSession && currentLabSession.status === 'RUNNING';
  const isStarting = currentLabSession && currentLabSession.status === 'STARTING';
  const ip = (isRunning && currentLabSession.target_ip) ? currentLabSession.target_ip : (isStarting ? '10.10.15.90' : 'OFFLINE');
  const attackerIp = (isRunning && currentLabSession.attacker_ip) ? currentLabSession.attacker_ip : (isStarting ? '10.10.14.10' : 'Standby');
  const port = (isRunning && currentLabSession.target_port) ? currentLabSession.target_port : (8080 + roomNum);

  // 1. Top Header Status Pill
  const statusPill = document.getElementById('fsStatusPill');
  const statusText = document.getElementById('fsStatusText');
  if (statusPill && statusText) {
    if (isRunning) {
      statusPill.className = 'fs-status-pill online';
      statusText.textContent = 'ONLINE';
    } else if (isStarting) {
      statusPill.className = 'fs-status-pill starting';
      statusText.textContent = 'STARTING...';
    } else {
      statusPill.className = 'fs-status-pill offline';
      statusText.textContent = 'STOPPED';
    }
  }

  // 2. Terminal Titlebar Ready Badge
  const termBadge = document.getElementById('fsTermReadyBadge');
  if (termBadge) {
    if (isRunning) {
      termBadge.className = 'fs-term-ready-badge';
      termBadge.textContent = '▶ READY';
    } else if (isStarting) {
      termBadge.className = 'fs-term-ready-badge starting';
      termBadge.textContent = '⏳ SPAWNING';
    } else {
      termBadge.className = 'fs-term-ready-badge standby';
      termBadge.textContent = '⏸ STANDBY';
    }
  }

  // 3. Lab Intelligence Rows
  const intelIp = document.getElementById('fsIntelIp');
  const intelOperatorIp = document.getElementById('fsIntelOperatorIp');
  const intelStatus = document.getElementById('fsIntelStatus');
  const intelPorts = document.getElementById('fsIntelPorts');
  const intelContainer = document.getElementById('fsIntelContainer');
  const sessionIp = document.getElementById('fsSessionIp');

  if (intelIp) {
    if (isRunning) {
      intelIp.innerHTML = `${ip} <button id="btnFsCopyIp" class="fs-copy-inline" title="Copy Target IP">📋</button>`;
    } else {
      intelIp.textContent = 'OFFLINE';
    }
  }

  if (intelOperatorIp) {
    if (isRunning) {
      intelOperatorIp.textContent = attackerIp;
      intelOperatorIp.style.color = '#00ff66';
    } else if (isStarting) {
      intelOperatorIp.textContent = 'PROVISIONING...';
      intelOperatorIp.style.color = '#00e5ff';
    } else {
      intelOperatorIp.textContent = 'OFFLINE';
      intelOperatorIp.style.color = '#94a3b8';
    }
  }

  // Active Sessions must display the operator IP, NOT the target IP
  if (sessionIp) sessionIp.textContent = attackerIp;

  if (intelStatus) {
    if (isRunning) {
      intelStatus.className = 'fs-intel-val online';
      intelStatus.innerHTML = '<span class="dot green"></span> ONLINE';
    } else if (isStarting) {
      intelStatus.className = 'fs-intel-val starting';
      intelStatus.innerHTML = '<span class="dot cyan"></span> STARTING';
    } else {
      intelStatus.className = 'fs-intel-val stopped';
      intelStatus.innerHTML = '<span class="dot amber"></span> STOPPED';
    }
  }

  if (intelPorts) {
    if (isRunning) {
      intelPorts.innerHTML = `<span class="dot green"></span> 22, 80, 443`;
    } else {
      intelPorts.innerHTML = `<span class="dot amber"></span> closed`;
    }
  }

  if (intelContainer) {
    if (isRunning) {
      intelContainer.innerHTML = `<span class="dot green"></span> running`;
    } else if (isStarting) {
      intelContainer.innerHTML = `<span class="dot cyan"></span> booting...`;
    } else {
      intelContainer.innerHTML = `<span class="dot amber"></span> stopped`;
    }
  }

  // 4. Lab Action Controls (Start / Stop / Reset)
  const btnFsStartLab = document.getElementById('btnFsStartLab');
  const btnFsStopLab = document.getElementById('btnFsStopLab');
  const btnFsResetLab = document.getElementById('btnFsResetLab');
  if (btnFsStartLab && btnFsStopLab && btnFsResetLab) {
    if (isRunning) {
      btnFsStartLab.style.display = 'none';
      btnFsStopLab.style.display = 'inline-block';
      btnFsResetLab.style.display = 'inline-block';
    } else if (isStarting) {
      btnFsStartLab.style.display = 'inline-block';
      btnFsStartLab.disabled = true;
      btnFsStartLab.innerHTML = '⏳ SPAWNING...';
      btnFsStopLab.style.display = 'none';
      btnFsResetLab.style.display = 'none';
    } else {
      btnFsStartLab.style.display = 'inline-block';
      btnFsStartLab.disabled = false;
      btnFsStartLab.innerHTML = '▶ START LAB';
      btnFsStopLab.style.display = 'none';
      btnFsResetLab.style.display = 'none';
    }
  }

  // 5. Active Sessions Panel
  const sessionCount = document.getElementById('fsSessionCount');
  const sessionStatus = document.querySelector('.fs-session-status');
  if (sessionCount) {
    sessionCount.textContent = isRunning ? '1 / 1' : '0 / 1';
  }
  if (sessionStatus) {
    if (isRunning) {
      sessionStatus.className = 'fs-session-status badge-active';
      sessionStatus.textContent = 'Active';
    } else if (isStarting) {
      sessionStatus.className = 'fs-session-status badge-starting';
      sessionStatus.textContent = 'Connecting';
    } else {
      sessionStatus.className = 'fs-session-status badge-standby';
      sessionStatus.textContent = 'Offline';
    }
  }

  // Re-bind copy button if recreated
  const newCopyIp = document.getElementById('btnFsCopyIp');
  if (newCopyIp) {
    newCopyIp.addEventListener('click', () => {
      navigator.clipboard.writeText(ip).then(() => {
        newCopyIp.textContent = '✓';
        sound.alertBlip();
        setTimeout(() => { newCopyIp.textContent = '📋'; }, 1800);
      }).catch(() => {});
    });
  }

  // Workstation Timer & Rail Controls Sync
  const fsRailStartText = document.getElementById('fsRailStartText');
  const fsRailStartIcon = document.getElementById('fsRailStartIcon');
  if (fsRailStartText) fsRailStartText.textContent = isRunning ? 'STOP LAB' : 'START LAB';
  if (fsRailStartIcon) fsRailStartIcon.textContent = isRunning ? '⏹' : '▶';

  if (isRunning) {
    startWorkstationTimer(currentLabSession.remaining_seconds || 3600);
  } else {
    const timerVal = document.getElementById('fsTimerVal');
    if (timerVal) timerVal.textContent = '--:--';
    if (wsCountdownInterval) clearInterval(wsCountdownInterval);
  }

  // Track Progress Gauge
  const pct = Math.min(100, Math.round((roomNum / 20) * 100));
  const gaugeBar = document.getElementById('fsGaugeBar');
  const gaugeVal = document.getElementById('fsGaugeVal');
  const progRooms = document.getElementById('fsProgressRooms');

  if (gaugeBar) {
    const circumference = 201;
    const offset = circumference - (circumference * pct) / 100;
    gaugeBar.style.strokeDashoffset = offset;
  }
  if (gaugeVal) gaugeVal.textContent = `${pct}%`;
  if (progRooms) progRooms.textContent = `${roomNum} / 20 Rooms`;

  // Mission Objectives & Timeline
  const totalTasks = currentRoom.tasks ? currentRoom.tasks.length : 4;
  const completedTasks = currentRoom.tasks ? currentRoom.tasks.filter(t => t.is_completed).length : 1;

  const objCount = document.getElementById('fsObjCount');
  const objFill = document.getElementById('fsObjBarFill');
  if (objCount) objCount.textContent = `${completedTasks} / ${totalTasks}`;
  if (objFill) objFill.style.width = `${totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 25}%`;

  // Update 5-Phase Mission Timeline
  // Step 1: Setup Environment
  // Step 2: Analyze Target
  // Step 3: Find Vulnerabilities
  // Step 4: Exploit (Optional)
  // Step 5: Report Findings
  const activePhase = Math.min(5, Math.max(1, completedTasks + 1));
  for (let i = 1; i <= 5; i++) {
    const stepEl = document.getElementById(`fsStep${i}`);
    if (!stepEl) continue;
    stepEl.classList.remove('completed', 'active');
    const indicator = stepEl.querySelector('.fs-step-indicator');
    if (indicator) indicator.classList.remove('pulse-ring');

    if (i < activePhase) {
      stepEl.classList.add('completed');
      if (indicator) indicator.innerHTML = '<span class="fs-step-check">✔</span>';
    } else if (i === activePhase) {
      stepEl.classList.add('active');
      if (indicator) {
        indicator.classList.add('pulse-ring');
        indicator.innerHTML = '<span class="fs-step-target">🎯</span>';
      }
    } else {
      if (indicator) indicator.innerHTML = '<span class="fs-step-dot"></span>';
    }
  }

  // Update Timeline Connectors
  const conn1 = document.getElementById('fsConn1');
  const conn2 = document.getElementById('fsConn2');
  const conn3 = document.getElementById('fsConn3');
  const conn4 = document.getElementById('fsConn4');
  if (conn1) { conn1.className = 'fs-step-connector ' + (activePhase > 1 ? 'completed' : ''); }
  if (conn2) { conn2.className = 'fs-step-connector ' + (activePhase > 2 ? 'completed' : (activePhase === 2 ? 'active' : '')); }
  if (conn3) { conn3.className = 'fs-step-connector ' + (activePhase > 3 ? 'completed' : (activePhase === 3 ? 'active' : '')); }
  if (conn4) { conn4.className = 'fs-step-connector ' + (activePhase > 4 ? 'completed' : (activePhase === 4 ? 'active' : '')); }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ---------------------------------------------------------------------------
// GHOST AI MENTOR STEP-BY-STEP GUIDED WORKFLOW & PROGRESSIVE HINTS
// ---------------------------------------------------------------------------

let ghostGuideData = null;
let currentGhostStep = 1;
let currentGhostHintLevel = 1;

async function initGhostMentor() {
  const header = document.getElementById('ghostMentorHeader');
  const content = document.getElementById('ghostMentorContent');
  const icon = document.getElementById('ghostMentorToggleIcon');

  if (header && content && icon) {
    header.addEventListener('click', () => {
      sound.keyClick();
      const isCollapsed = content.style.display === 'none';
      content.style.display = isCollapsed ? 'block' : 'none';
      icon.innerHTML = isCollapsed ? '&#9660;' : '&#9658;';
    });
  }

  // Bind Ask GHOST button and Enter key
  const btnAsk = document.getElementById('btnGhostAsk');
  const inputAsk = document.getElementById('inputGhostAsk');
  const replyBox = document.getElementById('ghostAskReplyBox');

  const handleAsk = async () => {
    if (!inputAsk) return;
    const q = inputAsk.value.trim();
    if (!q) return;
    sound.keyClick();
    if (replyBox) {
      replyBox.style.display = 'block';
      replyBox.innerHTML = '<span style="color:#00E5FF;">🤖 GHOST ANALYZING MISSION CONTEXT...</span>';
    }
    try {
      const res = await fetch(`/api/ghost/room/${roomId}/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q, current_step: currentGhostStep }),
      });
      if (!res.ok) {
        if (replyBox) replyBox.innerHTML = '<span style="color:#ef4444;">[-] GHOST guidance temporarily unavailable. Consult the guided steps.</span>';
        return;
      }
      const data = await res.json();
      sound.alertBlip();
      if (replyBox) {
        replyBox.innerHTML = `<span style="color:#00E5FF;font-weight:700;">🤖 GHOST MENTOR:</span><br>${escapeHtml(data.answer)}`;
      }
    } catch (err) {
      if (replyBox) replyBox.innerHTML = '<span style="color:#ef4444;">[-] GHOST communication failure.</span>';
    }
  };

  if (btnAsk) btnAsk.addEventListener('click', handleAsk);
  if (inputAsk) {
    inputAsk.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleAsk();
      }
    });
  }

  // Progressive Hint Buttons
  const btnRequestHint = document.getElementById('btnGhostRequestHint');
  const btnResetHint = document.getElementById('btnGhostResetHint');
  const hintTextEl = document.getElementById('ghostHintText');
  const hintBadgeEl = document.getElementById('ghostHintLevelBadge');
  const hintCmdBox = document.getElementById('ghostHintCmdBox');
  const hintCmdCode = document.getElementById('ghostHintCmdCode');
  const btnHintCopy = document.getElementById('btnGhostHintCopyCmd');

  const fetchHint = async (level) => {
    try {
      const res = await fetch(`/api/ghost/room/${roomId}/hint?level=${level}`);
      if (!res.ok) return;
      const data = await res.json();
      sound.alertBlip();
      if (hintBadgeEl) hintBadgeEl.textContent = `LEVEL ${data.level} / 4: ${(data.label || '').toUpperCase()}`;
      if (hintTextEl) hintTextEl.textContent = data.hint;
      if (data.command && hintCmdBox && hintCmdCode) {
        hintCmdBox.style.display = 'flex';
        hintCmdCode.textContent = data.command;
      } else if (hintCmdBox) {
        hintCmdBox.style.display = 'none';
      }
    } catch (err) {
      console.error('Failed to query hint:', err);
    }
  };

  if (btnRequestHint) {
    btnRequestHint.addEventListener('click', () => {
      sound.keyClick();
      currentGhostHintLevel = Math.min(4, currentGhostHintLevel + 1);
      fetchHint(currentGhostHintLevel);
    });
  }

  if (btnResetHint) {
    btnResetHint.addEventListener('click', () => {
      sound.keyClick();
      currentGhostHintLevel = 1;
      fetchHint(1);
    });
  }

  if (btnHintCopy && hintCmdCode) {
    btnHintCopy.addEventListener('click', () => {
      const cmd = hintCmdCode.textContent;
      if (cmd) {
        navigator.clipboard.writeText(cmd).then(() => {
          btnHintCopy.textContent = '✓ COPIED';
          sound.alertBlip();
          setTimeout(() => { btnHintCopy.textContent = '📋 COPY'; }, 1800);
        });
      }
    });
  }

  // Load guide data from API
  try {
    const res = await fetch(`/api/ghost/room/${roomId}/guide`);
    if (!res.ok) return;
    ghostGuideData = await res.json();
    renderGhostSteps();
  } catch (err) {
    console.error('Failed to load GHOST guide:', err);
  }
}

function renderGhostSteps() {
  if (!ghostGuideData || !ghostGuideData.steps) return;
  const container = document.getElementById('ghostStepsList');
  if (!container) return;

  container.innerHTML = '';
  ghostGuideData.steps.forEach((step) => {
    const btn = document.createElement('button');
    btn.className = `btn-hud-action ${step.step === currentGhostStep ? 'highlight' : ''}`;
    btn.style.fontSize = '10px';
    btn.style.padding = '3px 8px';
    btn.textContent = `[0${step.step}] ${step.title.split(' ')[0]}`;
    btn.title = `${step.title}: ${step.goal}`;
    btn.addEventListener('click', () => {
      sound.keyClick();
      currentGhostStep = step.step;
      renderGhostSteps();
      updateGhostActiveStep();
    });
    container.appendChild(btn);
  });

  updateGhostActiveStep();
}

function updateGhostActiveStep() {
  if (!ghostGuideData || !ghostGuideData.steps) return;
  const step = ghostGuideData.steps.find((s) => s.step === currentGhostStep) || ghostGuideData.steps[0];
  if (!step) return;

  const badge = document.getElementById('ghostStepBadge');
  const tool = document.getElementById('ghostToolBadge');
  const goal = document.getElementById('ghostStepGoal');
  const cmd = document.getElementById('ghostStepCmd');
  const expl = document.getElementById('ghostStepExpl');
  const btnCopy = document.getElementById('btnGhostCopyCmd');
  const btnRun = document.getElementById('btnGhostRunCmd');

  if (badge) badge.textContent = `STEP ${step.step} / 6: ${step.title.toUpperCase()}`;
  if (tool) tool.textContent = `TOOL: ${step.tool}`;
  if (goal) goal.textContent = step.goal;
  if (cmd) cmd.textContent = step.command;
  if (expl) expl.textContent = step.explanation;

  if (btnCopy) {
    btnCopy.onclick = () => {
      navigator.clipboard.writeText(step.command).then(() => {
        btnCopy.textContent = '✓ COPIED';
        sound.alertBlip();
        setTimeout(() => { btnCopy.textContent = '📋 COPY'; }, 1800);
      });
    };
  }

  if (btnRun) {
    btnRun.onclick = () => {
      executeWorkstationCommand(step.command);
    };
  }
}

document.addEventListener('DOMContentLoaded', initRoomWorkspace);

/**
 * NO ENTRY Academy Room Workspace
 * Cinematic, hands-on cybersecurity training room interface.
 * Connects concept theory, interactive tasks, lab session controls,
 * simulated/Docker target services, xterm.js terminal, and audio-visual feedback.
 */

import { sound } from '../core/sound.js';

let currentRoom = null;
let roomDataLoaded = false;
let currentLabSession = null;
let terminal = null;
let termFitAddon = null;
let termSocket = null;
let timerInterval = null;
let labOperation = null;

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
  if (currentLabSession?.status === 'AUTH_REQUIRED' && currentLabSession.error_message) {
    terminal.writeln(`\r\n\x1b[31m[-] ${currentLabSession.error_message}\x1b[0m\r\n`);
  }
  setupQuickCommands();
  setupEvidenceDrawer();
  initGhostMentor();
  syncFullscreenWorkstationData();

  if (window.location.search.includes('fullscreen') || window.location.search.includes('workstation') || sessionStorage.getItem('auto_workstation') === 'true') {
    setTimeout(openFullscreenWorkstation, 180);
  }
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
    const showBriefing = !roomDataLoaded && !sessionStorage.getItem(`briefing_seen_${roomId}`);
    applyTrackTheme();
    renderRoomHeader();
    renderConcept();
    renderTasks();
    populateMissionBriefing();
    updateProgress();

    // Auto-display Mission Briefing on first entry
    if (showBriefing) {
      setTimeout(() => {
        const briefingModal = document.getElementById('missionBriefingModal');
        if (briefingModal) {
          briefingModal.style.display = 'flex';
          sound.alertBlip();
        }
      }, 350);
    }
    roomDataLoaded = true;
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
  if (targetEl) targetEl.textContent = currentLabSession?.target_ip ? `${currentLabSession.target_ip}:${currentLabSession.target_port}` : 'Assigned when lab starts';

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
  const task = currentRoom.tasks?.find(item => !item.is_completed) || currentRoom.tasks?.[0];
  const practicalTool = currentRoom.required_practical_skills?.[0] || 'the room workstation';

  // 1. What is this? (Plain-English definition avoiding heavy jargon)
  const whatIsThis = c.what_is_this || c.overview || `${term}: ${desc}`;

  // 2. Everyday Analogy (Relatable real-world non-technical comparison)
  const analogy = c.simple_analogy || `Think of ${term} as a real-world version of the room objective: ${task?.title || desc}. The practical exercise shows what changes when this control is checked or missed.`;

  // 3. How it Works (Step-by-step breakdown of mechanics)
  let steps = c.how_it_works || [];
  if (!Array.isArray(steps) || steps.length === 0) {
    steps = (currentRoom.learning_objectives || []).slice(0, 4);
    if (!steps.length && task) steps = [task.instructions];
  }

  // 4. Technical Explanation (The actual protocols, code, flags, or configurations)
  const techDef = c.technical_definition ? `${c.technical_term ? c.technical_term + ': ' : ''}${c.technical_definition}` : c.cybersecurity_context || desc;

  // 5. Real-World Application & Impact (Why organizations care, CVE examples, breach history)
  const realWorld = c.real_world_application || c.why_it_matters || c.cybersecurity_context || desc;

  // 6. What to Observe in this Lab (Specific signs, logs, response codes, or flags)
  const observe = c.what_to_observe || task?.instructions || `Use ${practicalTool} and compare the result with this room's assessment criteria.`;

  // 7. Common Mistakes & Gotchas (What beginners do wrong and how to avoid it)
  const mistakes = c.common_mistakes || c.remediation_guide || task?.hint || `Use the room's assigned target and the syntax for ${practicalTool}; verify the returned evidence before submitting.`;

  // 8. Key Takeaway (One-sentence summary to remember)
  const takeaway = c.key_takeaway || currentRoom.learning_objectives?.[0] || desc;

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
  const targetLabel = currentLabSession?.status === 'RUNNING' && currentLabSession.target_ip
    ? `${currentLabSession.target_ip} (assigned)`
    : 'Assigned when lab starts';

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
        <text x="460" y="60" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">${targetLabel}</text>
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
      await loadRoomData();
      await refreshGhostGuide();

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
    if (res.status === 401) {
      throw new Error('Sign in or choose Guest Access at /access, then return to this room.');
    }
    if (!res.ok) throw new Error(`Lab status request failed (${res.status})`);
    const data = await res.json();
    currentLabSession = data;
    updateLabUI();
  } catch (err) {
    console.error('Failed to query lab status:', err);
    currentLabSession = {
      status: err.message.includes('/access') ? 'AUTH_REQUIRED' : 'UNKNOWN',
      error_message: err.message || 'Unable to retrieve authoritative lab status. Retry the status check.',
    };
    updateLabUI();
    addLiveActivityLog('ERR', currentLabSession.error_message);
  }
}

async function startLabSession() {
  if (labOperation) return;
  const btnStart = document.getElementById('btnStartLab');
  labOperation = 'STARTING';
  currentLabSession = { ...(currentLabSession || {}), status: 'STARTING' };
  updateLabUI();
  sound.keyClick();
  addLiveActivityLog('INFO', 'Provisioning isolated Docker containers...');

  try {
    const res = await fetch(`/api/academy/labs/${roomId}/start`, { method: 'POST' });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const detail = errData.detail || {};
      const statusTitle = detail.error || 'DOCKER_ERROR';
      const errMsg = res.status === 401
        ? 'Sign in or choose Guest Access at /access, then return to this room.'
        : detail.message || 'Failed to start lab session.';
      currentLabSession = {
        status: 'STOPPED',
        docker_status: res.status === 401 ? 'AUTH_REQUIRED' : statusTitle,
        error_message: `${errMsg}${detail.guidance ? ` ${detail.guidance}` : ''}`,
      };

      if (terminal) {
        terminal.writeln(`\r\n\x1b[31m[-] [${statusTitle}] ${errMsg}\x1b[0m`);
        if (detail.guidance) {
          terminal.writeln(`\x1b[36m[*] Guidance: ${detail.guidance}\x1b[0m\r\n`);
        }
      }
      addLiveActivityLog('ERR', `Startup failed: ${statusTitle}`);
      updateLabUI();
      return;
    }
    currentLabSession = await res.json();
    if (currentLabSession.status !== 'RUNNING') {
      throw new Error('Backend did not confirm the lab as RUNNING.');
    }
    sound.bootHum();
    await loadRoomData();
    updateLabUI();
    await refreshGhostGuide();
    addLiveActivityLog('INFO', `Lab range active at ${currentLabSession.target_ip}`);
    if (terminal) {
      terminal.clear();
    }
    reconnectTerminalWebSocket();
  } catch (err) {
    console.error('Failed to start lab:', err);
    currentLabSession = {
      ...(currentLabSession || {}),
      status: 'ERROR',
      error_message: err.message || 'Lab start connection error.',
    };
    addLiveActivityLog('ERR', currentLabSession.error_message);
    if (terminal) terminal.writeln(`\r\n\x1b[31m[-] ${currentLabSession.error_message}\x1b[0m`);
  } finally {
    labOperation = null;
    if (btnStart) btnStart.innerHTML = '&#9654; START LAB';
    updateLabUI();
  }
}

async function resetLabSession() {
  if (labOperation) return;
  sound.keyClick();
  if (!confirm('Are you sure you want to reset the lab database and workstation files to initial clean state?')) return;
  labOperation = 'RESETTING';
  currentLabSession = { ...(currentLabSession || {}), status: 'RESETTING' };
  updateLabUI();
  addLiveActivityLog('WARN', 'Resetting target database & operator workspace...');
  try {
    const res = await fetch(`/api/academy/labs/${roomId}/reset`, { method: 'POST' });
    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.detail?.message || error.detail || `Lab reset failed (${res.status}).`);
    }
    currentLabSession = await res.json();
    if (currentLabSession.status !== 'RUNNING') throw new Error('Backend did not confirm the reset lab as RUNNING.');
    await loadRoomData();
    await refreshGhostGuide();
    if (terminal) terminal.clear();
    updateLabUI();
    reconnectTerminalWebSocket();
    addLiveActivityLog('INFO', 'Fresh lab environment is online.');
  } catch (err) {
    console.error('Failed to reset lab:', err);
    currentLabSession = { ...(currentLabSession || {}), status: 'ERROR', error_message: err.message };
    addLiveActivityLog('ERR', err.message || 'Failed to reset lab.');
  } finally {
    labOperation = null;
    updateLabUI();
  }
}

async function stopLabSession() {
  if (labOperation) return;
  sound.keyClick();
  labOperation = 'STOPPING';
  currentLabSession = { ...(currentLabSession || {}), status: 'STOPPING' };
  updateLabUI();
  addLiveActivityLog('WARN', 'Stopping lab session and dismantling containers...');
  try {
    const res = await fetch(`/api/academy/labs/${roomId}/stop`, { method: 'POST' });
    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.detail?.message || error.detail || `Lab stop failed (${res.status}).`);
    }
    await checkLabStatus();
    await loadRoomData();
    await refreshGhostGuide();
    if (terminal) terminal.writeln('\r\n\x1b[31m[-] Lab session stopped.\x1b[0m\r\n');
    addLiveActivityLog('WARN', 'Lab in standby.');
    if (termSocket) {
      try { termSocket.close(); } catch (_) {}
      termSocket = null;
    }
  } catch (err) {
    console.error('Failed to stop lab:', err);
    currentLabSession = { ...(currentLabSession || {}), status: 'ERROR', error_message: err.message };
    addLiveActivityLog('ERR', err.message || 'Failed to stop lab.');
  } finally {
    labOperation = null;
    updateLabUI();
  }
}

function updateLabUI() {
  const targetIpEl = document.getElementById('labTargetIpText');
  const attackerIpEl = document.getElementById('labAttackerIpText');
  const runnerBadge = document.getElementById('labRunnerBadge');
  const timerEl = document.getElementById('labTimerText');
  const webLink = document.getElementById('btnTargetAppWebLink');
  const termDot = document.getElementById('termDotIndicator');
  const termBadge = document.getElementById('termStatusBadge');
  const btnStart = document.getElementById('btnStartLab');
  const btnReset = document.getElementById('btnResetLab');
  const btnStop = document.getElementById('btnStopLab');
  const state = currentLabSession?.status || 'STOPPED';
  const isDockerOnline = state === 'RUNNING' && currentLabSession.runner_mode === 'docker';
  const isTransitioning = ['STARTING', 'STOPPING', 'RESETTING'].includes(state);

  [btnStart, btnReset, btnStop].forEach(button => {
    if (button) button.disabled = Boolean(labOperation);
  });

  if (isDockerOnline) {
    if (termDot) termDot.classList.add('online');
    if (termBadge) {
      termBadge.textContent = 'ONLINE';
      termBadge.className = 'term-status-badge online';
    }
    if (targetIpEl) targetIpEl.textContent = `${currentLabSession.target_ip}:${currentLabSession.target_port}`;
    if (attackerIpEl) attackerIpEl.textContent = currentLabSession.attacker_ip || 'UNAVAILABLE';
    if (webLink) {
      webLink.style.display = 'none';
    }

    if (runnerBadge) {
      runnerBadge.textContent = 'DOCKER CONTAINERS [ISOLATED]';
      runnerBadge.className = 'runner-badge docker';
    }

    startTimer(currentLabSession.remaining_seconds || 3600);
  } else {
    if (termDot) termDot.classList.remove('online');
    if (termBadge) {
      termBadge.textContent = isTransitioning ? state : state === 'RUNNING' ? 'EMULATED' : state;
      termBadge.className = 'term-status-badge standby';
    }
    if (targetIpEl) targetIpEl.textContent = currentLabSession?.target_ip ? `${currentLabSession.target_ip}:${currentLabSession.target_port}` : 'NOT ASSIGNED';
    if (attackerIpEl) attackerIpEl.textContent = currentLabSession?.attacker_ip || 'NOT ASSIGNED';
    if (timerEl) timerEl.textContent = '--:--';
    if (webLink) webLink.style.display = 'none';
    if (runnerBadge) {
      if (isTransitioning) {
        runnerBadge.textContent = state;
        runnerBadge.className = 'runner-badge';
      } else if (currentLabSession && currentLabSession.error_message) {
        runnerBadge.textContent = 'LAB ERROR';
        runnerBadge.className = 'runner-badge emulated';
      } else if (currentLabSession?.status === 'RUNNING' && currentLabSession.runner_mode === 'emulated') {
        runnerBadge.textContent = 'PROCESS EMULATION';
        runnerBadge.className = 'runner-badge emulated';
      } else if (currentLabSession && currentLabSession.docker_status === 'DOCKER_AVAILABLE') {
        runnerBadge.textContent = 'DOCKER READY';
        runnerBadge.className = 'runner-badge docker';
      } else if (currentLabSession && currentLabSession.docker_status) {
        runnerBadge.textContent = currentLabSession.docker_status;
        runnerBadge.className = 'runner-badge emulated';
      } else {
        runnerBadge.textContent = 'STOPPED';
        runnerBadge.className = 'runner-badge';
      }
    }
    if (timerInterval) clearInterval(timerInterval);
  }
  setupQuickCommands();
  if (termSocket && !isDockerOnline) {
    try { termSocket.close(); } catch (_) {}
    termSocket = null;
  }
  const targetEl = document.getElementById('briefingTarget');
  if (targetEl) targetEl.textContent = isDockerOnline ? `${currentLabSession.target_ip}:${currentLabSession.target_port}` : 'Assigned when lab starts';
  if (currentRoom) renderConcept();
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

  const activeTask = currentRoom.tasks?.find(task => !task.is_completed) || currentRoom.tasks?.[0];
  const hasDockerLab = currentLabSession?.status === 'RUNNING' && currentLabSession.runner_mode === 'docker';
  const reference = {
    source: 'academy curriculum reference (not live lab evidence)',
    room_id: currentRoom.room_id,
    title: currentRoom.title,
    lab_status: currentLabSession?.status || 'STOPPED',
    assigned_target: hasDockerLab
      ? `${currentLabSession.target_ip}:${currentLabSession.target_port}`
      : null,
    learning_objectives: currentRoom.learning_objectives || [],
    current_task: activeTask
      ? { title: activeTask.title, instructions: activeTask.instructions, hint: activeTask.hint }
      : null,
    assessment_criteria: currentRoom.assessment_criteria || [],
    evidence_notice: 'No room-specific evidence file is supplied by this panel. Use the running lab and task instructions for evidence.',
  };
  filePathEl.textContent = `ACADEMY CURRICULUM // ${currentRoom.room_id}`;
  contentPre.textContent = JSON.stringify(reference, null, 2);
  const copyEvidenceButton = document.getElementById('btnCopyEvidenceCmd');
  if (copyEvidenceButton) {
    copyEvidenceButton.disabled = true;
    copyEvidenceButton.title = 'This room does not provide an evidence file.';
  }
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

  // Wire terminal toolbar buttons
  const btnClear = document.getElementById('btnTermClear');
  const btnReset = document.getElementById('btnTermReset');
  if (btnClear) {
    btnClear.addEventListener('click', () => {
      sound.keyClick();
      if (terminal) terminal.clear();
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
      termFitAddon.fit();
    } else if (terminal && container) {
      const cols = Math.max(40, Math.floor(container.clientWidth / 7.5));
      const rows = Math.max(15, Math.floor(container.clientHeight / 17));
      terminal.resize(cols, rows);
    }
  };
  setTimeout(updateSize, 100);

  terminal.onData(data => {
    sound.keyClick();
    if (termSocket && termSocket.readyState === WebSocket.OPEN) {
      termSocket.send(JSON.stringify({ type: 'input', data: data }));
    }
  });

  window.addEventListener('resize', updateSize);
  if (currentLabSession?.status === 'RUNNING' && currentLabSession.runner_mode === 'docker') {
    reconnectTerminalWebSocket();
  } else {
    terminal.writeln('\x1b[33mLab stopped. Start the Docker lab to connect to the isolated attacker container.\x1b[0m');
  }
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
  if (!currentLabSession || currentLabSession.status !== 'RUNNING' || currentLabSession.runner_mode !== 'docker') {
    return;
  }
  if (termSocket) {
    try { termSocket.close(); } catch (_) {}
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/academy/${roomId}/terminal`;

  const socket = new WebSocket(wsUrl);
  termSocket = socket;

  socket.onmessage = evt => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'output' && terminal) {
        terminal.write(msg.data);
      } else if (msg.type === 'exit_status') {
        if (terminal && Number.isInteger(msg.code)) {
          terminal.write(`\r\n\x1b[90m[exit status: ${msg.code}]\x1b[0m\r\n`);
        }
        refreshGhostGuide();
      }
    } catch (_) {
      if (terminal) terminal.write(evt.data);
    }
  };

  socket.onerror = err => {
    console.error('Terminal WebSocket error:', err);
    if (terminal && termSocket === socket) {
      terminal.writeln('\r\n\x1b[31m[-] Terminal WebSocket connection failed.\x1b[0m');
    }
  };
  socket.onclose = () => {
    if (terminal && termSocket === socket && currentLabSession?.status === 'RUNNING') {
      terminal.writeln('\r\n\x1b[31m[-] Terminal connection closed. Check the lab status before reconnecting.\x1b[0m');
    }
  };
}

// ---------------------------------------------------------------------------
// DYNAMIC QUICK PROBES (ALL 80 ROOMS)
// ---------------------------------------------------------------------------

function setupQuickCommands() {
  const bar = document.getElementById('quickCmdBar');
  if (!bar || !roomId) return;

  bar.innerHTML = '<span style="font-family:var(--font-mono);font-size:10px;color:#64748b;align-self:center;">QUICK PROBES:</span>';
  if (currentLabSession?.status !== 'RUNNING' || currentLabSession.runner_mode !== 'docker' || !currentLabSession.target_ip) {
    bar.insertAdjacentHTML('beforeend', '<span style="font-family:var(--font-mono);font-size:10px;color:#64748b;align-self:center;">START LAB TO LOAD VERIFIED COMMANDS</span>');
    return;
  }
  const buttons = getQuickProbes(currentLabSession.target_ip, currentLabSession.target_port);
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
      if (termSocket && termSocket.readyState === WebSocket.OPEN) {
        termSocket.send(JSON.stringify({ type: 'command', command: cmd }));
      }
    });
  });
}

function getQuickProbes(targetIp, port) {
  return [
    { label: 'whoami / id', cmd: 'whoami && id' },
    { label: 'ip -br addr', cmd: 'ip -br addr' },
    { label: 'nmap room service', cmd: `nmap -sV --version-light -T4 --max-retries 1 -p ${port} ${targetIp}` },
    { label: `curl target :${port}`, cmd: `curl -sS -i http://${targetIp}:${port}/` },
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
      if (terminal) terminal.clear();
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
      const ip = currentLabSession?.status === 'RUNNING' && currentLabSession.runner_mode === 'docker'
        ? currentLabSession.target_ip
        : null;
      if (!ip) return;
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

  // 8. Left Navigation Rail
  setupLeftRailControls();

  // 9. Quick Commands in Right Panel
  setupWorkstationQuickCommands();

  // 10. Drawer Close
  if (btnFsCloseDrawer) {
    btnFsCloseDrawer.addEventListener('click', () => {
      const drawer = document.getElementById('fsDrawerOverlay');
      if (drawer) drawer.style.display = 'none';
    });
  }

  // 11. Start Countdown Timer
  startWorkstationTimer();
}

function openFullscreenWorkstation() {
  const ws = document.getElementById('fullscreenWorkstation');
  const termContainer = document.getElementById('terminalContainer');
  const fsMount = document.getElementById('fsTerminalMount');
  if (!ws || !termContainer || !fsMount) return;

  sound.bootHum();
  ws.style.display = 'flex';
  void ws.offsetWidth; // force reflow
  ws.classList.add('active');

  // Reparent terminal container into workstation
  fsMount.appendChild(termContainer);

  if (document.documentElement.requestFullscreen) {
    document.documentElement.requestFullscreen().catch(() => {});
  }

  syncFullscreenWorkstationData();

  setTimeout(() => {
    if (termFitAddon) {
      termFitAddon.fit();
    }
    if (terminal) {
      terminal.focus();
    }
  }, 120);

  addLiveActivityLog('INFO', 'Operator workstation initialized in full-screen mode');
}

function closeFullscreenWorkstation() {
  const ws = document.getElementById('fullscreenWorkstation');
  const termContainer = document.getElementById('terminalContainer');
  const normalMount = document.getElementById('normalTerminalMount');
  if (!ws || !termContainer || !normalMount) return;

  sound.keyClick();
  ws.classList.remove('active', 'terminal-focus-active');
  ws.style.display = 'none';

  // Reparent terminal container back to normal room workspace
  normalMount.appendChild(termContainer);

  if (document.fullscreenElement && document.exitFullscreen) {
    document.exitFullscreen().catch(() => {});
  }

  setTimeout(() => {
    if (termFitAddon) {
      termFitAddon.fit();
    }
    if (terminal) {
      terminal.focus();
    }
  }, 100);
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

function setupLeftRailControls() {
  const btnTerm = document.getElementById('btnFsRailTerm');
  const btnConcept = document.getElementById('btnFsRailConcept');
  const btnEvidence = document.getElementById('btnFsRailEvidence');
  const btnHints = document.getElementById('btnFsRailHints');
  const btnProbes = document.getElementById('btnFsRailProbes');
  const btnReset = document.getElementById('btnFsRailReset');

  const railBtns = [btnTerm, btnConcept, btnEvidence, btnHints, btnProbes];
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

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      sound.keyClick();
      addLiveActivityLog('WARN', 'Triggering lab session reset...');
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
    title.textContent = '💡 MISSION TACTICAL HINTS & GUIDANCE';
    let hintsHtml = '<div style="display:flex;flex-direction:column;gap:12px;padding:12px;">';
    if (currentRoom && currentRoom.tasks && currentRoom.tasks.length > 0) {
      currentRoom.tasks.forEach((t, idx) => {
        hintsHtml += `
          <div style="background:#050a14;border:1px solid rgba(255,230,0,0.3);border-radius:6px;padding:12px;">
            <div style="font-family:var(--font-mono);color:#FFE600;font-weight:800;font-size:11px;margin-bottom:6px;">TASK ${idx + 1}: ${escapeHtml(t.title)}</div>
            <div style="color:#cbd5e1;font-size:12px;line-height:1.4;">${t.hint ? escapeHtml(t.hint) : 'Execute standard reconnaissance commands and inspect target responses.'}</div>
          </div>`;
      });
    } else {
      hintsHtml += '<p style="color:#94a3b8;">Execute network probes and inspect system processes to reveal vulnerabilities.</p>';
    }
    hintsHtml += '</div>';
    body.innerHTML = hintsHtml;
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
  if (currentLabSession?.status !== 'RUNNING' || currentLabSession.runner_mode !== 'docker') {
    terminal.writeln('\r\n\x1b[31m[-] Start the Docker lab before running commands.\x1b[0m');
    return;
  }
  if (!termSocket || termSocket.readyState !== WebSocket.OPEN) {
    terminal.writeln('\r\n\x1b[31m[-] No active Docker terminal connection. The command was not sent.\x1b[0m');
    return;
  }
  sound.keyClick();
  termSocket.send(JSON.stringify({ type: 'command', command: cmd }));
  addLiveActivityLog('CMD', `Sent to Docker terminal: ${cmd}`);
}

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

function startWorkstationTimer() {
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
    }
  }, 1000);
}

function syncFullscreenWorkstationData() {
  if (!currentRoom) return;

  // Header & Info
  const roomNum = currentRoom.room_number || 0;
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
  if (xp) xp.textContent = `XP ${currentRoom.total_xp || 0}`;
  if (desc) desc.textContent = currentRoom.concept?.overview || currentRoom.short_description || '';
  if (chipTrack) chipTrack.textContent = `🛡️ ${(currentRoom.track || 'Red').toUpperCase()} TEAM`;
  if (chipDiff) chipDiff.textContent = `📶 ${currentRoom.difficulty || 'Medium'}`;
  if (chipDuration) chipDuration.textContent = `⏱ ~ ${currentRoom.estimated_duration || '—'}`;
  if (chipXp) chipXp.textContent = `★ ${currentRoom.total_xp || 0} XP`;

  // Lab Intel
  const isRunning = currentLabSession?.status === 'RUNNING' && currentLabSession.runner_mode === 'docker';
  const ip = isRunning ? currentLabSession.target_ip : 'NOT ASSIGNED';
  const attackerIp = isRunning ? currentLabSession.attacker_ip : 'NOT ASSIGNED';
  const port = isRunning ? currentLabSession.target_port : null;
  const openPorts = isRunning && Array.isArray(currentLabSession.open_ports)
    ? currentLabSession.open_ports
    : [];
  const statusStr = isRunning
    ? 'ONLINE'
    : currentLabSession?.status === 'RUNNING' && currentLabSession.runner_mode === 'emulated'
      ? 'EMULATED'
      : currentLabSession?.status || 'STOPPED';

  const intelIp = document.getElementById('fsIntelIp');
  const intelOperatorIp = document.getElementById('fsIntelOperatorIp');
  const intelStatus = document.getElementById('fsIntelStatus');
  const intelPorts = document.getElementById('fsIntelPorts');
  const intelContainer = document.getElementById('fsIntelContainer');
  const sessionIp = document.getElementById('fsSessionIp');
  const fsStatusPill = document.getElementById('fsStatusPill');
  const fsStatusText = document.getElementById('fsStatusText');
  const fsTermReadyBadge = document.getElementById('fsTermReadyBadge');
  const sessionCount = document.getElementById('fsSessionCount');
  const sessionDot = document.getElementById('fsSessionDot');
  const sessionStatus = document.getElementById('fsSessionStatus');

  if (intelIp) intelIp.innerHTML = `${ip} <button id="btnFsCopyIp" class="fs-copy-inline" title="Copy Target IP" ${isRunning ? '' : 'disabled'}>📋</button>`;
  if (intelOperatorIp) intelOperatorIp.textContent = attackerIp;
  if (sessionIp) sessionIp.textContent = ip;
  if (sessionCount) sessionCount.textContent = String(isRunning ? currentLabSession.active_sessions_count || 1 : 0);
  if (sessionDot) sessionDot.className = `dot ${isRunning ? 'green' : 'red'}`;
  if (sessionStatus) {
    sessionStatus.textContent = isRunning ? 'Active' : statusStr === 'EXPIRED' ? 'Expired' : 'Standby';
    sessionStatus.className = `fs-session-status${isRunning ? ' badge-active' : ''}`;
  }

  if (isRunning) {
    if (intelStatus) intelStatus.innerHTML = `<span class="dot green"></span> ONLINE`;
    if (intelPorts) intelPorts.innerHTML = `<span class="dot green"></span> ${openPorts.join(', ') || 'No ports reported'}`;
    if (intelContainer) intelContainer.innerHTML = `<span class="dot green"></span> ${currentLabSession.running_containers?.length || 0} containers running`;
    if (fsStatusPill) fsStatusPill.className = 'fs-status-pill online';
    if (fsStatusText) fsStatusText.textContent = 'ONLINE';
    if (fsTermReadyBadge) {
      fsTermReadyBadge.textContent = '▶ READY';
      fsTermReadyBadge.style.color = '#00FF6A';
    }
  } else {
    if (intelStatus) intelStatus.innerHTML = `<span class="dot red"></span> ${statusStr}`;
    if (intelPorts) intelPorts.innerHTML = `<span class="dot red"></span> OFFLINE`;
    if (intelContainer) intelContainer.innerHTML = `<span class="dot red"></span> stopped`;
    if (fsStatusPill) fsStatusPill.className = 'fs-status-pill offline';
    if (fsStatusText) fsStatusText.textContent = statusStr;
    if (fsTermReadyBadge) {
      fsTermReadyBadge.textContent = '⏸ STANDBY';
      fsTermReadyBadge.style.color = '#ef4444';
    }
  }

  // Update quick command buttons target IP dynamically
  const quickBtns = document.querySelectorAll('#fsQuickCmdGrid .fs-cmd-btn');
  quickBtns.forEach(btn => {
    const rawCmd = btn.dataset.cmd;
    btn.disabled = !isRunning;
    if (!isRunning || !ip || !port) {
      return;
    } else if (rawCmd && rawCmd.includes('nmap')) {
      btn.disabled = false;
      btn.dataset.cmd = `nmap -sV --version-light -T4 --max-retries 1 -F ${ip}`;
    } else if (rawCmd && rawCmd.startsWith('curl')) {
      btn.disabled = false;
      btn.dataset.cmd = `curl -s http://${ip}:${port}/`;
    }
  });

  // Re-bind copy button if recreated
  const newCopyIp = document.getElementById('btnFsCopyIp');
  if (newCopyIp) {
    newCopyIp.disabled = !isRunning;
    newCopyIp.addEventListener('click', () => {
      if (!isRunning || !currentLabSession?.target_ip) return;
      navigator.clipboard.writeText(ip).then(() => {
        newCopyIp.textContent = '✓';
        sound.alertBlip();
        setTimeout(() => { newCopyIp.textContent = '📋'; }, 1800);
      }).catch(() => {});
    });
  }

  // Track Progress Gauge
  const totalTasks = currentRoom.tasks?.length || 0;
  const completedTasks = currentRoom.tasks?.filter(task => task.is_completed).length || 0;
  const pct = totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0;
  const gaugeBar = document.getElementById('fsGaugeBar');
  const gaugeVal = document.getElementById('fsGaugeVal');
  const progRooms = document.getElementById('fsProgressRooms');

  if (gaugeBar) {
    const circumference = 201;
    const offset = circumference - (circumference * pct) / 100;
    gaugeBar.style.strokeDashoffset = offset;
  }
  if (gaugeVal) gaugeVal.textContent = `${pct}%`;
  if (progRooms) progRooms.textContent = `${completedTasks} / ${totalTasks} Tasks`;

  // Mission Objectives & Timeline
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
  const activePhase = currentRoom.user_status === 'COMPLETED'
    ? 6
    : Math.min(5, Math.max(1, completedTasks + 1));
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

  await refreshGhostGuide();
}

async function refreshGhostGuide() {
  try {
    const res = await fetch(`/api/ghost/room/${roomId}/guide`);
    if (!res.ok) return;
    ghostGuideData = await res.json();
    currentGhostStep = ghostGuideData.active_step || 1;
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
    if (step.completed) btn.classList.add('completed');
    btn.style.fontSize = '10px';
    btn.style.padding = '3px 8px';
    btn.textContent = `${step.completed ? '✓ ' : ''}[0${step.step}] ${step.title.split(' ')[0]}`;
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
  if (cmd) cmd.textContent = step.command || 'Start the Docker lab to receive a verified command for this step.';
  if (expl) expl.textContent = step.explanation;

  if (btnCopy) {
    btnCopy.disabled = !step.command;
    btnCopy.onclick = () => {
      if (!step.command) return;
      navigator.clipboard.writeText(step.command).then(() => {
        btnCopy.textContent = '✓ COPIED';
        sound.alertBlip();
        setTimeout(() => { btnCopy.textContent = '📋 COPY'; }, 1800);
      });
    };
  }

  if (btnRun) {
    btnRun.disabled = !step.command || currentLabSession?.status !== 'RUNNING' || currentLabSession?.runner_mode !== 'docker';
    btnRun.onclick = () => {
      if (step.command) executeWorkstationCommand(step.command);
    };
  }
}

document.addEventListener('DOMContentLoaded', initRoomWorkspace);

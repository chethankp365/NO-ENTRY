/**
 * NO ENTRY Academy Room Workspace
 * TryHackMe-style hands-on room interface.
 * Connects concept theory, interactive tasks, lab session controls, and xterm.js terminal.
 */

let currentRoom = null;
let currentLabSession = null;
let terminal = null;
let termFitAddon = null;
let termSocket = null;
let timerInterval = null;

const containerEl = document.querySelector('.workspace-container');
const roomId = containerEl ? containerEl.dataset.roomId : null;

async function initRoomWorkspace() {
  if (!roomId) return;

  setupConceptToggle();
  setupLabButtons();
  setupQuickCommands();

  await loadRoomData();
  await checkLabStatus();
  initTerminal();
}

function setupConceptToggle() {
  const header = document.getElementById('conceptHeader');
  const content = document.getElementById('conceptContent');
  const icon = document.getElementById('conceptToggleIcon');

  if (header && content) {
    header.addEventListener('click', () => {
      const isHidden = content.style.display === 'none';
      content.style.display = isHidden ? 'block' : 'none';
      if (icon) icon.innerHTML = isHidden ? '&#9660;' : '&#9654;';
    });
  }
}

async function loadRoomData() {
  try {
    const res = await fetch(`/api/academy/rooms/${roomId}`);
    if (!res.ok) {
      alert(`Error loading room: ${res.statusText}`);
      return;
    }
    currentRoom = await res.json();
    renderRoomHeader();
    renderConcept();
    renderTasks();
    updateProgress();
  } catch (err) {
    console.error('Failed to load room details:', err);
  }
}

function renderRoomHeader() {
  if (!currentRoom) return;

  const trackBreadcrumb = document.getElementById('roomTrackBreadcrumb');
  const numberBreadcrumb = document.getElementById('roomNumberBreadcrumb');
  const titleText = document.getElementById('roomTitleText');
  const diffBadge = document.getElementById('roomDifficultyBadge');
  const durBadge = document.getElementById('roomDurationBadge');
  const xpBadge = document.getElementById('roomXpBadge');

  if (trackBreadcrumb) trackBreadcrumb.textContent = `${currentRoom.track.toUpperCase()} TEAM`;
  if (numberBreadcrumb) numberBreadcrumb.textContent = `ROOM ${String(currentRoom.room_number).padStart(2, '0')}`;
  if (titleText) titleText.textContent = currentRoom.title;
  if (diffBadge) diffBadge.textContent = currentRoom.difficulty;
  if (durBadge) durBadge.textContent = currentRoom.estimated_duration;
  if (xpBadge) xpBadge.textContent = `+${currentRoom.total_xp} XP`;
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
          <input type="text" class="task-input" id="input_${task.task_id}" placeholder="${task.question || 'Enter flag or answer...'}" value="${task.is_completed ? '[COMPLETED]' : ''}" ${task.is_completed ? 'disabled' : ''}>
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
          alert(`🏆 CONGRATULATIONS! You have completed Room: ${currentRoom.title}!\nTotal XP Earned: +${currentRoom.total_xp} XP!`);
        }, 300);
      }
    } else {
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

  try {
    const res = await fetch(`/api/academy/labs/${roomId}/start`, { method: 'POST' });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const detail = errData.detail || {};
      const statusTitle = detail.error || 'DOCKER_ERROR';
      const errMsg = detail.message || 'Failed to start lab session.';
      const guidance = detail.guidance ? `\n\nGUIDANCE: ${detail.guidance}` : '';
      alert(`[${statusTitle}]\n${errMsg}${guidance}`);

      if (terminal) {
        terminal.writeln(`\r\n\x1b[31m[-] [${statusTitle}] ${errMsg}\x1b[0m`);
        if (detail.guidance) {
          terminal.writeln(`\x1b[36m[*] Guidance: ${detail.guidance}\x1b[0m\r\n`);
        }
      }
      return;
    }
    currentLabSession = await res.json();
    updateLabUI();
    if (terminal) {
      terminal.writeln('\r\n\x1b[32m[+] Isolated Docker lab environment ready! Connecting...\x1b[0m\r\n');
    }
    reconnectTerminalWebSocket();
  } catch (err) {
    console.error('Failed to start lab:', err);
  } finally {
    if (btnStart) btnStart.innerHTML = '&#9654; START LAB';
  }
}

async function resetLabSession() {
  if (!confirm('Are you sure you want to reset the lab database to its initial state?')) return;
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
  try {
    const res = await fetch(`/api/academy/labs/${roomId}/stop`, { method: 'POST' });
    if (res.ok) {
      currentLabSession = null;
      updateLabUI();
      if (terminal) terminal.writeln('\r\n\x1b[31m[-] Lab session stopped and containers destroyed.\x1b[0m\r\n');
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
        // In Docker mode, target is strictly isolated inside the private bridge network
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
// XTERM.JS TERMINAL INTEGRATION
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
      magenta: '#bd00ff',
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

  terminal.onData(data => {
    if (termSocket && termSocket.readyState === WebSocket.OPEN) {
      termSocket.send(JSON.stringify({ type: 'input', data: data }));
    }
  });

  window.addEventListener('resize', updateSize);

  reconnectTerminalWebSocket();
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

function setupQuickCommands() {
  const bar = document.querySelector('.quick-cmd-bar');
  if (bar && roomId) {
    let buttons = [];
    if (roomId.startsWith('blue-01') || roomId.includes('blue-team-foundations') || roomId.includes('soc-fundamentals')) {
      buttons = [
        { label: 'curl soc events (:8201)', cmd: 'curl -s http://10.10.14.90:8201/api/soc/events' },
        { label: 'python soc_query.py', cmd: 'python3 /home/operator/tools/soc_query.py' },
        { label: 'curl siem alerts', cmd: 'curl -s http://10.10.14.90:8201/api/soc/alerts' },
        { label: 'curl post triage', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"event_id\":\"EVT-1003\",\"classification\":\"TRUE_POSITIVE\",\"severity\":\"HIGH\"}' http://10.10.14.90:8201/api/soc/triage" },
        { label: 'curl post challenge', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"incident_id\":\"INC-2026-01\",\"timeline_entry\":\"DC_BRUTEFORCE_SUCCESS\",\"dc_host\":\"DC-VOLT01\"}' http://10.10.14.90:8201/challenge" },
        { label: 'curl post remediate', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"block_ip\":\"198.51.100.42\",\"action\":\"CONTAIN_SESSION\"}' http://10.10.14.90:8201/api/soc/remediate" },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-02') || roomId.includes('windows-security') || roomId.includes('windows-event-logs')) {
      buttons = [
        { label: 'curl logon events (:8202)', cmd: 'curl -s http://10.10.14.90:8202/api/windows/events/logon' },
        { label: 'python parse_evtx.py', cmd: 'python3 /home/operator/tools/parse_evtx.py' },
        { label: 'curl privilege audit', cmd: 'curl -s http://10.10.14.90:8202/api/windows/events/privileged' },
        { label: 'curl post challenge', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"audit_type\":\"SEDEBUG_PRIVILEGE\",\"user\":\"corp\\\\operator\",\"status\":\"REVOKED\"}' http://10.10.14.90:8202/challenge" },
        { label: 'curl post remediate', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"lockout_threshold\":5,\"reset_duration_mins\":30}' http://10.10.14.90:8202/api/windows/remediate" },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-03') || roomId.includes('linux-security') || roomId.includes('linux-log-analysis')) {
      buttons = [
        { label: 'cat /var/log/auth.log', cmd: 'cat /var/log/auth.log' },
        { label: 'curl ssh auth logs (:8203)', cmd: 'curl -s http://10.10.14.90:8203/api/linux/logs/auth' },
        { label: 'curl sudo logs', cmd: 'curl -s http://10.10.14.90:8203/api/linux/logs/sudo' },
        { label: 'curl post challenge', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"attacker_ip\":\"192.0.2.144\",\"service\":\"ssh\",\"action\":\"BLOCK_AND_LOG\"}' http://10.10.14.90:8203/challenge" },
        { label: 'curl post remediate', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"harden_ssh\":true,\"enable_fail2ban\":true}' http://10.10.14.90:8203/api/linux/remediate" },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-04') || roomId.includes('traffic-analysis') || roomId.includes('wireshark-packets')) {
      buttons = [
        { label: 'tcpdump -r incident_capture.pcap', cmd: 'tcpdump -nn -r /home/operator/pcaps/incident_capture.pcap' },
        { label: 'curl pcap summary (:8204)', cmd: 'curl -s http://10.10.14.90:8204/api/traffic/summary' },
        { label: 'curl dns exfil analysis', cmd: 'curl -s http://10.10.14.90:8204/api/traffic/dns-exfil' },
        { label: 'curl post challenge', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"covert_channel\":\"dns\",\"tunnel_domain\":\"exfil-chunk-data.corp.noentry.internal\"}' http://10.10.14.90:8204/challenge" },
        { label: 'curl post remediate', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"enforce_tls\":true,\"sinkhole_malicious_dns\":true}' http://10.10.14.90:8204/api/traffic/remediate" },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-05') || roomId.includes('wireshark-fundamentals') || roomId.includes('wireshark-packets')) {
      buttons = [
        { label: 'tshark pcap summary', cmd: 'tshark -r /home/operator/pcaps/suspicious_http_dns.pcap -c 10' },
        { label: 'tshark HTTP requests', cmd: 'tshark -r /home/operator/pcaps/suspicious_http_dns.pcap -Y "http.request" -T fields -e http.host -e http.request.uri' },
        { label: 'curl pcap summary (:8205)', cmd: 'curl -s http://10.10.14.90:8205/api/pcap/summary' },
        { label: 'curl http streams (:8205)', cmd: 'curl -s http://10.10.14.90:8205/api/pcap/streams/http' },
        { label: 'curl dns queries (:8205)', cmd: 'curl -s http://10.10.14.90:8205/api/pcap/queries/dns' },
        { label: 'curl tcp flags (:8205)', cmd: 'curl -s http://10.10.14.90:8205/api/pcap/handshake/tcp' },
        { label: 'curl post challenge', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"suspicious_domain":"c2-beacon.corp.noentry.internal","filter":"dns.qry.name contains \\"c2-beacon\\""}\' http://10.10.14.90:8205/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-06') || roomId.includes('log-analysis-fundamentals') || roomId.includes('log-analysis')) {
      buttons = [
        { label: 'cat nginx access.log', cmd: 'cat /var/log/nginx/access.log | head -n 15' },
        { label: 'awk status codes', cmd: "awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c" },
        { label: 'grep 404 access.log', cmd: 'grep " 404 " /var/log/nginx/access.log' },
        { label: 'grep CRITICAL app.log', cmd: 'grep "CRITICAL" /var/log/app/app.log' },
        { label: 'curl nginx summary (:8206)', cmd: 'curl -s http://10.10.14.90:8206/api/logs/nginx/summary' },
        { label: 'curl app critical (:8206)', cmd: 'curl -s http://10.10.14.90:8206/api/logs/app/critical' },
        { label: 'curl post challenge', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"attacker_ip":"203.0.113.88","log_level":"CRITICAL"}\' http://10.10.14.90:8206/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-07') || roomId.includes('siem-fundamentals') || roomId.includes('siem-splunk-elk')) {
      buttons = [
        { label: 'python siem_query.py', cmd: 'python3 /home/operator/tools/siem_query.py' },
        { label: 'curl siem search (:8207)', cmd: 'curl -s http://10.10.14.90:8207/api/siem/search' },
        { label: 'curl siem alerts (:8207)', cmd: 'curl -s http://10.10.14.90:8207/api/siem/alerts' },
        { label: 'curl filter high severity', cmd: 'curl -s "http://10.10.14.90:8207/api/siem/alerts?severity=HIGH"' },
        { label: 'curl post custom rule', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_name":"RULE_ANOMALOUS_EGRESS","condition":"bytes_out > 10000000","severity":"HIGH"}\' http://10.10.14.90:8207/api/siem/rules' },
        { label: 'curl post challenge', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"alert_id":"ALRT-701","rule_name":"RULE_BRUTE_FORCE_EXFIL","priority":"CRITICAL"}\' http://10.10.14.90:8207/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-08') || roomId.includes('windows-event-investigation') || roomId.includes('windows-event-logs')) {
      buttons = [
        { label: 'python investigate_win_events.py', cmd: 'python3 /home/operator/tools/investigate_win_events.py' },
        { label: 'curl process events (:8208)', cmd: 'curl -s http://10.10.14.90:8208/api/winevent/process' },
        { label: 'curl group events (:8208)', cmd: 'curl -s http://10.10.14.90:8208/api/winevent/groups' },
        { label: 'curl scriptblock events (:8208)', cmd: 'curl -s http://10.10.14.90:8208/api/winevent/scriptblock' },
        { label: 'curl antiforensics (:8208)', cmd: 'curl -s http://10.10.14.90:8208/api/winevent/antiforensics' },
        { label: 'curl post challenge', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"tamper_event_id":1102,"malicious_process":"powershell.exe","added_group":"Administrators"}\' http://10.10.14.90:8208/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-09') || roomId.includes('bruteforce')) {
      buttons = [
        { label: 'python detect_bruteforce.py', cmd: 'python3 /home/operator/tools/detect_bruteforce.py' },
        { label: 'cat auth_bruteforce.log', cmd: 'cat /var/log/auth_bruteforce.log' },
        { label: 'curl auth telemetry (:8209)', cmd: 'curl -s http://10.10.14.90:8209/api/auth/telemetry' },
        { label: 'curl spray indicators (:8209)', cmd: 'curl -s http://10.10.14.90:8209/api/auth/spray-indicators' },
        { label: 'deploy siem rule (:8209)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_name":"RULE_AUTH_BURST_SPRAY","threshold":5,"group_by":"source_ip"}\' http://10.10.14.90:8209/api/auth/rules' },
        { label: 'curl post challenge (:8209)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"source_ip":"198.51.100.55","attack_type":"PASSWORD_SPRAY","targeted_accounts_count":12}\' http://10.10.14.90:8209/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-10') || roomId.includes('malware')) {
      buttons = [
        { label: 'python yara_scanner.py', cmd: 'python3 /home/operator/tools/yara_scanner.py /home/operator/samples/dropper_sample.bin' },
        { label: 'strings dropper_sample.bin', cmd: 'strings /home/operator/samples/dropper_sample.bin' },
        { label: 'curl samples (:8210)', cmd: 'curl -s http://10.10.14.90:8210/api/malware/samples' },
        { label: 'curl dropper headers (:8210)', cmd: 'curl -s http://10.10.14.90:8210/api/malware/sample/dropper/headers' },
        { label: 'validate yara (:8210)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_text":"rule Dropper_VoltStage_Win32 { strings: $a = \\"VoltStage2_Payload\\" condition: $a }"}\' http://10.10.14.90:8210/api/malware/yara/validate' },
        { label: 'curl post challenge (:8210)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"sample_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","c2_url":"http://c2-stage.voltcorp.internal/gate.php","persistence_mechanism":"Registry RunKey"}\' http://10.10.14.90:8210/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-11') || roomId.includes('phishing')) {
      buttons = [
        { label: 'python inspect_email.py', cmd: 'python3 /home/operator/tools/inspect_email.py /home/operator/emails/password_reset.eml' },
        { label: 'cat password_reset.eml', cmd: 'cat /home/operator/emails/password_reset.eml' },
        { label: 'curl emails (:8211)', cmd: 'curl -s http://10.10.14.90:8211/api/phishing/emails' },
        { label: 'curl headers EML-2026-02 (:8211)', cmd: 'curl -s http://10.10.14.90:8211/api/phishing/headers/EML-2026-02' },
        { label: 'post triage (:8211)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"email_id":"EML-2026-02","threat_category":"SPEAR_PHISHING","spoofed_domain":"v0ltcorp.internal"}\' http://10.10.14.90:8211/api/phishing/triage' },
        { label: 'curl post challenge (:8211)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"email_id":"EML-2026-02","dmarc_result":"FAIL","lookalike_domain":"v0ltcorp.internal","remediation_action":"PURGE_AND_BLOCK"}\' http://10.10.14.90:8211/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.startsWith('blue-12') || roomId.includes('endpoint')) {
      buttons = [
        { label: 'python edr_query.py', cmd: 'python3 /home/operator/tools/edr_query.py' },
        { label: 'cat endpoint_events.json', cmd: 'cat /home/operator/endpoint_telemetry/endpoint_events.json' },
        { label: 'curl processes (:8212)', cmd: 'curl -s http://10.10.14.90:8212/api/endpoint/telemetry/processes' },
        { label: 'curl network sockets (:8212)', cmd: 'curl -s http://10.10.14.90:8212/api/endpoint/telemetry/network' },
        { label: 'deploy edr rule (:8212)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"parent_process":"winword.exe","child_process":"powershell.exe"}\' http://10.10.14.90:8212/api/endpoint/rules' },
        { label: 'curl post challenge (:8212)', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d \'{"malicious_pid":4812,"parent_process":"winword.exe","lolbin":"powershell.exe","c2_ip":"198.51.100.88"}\' http://10.10.14.90:8212/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('01') || roomId.includes('foundations')) {
      buttons = [
        { label: 'ls assets/', cmd: 'ls -la /home/operator/assets/' },
        { label: 'read backup_codes.txt', cmd: 'cat /home/operator/assets/backup_codes.txt' },
        { label: 'read cia_scenario.txt', cmd: 'cat /home/operator/assets/cia_scenario.txt' },
        { label: 'curl asset audit (:8081)', cmd: 'curl -s http://10.10.14.90:8081/audit' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('02') || roomId.includes('linux')) {
      buttons = [
        { label: 'pwd', cmd: 'pwd' },
        { label: 'whoami', cmd: 'whoami' },
        { label: 'ls challenges/', cmd: 'ls -la /home/operator/challenges/' },
        { label: 'chmod +x script', cmd: 'chmod +x /home/operator/challenges/restricted_script.sh && /home/operator/challenges/restricted_script.sh' },
        { label: 'ps aux | grep agent', cmd: 'ps aux | grep shadow_agent' },
        { label: 'grep SECURITY_FLAG', cmd: 'grep SECURITY_FLAG /home/operator/challenges/system_telemetry.log' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('03') || roomId.includes('network')) {
      buttons = [
        { label: 'ip addr', cmd: 'ip addr show eth0' },
        { label: 'nc tcp:9001', cmd: 'nc 10.10.14.90 9001' },
        { label: 'curl network-info (:8080)', cmd: 'curl -s http://10.10.14.90:8080/network-info' },
        { label: 'curl status (:8080)', cmd: 'curl -s http://10.10.14.90:8080/status' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('04') || roomId.includes('recon')) {
      buttons = [
        { label: 'curl -I (:8090)', cmd: 'curl -I http://10.10.14.90:8090/' },
        { label: 'curl robots.txt', cmd: 'curl -s http://10.10.14.90:8090/robots.txt' },
        { label: 'curl staging admin', cmd: 'curl -s http://10.10.14.90:8090/admin-portal-staging-7712/' },
        { label: 'curl health API', cmd: 'curl -s http://10.10.14.90:8090/api/v1/health' },
        { label: 'curl internal-docs', cmd: 'curl -s http://10.10.14.90:8090/api/v1/internal-docs' },
        { label: 'curl database_credentials.bak', cmd: 'curl -s http://10.10.14.90:8090/secret-assets/database_credentials.bak' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('05') || roomId.includes('scan')) {
      buttons = [
        { label: 'nmap -sn 10.10.14.0/24', cmd: 'nmap -sn 10.10.14.0/24' },
        { label: 'nmap -sT 10.10.14.90', cmd: 'nmap -sT 10.10.14.90' },
        { label: 'curl scan-status (:8085)', cmd: 'curl -s http://10.10.14.90:8085/scan-status' },
        { label: 'curl challenge (:8085)', cmd: 'curl -s http://10.10.14.90:8085/challenge' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('06') || roomId.includes('enum')) {
      buttons = [
        { label: 'nc ftp:2121', cmd: 'nc 10.10.14.90 2121' },
        { label: 'nc ssh:2222', cmd: 'nc 10.10.14.90 2222' },
        { label: 'curl -I enum (:8086)', cmd: 'curl -I http://10.10.14.90:8086/' },
        { label: 'curl services (:8086)', cmd: 'curl -s http://10.10.14.90:8086/api/v1/services' },
        { label: 'curl admin-internal', cmd: 'curl -s http://10.10.14.90:8086/admin-internal/' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('07') || roomId.includes('vuln')) {
      buttons = [
        { label: 'curl components (:8087)', cmd: 'curl -s http://10.10.14.90:8087/api/components' },
        { label: 'cat cve_catalog.json', cmd: 'cat /home/operator/vuln_db/cve_catalog.json' },
        { label: 'python3 vuln_audit.py', cmd: 'python3 /home/operator/tools/vuln_audit.py' },
        { label: 'curl report (:8087)', cmd: 'curl -s http://10.10.14.90:8087/audit/report' },
        { label: 'curl apply patch', cmd: "curl -s -X POST http://10.10.14.90:8087/audit/remediate -d 'action=apply_patch&cve=CVE-2024-2104'" },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('08') || roomId.includes('web')) {
      buttons = [
        { label: 'curl root (:8088)', cmd: 'curl -s http://10.10.14.90:8088/' },
        { label: 'curl login POST', cmd: 'curl -s -X POST http://10.10.14.90:8088/api/auth/login -d "username=operator&password=voltpass123"' },
        { label: 'curl profile (no cookie)', cmd: 'curl -s http://10.10.14.90:8088/api/profile' },
        { label: 'curl profile (with cookie)', cmd: 'curl -s -b "session_id=op_sess_88291a" http://10.10.14.90:8088/api/profile' },
        { label: 'curl PUT item 42', cmd: 'curl -s -X PUT http://10.10.14.90:8088/api/items/42 -H "Content-Type: application/json" -d \'{"price": 0.00}\'' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('09') || roomId.includes('sqli')) {
      buttons = [
        { label: "test quote injection", cmd: "curl -s \"http://10.10.14.90:8089/products?category=Hardware'\"" },
        { label: "auth bypass OR 1=1", cmd: "curl -s \"http://10.10.14.90:8089/products?category=Hardware'%20OR%201=1--\"" },
        { label: "UNION SELECT users", cmd: "curl -s \"http://10.10.14.90:8089/products?category='%20UNION%20SELECT%201,username,password,role%20FROM%20users--\"" },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('10') || roomId.includes('xss')) {
      buttons = [
        { label: 'curl reflected XSS (:8091)', cmd: 'curl -s "http://10.10.14.90:8091/reflected?q=<script>alert(1)</script>"' },
        { label: 'curl stored comment', cmd: 'curl -s -X POST http://10.10.14.90:8091/comments -d "author=attacker&comment=<script>alert(1)</script>"' },
        { label: 'curl context challenge', cmd: 'curl -s "http://10.10.14.90:8091/challenge?theme=\\"onmouseover=\\"alert(1)"' },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8091/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('11') || roomId.includes('auth')) {
      buttons = [
        { label: 'cat passwords.txt', cmd: 'cat /home/operator/wordlists/passwords.txt' },
        { label: 'curl dictionary login (:8092)', cmd: 'curl -s -X POST http://10.10.14.90:8092/api/login -d "username=support&password=voltcorp2024"' },
        { label: 'curl telemetry logs', cmd: 'curl -s http://10.10.14.90:8092/api/logs' },
        { label: 'curl verify policy challenge', cmd: 'curl -s "http://10.10.14.90:8092/challenge?action=verify_policy"' },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8092/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('12') || roomId.includes('access')) {
      buttons = [
        { label: 'curl IDOR doc 101 (:8093)', cmd: "curl -s -H 'Authorization: Bearer bob_token' http://10.10.14.90:8093/api/documents/101" },
        { label: 'curl vertical admin users', cmd: "curl -s -H 'Authorization: Bearer bob_token' http://10.10.14.90:8093/api/admin/users" },
        { label: 'curl BOLA challenge', cmd: 'curl -s "http://10.10.14.90:8093/challenge?account_id=101"' },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8093/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('13') || roomId.includes('upload')) {
      buttons = [
        { label: 'ls uploads/', cmd: 'ls -la /home/operator/uploads/' },
        { label: 'curl bypass upload (:8094)', cmd: "curl -s -F 'file=@/home/operator/uploads/poc.php.png' http://10.10.14.90:8094/api/upload" },
        { label: 'curl path traversal upload', cmd: "curl -s -F 'file=@/home/operator/uploads/avatar.png;filename=../../uploads/poc.txt' http://10.10.14.90:8094/api/upload" },
        { label: 'curl MIME challenge', cmd: 'curl -s "http://10.10.14.90:8094/challenge?mime=application/x-php"' },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8094/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('14') || roomId.includes('command')) {
      buttons = [
        { label: 'curl ping probe (:8095)', cmd: "curl -s 'http://10.10.14.90:8095/api/diagnostics/ping?host=127.0.0.1%3Bid'" },
        { label: 'curl DNS chain', cmd: "curl -s 'http://10.10.14.90:8095/api/diagnostics/dns?domain=target.noentry.internal%26%26whoami'" },
        { label: 'curl breakout challenge', cmd: "curl -s 'http://10.10.14.90:8095/challenge?probe=127.0.0.1%24(whoami)'" },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8095/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('15') || roomId.includes('traversal')) {
      buttons = [
        { label: 'curl view vault (:8096)', cmd: "curl -s 'http://10.10.14.90:8096/api/files/view?file=../../vault/recovery.key'" },
        { label: 'curl arbitrary download', cmd: "curl -s 'http://10.10.14.90:8096/api/files/download?file=/etc/telemetry.log'" },
        { label: 'curl encoded challenge', cmd: "curl -s 'http://10.10.14.90:8096/challenge?doc=%2e%2e%2fsecret'" },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8096/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('16') || roomId.includes('password')) {
      buttons = [
        { label: 'cat hashes.txt', cmd: 'cat /home/operator/hashes/hashes.txt' },
        { label: 'curl dump users (:8097)', cmd: 'curl -s http://10.10.14.90:8097/api/users/dump' },
        { label: 'curl verify login', cmd: 'curl -s -X POST http://10.10.14.90:8097/api/verify -H "Content-Type: application/json" -d \'{"username":"alice","password":"password"}\'' },
        { label: 'curl bcrypt challenge', cmd: "curl -s 'http://10.10.14.90:8097/challenge?algorithm=bcrypt'" },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8097/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('17') || roomId.includes('privesc')) {
      buttons = [
        { label: 'sh privesc_audit.sh', cmd: 'sh /home/operator/tools/privesc_audit.sh' },
        { label: 'curl system audit (:8098)', cmd: 'curl -s http://10.10.14.90:8098/api/system/audit' },
        { label: 'curl sudo check', cmd: "curl -s 'http://10.10.14.90:8098/api/sudo/check?user=backup_svc'" },
        { label: 'curl simulate escalate', cmd: 'curl -s -X POST http://10.10.14.90:8098/api/escalate/simulate -H "Content-Type: application/json" -d \'{"command":"whoami"}\'' },
        { label: 'curl vector challenge', cmd: "curl -s 'http://10.10.14.90:8098/challenge?vector=suid'" },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8098/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('18') || roomId.includes('active-directory') || roomId.includes('ad')) {
      buttons = [
        { label: 'curl domain hierarchy (:8099)', cmd: 'curl -s http://10.10.14.90:8099/api/ad/domain' },
        { label: 'python ldap_query.py', cmd: 'python3 /home/operator/tools/ad_ldap_query.py' },
        { label: 'curl request TGT', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\":\"svc_backup\"}' http://10.10.14.90:8099/api/ad/kerberos/request_tgt" },
        { label: 'curl audit challenge', cmd: "curl -s 'http://10.10.14.90:8099/challenge?audit=spn'" },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8099/api/ad/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('19') || roomId.includes('exploitation') || roomId.includes('exploit')) {
      buttons = [
        { label: 'python exploit_runner.py (:8100)', cmd: 'python3 /home/operator/tools/exploit_runner.py' },
        { label: 'curl post recon', cmd: "curl -s 'http://10.10.14.90:8100/api/post/recon?session=sess_post_99182'" },
        { label: 'curl persist marker', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"session\":\"sess_post_99182\",\"mechanism\":\"cron\"}' http://10.10.14.90:8100/api/post/persist" },
        { label: 'curl lateral challenge', cmd: "curl -s 'http://10.10.14.90:8100/challenge?stage=lateral'" },
        { label: 'curl POST remediate', cmd: 'curl -s -X POST http://10.10.14.90:8100/api/remediate' },
        { label: 'clear', cmd: 'clear' },
      ];
    } else if (roomId.includes('20') || roomId.includes('capstone')) {
      buttons = [
        { label: 'curl scope ROE (:8101)', cmd: 'curl -s http://10.10.14.90:8101/api/capstone/scope' },
        { label: 'curl recon gateway', cmd: 'curl -s http://10.10.14.90:8101/api/capstone/recon' },
        { label: 'curl exploit foothold', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"action\":\"foothold\"}' http://10.10.14.90:8101/api/capstone/exploit" },
        { label: 'curl privesc root', cmd: "curl -s -X POST -H 'Content-Type: application/json' -d '{\"technique\":\"suid\"}' http://10.10.14.90:8101/api/capstone/privesc" },
        { label: 'curl submit report', cmd: 'curl -s -X POST -H "Content-Type: application/json" -d @/home/operator/capstone/report_template.json http://10.10.14.90:8101/api/capstone/report' },
        { label: 'clear', cmd: 'clear' },
      ];
    }

    if (buttons.length > 0) {
      bar.innerHTML = '<span style="font-family:var(--font-mono);font-size:10px;color:#64748b;align-self:center;">QUICK PROBES:</span>';
      buttons.forEach(b => {
        const btnEl = document.createElement('button');
        btnEl.className = 'btn-quick-cmd';
        btnEl.dataset.cmd = b.cmd;
        btnEl.textContent = b.label;
        bar.appendChild(btnEl);
      });
    }
  }

  document.querySelectorAll('.btn-quick-cmd').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.dataset.cmd;
      if (!cmd || !terminal) return;
      if (cmd === 'clear') {
        terminal.clear();
        return;
      }
      if (termSocket && termSocket.readyState === WebSocket.OPEN) {
        termSocket.send(JSON.stringify({ type: 'command', command: cmd }));
      }
    });
  });
}

document.addEventListener('DOMContentLoaded', initRoomWorkspace);

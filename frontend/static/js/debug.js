/**
 * NO ENTRY - Debug Console JavaScript
 * Connects to /ws/events, streams live events, handles interactive scenario testing.
 */

let ws = null;
let currentScenario = null;
let autopilotActive = true;
let hostStates = {};
let playbooks = [];

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/events`;
  const statusEl = document.getElementById('wsStatus');

  statusEl.className = 'status-badge disconnected';
  statusEl.innerText = 'CONNECTING...';

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    statusEl.className = 'status-badge connected';
    statusEl.innerText = 'ONLINE / LIVE';
    console.log('[NO ENTRY] WebSocket connected.');
  };

  ws.onclose = () => {
    statusEl.className = 'status-badge disconnected';
    statusEl.innerText = 'DISCONNECTED';
    console.warn('[NO ENTRY] WebSocket disconnected. Reconnecting in 2s...');
    setTimeout(initWebSocket, 2000);
  };

  ws.onerror = (err) => {
    console.error('[NO ENTRY] WebSocket error:', err);
    ws.close();
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleMessage(msg);
    } catch (e) {
      console.error('[NO ENTRY] Error parsing WebSocket message:', e);
    }
  };
}

function handleMessage(msg) {
  switch (msg.type) {
    case 'snapshot':
      renderSnapshot(msg.data);
      break;
    case 'event':
      appendEvent(msg.data);
      break;
    case 'breach':
      handleBreach(msg.data);
      break;
    case 'metrics':
      updateMetrics(msg.data);
      break;
    case 'host':
      updateHost(msg.data);
      break;
    case 'reflex_action':
      appendReflexAction(msg.data);
      break;
    case 'scenario_step':
      handleScenarioStep(msg.data);
      break;
    default:
      console.log('[NO ENTRY] Unhandled message:', msg);
  }
}

function renderSnapshot(data) {
  if (data.metrics) updateMetrics(data.metrics);
  if (data.autopilot_enabled !== undefined) {
    autopilotActive = data.autopilot_enabled;
    updateAutopilotButton();
  }

  // Hosts
  if (data.hosts) {
    hostStates = data.hosts;
    renderHosts();
  }

  // Playbooks
  if (data.playbooks) {
    playbooks = data.playbooks;
    renderPlaybooks();
  }

  // Reflex actions
  if (data.reflex_actions) {
    const rfEl = document.getElementById('reflexFeed');
    rfEl.innerHTML = '';
    data.reflex_actions.forEach(appendReflexAction);
  }

  // Events
  if (data.recent_events) {
    const feed = document.getElementById('terminalFeed');
    feed.innerHTML = '';
    // Reverse so newest is at the top
    data.recent_events.slice().reverse().forEach(appendEvent);
  }
}

function appendEvent(evt) {
  const feed = document.getElementById('terminalFeed');
  const row = document.createElement('div');
  row.className = `log-entry ${evt.breach ? 'breach' : ''}`;

  const stateClass = evt.state || 'DETECTED';

  row.innerHTML = `
    <span class="log-time">${escapeHtml(evt.time)}</span>
    <span class="log-tech">${escapeHtml(evt.technique_id)}</span>
    <span class="log-state ${stateClass}">${escapeHtml(evt.state)}</span>
    <span class="log-msg">${escapeHtml(evt.event)}</span>
    <span class="log-src">${escapeHtml(evt.source_ip)} &rarr; ${escapeHtml(evt.target_host)}</span>
  `;

  feed.prepend(row);

  // Keep terminal feed from growing infinitely
  if (feed.children.length > 150) {
    feed.removeChild(feed.lastChild);
  }
}

function handleBreach(evt) {
  console.warn('[NO ENTRY] BREACH EVENT:', evt);
  const threatEl = document.getElementById('metricThreat');
  threatEl.className = 'metric-value danger';
  threatEl.innerText = 'CRITICAL';
}

function updateMetrics(metrics) {
  if (metrics.threat_level) {
    const threatEl = document.getElementById('metricThreat');
    threatEl.innerText = metrics.threat_level;
    threatEl.className = `metric-value ${metrics.threat_level === 'CRITICAL' ? 'danger' : (metrics.threat_level === 'ELEVATED' ? 'danger' : 'success')}`;
  }
  if (metrics.alerts_today !== undefined) {
    document.getElementById('metricAlerts').innerText = metrics.alerts_today;
  }
  if (metrics.mean_time_to_detect !== undefined) {
    document.getElementById('metricMttd').innerText = `${metrics.mean_time_to_detect} s`;
  }
  if (metrics.mean_time_to_respond !== undefined) {
    document.getElementById('metricMttr').innerText = `${metrics.mean_time_to_respond} s`;
  }
  if (metrics.module_percentages) {
    const p = metrics.module_percentages;
    document.getElementById('metricSensors').innerText = `Watch ${p.Watch}% | Reflex ${p.Reflex}%`;
  }
}

function renderHosts() {
  const container = document.getElementById('hostsContainer');
  container.innerHTML = '';

  Object.values(hostStates).forEach(host => {
    const row = document.createElement('div');
    row.className = 'host-item';
    row.id = `host-${host.id}`;
    row.innerHTML = `
      <span>${escapeHtml(host.name)} <span style="color:var(--muted); font-size:10px;">(${escapeHtml(host.ip)})</span></span>
      <span class="host-status ${host.status}">${escapeHtml(host.status)}</span>
    `;
    container.appendChild(row);
  });
}

function updateHost(host) {
  hostStates[host.id] = host;
  const el = document.getElementById(`host-${host.id}`);
  if (el) {
    el.querySelector('.host-status').className = `host-status ${host.status}`;
    el.querySelector('.host-status').innerText = host.status;
  } else {
    renderHosts();
  }
}

function renderPlaybooks() {
  const container = document.getElementById('playbooksContainer');
  container.innerHTML = '';

  playbooks.forEach(pb => {
    const row = document.createElement('div');
    row.className = 'playbook-item';
    row.innerHTML = `
      <span>${escapeHtml(pb.name)}</span>
      <button class="toggle-btn ${pb.enabled ? 'on' : 'off'}" onclick="togglePlaybook('${pb.id}', ${!pb.enabled})">
        ${pb.enabled ? 'ON' : 'OFF'}
      </button>
    `;
    container.appendChild(row);
  });
}

function appendReflexAction(action) {
  const feed = document.getElementById('reflexFeed');
  const line = document.createElement('div');
  line.className = 'reflex-line';
  line.innerHTML = `<span style="color:var(--cyan);">${escapeHtml(action.time)}</span> ${escapeHtml(action.action)} <span style="color:var(--muted);">(${action.response_time}s)</span>`;
  feed.prepend(line);
  if (feed.children.length > 20) {
    feed.removeChild(feed.lastChild);
  }
}

function handleScenarioStep(data) {
  const tag = document.getElementById('activeScenarioTag');
  if (data.status === 'completed' || data.status === 'stopped') {
    tag.style.display = 'none';
    currentScenario = null;
  } else {
    tag.style.display = 'inline';
    tag.innerText = `[${escapeHtml(data.scenario_name || data.scenario_id)}] STEP ${data.step_index}/${data.total_steps}: ${escapeHtml(data.stage)}`;
    currentScenario = data.scenario_id;
  }
}

// User Actions
async function startScenario(scenarioId) {
  try {
    currentScenario = scenarioId;
    const res = await fetch(`/api/scenarios/${scenarioId}/start`, { method: 'POST' });
    const data = await res.json();
    console.log('[NO ENTRY] Started scenario:', data);
  } catch (err) {
    console.error('Error starting scenario:', err);
  }
}

async function stopActiveScenario() {
  if (!currentScenario) return;
  try {
    await fetch(`/api/scenarios/${currentScenario}/stop`, { method: 'POST' });
    const tag = document.getElementById('activeScenarioTag');
    tag.style.display = 'none';
    currentScenario = null;
  } catch (err) {
    console.error('Error stopping scenario:', err);
  }
}

async function toggleAutopilot() {
  autopilotActive = !autopilotActive;
  try {
    await fetch('/api/sim/autopilot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: autopilotActive })
    });
    updateAutopilotButton();
  } catch (err) {
    console.error('Error toggling autopilot:', err);
  }
}

function updateAutopilotButton() {
  const btn = document.getElementById('btnAutopilot');
  if (autopilotActive) {
    btn.className = 'btn-active';
    btn.innerText = 'Autopilot: ON';
  } else {
    btn.className = '';
    btn.innerText = 'Autopilot: OFF';
  }
}

async function togglePlaybook(playbookId, newState) {
  try {
    const res = await fetch('/api/reflex/playbooks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ playbook_id: playbookId, enabled: newState })
    });
    const updated = await res.json();
    const pb = playbooks.find(p => p.id === playbookId);
    if (pb) pb.enabled = updated.enabled;
    renderPlaybooks();
  } catch (err) {
    console.error('Error updating playbook:', err);
  }
}

function clearTerminal() {
  document.getElementById('terminalFeed').innerHTML = '';
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

document.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
});

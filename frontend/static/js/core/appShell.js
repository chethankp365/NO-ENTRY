/**
 * NO ENTRY - Shared App Shell Controller
 * Manages tactical 15-item sidebar, top HUD, live threat level updates from WebSocket,
 * glitch page transitions, and the "/" command palette.
 */

import { store } from './store.js';
import { sound } from './sound.js';
import { wsClient } from './ws.js';
import { api } from './api.js';
import { toast } from './ui.js';
import { initOverlays } from '../fx/overlays.js';
import { initCursorFx } from '../fx/cursorFx.js';
import { navigateWithGlitch } from '../fx/glitchTransition.js';
import { MatrixRain } from '../fx/matrixRain.js';
import { ghostAssistant } from './ghostAssistant.js';
import './logo.js';

export function initAppShell(activeRouteKey) {
  // 1. Initial Overlays & Crosshair Cursor
  initOverlays();
  initCursorFx();

  // 2. Matrix Rain Canvas in background
  const rainCanvas = document.getElementById('appRainCanvas');
  if (rainCanvas) {
    const rain = new MatrixRain(rainCanvas);
    rain.start();
  }

  // 3. Connect to live WebSocket event bus
  wsClient.connect();

  // 4. Bind Threat Level Indicator
  bindThreatLevel();

  // 5. Bind Operator ID
  bindOperatorProfile();

  // 6. Glitch Navigation on sidebar links
  setupGlitchNavigation(activeRouteKey);

  // 7. Tactical Command Palette ("/")
  setupCommandPalette();

  // 8. Unified Floating Ghost AI Mentor Assistant
  ghostAssistant.mount(activeRouteKey);
}

function bindThreatLevel() {
  const chip = document.getElementById('shellThreatChip');
  if (!chip) return;

  function updateThreatDisplay(level) {
    chip.className = 'threat-chip';
    const lvl = (level || 'ELEVATED').toUpperCase();
    chip.innerText = `THREAT: ${lvl}`;

    if (lvl === 'LOW') {
      chip.classList.add('threat--low');
    } else if (lvl === 'CRITICAL') {
      chip.classList.add('threat--critical');
    }
  }

  store.subscribe('threatLevel', updateThreatDisplay);
  updateThreatDisplay(store.get('threatLevel'));
}

async function bindOperatorProfile() {
  const chip = document.getElementById('shellOperatorChip');
  if (!chip) return;

  // Try fetching current authenticated operator
  try {
    const me = await api.get('/auth/me');
    if (me && me.operator_id) {
      chip.innerText = me.operator_id;
      store.set('operatorId', me.operator_id);
    }
  } catch (_) {
    chip.innerText = store.get('operatorId') || 'op-0x7f3a';
  }
}

function setupGlitchNavigation(activeRouteKey) {
  // Mark active nav link
  if (activeRouteKey) {
    const activeItem = document.querySelector(`.nav-item[data-nav="${activeRouteKey}"]`);
    if (activeItem) activeItem.classList.add('active');
  }

  // Intercept navigation for glitch transition
  document.querySelectorAll('.sidebar-nav a, .glitch-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const targetUrl = link.getAttribute('href');
      if (targetUrl && !targetUrl.startsWith('#') && targetUrl !== window.location.pathname) {
        e.preventDefault();
        sound.keyClick();
        navigateWithGlitch(targetUrl);
      }
    });
  });
}

const COMMAND_PALETTE_ITEMS = [
  { label: 'Jump to: Command Center', action: () => navigateWithGlitch('/command-center'), shortcut: 'G C' },
  { label: 'Jump to: Lab Network Map', action: () => navigateWithGlitch('/lab-map'), shortcut: 'G M' },
  { label: 'Jump to: Red Attack Launcher', action: () => navigateWithGlitch('/red'), shortcut: 'G R' },
  { label: 'Jump to: Watch SIEM Alerts', action: () => navigateWithGlitch('/watch'), shortcut: 'G W' },
  { label: 'Jump to: Shield Hardening', action: () => navigateWithGlitch('/shield'), shortcut: 'G S' },
  { label: 'Jump to: Trap Deception', action: () => navigateWithGlitch('/trap'), shortcut: 'G T' },
  { label: 'Jump to: Reflex SOAR Playbooks', action: () => navigateWithGlitch('/reflex'), shortcut: 'G X' },
  { label: 'Jump to: Intel Threat Feeds', action: () => navigateWithGlitch('/intel'), shortcut: 'G I' },
  { label: 'Jump to: Forensics Timeline', action: () => navigateWithGlitch('/forensics'), shortcut: 'G F' },
  { label: 'Jump to: Missions', action: () => navigateWithGlitch('/missions'), shortcut: 'G N' },
  { label: 'Jump to: ATT&CK Coverage Heatmap', action: () => navigateWithGlitch('/attack'), shortcut: 'G A' },
  { label: 'Jump to: Incident Reports', action: () => navigateWithGlitch('/reports'), shortcut: 'G P' },
  { label: 'Jump to: Learning & Leaderboard', action: () => navigateWithGlitch('/learn'), shortcut: 'G L' },
  { label: 'Jump to: Purple Team View', action: () => navigateWithGlitch('/purple-team'), shortcut: 'G U' },
  { label: 'Jump to: Docs & Ethics', action: () => navigateWithGlitch('/docs'), shortcut: 'G D' },
  {
    label: 'Action: Run Web App Breach Attack',
    action: async () => {
      await api.post('/scenarios/web-breach/start');
      toast('Launched scenario: Web app breach (T1190)', 'danger');
    },
    shortcut: 'RUN'
  },
  {
    label: 'Action: Run Ransomware Simulation',
    action: async () => {
      await api.post('/scenarios/ransomware/start');
      toast('Launched scenario: Ransomware simulation (T1486)', 'danger');
    },
    shortcut: 'RUN'
  },
  {
    label: 'Action: Toggle Audio Synthesis',
    action: () => {
      const next = !store.get('audioOn');
      store.set('audioOn', next);
      toast(`Audio synthesis ${next ? 'ENABLED' : 'MUTED'}`, next ? 'success' : 'info');
    },
    shortcut: 'MUTE'
  },
  {
    label: 'Action: Isolate DMZ Web Server (web01)',
    action: async () => {
      await api.post('/hosts/web01/isolate');
      toast('Host web01 quarantined from network', 'danger');
    },
    shortcut: 'QUAR'
  },
  {
    label: 'Action: Logout Operator Session',
    action: async () => {
      await api.post('/auth/logout');
      navigateWithGlitch('/access');
    },
    shortcut: 'EXIT'
  }
];

function setupCommandPalette() {
  const palette = document.getElementById('commandPalette');
  const input = document.getElementById('paletteInput');
  const list = document.getElementById('paletteList');
  if (!palette || !input || !list) return;

  let selectedIdx = 0;
  let filteredItems = [...COMMAND_PALETTE_ITEMS];

  function openPalette() {
    palette.classList.add('active');
    input.value = '';
    filterItems('');
    input.focus();
    sound.alertBlip();
  }

  function closePalette() {
    palette.classList.remove('active');
  }

  function filterItems(query) {
    const q = query.toLowerCase().trim();
    filteredItems = COMMAND_PALETTE_ITEMS.filter(item =>
      !q || item.label.toLowerCase().includes(q)
    );
    selectedIdx = 0;
    renderItems();
  }

  function renderItems() {
    list.innerHTML = '';
    filteredItems.forEach((item, idx) => {
      const li = document.createElement('li');
      li.className = `palette-item ${idx === selectedIdx ? 'selected' : ''}`;
      li.innerHTML = `
        <span>${item.label}</span>
        <span class="palette-shortcut">${item.shortcut}</span>
      `;
      li.addEventListener('click', () => {
        executeItem(item);
      });
      list.appendChild(li);
    });
  }

  function executeItem(item) {
    closePalette();
    sound.keyClick();
    item.action();
  }

  // Keyboard shortcut "/" to open palette (if not typing in an input)
  window.addEventListener('keydown', (e) => {
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
    const isInputActive = activeTag === 'input' || activeTag === 'textarea';

    if (e.key === '/' && !isInputActive && !palette.classList.contains('active')) {
      e.preventDefault();
      openPalette();
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (palette.classList.contains('active')) closePalette();
      else openPalette();
    } else if (palette.classList.contains('active')) {
      if (e.key === 'Escape') {
        closePalette();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIdx = (selectedIdx + 1) % filteredItems.length;
        renderItems();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIdx = (selectedIdx - 1 + filteredItems.length) % filteredItems.length;
        renderItems();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filteredItems[selectedIdx]) {
          executeItem(filteredItems[selectedIdx]);
        }
      }
    }
  });

  input.addEventListener('input', () => {
    filterItems(input.value);
  });

  palette.addEventListener('click', (e) => {
    if (e.target === palette) closePalette();
  });
}

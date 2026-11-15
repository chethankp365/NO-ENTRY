/**
 * NO ENTRY - Red Team Screen Controller (Screen 6)
 * Drives the attack launcher, interactive xterm.js offensive console,
 * kill-chain stage progression rail, and 3D victim host damage visualizer.
 */

import * as THREE from 'three';
import { initAppShell } from '../core/appShell.js';
import { sound } from '../core/sound.js';
import { screenShake } from '../fx/screenShake.js';
import { toast } from '../core/ui.js';

class RedTeamController {
  constructor() {
    this.term = null;
    this.ws = null;
    this.currentInput = '';
    this.activeScenario = null;
    this.pendingScenario = null;
    this.isScenarioRunning = false;
    this.awaitingCommandPrompt = false;
    this.commandPromptTimer = null;
    this.finishPromptTimer = null;
    this.reconnectTimer = null;
    this.victimHost = 'web01';
  }

  init() {
    initAppShell('red');
    this.initTerminal();
    this.initWebSocket();
    this.initScenarioButtons();
    this.initVictim3D();
  }

  fitTerminal() {
    const container = document.getElementById('terminalContainer');
    if (!container || !this.term) return;
    const width = container.clientWidth - 28;
    const height = container.clientHeight - 20;
    if (width <= 0 || height <= 0) return;
    const cols = Math.max(50, Math.min(140, Math.floor(width / 7.4)));
    const rows = Math.max(12, Math.min(45, Math.floor(height / (12 * 1.35))));
    try {
      this.term.resize(cols, rows);
    } catch (_) {}
  }

  initTerminal() {
    const container = document.getElementById('terminalContainer');
    if (!container || !window.Terminal) return;

    this.term = new window.Terminal({
      fontFamily: '"JetBrains Mono", monospace',
      fontSize: 12,
      lineHeight: 1.35,
      cursorBlink: true,
      convertEol: true,
      theme: {
        background: '#04060A',
        foreground: '#E6E9EF',
        cursor: '#00E5FF',
        cursorAccent: '#04060A',
        selectionBackground: 'rgba(0, 229, 255, 0.3)',
        black: '#080B10',
        red: '#FF1F3D',
        green: '#00FF6A',
        yellow: '#FFB800',
        blue: '#00B0FF',
        magenta: '#D500F9',
        cyan: '#00E5FF',
        white: '#FFFFFF',
        brightBlack: '#8A93A3',
        brightRed: '#FF5252',
        brightGreen: '#69F0AE',
        brightYellow: '#FFE57F',
        brightBlue: '#40C4FF',
        brightMagenta: '#EA80FC',
        brightCyan: '#84FFFF',
        brightWhite: '#FFFFFF'
      }
    });

    this.term.open(container);
    this.fitTerminal();
    window.addEventListener('resize', () => this.fitTerminal());

    // Initial prompt
    this.term.write('kali@offensive:~/range$ ');

    // Handle user keyboard input in simulated shell
    this.term.onData(data => {
      if (data === '\r') {
        // Enter pressed
        this.term.write('\r\n');
        const trimmed = this.currentInput.trim();
        this.currentInput = '';
        if (trimmed) {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.awaitingCommandPrompt = true;
            this.scheduleCommandPrompt(250);
            this.ws.send(JSON.stringify({ type: 'command', command: trimmed }));
          } else {
            this.term.write('\x1b[38;2;255;31;61m[!] Terminal WebSocket disconnected.\x1b[0m\r\n');
            this.term.write('kali@offensive:~/range$ ');
          }
        } else {
          this.term.write('kali@offensive:~/range$ ');
        }
      } else if (data === '\u007F' || data === '\b') {
        // Backspace
        if (this.currentInput.length > 0) {
          this.currentInput = this.currentInput.slice(0, -1);
          this.term.write('\b \b');
        }
      } else if (data === '\u0003') {
        // Ctrl+C
        this.term.write('^C\r\nkali@offensive:~/range$ ');
        this.currentInput = '';
      } else {
        // Regular printable characters
        if (data >= ' ' || data === '\t') {
          this.currentInput += data;
          this.term.write(data);
        }
      }
    });
  }

  scheduleCommandPrompt(delayMs = 120) {
    if (this.commandPromptTimer) {
      clearTimeout(this.commandPromptTimer);
    }
    this.commandPromptTimer = setTimeout(() => {
      this.commandPromptTimer = null;
      if (this.awaitingCommandPrompt && this.term) {
        this.awaitingCommandPrompt = false;
        this.term.write('kali@offensive:~/range$ ');
      }
    }, delayMs);
  }

  updateWsStatus(text, color = 'var(--color-cyan)') {
    const el = document.getElementById('terminalWsStatus');
    if (el) {
      el.innerHTML = `WS: /ws/terminal &bull; <span style="color:${color};">${text}</span>`;
    }
  }

  initWebSocket() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal`;

    this.updateWsStatus('CONNECTING...', '#FFB800');

    try {
      this.ws = new WebSocket(wsUrl);
    } catch (err) {
      console.error('[RED WS] Connection attempt failed:', err);
      this.updateWsStatus('FAILED', 'var(--color-red)');
      toast('Failed to connect to /ws/terminal', 'danger');
      this.reconnectTimer = setTimeout(() => this.initWebSocket(), 3000);
      return;
    }

    this.ws.onopen = () => {
      this.updateWsStatus('ACTIVE', 'var(--color-cyan)');
      // If a scenario was requested while connecting, run it immediately now
      if (this.pendingScenario) {
        const sc = this.pendingScenario;
        this.pendingScenario = null;
        this.startScenario(sc);
      }
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        this.handleWsMessage(msg);
      } catch (err) {
        if (this.term) this.term.write(event.data);
      }
    };

    this.ws.onerror = (err) => {
      console.error('[RED WS] WebSocket error:', err);
      this.updateWsStatus('ERROR', 'var(--color-red)');
      toast('Terminal WebSocket connection error', 'danger');
    };

    this.ws.onclose = () => {
      this.updateWsStatus('DISCONNECTED (RECONNECTING)', 'var(--color-red)');
      if (this.term) {
        this.term.write('\r\n\x1b[38;2;255;31;61m[!] Disconnected from /ws/terminal. Reconnecting in 3s...\x1b[0m\r\n');
      }
      if (!this.reconnectTimer) {
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.initWebSocket();
        }, 3000);
      }
    };
  }

  handleWsMessage(msg) {
    if (!this.term) return;

    if (msg.type === 'output') {
      this.term.write(msg.data);
      this.term.scrollToBottom();
      if (this.awaitingCommandPrompt) {
        this.scheduleCommandPrompt(120);
      }
    } else if (msg.type === 'clear') {
      this.awaitingCommandPrompt = false;
      if (this.commandPromptTimer) {
        clearTimeout(this.commandPromptTimer);
        this.commandPromptTimer = null;
      }
      this.term.clear();
      this.term.write('kali@offensive:~/range$ ');
    } else if (msg.type === 'scenario_start') {
      this.onScenarioStarted(msg);
    } else if (msg.type === 'stage') {
      this.updateKillChainStage(msg.stage, msg.target);
    } else if (msg.type === 'scenario_done' || msg.type === 'scenario_stopped') {
      this.onScenarioFinished(msg);
    }
  }

  initScenarioButtons() {
    const runBtns = document.querySelectorAll('.run-scenario-btn');
    runBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const scenarioId = btn.dataset.scenario;
        this.startScenario(scenarioId);
      });
    });

    const stopBtn = document.getElementById('stopScenarioBtn');
    if (stopBtn) {
      stopBtn.addEventListener('click', () => {
        this.pendingScenario = null;
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({ type: 'stop_scenario' }));
        } else {
          this.onScenarioFinished({ type: 'scenario_stopped', scenario_id: this.activeScenario });
        }
        this.resetKillChain();
      });
    }
  }

  startScenario(scenarioId) {
    try {
      sound.threatAlert();
    } catch (_) {}

    if (this.finishPromptTimer) {
      clearTimeout(this.finishPromptTimer);
      this.finishPromptTimer = null;
    }

    this.awaitingCommandPrompt = false;
    this.activeScenario = scenarioId;
    this.isScenarioRunning = true;

    // Send start to terminal WebSocket
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'run_scenario',
        scenario_id: scenarioId
      }));
    } else if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
      this.pendingScenario = scenarioId;
      if (this.term) {
        this.term.write(`\r\n\x1b[38;2;0;229;255m[*] Connecting terminal uplink... Starting ${scenarioId} momentarily.\x1b[0m\r\n`);
      }
    } else {
      this.pendingScenario = scenarioId;
      this.initWebSocket();
      toast('Establishing terminal connection for scenario...', 'info');
    }

    // UI state
    document.querySelectorAll('.scenario-card').forEach(c => {
      c.classList.toggle('active', c.dataset.scenario === scenarioId);
    });

    const stopBtn = document.getElementById('stopScenarioBtn');
    if (stopBtn) stopBtn.style.display = 'inline-block';

    const layout = document.getElementById('redLayout');
    if (layout) layout.classList.add('running-attack');

    const ind = document.getElementById('activeScenarioIndicator');
    if (ind) {
      ind.innerText = `[RUNNING: ${scenarioId.toUpperCase()}]`;
      ind.style.color = 'var(--color-red)';
    }

    this.resetKillChain();
  }

  onScenarioStarted(msg) {
    this.isScenarioRunning = true;
    if (msg.scenario_id) {
      this.activeScenario = msg.scenario_id;
    }
    if (msg.target) {
      this.victimHost = msg.target;
      const vName = document.getElementById('victimHostName');
      if (vName) vName.innerText = msg.target;
    }
  }

  updateKillChainStage(stageName, target) {
    const stage = (stageName || '').toLowerCase();
    const stageMap = {
      'recon': 'kcRecon',
      'initial access': 'kcAccess',
      'execution': 'kcExec',
      'priv esc': 'kcPriv',
      'lateral': 'kcLateral',
      'impact': 'kcImpact'
    };

    // Activate stages up to current
    const stagesOrdered = ['recon', 'initial access', 'execution', 'priv esc', 'lateral', 'impact'];
    const currentIdx = stagesOrdered.indexOf(stage);

    stagesOrdered.forEach((s, idx) => {
      const elId = stageMap[s];
      const el = document.getElementById(elId);
      if (el) {
        if (idx <= currentIdx) {
          el.classList.add('active');
        } else {
          el.classList.remove('active');
        }
      }
    });

    // Update 3D victim box damage
    this.setVictimDamage(stageName);

    // Audio cue
    try {
      sound.blip(850 + (Math.max(0, currentIdx) * 120), 0.08);
    } catch (_) {}

    if (stage === 'impact') {
      try {
        screenShake(6, 400);
        sound.screenShake();
      } catch (_) {}
    }
  }

  resetKillChain() {
    document.querySelectorAll('.kc-stage').forEach(el => el.classList.remove('active'));
    this.resetVictim3D();
  }

  onScenarioFinished(msg) {
    if (msg && msg.scenario_id && this.activeScenario && msg.scenario_id !== this.activeScenario) {
      return;
    }
    this.isScenarioRunning = false;

    const stopBtn = document.getElementById('stopScenarioBtn');
    if (stopBtn) stopBtn.style.display = 'none';

    const layout = document.getElementById('redLayout');
    if (layout) layout.classList.remove('running-attack');

    const ind = document.getElementById('activeScenarioIndicator');
    if (ind) {
      ind.innerText = msg?.type === 'scenario_stopped' ? '[IDLE // ATTACK STOPPED]' : '[IDLE // ATTACK FINISHED]';
      ind.style.color = msg?.type === 'scenario_stopped' ? '#FFB800' : 'var(--color-green)';
    }

    if (this.finishPromptTimer) {
      clearTimeout(this.finishPromptTimer);
    }
    this.finishPromptTimer = setTimeout(() => {
      this.finishPromptTimer = null;
      if (!this.isScenarioRunning && this.term) {
        this.term.write('\r\nkali@offensive:~/range$ ');
      }
    }, 300);
  }

  initVictim3D() {
    const container = document.getElementById('victimCanvasContainer');
    if (!container) return;

    try {
      const w = container.clientWidth || 170;
      const h = container.clientHeight || 170;

      this.scene = new THREE.Scene();
      this.camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 100);
      this.camera.position.set(0, 1.5, 4.5);
      this.camera.lookAt(0, 0, 0);

      this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      this.renderer.setSize(w, h);
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      container.appendChild(this.renderer.domElement);

      // 1. Server Wireframe Box
      const boxGeo = new THREE.BoxGeometry(1.6, 1.6, 1.6);
      const edges = new THREE.EdgesGeometry(boxGeo);
      this.wireMat = new THREE.LineBasicMaterial({
        color: 0x00E5FF,
        transparent: true,
        opacity: 0.85
      });
      this.wireMesh = new THREE.LineSegments(edges, this.wireMat);
      this.scene.add(this.wireMesh);

      // 2. Dark Inner Core
      const coreMat = new THREE.MeshBasicMaterial({ color: 0x04060A, transparent: true, opacity: 0.8 });
      const coreMesh = new THREE.Mesh(boxGeo, coreMat);
      coreMesh.scale.setScalar(0.96);
      this.scene.add(coreMesh);

      // 3. Shockwave Ring
      const ringGeo = new THREE.RingGeometry(0.9, 1.2, 32);
      this.ringMat = new THREE.MeshBasicMaterial({
        color: 0xFF1F3D,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.0,
        blending: THREE.AdditiveBlending
      });
      this.ringMesh = new THREE.Mesh(ringGeo, this.ringMat);
      this.ringMesh.rotation.x = Math.PI / 2;
      this.scene.add(this.ringMesh);

      // Animation Loop
      let time = 0;
      const animate = () => {
        requestAnimationFrame(animate);
        time += 0.02;

        this.wireMesh.rotation.y += 0.015;
        this.wireMesh.rotation.x += 0.008;

        if (this.isGlitching) {
          // Glitch vibration
          this.wireMesh.position.x = (Math.random() - 0.5) * 0.12;
          this.wireMesh.position.y = (Math.random() - 0.5) * 0.12;

          const pulse = (time * 3) % 1.0;
          this.ringMesh.scale.setScalar(1.0 + pulse * 1.8);
          this.ringMat.opacity = Math.max(0, 0.85 - pulse);
        } else {
          this.wireMesh.position.set(0, 0, 0);
          this.ringMat.opacity = 0.0;
        }

        this.renderer.render(this.scene, this.camera);
      };
      animate();
    } catch (err) {
      console.warn('[RED 3D] Victim WebGL fallback:', err);
    }
  }

  setVictimDamage(stageName) {
    const stage = (stageName || '').toLowerCase();
    const statusEl = document.getElementById('victimHostStatus');

    if (stage === 'recon' || stage === 'initial access') {
      if (this.wireMat) this.wireMat.color.set(0x00E5FF);
      this.isGlitching = false;
      if (statusEl) {
        statusEl.innerText = 'PROBING';
        statusEl.style.color = 'var(--color-cyan)';
      }
    } else if (stage === 'execution' || stage === 'priv esc') {
      if (this.wireMat) this.wireMat.color.set(0xFFB800);
      this.isGlitching = true;
      if (statusEl) {
        statusEl.innerText = 'EXPLOITED';
        statusEl.style.color = '#FFB800';
      }
    } else if (stage === 'lateral' || stage === 'impact') {
      if (this.wireMat) this.wireMat.color.set(0xFF1F3D);
      this.isGlitching = true;
      if (statusEl) {
        statusEl.innerText = 'COMPROMISED';
        statusEl.style.color = 'var(--color-red)';
      }
    }
  }

  resetVictim3D() {
    if (this.wireMat) this.wireMat.color.set(0x00E5FF);
    this.isGlitching = false;
    const statusEl = document.getElementById('victimHostStatus');
    if (statusEl) {
      statusEl.innerText = 'HEALTHY';
      statusEl.style.color = 'var(--color-cyan)';
    }
  }
}

function startRedController() {
  const red = new RedTeamController();
  red.init();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startRedController);
} else {
  startRedController();
}

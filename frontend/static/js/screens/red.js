/**
 * NO ENTRY - Red Team Screen Controller (Screen 6)
 * Drives the attack launcher, interactive xterm.js offensive console,
 * kill-chain stage progression rail, and 3D victim host damage visualizer.
 */

import * as THREE from 'three';
import { initAppShell } from '../core/appShell.js';
import { sound } from '../core/sound.js';
import { screenShake } from '../fx/screenShake.js';

class RedTeamController {
  constructor() {
    this.term = null;
    this.ws = null;
    this.currentInput = '';
    this.activeScenario = null;
    this.victimHost = 'web01';
  }

  init() {
    initAppShell('red');
    this.initTerminal();
    this.initWebSocket();
    this.initScenarioButtons();
    this.initVictim3D();
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

    // Initial prompt
    this.term.write('kali@offensive:~/range$ ');

    // Handle user keyboard input in simulated shell
    this.term.onData(data => {
      if (data === '\r') {
        // Enter pressed
        this.term.write('\r\n');
        const trimmed = this.currentInput.trim();
        if (trimmed) {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'command', command: trimmed }));
          } else {
            this.term.write('\033[38;2;255;31;61m[!] Terminal WebSocket disconnected.\033[0m\r\n');
          }
        }
        this.currentInput = '';
        setTimeout(() => {
          this.term.write('kali@offensive:~/range$ ');
        }, 80);
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

  initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        this.handleWsMessage(msg);
      } catch (err) {
        if (this.term) this.term.write(event.data);
      }
    };

    this.ws.onclose = () => {
      if (this.term) {
        this.term.write('\r\n\033[38;2;255;31;61m[!] Disconnected from /ws/terminal. Reconnecting in 3s...\033[0m\r\n');
      }
      setTimeout(() => this.initWebSocket(), 3000);
    };
  }

  handleWsMessage(msg) {
    if (!this.term) return;

    if (msg.type === 'output') {
      this.term.write(msg.data);
    } else if (msg.type === 'clear') {
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
      btn.addEventListener('click', (e) => {
        const scenarioId = btn.dataset.scenario;
        this.startScenario(scenarioId);
      });
    });

    const stopBtn = document.getElementById('stopScenarioBtn');
    if (stopBtn) {
      stopBtn.addEventListener('click', () => {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({ type: 'stop_scenario' }));
        }
        this.resetKillChain();
      });
    }
  }

  startScenario(scenarioId) {
    sound.threatAlert();
    this.activeScenario = scenarioId;

    // Send start to terminal WebSocket
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'run_scenario',
        scenario_id: scenarioId
      }));
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
    sound.blip(850 + (currentIdx * 120), 0.08);

    if (stage === 'impact') {
      screenShake(6, 400);
      sound.screenShake();
    }
  }

  resetKillChain() {
    document.querySelectorAll('.kc-stage').forEach(el => el.classList.remove('active'));
    this.resetVictim3D();
  }

  onScenarioFinished(msg) {
    const stopBtn = document.getElementById('stopScenarioBtn');
    if (stopBtn) stopBtn.style.display = 'none';

    const layout = document.getElementById('redLayout');
    if (layout) layout.classList.remove('running-attack');

    const ind = document.getElementById('activeScenarioIndicator');
    if (ind) {
      ind.innerText = '[IDLE // ATTACK FINISHED]';
      ind.style.color = 'var(--color-green)';
    }

    setTimeout(() => {
      if (this.term) {
        this.term.write('\r\nkali@offensive:~/range$ ');
      }
    }, 400);
  }

  initVictim3D() {
    const container = document.getElementById('victimCanvasContainer');
    if (!container) return;

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
  }

  setVictimDamage(stageName) {
    const stage = (stageName || '').toLowerCase();
    const statusEl = document.getElementById('victimHostStatus');

    if (stage === 'recon' || stage === 'initial access') {
      this.wireMat.color.set(0x00E5FF);
      this.isGlitching = false;
      if (statusEl) {
        statusEl.innerText = 'PROBING';
        statusEl.style.color = 'var(--color-cyan)';
      }
    } else if (stage === 'execution' || stage === 'priv esc') {
      this.wireMat.color.set(0xFFB800);
      this.isGlitching = true;
      if (statusEl) {
        statusEl.innerText = 'EXPLOITED';
        statusEl.style.color = '#FFB800';
      }
    } else if (stage === 'lateral' || stage === 'impact') {
      this.wireMat.color.set(0xFF1F3D);
      this.isGlitching = true;
      if (statusEl) {
        statusEl.innerText = 'COMPROMISED';
        statusEl.style.color = 'var(--color-red)';
      }
    }
  }

  resetVictim3D() {
    this.wireMat.color.set(0x00E5FF);
    this.isGlitching = false;
    const statusEl = document.getElementById('victimHostStatus');
    if (statusEl) {
      statusEl.innerText = 'HEALTHY';
      statusEl.style.color = 'var(--color-cyan)';
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const red = new RedTeamController();
  red.init();
});

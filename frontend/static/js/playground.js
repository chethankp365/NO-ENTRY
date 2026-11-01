/**
 * NO ENTRY - Playground Controller Script
 * Integrates 3D WebGL scene, Matrix Rain, WebAudio synthesis,
 * Tactical HUD components, and interactive FX triggers.
 */

import * as THREE from 'three';
import { store } from './core/store.js';
import { sound } from './core/sound.js';
import { wsClient } from './core/ws.js';
import { countUp, tag, toast, escapeHtml } from './core/ui.js';
import './core/logo.js';

import { MatrixRain } from './fx/matrixRain.js';
import { initOverlays } from './fx/overlays.js';
import { glitchText } from './fx/glitchText.js';
import { decryptText } from './fx/decryptText.js';
import { typeWriter } from './fx/typeWriter.js';
import { triggerGlitchTransition } from './fx/glitchTransition.js';
import { initCursorFx } from './fx/cursorFx.js';
import { shake } from './fx/screenShake.js';

import { CyberScene } from './three/scene.js';
import { createParticleField } from './three/particleField.js';
import { createGridFloor } from './three/gridFloor.js';
import { createHoloGlobe, latLongToVector3 } from './three/holoGlobe.js';
import { createAttackArc } from './three/attackArc.js';
import { createDataPacket } from './three/dataPacket.js';
import { createNodeBox } from './three/nodeBox.js';

let cyberScene = null;
let attackArcs = [];

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize Overlays (Scanlines, Vignette, Film Grain)
  initOverlays();

  // 2. Initialize Custom Crosshair Cursor with Particle Trail
  initCursorFx();

  // 3. Initialize Background Matrix Digital Rain
  const rainCanvas = document.getElementById('rainCanvas');
  if (rainCanvas) {
    const matrixRain = new MatrixRain(rainCanvas);
    matrixRain.start();
  }

  // 4. Initialize 3D WebGL Cyber Scene
  init3DScene();

  // 5. Connect WebSocket Client to Live Engine
  wsClient.connect();
  wsClient.subscribe('metrics', (metrics) => {
    if (metrics.alerts_today) countUp(document.getElementById('statAlerts'), metrics.alerts_today);
    if (metrics.mean_time_to_detect) {
      const el = document.getElementById('statMttd');
      if (el) el.innerText = `${metrics.mean_time_to_detect} s`;
    }
  });

  // 6. Initial Typewriter Effect Demo
  const typeTarget = document.getElementById('typewriterTarget');
  if (typeTarget) {
    typeWriter(typeTarget, 'wazuh-agent: monitoring 5 core endpoints. pfSense: drop rules active.');
  }

  // 7. Wire UI Setting Toggles
  setupSettingButtons();
});

function init3DScene() {
  const container = document.getElementById('webglContainer');
  if (!container) return;

  cyberScene = new CyberScene(container);

  // Add Ambient Particle Field (dust)
  const particles = createParticleField(700, 60);
  cyberScene.scene.add(particles.object);
  cyberScene.addUpdatable(particles.update);

  // Add Neon Grid Floor
  const grid = createGridFloor(90, 45, -7.5);
  cyberScene.scene.add(grid.object);
  cyberScene.addUpdatable(grid.update);

  // Add Holographic Dotted Earth Globe
  const globe = createHoloGlobe(5.0, 2000);
  globe.object.position.set(0, 0, -2);
  cyberScene.scene.add(globe.object);
  cyberScene.addUpdatable(globe.update);

  // Global coordinates (Bucharest, Amsterdam, New York, Tokyo, Sydney)
  const bucharest = latLongToVector3(44.42, 26.10, 5.0);
  const amsterdam = latLongToVector3(52.36, 4.90, 5.0);
  const newyork = latLongToVector3(40.71, -74.00, 5.0);
  const tokyo = latLongToVector3(35.67, 139.65, 5.0);

  // Attach ballistic attack arcs to the rotating globe
  const arc1 = createAttackArc(bucharest, newyork, { color: 0xFF1F3D, speed: 0.9, altitude: 2.2 });
  const arc2 = createAttackArc(amsterdam, tokyo, { color: 0xFF1F3D, speed: 0.7, altitude: 2.5 });
  globe.object.add(arc1.object);
  globe.object.add(arc2.object);
  attackArcs.push(arc1, arc2);

  // Attach glowing data packets traveling along arcs
  const packet1 = createDataPacket(arc1.curve, { color: 0x00E5FF, speed: 1.5, size: 0.12 });
  const packet2 = createDataPacket(arc2.curve, { color: 0xFF1F3D, speed: 1.8, size: 0.12 });
  globe.object.add(packet1.object);
  globe.object.add(packet2.object);

  // Add floating tactical node boxes flanking the globe
  const nodeWeb01 = createNodeBox('web01: dmz', new THREE.Vector3(-10, 2, -1), { color: 0xFF1F3D, size: 0.9 });
  const nodeAd01 = createNodeBox('ad01: corp lan', new THREE.Vector3(10, 1.5, -2), { color: 0x00E5FF, size: 0.9 });
  cyberScene.scene.add(nodeWeb01.object);
  cyberScene.scene.add(nodeAd01.object);

  // Register frame updates
  cyberScene.addUpdatable((delta) => {
    arc1.update(delta);
    arc2.update(delta);
    packet1.update(delta);
    packet2.update(delta);
    nodeWeb01.update(delta);
    nodeAd01.update(delta);
  });

  cyberScene.start();
}

function setupSettingButtons() {
  const audioBtn = document.getElementById('audioToggleBtn');
  const perfBtn = document.getElementById('perfToggleBtn');
  const motionBtn = document.getElementById('motionToggleBtn');

  // Audio Toggle
  store.subscribe('audioOn', (isOn) => {
    if (audioBtn) {
      audioBtn.innerText = isOn ? 'AUDIO: ENABLED' : 'ENABLE AUDIO';
      audioBtn.className = isOn ? 'btn btn-outline' : 'btn btn-red';
      if (isOn) audioBtn.style.color = 'var(--color-green)';
      else audioBtn.style.color = '';
    }
  });

  if (audioBtn) {
    audioBtn.addEventListener('click', () => {
      const next = !store.get('audioOn');
      store.set('audioOn', next);
      if (next) sound.bootHum();
    });
  }

  // Perf Toggle
  store.subscribe('performanceMode', (perf) => {
    if (perfBtn) {
      perfBtn.innerText = perf ? 'PERF: MAX' : 'PERF: NORMAL';
    }
  });

  if (perfBtn) {
    perfBtn.addEventListener('click', () => {
      store.set('performanceMode', !store.get('performanceMode'));
    });
  }

  // Motion Toggle
  store.subscribe('reduceMotion', (reduced) => {
    if (motionBtn) {
      motionBtn.innerText = reduced ? 'MOTION: REDUCED' : 'MOTION: ON';
    }
  });

  if (motionBtn) {
    motionBtn.addEventListener('click', () => {
      store.set('reduceMotion', !store.get('reduceMotion'));
    });
  }
}

// Window Exposed Handlers for HTML Buttons
window.playSfx = (name) => {
  if (typeof sound[name] === 'function') {
    sound[name]();
  }
};

window.runScreenGlitch = async () => {
  await triggerGlitchTransition(400);
};

window.runScreenShake = () => {
  sound.glitchCrackle();
  shake(14, 400);
};

window.runTextGlitch = () => {
  const title = document.getElementById('centerHeadline');
  if (title) glitchText(title, 500);
};

window.runTextDecrypt = () => {
  const target = document.getElementById('decryptTarget');
  if (target) {
    const options = [
      'CLASSIFIED THREAT INTELLIGENCE FEED',
      'ANOMALOUS DNS TUNNEL INTERCEPTED',
      'REFLEX PLAYBOOK: ISOLATE WS-02 QUARANTINE',
      'T1558 KERBEROAST RC4 ENCRYPTION DETECTED'
    ];
    const picked = options[Math.floor(Math.random() * options.length)];
    decryptText(target, picked, { duration: 900, speed: 25 });
  }
};

window.triggerFullBreachAlert = () => {
  sound.accessDenied();
  shake(18, 450);
  triggerGlitchTransition(400);
  toast('SECURITY BREACH DETECTED: T1486 Ransomware triggered on ws-02', 'danger');

  store.set('threatLevel', 'CRITICAL');
  const threatChip = document.getElementById('threatChip');
  if (threatChip) {
    threatChip.innerText = 'THREAT: CRITICAL';
    threatChip.className = 'chip chip--danger';
  }

  const statThreat = document.getElementById('statThreat');
  if (statThreat) statThreat.innerText = 'CRITICAL';
};

window.toggleLogoPulse = () => {
  const logos = document.querySelectorAll('ne-logo');
  logos.forEach(logo => {
    if (logo.hasAttribute('pulse')) logo.removeAttribute('pulse');
    else logo.setAttribute('pulse', '');
  });
};

window.toggleLogoGlitch = () => {
  const logos = document.querySelectorAll('ne-logo');
  logos.forEach(logo => {
    if (logo.hasAttribute('glitch')) logo.removeAttribute('glitch');
    else logo.setAttribute('glitch', '');
  });
};

window.trigger3DAttackPulse = () => {
  sound.alertBlip();
  toast('Simulated red attack trajectory dispatched.', 'info');
  // Intensify bloom momentarily
  if (cyberScene && cyberScene.bloomPass) {
    const orig = cyberScene.bloomPass.strength;
    cyberScene.bloomPass.strength = 1.6;
    setTimeout(() => { cyberScene.bloomPass.strength = orig; }, 350);
  }
};

window.addFakeEventRow = () => {
  const tbody = document.getElementById('demoTableBody');
  if (!tbody) return;

  sound.keyClick();
  const now = new Date().toTimeString().split(' ')[0];
  const tr = document.createElement('tr');
  tr.className = 'new-row';

  const samples = [
    { tech: 'T1048 dns tunnel', state: 'DETECTED', class: 'tag--detected' },
    { tech: 'T1486 ransomware mass encrypt', state: 'ALERT', class: 'tag--alert' },
    { tech: 'T1110 ssh brute force', state: 'BLOCKED', class: 'tag--blocked' },
    { tech: 'T1021 smb lateral move', state: 'ISOLATED', class: 'tag--isolated' }
  ];
  const item = samples[Math.floor(Math.random() * samples.length)];

  tr.innerHTML = `
    <td style="color:var(--color-muted);">${escapeHtml(now)}</td>
    <td>${escapeHtml(item.tech)}</td>
    <td><span class="tag ${item.class}">${escapeHtml(item.state)}</span></td>
  `;

  tbody.prepend(tr);
  if (tbody.children.length > 8) {
    tbody.removeChild(tbody.lastChild);
  }
};

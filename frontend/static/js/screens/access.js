/**
 * NO ENTRY - Access Terminal Controller (Screen 3)
 * Handles operator authentication, guest sessions, keystroke audio feedback,
 * 3D background atmosphere, denial shockwaves, and successful handoff to command center.
 */

import * as THREE from 'three';
import { store } from '../core/store.js';
import { sound } from '../core/sound.js';
import { api } from '../core/api.js';
import { shake } from '../fx/screenShake.js';
import { triggerGlitchTransition } from '../fx/glitchTransition.js';
import { initOverlays } from '../fx/overlays.js';
import { initCursorFx } from '../fx/cursorFx.js';
import { createParticleField } from '../three/particleField.js';
import { createGridFloor } from '../three/gridFloor.js';
import '../core/logo.js';

let accessScene, accessCamera, accessRenderer;
let keyholeRingMesh;

document.addEventListener('DOMContentLoaded', () => {
  initOverlays();
  initCursorFx();
  init3DBackdrop();
  setupFormHandlers();
});

function init3DBackdrop() {
  const container = document.getElementById('accessWebgl');
  if (!container) return;

  accessScene = new THREE.Scene();
  accessScene.fog = new THREE.FogExp2(0x04060A, 0.03);

  accessCamera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 1000);
  accessCamera.position.set(0, 0, 20);

  accessRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
  accessRenderer.setSize(window.innerWidth, window.innerHeight);
  accessRenderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  container.appendChild(accessRenderer.domElement);

  // Floating Ambient Dust Particles
  const particles = createParticleField(350, 40);
  accessScene.add(particles.object);

  // Neon Grid Floor
  const grid = createGridFloor(80, 40, -6.5);
  accessScene.add(grid.object);

  // Dim Rotating Keyhole Hologram Ring behind panel
  const ringGeo = new THREE.TorusGeometry(7.5, 0.05, 16, 100);
  const ringMat = new THREE.MeshBasicMaterial({
    color: 0xFF1F3D,
    transparent: true,
    opacity: 0.22,
    blending: THREE.AdditiveBlending
  });
  keyholeRingMesh = new THREE.Mesh(ringGeo, ringMat);
  keyholeRingMesh.position.set(0, 0, -2);
  accessScene.add(keyholeRingMesh);

  // Window Resize
  window.addEventListener('resize', () => {
    accessCamera.aspect = window.innerWidth / window.innerHeight;
    accessCamera.updateProjectionMatrix();
    accessRenderer.setSize(window.innerWidth, window.innerHeight);
  });

  const clock = new THREE.Clock();
  function render() {
    requestAnimationFrame(render);
    const delta = clock.getDelta();
    const time = clock.getElapsedTime();

    particles.update();
    grid.update(delta, time);

    keyholeRingMesh.rotation.z += delta * 0.15;
    keyholeRingMesh.rotation.y = Math.sin(time * 0.4) * 0.15;

    accessRenderer.render(accessScene, accessCamera);
  }

  render();
}

function setupFormHandlers() {
  const form = document.getElementById('accessForm');
  const card = document.getElementById('accessCard');
  const opInput = document.getElementById('operatorId');
  const passInput = document.getElementById('passphrase');
  const submitBtn = document.getElementById('btnRequestAccess');
  const statusEl = document.getElementById('handshakeStatus');
  const guestBtn = document.getElementById('btnGuestAccess');

  // Keystroke sound feedback
  [opInput, passInput].forEach(inp => {
    inp.addEventListener('input', () => {
      sound.keyClick();
    });
  });

  // Login Form Submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const operatorId = opInput.value.trim();
    const passphrase = passInput.value;

    if (!operatorId || !passphrase) {
      triggerAccessDenied('OPERATOR ID AND PASSPHRASE REQUIRED');
      return;
    }

    // Handshake animation
    submitBtn.classList.add('scanning');
    submitBtn.innerText = 'VERIFYING OPERATOR...';
    statusEl.style.color = 'var(--color-cyan)';
    statusEl.innerText = '> negotiating cryptographic session...';
    sound.keyClick();

    try {
      const res = await api.post('/auth/login', {
        operator_id: operatorId,
        passphrase: passphrase
      });

      handleAccessSuccess(res);
    } catch (err) {
      triggerAccessDenied(err.message || 'ACCESS DENIED');
    }
  });

  // Guest Access
  if (guestBtn) {
    guestBtn.addEventListener('click', async () => {
      submitBtn.classList.add('scanning');
      submitBtn.innerText = 'PROVISIONING GUEST...';
      statusEl.style.color = 'var(--color-cyan)';
      statusEl.innerText = '> provisioning ephemeral guest credentials...';
      sound.keyClick();

      try {
        const res = await api.post('/auth/guest');
        handleAccessSuccess(res);
      } catch (err) {
        triggerAccessDenied(err.message || 'GUEST PROVISIONING FAILED');
      }
    });
  }
}

function triggerAccessDenied(errorMsg) {
  const card = document.getElementById('accessCard');
  const submitBtn = document.getElementById('btnRequestAccess');
  const statusEl = document.getElementById('handshakeStatus');
  const stamp = document.getElementById('accessStopStamp');
  const logo = document.getElementById('accessLogo');

  sound.accessDenied();
  shake(14, 380, card);

  card.classList.add('denied-shake');
  if (stamp) stamp.classList.add('stamp-active');
  if (logo) logo.setAttribute('glitch', '');

  statusEl.style.color = 'var(--color-red)';
  statusEl.innerText = `[!!] ${errorMsg.toUpperCase()}`;

  setTimeout(() => {
    card.classList.remove('denied-shake');
    if (stamp) stamp.classList.remove('stamp-active');
    if (logo) logo.removeAttribute('glitch');

    submitBtn.classList.remove('scanning');
    submitBtn.innerText = 'REQUEST ACCESS';
  }, 900);
}

async function handleAccessSuccess(operatorData) {
  const card = document.getElementById('accessCard');
  const submitBtn = document.getElementById('btnRequestAccess');
  const statusEl = document.getElementById('handshakeStatus');

  sound.accessGranted();
  card.classList.add('granted-flash');
  submitBtn.classList.remove('scanning');
  submitBtn.style.background = 'var(--color-green)';
  submitBtn.style.borderColor = 'var(--color-green)';
  submitBtn.innerText = 'ACCESS GRANTED';

  statusEl.style.color = 'var(--color-green)';
  statusEl.innerText = `[ok] WELCOME, ${operatorData.operator_id} // UPLINK SYNCHRONIZED`;

  store.set('operatorId', operatorData.operator_id);

  // Camera dolly zoom forward into terminal panel
  const dollyInterval = setInterval(() => {
    if (accessCamera.position.z > 8) {
      accessCamera.position.z -= 0.6;
    } else {
      clearInterval(dollyInterval);
    }
  }, 20);

  await new Promise(r => setTimeout(r, 650));
  await triggerGlitchTransition(400);

  window.location.href = '/command-center';
}

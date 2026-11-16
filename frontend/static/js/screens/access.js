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
  const regForm = document.getElementById('registerForm');
  const forgotForm = document.getElementById('forgotForm');
  const card = document.getElementById('accessCard');

  const tabSignIn = document.getElementById('tabSignIn');
  const tabRegister = document.getElementById('tabRegister');
  const btnToggleForgot = document.getElementById('btnToggleForgot');
  const btnBackToLogin = document.getElementById('btnBackToLogin');

  const opInput = document.getElementById('operatorId');
  const passInput = document.getElementById('passphrase');
  const submitBtn = document.getElementById('btnRequestAccess');
  const statusEl = document.getElementById('handshakeStatus');
  const guestBtn = document.getElementById('btnGuestAccess');

  // Tab switching
  if (tabSignIn && tabRegister) {
    tabSignIn.addEventListener('click', () => {
      sound.keyClick();
      tabSignIn.classList.add('active');
      tabRegister.classList.remove('active');
      if (form) form.style.display = 'block';
      if (regForm) regForm.style.display = 'none';
      if (forgotForm) forgotForm.style.display = 'none';
    });

    tabRegister.addEventListener('click', () => {
      sound.keyClick();
      tabRegister.classList.add('active');
      tabSignIn.classList.remove('active');
      if (form) form.style.display = 'none';
      if (regForm) regForm.style.display = 'block';
      if (forgotForm) forgotForm.style.display = 'none';
    });
  }

  // Forgot password toggle
  if (btnToggleForgot) {
    btnToggleForgot.addEventListener('click', () => {
      sound.keyClick();
      if (form) form.style.display = 'none';
      if (regForm) regForm.style.display = 'none';
      if (forgotForm) forgotForm.style.display = 'block';
    });
  }

  if (btnBackToLogin) {
    btnBackToLogin.addEventListener('click', () => {
      sound.keyClick();
      if (tabSignIn) tabSignIn.click();
    });
  }

  // Keystroke sound feedback
  const allInputs = document.querySelectorAll('.form-input');
  allInputs.forEach(inp => {
    inp.addEventListener('input', () => {
      sound.keyClick();
    });
  });

  // 1. Sign In Form Submission
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const identifier = opInput.value.trim();
      const passphrase = passInput.value;

      if (!identifier || !passphrase) {
        triggerAccessDenied('OPERATOR ID AND PASSPHRASE REQUIRED');
        return;
      }

      submitBtn.classList.add('scanning');
      submitBtn.innerText = 'VERIFYING CREDENTIALS...';
      statusEl.style.color = 'var(--color-cyan)';
      statusEl.innerText = '> negotiating cryptographic session...';
      sound.keyClick();

      try {
        const res = await api.post('/auth/login', {
          identifier: identifier,
          passphrase: passphrase
        });

        handleAccessSuccess(res);
      } catch (err) {
        triggerAccessDenied(err.message || 'ACCESS DENIED');
      }
    });
  }

  // 2. Register Form Submission
  if (regForm) {
    regForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btnReg = document.getElementById('btnSubmitRegister');
      const regStatus = document.getElementById('regStatus');
      const fullName = document.getElementById('regFullName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const opId = document.getElementById('regOpId').value.trim();
      const pass = document.getElementById('regPassphrase').value;
      const confirmPass = document.getElementById('regConfirmPassphrase').value;

      if (pass !== confirmPass) {
        triggerAccessDenied('PASSWORDS DO NOT MATCH', regStatus);
        return;
      }

      if (btnReg) {
        btnReg.classList.add('scanning');
        btnReg.innerText = 'CREATING OPERATOR PROFILE...';
      }
      regStatus.style.color = 'var(--color-cyan)';
      regStatus.innerText = '> generating zero-trust operator identity...';
      sound.keyClick();

      try {
        const res = await api.post('/auth/register', {
          full_name: fullName,
          email: email,
          operator_id: opId || null,
          password: pass,
          confirm_password: confirmPass
        });

        handleAccessSuccess(res);
      } catch (err) {
        triggerAccessDenied(err.message || 'REGISTRATION FAILED', regStatus, btnReg, 'CREATE OPERATOR PROFILE >>');
      }
    });
  }

  // 3. Forgot Password Form Submission
  if (forgotForm) {
    forgotForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('forgotEmail').value.trim();
      const forgotStatus = document.getElementById('forgotStatus');
      const btnForgot = document.getElementById('btnSubmitForgot');

      if (!email) return;

      btnForgot.innerText = 'QUERYING REGISTRY...';
      sound.keyClick();

      try {
        const res = await api.post('/auth/forgot-password', { email });
        forgotStatus.style.color = 'var(--color-green)';
        if (res.reset_token) {
          forgotStatus.innerHTML = `[OK] TOKEN GENERATED: <code style="color:var(--color-cyan);">${res.reset_token}</code><br>Use this token with /api/auth/reset-password`;
        } else {
          forgotStatus.innerText = res.message || 'Recovery instructions generated.';
        }
      } catch (err) {
        forgotStatus.style.color = 'var(--color-red)';
        forgotStatus.innerText = `[!] ${err.message}`;
      } finally {
        btnForgot.innerText = 'GENERATE RECOVERY TOKEN';
      }
    });
  }

  // 4. Guest Access
  if (guestBtn) {
    guestBtn.addEventListener('click', async () => {
      if (submitBtn) {
        submitBtn.classList.add('scanning');
        submitBtn.innerText = 'PROVISIONING GUEST...';
      }
      if (statusEl) {
        statusEl.style.color = 'var(--color-cyan)';
        statusEl.innerText = '> provisioning ephemeral guest credentials...';
      }
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

function triggerAccessDenied(errorMsg, targetStatusEl = null, targetBtn = null, resetBtnText = 'REQUEST ACCESS') {
  const card = document.getElementById('accessCard');
  const submitBtn = targetBtn || document.getElementById('btnRequestAccess');
  const statusEl = targetStatusEl || document.getElementById('handshakeStatus');
  const stamp = document.getElementById('accessStopStamp');
  const logo = document.getElementById('accessLogo');

  sound.accessDenied();
  shake(14, 380, card);

  card.classList.add('denied-shake');
  if (stamp) stamp.classList.add('stamp-active');
  if (logo) logo.setAttribute('glitch', '');

  if (statusEl) {
    statusEl.style.color = 'var(--color-red)';
    statusEl.innerText = `[!!] ${errorMsg.toUpperCase()}`;
  }

  setTimeout(() => {
    card.classList.remove('denied-shake');
    if (stamp) stamp.classList.remove('stamp-active');
    if (logo) logo.removeAttribute('glitch');

    if (submitBtn) {
      submitBtn.classList.remove('scanning');
      submitBtn.innerText = resetBtnText;
    }
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

/**
 * NO ENTRY - Boot Sequence Controller (Screen 1)
 * Orchestrates 3D particle tunnel warp, logo assembly, audio-synthesized boot terminal,
 * denial shockwave, and seamless glitch handoff to landing.
 */

import * as THREE from 'three';
import { store } from '../core/store.js';
import { sound } from '../core/sound.js';
import { decryptText } from '../fx/decryptText.js';
import { typeWriter } from '../fx/typeWriter.js';
import { triggerGlitchTransition } from '../fx/glitchTransition.js';
import { shake } from '../fx/screenShake.js';
import { initOverlays } from '../fx/overlays.js';
import '../core/logo.js';

let tunnelScene, tunnelCamera, tunnelRenderer;
let particleSystem;
let isBooting = false;

document.addEventListener('DOMContentLoaded', () => {
  // If already booted in this session, skip straight to landing
  if (sessionStorage.getItem('ne_booted') === 'true') {
    window.location.replace('/');
    return;
  }

  initOverlays();
  initTunnelScene();

  const gate = document.getElementById('audioGate');
  const skipBtn = document.getElementById('skipBtn');

  gate.addEventListener('click', () => {
    store.set('audioOn', true);
    gate.style.opacity = '0';
    setTimeout(() => gate.remove(), 400);
    startBootSequence();
  });

  skipBtn.addEventListener('click', (e) => {
    e.preventDefault();
    skipToLanding();
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') skipToLanding();
  });
});

function initTunnelScene() {
  const container = document.getElementById('bootWebgl');
  if (!container) return;

  tunnelScene = new THREE.Scene();
  tunnelScene.fog = new THREE.FogExp2(0x000000, 0.035);

  tunnelCamera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
  tunnelCamera.position.z = 80;

  tunnelRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  tunnelRenderer.setSize(window.innerWidth, window.innerHeight);
  tunnelRenderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  container.appendChild(tunnelRenderer.domElement);

  // Streaming particle tunnel geometry
  const pCount = 1600;
  const geometry = new THREE.BufferGeometry();
  const positions = new Float32Array(pCount * 3);
  const colors = new Float32Array(pCount * 3);

  for (let i = 0; i < pCount; i++) {
    const angle = Math.random() * Math.PI * 2;
    const radius = 2.5 + Math.random() * 15;
    positions[i * 3] = Math.cos(angle) * radius;
    positions[i * 3 + 1] = Math.sin(angle) * radius;
    positions[i * 3 + 2] = (Math.random() - 0.5) * 160;

    // Mix of Red, Green, and Cyan streaming data points
    const rand = Math.random();
    if (rand < 0.5) {
      colors[i * 3] = 1.0; colors[i * 3 + 1] = 0.12; colors[i * 3 + 2] = 0.24; // Red
    } else if (rand < 0.8) {
      colors[i * 3] = 0.0; colors[i * 3 + 1] = 0.9; colors[i * 3 + 2] = 1.0;  // Cyan
    } else {
      colors[i * 3] = 0.0; colors[i * 3 + 1] = 1.0; colors[i * 3 + 2] = 0.4;  // Green
    }
  }

  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

  const material = new THREE.PointsMaterial({
    size: 0.28,
    vertexColors: true,
    transparent: true,
    opacity: 0.85,
    blending: THREE.AdditiveBlending
  });

  particleSystem = new THREE.Points(geometry, material);
  tunnelScene.add(particleSystem);

  window.addEventListener('resize', () => {
    tunnelCamera.aspect = window.innerWidth / window.innerHeight;
    tunnelCamera.updateProjectionMatrix();
    tunnelRenderer.setSize(window.innerWidth, window.innerHeight);
  });

  function render() {
    requestAnimationFrame(render);
    if (!isBooting) {
      // Idle gentle drift
      particleSystem.rotation.z += 0.002;
    } else {
      // High-speed warp tunnel motion
      const pos = geometry.attributes.position.array;
      for (let i = 0; i < pCount; i++) {
        pos[i * 3 + 2] += 1.8;
        if (pos[i * 3 + 2] > 100) pos[i * 3 + 2] = -80;
      }
      geometry.attributes.position.needsUpdate = true;
      particleSystem.rotation.z += 0.008;
    }
    tunnelRenderer.render(tunnelScene, tunnelCamera);
  }

  render();
}

async function startBootSequence() {
  isBooting = true;
  sound.bootHum();

  const stage = document.getElementById('bootStage');
  stage.style.opacity = '1';

  // Step 1: Camera zoom into tunnel
  let zoomCount = 0;
  const zoomInterval = setInterval(() => {
    if (tunnelCamera.position.z > 25) {
      tunnelCamera.position.z -= 1.2;
    } else {
      clearInterval(zoomInterval);
    }
  }, 30);

  await sleep(600);

  // Step 2: Decrypt Title "NO ENTRY"
  const titleNo = document.getElementById('bootTitleNo');
  const titleEntry = document.getElementById('bootTitleEntry');
  decryptText(titleNo, 'NO', { duration: 400 });
  await decryptText(titleEntry, 'ENTRY', { duration: 700 });

  // Step 3: Typewriter Tagline
  const tagline = document.getElementById('bootTagline');
  await typeWriter(tagline, 'Open-source attack simulation and automated threat detection.', { speed: 20 });

  await sleep(300);

  // Step 4: Step-by-step Terminal output
  const lines = [
    { id: 'termLine1', sound: 'keyClick', delay: 400 },
    { id: 'termLine2', sound: 'keyClick', delay: 400 },
    { id: 'termLine3', sound: 'keyClick', delay: 450 },
    { id: 'termLine4', sound: 'denied', delay: 700 }, // ACCESS DENIED
    { id: 'termLine5', sound: 'granted', delay: 600 }  // ACCESS GRANTED
  ];

  for (let i = 0; i < lines.length; i++) {
    const item = lines[i];
    const el = document.getElementById(item.id);
    if (!el) continue;

    if (item.sound === 'keyClick') {
      sound.keyClick();
    } else if (item.sound === 'denied') {
      sound.accessDenied();
      shake(15, 400);

      // Flash STOP stamp & logo glitch
      const stamp = document.getElementById('stopStamp');
      const bootLogo = document.getElementById('bootLogo');
      if (stamp) stamp.classList.add('stamp-active');
      if (bootLogo) bootLogo.setAttribute('glitch', '');

      setTimeout(() => {
        if (stamp) stamp.classList.remove('stamp-active');
        if (bootLogo) bootLogo.removeAttribute('glitch');
      }, 500);

    } else if (item.sound === 'granted') {
      sound.accessGranted();
    }

    el.classList.add('visible');
    await sleep(item.delay);
  }

  // Step 5: Red progress bar fill
  const progBar = document.getElementById('bootProgress');
  if (progBar) {
    progBar.style.transition = 'width 0.7s ease-in-out';
    progBar.style.width = '100%';
  }
  await sleep(750);

  // Step 6: LAB STATUS: ARMED
  const statusLine = document.getElementById('labStatusLine');
  if (statusLine) {
    statusLine.classList.add('armed');
    sound.alertBlip();
  }

  await sleep(900);

  // Step 7: Glitch transition to landing
  skipToLanding();
}

async function skipToLanding() {
  sessionStorage.setItem('ne_booted', 'true');
  await triggerGlitchTransition(400);
  window.location.href = '/';
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * NO ENTRY - Landing Page Controller (Screen 2)
 * Orchestrates 3D interactive HoloGlobe with random attack arcs, Matrix Rain,
 * DecryptText headline sequencing, GSAP ScrollTrigger camera motion, and tilt cards.
 */

import * as THREE from 'three';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

import { store } from '../core/store.js';
import { sound } from '../core/sound.js';
import { decryptText } from '../fx/decryptText.js';
import { initOverlays } from '../fx/overlays.js';
import { initCursorFx } from '../fx/cursorFx.js';
import { MatrixRain } from '../fx/matrixRain.js';
import { createHoloGlobe, latLongToVector3 } from '../three/holoGlobe.js';
import { createAttackArc } from '../three/attackArc.js';
import { createParticleField } from '../three/particleField.js';
import { countUp } from '../core/ui.js';
import '../core/logo.js';

gsap.registerPlugin(ScrollTrigger);

let globeScene, globeCamera, globeRenderer;
let globeGroup;
let activeArcs = [];

document.addEventListener('DOMContentLoaded', () => {
  // If not booted yet, redirect to /boot (unless bypassed with ?noboot=1)
  if (sessionStorage.getItem('ne_booted') !== 'true' && !window.location.search.includes('noboot=1')) {
    window.location.replace('/boot');
    return;
  }

  // 1. Initial Overlays & Custom Crosshair Cursor
  initOverlays();
  initCursorFx();

  // 2. Matrix Digital Rain in Background
  const rainCanvas = document.getElementById('rainCanvas');
  if (rainCanvas) {
    const rain = new MatrixRain(rainCanvas);
    rain.start();
  }

  // 3. Three.js HoloGlobe in Background
  init3DGlobe();

  // 4. Headline Decrypt Sequencing
  runHeadlineDecrypt();

  // 5. Floating Terminal Card Looper
  initTerminalCardLoop();

  // 6. Interactive 3D Tilt Cards
  initTiltCards();

  // 7. Modal Handlers
  setupWatchModal();

  // 8. GSAP ScrollTrigger Animations
  setupScrollAnimations();
});

function init3DGlobe() {
  const container = document.getElementById('globeBackground');
  if (!container) return;

  globeScene = new THREE.Scene();
  globeScene.fog = new THREE.FogExp2(0x04060A, 0.02);

  globeCamera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);
  // Position camera so globe sits on the right side of hero
  globeCamera.position.set(4.5, 0.5, 17);
  globeCamera.lookAt(4.5, 0, 0);

  globeRenderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
  globeRenderer.setSize(window.innerWidth, window.innerHeight);
  globeRenderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  container.appendChild(globeRenderer.domElement);

  // Add Ambient Dust
  const dust = createParticleField(450, 40);
  globeScene.add(dust.object);

  // Add HoloGlobe
  const globe = createHoloGlobe(4.2, 1900);
  globeGroup = globe.object;
  globeGroup.position.set(5.0, 0, 0);
  globeScene.add(globeGroup);

  // Global coordinates pool for random arcs
  const coords = [
    { name: 'Bucharest', lat: 44.42, lon: 26.10 },
    { name: 'Amsterdam', lat: 52.36, lon: 4.90 },
    { name: 'New York', lat: 40.71, lon: -74.00 },
    { name: 'Tokyo', lat: 35.67, lon: 139.65 },
    { name: 'London', lat: 51.50, lon: -0.12 },
    { name: 'Frankfurt', lat: 50.11, lon: 8.68 },
    { name: 'San Francisco', lat: 37.77, lon: -122.41 },
    { name: 'Singapore', lat: 1.35, lon: 103.81 }
  ];

  function launchRandomArc() {
    const src = coords[Math.floor(Math.random() * coords.length)];
    let dst = coords[Math.floor(Math.random() * coords.length)];
    while (dst === src) dst = coords[Math.floor(Math.random() * coords.length)];

    const v1 = latLongToVector3(src.lat, src.lon, 4.2);
    const v2 = latLongToVector3(dst.lat, dst.lon, 4.2);

    const arc = createAttackArc(v1, v2, {
      color: 0xFF1F3D,
      speed: 0.8 + Math.random() * 0.4,
      altitude: 1.6 + Math.random() * 1.0
    });

    globeGroup.add(arc.object);
    activeArcs.push(arc);

    if (activeArcs.length > 5) {
      const old = activeArcs.shift();
      globeGroup.remove(old.object);
    }
  }

  // Launch initial arcs
  launchRandomArc();
  launchRandomArc();
  setInterval(launchRandomArc, 2800);

  // Mouse Parallax & Drag Orbit on Globe
  let isDragging = false;
  let prevMouseX = 0;
  let prevMouseY = 0;

  window.addEventListener('mousedown', (e) => {
    isDragging = true;
    prevMouseX = e.clientX;
    prevMouseY = e.clientY;
  });

  window.addEventListener('mouseup', () => { isDragging = false; });

  window.addEventListener('mousemove', (e) => {
    if (isDragging && !store.get('reduceMotion')) {
      const deltaX = e.clientX - prevMouseX;
      const deltaY = e.clientY - prevMouseY;
      globeGroup.rotation.y += deltaX * 0.005;
      globeGroup.rotation.x += deltaY * 0.005;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    } else if (!store.get('reduceMotion')) {
      // Subtle parallax tilt
      const px = (e.clientX / window.innerWidth - 0.5) * 0.4;
      const py = (e.clientY / window.innerHeight - 0.5) * 0.4;
      globeCamera.position.x = 4.5 + px;
      globeCamera.position.y = 0.5 - py;
      globeCamera.lookAt(4.5, 0, 0);
    }
  });

  // Resize
  window.addEventListener('resize', () => {
    globeCamera.aspect = window.innerWidth / window.innerHeight;
    globeCamera.updateProjectionMatrix();
    globeRenderer.setSize(window.innerWidth, window.innerHeight);
  });

  // Animation Loop
  const clock = new THREE.Clock();
  function animate() {
    requestAnimationFrame(animate);
    const delta = clock.getDelta();

    dust.update();
    globe.update(delta, clock.getElapsedTime());

    activeArcs.forEach(a => a.update(delta));
    globeRenderer.render(globeScene, globeCamera);
  }

  animate();
}

async function runHeadlineDecrypt() {
  const l1 = document.getElementById('hlLine1');
  const l2 = document.getElementById('hlLine2');
  const l3 = document.getElementById('hlLine3');

  if (l1) await decryptText(l1, 'Break in.', { duration: 600 });
  if (l2) await decryptText(l2, 'Watch it happen.', { duration: 700 });
  if (l3) await decryptText(l3, 'Shut it down.', { duration: 800 });
}

function initTerminalCardLoop() {
  const line1 = document.getElementById('cardLine1');
  const line2 = document.getElementById('cardLine2');
  const line3 = document.getElementById('cardLine3');

  const scenarios = [
    {
      l1: 'T1110 brute force from 185.220.101.4',
      l2: 'rule 100231 fired in 3.2s',
      l3: 'ip blocked at firewall'
    },
    {
      l1: 'T1190 sqli on web01 from 45.9.148.22',
      l2: 'rule 100190 matched UNION SELECT in 2.8s',
      l3: 'WAF dropped malicious session'
    },
    {
      l1: 'T1558 kerberoast request for svc_backup',
      l2: 'honeytoken rule 100558 fired in 1.4s',
      l3: 'AD user account locked automatically'
    },
    {
      l1: 'T1071 dns tunnel from 10.0.2.31',
      l2: 'Zeek anomalous TXT threshold crossed in 3.5s',
      l3: 'network port isolated by Reflex'
    }
  ];

  let index = 0;
  setInterval(() => {
    index = (index + 1) % scenarios.length;
    const s = scenarios[index];
    if (line1 && line2 && line3) {
      line1.style.opacity = '0';
      line2.style.opacity = '0';
      line3.style.opacity = '0';

      setTimeout(() => {
        line1.innerText = s.l1;
        line2.innerText = s.l2;
        line3.innerText = s.l3;

        line1.style.opacity = '1';
        line2.style.opacity = '1';
        line3.style.opacity = '1';
        if (store.get('audioOn')) sound.keyClick();
      }, 250);
    }
  }, 4200);
}

function initTiltCards() {
  const cards = document.querySelectorAll('.tilt-card');
  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      if (store.get('reduceMotion')) return;
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      const rx = -(y / rect.height) * 16;
      const ry = (x / rect.width) * 16;
      card.style.transform = `perspective(800px) rotateX(${rx}deg) rotateY(${ry}deg) translateY(-4px)`;
    });

    card.addEventListener('mouseleave', () => {
      card.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg) translateY(0)';
    });
  });
}

function setupWatchModal() {
  const modal = document.getElementById('watchModal');
  const openBtn = document.getElementById('btnWatchAttack');
  const closeBtn = document.getElementById('closeModalBtn');

  if (openBtn && modal) {
    openBtn.addEventListener('click', () => {
      modal.classList.add('active');
      if (store.get('audioOn')) sound.alertBlip();
    });
  }

  if (closeBtn && modal) {
    closeBtn.addEventListener('click', () => {
      modal.classList.remove('active');
    });
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('active');
    });
  }
}

function setupScrollAnimations() {
  if (store.get('reduceMotion')) return;

  // Move 3D background camera as page scrolls
  gsap.to(globeCamera.position, {
    x: 0,
    y: -2,
    z: 22,
    scrollTrigger: {
      trigger: '#loop',
      start: 'top bottom',
      end: 'bottom top',
      scrub: 1
    }
  });

  // Count up stats when in view
  ScrollTrigger.create({
    trigger: '.stats-row',
    start: 'top 85%',
    onEnter: () => {
      const elMttd = document.getElementById('statMttd');
      const elMttr = document.getElementById('statMttr');
      if (elMttd) countUp(elMttd, 3.2, 1000, ' s', 1);
      if (elMttr) countUp(elMttr, 8.4, 1000, ' s', 1);
    }
  });
}

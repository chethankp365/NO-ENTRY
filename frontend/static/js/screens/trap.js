/**
 * NO ENTRY - Trap Deception Screen Controller (Screen 9)
 * Manages honeypot session capture, interactive honeytoken tripwires,
 * 3D glowing mesh sphere with ripple physics, and attacker origin map.
 */

import * as THREE from 'three';
import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { wsClient } from '../core/ws.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class TrapController {
  constructor() {
    this.state = null;
    this.meshSphere = null;
    this.sphereMaterial = null;
    this.rippleIntensity = 0;
    this.origins = [];
  }

  async init() {
    initAppShell('trap');
    this.init3DSphere();
    this.initWorldMap();
    this.bindWebSocket();
    await this.loadTrapData();
  }

  async loadTrapData() {
    try {
      const data = await api.get('/api/trap');
      this.state = data;
      this.origins = data.attacker_origins || [];
      this.renderAll();
    } catch (err) {
      console.error('Failed to load trap data:', err);
      toast('Failed to load honeypot state', 'error');
    }
  }

  renderAll() {
    if (!this.state) return;
    this.renderStats();
    this.renderHoneytokens();
    this.renderSessions();
    this.drawWorldMap();
  }

  renderStats() {
    const elSessions = document.getElementById('statSessionsCount');
    const elCountries = document.getElementById('statCountriesCount');
    const elTripped = document.getElementById('statTrippedCount');

    if (elSessions) elSessions.textContent = this.state.sessions_captured;
    if (elCountries) elCountries.textContent = this.state.unique_countries;
    if (elTripped) elTripped.textContent = this.state.honeytokens_tripped;

    const mapOrigin = document.getElementById('mapOriginCount');
    if (mapOrigin) mapOrigin.textContent = `${this.state.unique_countries} REGIONS`;
  }

  renderHoneytokens() {
    const container = document.getElementById('honeytokensList');
    if (!container || !this.state.honeytokens) return;

    container.innerHTML = '';
    this.state.honeytokens.forEach(token => {
      const isTriggered = token.status === 'TRIGGERED';
      const card = document.createElement('div');
      card.className = 'honeytoken-card';
      card.id = `token-${token.id}`;

      card.innerHTML = `
        <div style="flex: 1; padding-right: 12px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
            <span style="font-weight: 700; color: #FFFFFF; font-size: 13px;">${token.name}</span>
            <span class="token-badge ${isTriggered ? 'triggered' : 'armed'}">
              ${token.status}
            </span>
          </div>
          <div style="font-family: var(--font-mono); font-size: 11px; color: var(--color-muted);">
            Host: <span style="color: var(--color-cyan);">${token.target_host}</span> &bull; 
            Type: <span>${token.type}</span> &bull;
            Technique: <span style="color: #FFB800;">${token.technique_id}</span>
          </div>
          <div style="font-size: 11px; color: #8F9CAE; margin-top: 4px;">
            ${token.description}
          </div>
          ${token.last_tripped ? `
            <div style="font-family: var(--font-mono); font-size: 10px; color: var(--color-red); margin-top: 4px;">
              &bull; TRIPPED AT ${token.last_tripped}
            </div>
          ` : ''}
        </div>

        <div>
          <button class="btn-touch" data-token-id="${token.id}">
            SIMULATE TOUCH
          </button>
        </div>
      `;

      const btn = card.querySelector('.btn-touch');
      if (btn) {
        btn.addEventListener('click', () => this.touchToken(token.id, card));
      }

      container.appendChild(card);
    });
  }

  renderSessions() {
    const tbody = document.getElementById('sessionsTbody');
    if (!tbody || !this.state.sessions) return;

    tbody.innerHTML = '';
    this.state.sessions.forEach(sess => {
      const tr = document.createElement('tr');
      const isAlert = sess.action === 'ALERT';

      tr.innerHTML = `
        <td style="color: var(--color-muted);">${sess.time}</td>
        <td style="color: var(--color-cyan); font-weight: 700;">${sess.honeypot}</td>
        <td style="color: #FFFFFF;">${sess.credentials}</td>
        <td style="color: var(--color-cyan);">${sess.source_ip}</td>
        <td style="color: #FFB800;">${sess.country_code}</td>
        <td>
          <span class="status-badge ${isAlert ? 'open' : 'pass'}" style="font-size: 9px;">
            ${sess.action}
          </span>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  async touchToken(tokenId, cardEl) {
    try {
      sound.threatAlert();
      this.triggerRipple();

      cardEl.classList.add('tripped-flash');
      setTimeout(() => cardEl.classList.remove('tripped-flash'), 1200);

      const res = await api.post(`/api/trap/touch/${tokenId}`);
      this.state = res.state;
      this.renderAll();

      toast(`HONEYTOKEN TRIPPED: ${res.token.name}! Reflex SOAR alert dispatched!`, 'error');
    } catch (err) {
      console.error('Failed to touch honeytoken:', err);
      toast('Failed to simulate honeytoken trip', 'error');
    }
  }

  triggerRipple() {
    this.rippleIntensity = 1.0;
    const label = document.getElementById('meshStatusLabel');
    if (label) {
      label.textContent = 'FIELD: CRITICAL RIPPLE DISTORTION!';
      label.style.color = 'var(--color-red)';
      setTimeout(() => {
        if (label) {
          label.textContent = 'FIELD: RESONATING';
          label.style.color = 'var(--color-muted)';
        }
      }, 2000);
    }
  }

  bindWebSocket() {
    wsClient.on('event', (evt) => {
      if (evt && evt.module === 'Trap') {
        this.loadTrapData();
      }
    });
  }

  init3DSphere() {
    const container = document.getElementById('trapSphereCanvasContainer');
    if (!container) return;

    const width = container.clientWidth || 360;
    const height = container.clientHeight || 280;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 6.5);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    container.appendChild(renderer.domElement);

    // Glowing Mesh Sphere Geometry
    const radius = 2.0;
    const geo = new THREE.IcosahedronGeometry(radius, 4);

    // Store original positions for ripple displacement
    const pos = geo.attributes.position;
    const origPositions = new Float32Array(pos.count * 3);
    for (let i = 0; i < pos.count * 3; i++) {
      origPositions[i] = pos.array[i];
    }

    const mat = new THREE.MeshBasicMaterial({
      color: 0x00E5FF,
      wireframe: true,
      transparent: true,
      opacity: 0.8
    });

    const mesh = new THREE.Mesh(geo, mat);
    scene.add(mesh);
    this.meshSphere = mesh;
    this.sphereMaterial = mat;

    // Inner Core Pulsing Sphere
    const innerGeo = new THREE.SphereGeometry(1.2, 16, 16);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0xFF1F3D,
      wireframe: true,
      transparent: true,
      opacity: 0.3
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    scene.add(innerMesh);

    let clock = new THREE.Clock();

    const animate = () => {
      requestAnimationFrame(animate);
      const time = clock.getElapsedTime();

      mesh.rotation.y = time * 0.3;
      mesh.rotation.x = time * 0.15;
      innerMesh.rotation.y = -time * 0.5;

      // Ripple effect calculation
      if (this.rippleIntensity > 0.005) {
        this.rippleIntensity *= 0.94; // Decay
        mat.color.setHex(0xFF1F3D); // Turn red on ripple
        mat.opacity = 0.95;
      } else {
        mat.color.setHex(0x00E5FF); // Normal cyan
        mat.opacity = 0.75;
      }

      // Vertex vibration
      const pArr = pos.array;
      for (let i = 0; i < pos.count; i++) {
        const idx = i * 3;
        const ox = origPositions[idx];
        const oy = origPositions[idx + 1];
        const oz = origPositions[idx + 2];

        const wave = Math.sin(time * 5 + ox * 2 + oy * 2) * 0.04;
        const ripple = Math.sin(time * 20 + oz * 4) * (this.rippleIntensity * 0.35);
        const factor = 1 + wave + ripple;

        pArr[idx] = ox * factor;
        pArr[idx + 1] = oy * factor;
        pArr[idx + 2] = oz * factor;
      }
      pos.needsUpdate = true;

      renderer.render(scene, camera);
    };
    animate();

    window.addEventListener('resize', () => {
      const w = container.clientWidth || 360;
      const h = container.clientHeight || 280;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    });
  }

  initWorldMap() {
    window.addEventListener('resize', () => this.drawWorldMap());
  }

  drawWorldMap() {
    const canvas = document.getElementById('attackerMapCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const w = canvas.width = canvas.clientWidth || 340;
    const h = canvas.height = canvas.clientHeight || 200;

    ctx.fillStyle = '#06090E';
    ctx.fillRect(0, 0, w, h);

    // Draw grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 30) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 30) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Rough stylized continents (outline boxes for tactical hacker map look)
    ctx.fillStyle = 'rgba(0, 229, 255, 0.04)';
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.15)';
    // North America
    ctx.fillRect(w * 0.12, h * 0.22, w * 0.22, h * 0.32);
    ctx.strokeRect(w * 0.12, h * 0.22, w * 0.22, h * 0.32);
    // South America
    ctx.fillRect(w * 0.26, h * 0.58, w * 0.12, h * 0.3);
    ctx.strokeRect(w * 0.26, h * 0.58, w * 0.12, h * 0.3);
    // Europe
    ctx.fillRect(w * 0.46, h * 0.2, w * 0.14, h * 0.25);
    ctx.strokeRect(w * 0.46, h * 0.2, w * 0.14, h * 0.25);
    // Asia
    ctx.fillRect(w * 0.62, h * 0.18, w * 0.28, h * 0.4);
    ctx.strokeRect(w * 0.62, h * 0.18, w * 0.28, h * 0.4);
    // Africa
    ctx.fillRect(w * 0.48, h * 0.48, w * 0.16, h * 0.36);
    ctx.strokeRect(w * 0.48, h * 0.48, w * 0.16, h * 0.36);

    // Plot Attacker Origins
    const time = performance.now() * 0.003;
    this.origins.forEach((orig, idx) => {
      // Convert lat/lon (-90..90, -180..180) to canvas (x, y)
      const x = ((orig.lon + 180) / 360) * w;
      const y = ((90 - orig.lat) / 180) * h;

      // Pulsing radar ring
      const pulse = (Math.sin(time + idx) + 1) * 0.5;
      const r = 3 + pulse * 6;

      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255, 31, 61, ' + (1 - pulse * 0.8) + ')';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Center dot
      ctx.beginPath();
      ctx.arc(x, y, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = '#FF1F3D';
      ctx.fill();

      // Country Code Label
      ctx.fillStyle = '#FFB800';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.fillText(orig.code, x + 5, y - 3);
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new TrapController();
  controller.init();
});

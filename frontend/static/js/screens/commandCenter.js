/**
 * NO ENTRY - Command Center Screen Controller
 * Drives Screen 4 matching the design brief and reference screenshot:
 * 1. 4 StatCards with live counters and pulsing threat state
 * 2. 3D HoloGlobe with ballistic attack arcs and green shield ripples for blocked threats
 * 3. Live Alerts table with new row slide-in, cyan flash, and green glow for blocked rows
 * 4. Alerts by module animated progress bars drifting with live telemetry
 * 5. Dynamic activity pulse sparkline canvas and interactive event details modal
 */

import * as THREE from 'three';
import { initAppShell } from '../core/appShell.js';
import { wsClient } from '../core/ws.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';
import { sound } from '../core/sound.js';
import { countUp } from '../core/ui.js';
import { CyberScene } from '../three/scene.js';
import { createHoloGlobe, latLongToVector3 } from '../three/holoGlobe.js';
import { createAttackArc } from '../three/attackArc.js';

// Geo coordinates for simulated attack sources and defense targets
const LAB_GEO = { lat: 38.9, lon: -77.0 }; // US East Cyber Range Target
const GEO_POOLS = [
  { lat: 55.75, lon: 37.61, name: 'Moscow' },
  { lat: 39.90, lon: 116.40, name: 'Beijing' },
  { lat: 52.52, lon: 13.40, name: 'Berlin' },
  { lat: 51.50, lon: -0.12, name: 'London' },
  { lat: 35.67, lon: 139.65, name: 'Tokyo' },
  { lat: -23.55, lon: -46.63, name: 'Sao Paulo' },
  { lat: 1.35, lon: 103.81, name: 'Singapore' },
  { lat: 32.08, lon: 34.78, name: 'Tel Aviv' },
  { lat: 48.85, lon: 2.35, name: 'Paris' },
  { lat: -33.86, lon: 151.20, name: 'Sydney' }
];

function getIpGeo(ip) {
  if (!ip) return GEO_POOLS[0];
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = (hash << 5) - hash + ip.charCodeAt(i);
    hash |= 0;
  }
  const idx = Math.abs(hash) % GEO_POOLS.length;
  return GEO_POOLS[idx];
}

class CommandCenterController {
  constructor() {
    this.activeArcs = [];
    this.clickableTargets = [];
    this.sparklineHistory = [12, 18, 15, 22, 28, 20, 25, 30, 22, 35, 40, 28, 32, 45, 38];
    this.eventsCache = new Map();
    this.currentAlertsCount = 0;
    this.lastEventTime = Date.now();
  }

  async init() {
    // 1. Initialize shared App Shell
    initAppShell('command_center');

    // 2. Setup 3D HoloGlobe in Attack Map Panel
    this.initHoloGlobe();

    // 3. Setup Sparkline Activity Canvas
    this.initSparkline();

    // 4. Setup Event Details Modal Handlers
    this.initModal();

    // 5. Connect and listen to real-time WebSocket events
    this.bindWebSocket();

    // 6. Initial snapshot fetch via REST API
    await this.loadInitialData();
  }

  initHoloGlobe() {
    const container = document.getElementById('ccGlobeContainer');
    if (!container) return;

    // Use CyberScene controller with bloom and DPR cap 1.5
    this.cyberScene = new CyberScene(container);
    this.cyberScene.camera.position.set(0, 3, 14);
    this.cyberScene.camera.lookAt(0, 0, 0);

    // Create 3D HoloGlobe
    this.globe = createHoloGlobe(4.6, 2000);
    this.cyberScene.scene.add(this.globe.object);
    this.cyberScene.addUpdatable((delta, time) => this.globe.update(delta, time));

    // Target node marker at Cyber Range location
    const targetVec = latLongToVector3(LAB_GEO.lat, LAB_GEO.lon, 4.6);
    const targetGeo = new THREE.SphereGeometry(0.12, 12, 12);
    const targetMat = new THREE.MeshBasicMaterial({ color: 0x00E5FF, blending: THREE.AdditiveBlending });
    const targetMesh = new THREE.Mesh(targetGeo, targetMat);
    targetMesh.position.copy(targetVec);
    this.globe.object.add(targetMesh);

    // Target Pulse Ring
    const targetRingGeo = new THREE.RingGeometry(0.14, 0.22, 24);
    const targetRingMat = new THREE.MeshBasicMaterial({
      color: 0x00E5FF,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending
    });
    const targetRing = new THREE.Mesh(targetRingGeo, targetRingMat);
    targetRing.position.copy(targetVec);
    targetRing.lookAt(0, 0, 0);
    this.globe.object.add(targetRing);

    this.cyberScene.addUpdatable((delta, time) => {
      // Pulse target ring
      const scale = 1.0 + Math.sin(time * 4) * 0.35;
      targetRing.scale.set(scale, scale, 1);
      targetRingMat.opacity = 0.4 + Math.sin(time * 4) * 0.3;

      // Update active ballistic arcs
      for (let i = this.activeArcs.length - 1; i >= 0; i--) {
        const arc = this.activeArcs[i];
        arc.update(delta);
        arc.life -= delta;
        if (arc.life <= 0) {
          this.globe.object.remove(arc.object);
          this.activeArcs.splice(i, 1);
        }
      }

      // Update active arc count display
      const counterEl = document.getElementById('activeArcCount');
      if (counterEl) {
        counterEl.innerText = `${this.activeArcs.length} ACTIVE ARCS // RANGE SECURE`;
      }
    });

    // Raycast click detection on the globe container
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    container.addEventListener('click', (e) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, this.cyberScene.camera);
      const meshes = this.activeArcs.map(a => a.pulseMesh).filter(Boolean);
      const intersects = raycaster.intersectObjects(meshes, false);

      if (intersects.length > 0) {
        const hit = intersects[0].object;
        if (hit.userData && hit.userData.eventId) {
          this.openEventModal(hit.userData.eventId);
        }
      }
    });

    this.cyberScene.start();
  }

  spawnAttackArc(event) {
    if (!this.globe) return;

    const sourceGeo = getIpGeo(event.source_ip);
    const startVec = latLongToVector3(sourceGeo.lat, sourceGeo.lon, 4.6);
    const endVec = latLongToVector3(LAB_GEO.lat, LAB_GEO.lon, 4.6);

    const isBlocked = event.state === 'BLOCKED';
    const arcColor = isBlocked ? 0x00FF6A : 0xFF1F3D;

    // Create ballistic arc
    const arc = createAttackArc(startVec, endVec, {
      color: arcColor,
      speed: 1.0,
      altitude: 1.8
    });

    arc.life = 4.0; // arc stays alive for 4 seconds
    // Store event ID on pulse mesh for raycasting
    if (arc.object.children && arc.object.children.length > 1) {
      arc.pulseMesh = arc.object.children[1];
      arc.pulseMesh.userData = { eventId: event.id };
    }

    this.globe.object.add(arc.object);
    this.activeArcs.push(arc);

    // If blocked, spawn green defensive shield ripple
    if (isBlocked) {
      this.spawnShieldRipple(endVec);
    }
  }

  spawnShieldRipple(position) {
    const shieldGeo = new THREE.RingGeometry(0.2, 0.45, 32);
    const shieldMat = new THREE.MeshBasicMaterial({
      color: 0x00FF6A,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    shieldMesh.position.copy(position);
    shieldMesh.lookAt(0, 0, 0);
    this.globe.object.add(shieldMesh);

    let progress = 0;
    const updateRipple = (delta) => {
      progress += delta * 1.5;
      shieldMesh.scale.setScalar(1.0 + progress * 2.5);
      shieldMat.opacity = Math.max(0, 0.9 - progress);

      if (progress >= 1.0) {
        this.globe.object.remove(shieldMesh);
        // remove self from updatables
        const idx = this.cyberScene.updatables.indexOf(updateRipple);
        if (idx !== -1) this.cyberScene.updatables.splice(idx, 1);
      }
    };
    this.cyberScene.addUpdatable(updateRipple);
  }

  initSparkline() {
    this.canvas = document.getElementById('sparklineCanvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.drawSparkline();

    // Pulse sparkline regularly
    setInterval(() => {
      // Decay slightly towards baseline
      const last = this.sparklineHistory[this.sparklineHistory.length - 1] || 15;
      const decay = Math.max(8, last * 0.92);
      this.pushSparkline(decay);
    }, 1500);
  }

  pushSparkline(val) {
    this.sparklineHistory.push(val);
    if (this.sparklineHistory.length > 25) {
      this.sparklineHistory.shift();
    }
    this.drawSparkline();
  }

  drawSparkline() {
    if (!this.ctx || !this.canvas) return;
    const w = this.canvas.width = this.canvas.clientWidth || 120;
    const h = this.canvas.height = this.canvas.clientHeight || 28;

    this.ctx.clearRect(0, 0, w, h);

    const data = this.sparklineHistory;
    const max = Math.max(...data, 50);
    const step = w / (data.length - 1);

    // Draw Gradient Background
    const grad = this.ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(0, 229, 255, 0.35)');
    grad.addColorStop(1, 'rgba(0, 229, 255, 0.0)');

    this.ctx.beginPath();
    this.ctx.moveTo(0, h);
    for (let i = 0; i < data.length; i++) {
      const x = i * step;
      const y = h - (data[i] / max) * (h - 4) - 2;
      this.ctx.lineTo(x, y);
    }
    this.ctx.lineTo(w, h);
    this.ctx.closePath();
    this.ctx.fillStyle = grad;
    this.ctx.fill();

    // Draw Cyan Line
    this.ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
      const x = i * step;
      const y = h - (data[i] / max) * (h - 4) - 2;
      if (i === 0) this.ctx.moveTo(x, y);
      else this.ctx.lineTo(x, y);
    }
    this.ctx.strokeStyle = '#00E5FF';
    this.ctx.lineWidth = 1.5;
    this.ctx.shadowColor = '#00E5FF';
    this.ctx.shadowBlur = 4;
    this.ctx.stroke();
    this.ctx.shadowBlur = 0;
  }

  async loadInitialData() {
    try {
      const [stateRes, eventsRes] = await Promise.all([
        api.get('/state'),
        api.get('/events?limit=25')
      ]);

      if (stateRes) {
        this.updateMetrics(stateRes.metrics);
      }

      if (eventsRes && Array.isArray(eventsRes)) {
        const tbody = document.getElementById('liveAlertsTbody');
        if (tbody) tbody.innerHTML = '';
        eventsRes.forEach(evt => {
          this.eventsCache.set(evt.id, evt);
          this.appendAlertRow(evt, false);
        });
      }
    } catch (err) {
      console.warn('Initial Command Center data load note:', err.message);
    }
  }

  bindWebSocket() {
    wsClient.on('message', (msg) => {
      if (!msg) return;

      if (msg.type === 'snapshot') {
        if (msg.data && msg.data.metrics) {
          this.updateMetrics(msg.data.metrics);
        }
        if (msg.data && Array.isArray(msg.data.recent_events)) {
          msg.data.recent_events.forEach(evt => {
            this.eventsCache.set(evt.id, evt);
          });
        }
      } else if (msg.type === 'event') {
        const evt = msg.data;
        if (!evt) return;

        this.eventsCache.set(evt.id, evt);
        this.onNewEvent(evt);
      } else if (msg.type === 'metrics') {
        this.updateMetrics(msg.data);
      }
    });
  }

  onNewEvent(evt) {
    // 1. Increment live Alerts Today counter
    const alertsTodayEl = document.getElementById('statAlertsToday');
    if (alertsTodayEl) {
      this.currentAlertsCount++;
      alertsTodayEl.innerText = this.currentAlertsCount;
    }

    // 2. Play blip sound and spawn attack arc on 3D HoloGlobe
    if (evt.state === 'BLOCKED') {
      sound.blip(1100, 0.08);
    } else {
      sound.blip(650, 0.06);
    }

    this.spawnAttackArc(evt);

    // 3. Slide in new row to top of LIVE ALERTS table
    this.appendAlertRow(evt, true);

    // 4. Update sparkline with sudden activity jump
    const activitySpike = evt.severity === 'CRITICAL' ? 48 : evt.severity === 'HIGH' ? 36 : 24;
    this.pushSparkline(activitySpike);
  }

  updateMetrics(metrics) {
    if (!metrics) return;

    // 1. THREAT LEVEL
    const threatEl = document.getElementById('statThreatLevel');
    if (threatEl && metrics.threat_level) {
      const lvl = metrics.threat_level.toUpperCase();
      threatEl.innerText = lvl;
      threatEl.className = 'stat-val-cc';
      if (lvl === 'LOW') {
        threatEl.classList.add('stat-val-green');
      } else if (lvl === 'CRITICAL') {
        threatEl.classList.add('stat-val-red');
        threatEl.style.animation = 'pulse 1s infinite alternate';
      } else {
        threatEl.classList.add('stat-val-red');
      }
      store.set('threatLevel', lvl);
    }

    // 2. ALERTS TODAY (Count up)
    const alertsTodayEl = document.getElementById('statAlertsToday');
    if (alertsTodayEl && metrics.alerts_today !== undefined) {
      const targetVal = metrics.alerts_today;
      countUp(alertsTodayEl, targetVal, 0.8);
      this.currentAlertsCount = targetVal;
    }

    // 3. MEAN TIME TO DETECT
    const mttdEl = document.getElementById('statMttd');
    if (mttdEl && metrics.mean_time_to_detect !== undefined) {
      mttdEl.innerText = `${metrics.mean_time_to_detect.toFixed(1)} s`;
    }

    // 4. MEAN TIME TO RESPOND
    const mttrEl = document.getElementById('statMttr');
    if (mttrEl && metrics.mean_time_to_respond !== undefined) {
      mttrEl.innerText = `${metrics.mean_time_to_respond.toFixed(1)} s`;
    }

    // 5. ALERTS BY MODULE Bars
    if (metrics.module_percentages) {
      this.updateModuleBar('Watch', metrics.module_percentages.Watch ?? 78);
      this.updateModuleBar('Trap', metrics.module_percentages.Trap ?? 42);
      this.updateModuleBar('Reflex', metrics.module_percentages.Reflex ?? 64);
      this.updateModuleBar('Intel', metrics.module_percentages.Intel ?? 35);
    }
  }

  updateModuleBar(moduleName, percentage) {
    const bar = document.getElementById(`bar${moduleName}`);
    const val = document.getElementById(`val${moduleName}`);
    if (bar) bar.style.width = `${percentage}%`;
    if (val) val.innerText = `${percentage}%`;
  }

  appendAlertRow(evt, isNew = false) {
    const tbody = document.getElementById('liveAlertsTbody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    tr.className = 'alert-row-clickable';
    tr.dataset.eventId = evt.id;

    // State Tag
    const state = (evt.state || 'DETECTED').toUpperCase();
    let tagClass = 'tag--detected';
    if (state === 'BLOCKED') tagClass = 'tag--blocked';
    else if (state === 'ALERT') tagClass = 'tag--alert';
    else if (state === 'ISOLATED') tagClass = 'tag--isolated';

    tr.innerHTML = `
      <td style="color:var(--color-muted); font-size:11px;">${evt.time || 'NOW'}</td>
      <td><span class="badge" style="font-size:10px;">${evt.technique_id}</span></td>
      <td style="color:var(--color-text); font-size:12px; font-weight:500;">${evt.event}</td>
      <td><span class="tag ${tagClass}">${state}</span></td>
    `;

    // Click row to view details
    tr.addEventListener('click', () => this.openEventModal(evt.id));

    if (isNew) {
      // Slide-in and cyan flash effect
      tr.style.background = 'rgba(0, 229, 255, 0.28)';
      tr.style.transform = 'translateY(-12px)';
      tr.style.opacity = '0';
      tr.style.transition = 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)';

      tbody.insertBefore(tr, tbody.firstChild);

      // Force reflow
      void tr.offsetWidth;
      tr.style.transform = 'translateY(0)';
      tr.style.opacity = '1';

      setTimeout(() => {
        if (state === 'BLOCKED') {
          // BLOCKED rows briefly glow green
          tr.style.background = 'rgba(0, 255, 106, 0.18)';
          setTimeout(() => {
            tr.style.background = 'transparent';
          }, 800);
        } else {
          tr.style.background = 'transparent';
        }
      }, 350);

      // Maintain max 30 rows in DOM
      while (tbody.children.length > 30) {
        tbody.removeChild(tbody.lastChild);
      }
    } else {
      tbody.appendChild(tr);
    }
  }

  initModal() {
    const modal = document.getElementById('eventDetailModal');
    const closeBtn = document.getElementById('modalCloseBtn');
    if (!modal) return;

    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        modal.classList.remove('active');
        sound.keyClick();
      });
    }

    // Close on ESC
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal.classList.contains('active')) {
        modal.classList.remove('active');
      }
    });

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.classList.remove('active');
      }
    });
  }

  async openEventModal(eventId) {
    const modal = document.getElementById('eventDetailModal');
    if (!modal) return;

    sound.panelOpen();

    // Default placeholder while fetching
    document.getElementById('modalEventTitle').innerText = `EVENT // ${eventId}`;
    document.getElementById('modalMitreName').innerText = 'Loading...';
    document.getElementById('modalMitreDesc').innerText = 'Querying MITRE ATT&CK catalog...';
    document.getElementById('modalIntelScore').innerText = '...';
    document.getElementById('modalIntelDetails').innerText = 'Querying AbuseIPDB threat engine...';
    document.getElementById('modalRawJson').innerText = '// Fetching telemetry JSON...';

    modal.classList.add('active');

    try {
      const data = await api.get(`/events/${eventId}`);
      if (data) {
        const evt = data.event || {};
        const mitre = data.mitre_technique || {};
        const intel = data.enrichment || {};

        document.getElementById('modalEventTitle').innerText = `${evt.technique_id} - ${evt.technique_name || evt.event}`;
        document.getElementById('modalMitreName').innerText = `${mitre.id || evt.technique_id} : ${mitre.name || evt.technique_name}`;
        document.getElementById('modalMitreDesc').innerText = mitre.description || 'No extended description available.';

        document.getElementById('modalIntelScore').innerText = `${intel.threat_score ?? 88}% THREAT`;
        document.getElementById('modalIntelDetails').innerText = `${intel.ip || evt.source_ip} &bull; ${intel.country || 'External'} &bull; ${intel.isp || 'Host Provider'}`;

        document.getElementById('modalRawJson').innerText = JSON.stringify(data.raw_log || evt, null, 2);
      }
    } catch (err) {
      // Fallback from local cache
      const cached = this.eventsCache.get(eventId);
      if (cached) {
        document.getElementById('modalMitreName').innerText = `${cached.technique_id} : ${cached.technique_name}`;
        document.getElementById('modalMitreDesc').innerText = cached.event;
        document.getElementById('modalIntelScore').innerText = 'EXTERNAL SOURCE';
        document.getElementById('modalIntelDetails').innerText = `IP: ${cached.source_ip} &bull; Target: ${cached.target_host}`;
        document.getElementById('modalRawJson').innerText = JSON.stringify(cached, null, 2);
      }
    }
  }
}

// Instantiate on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  const cc = new CommandCenterController();
  cc.init();
});

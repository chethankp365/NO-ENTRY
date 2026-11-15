/**
 * NO ENTRY - Shield Hardening Screen Controller (Screen 8)
 * Drives compliance checklist, live interactive remediation fixes,
 * area posture bars, and 3D rotating hexagonal energy shield.
 */

import * as THREE from 'three';
import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class ShieldController {
  constructor() {
    this.state = null;
    this.threeScene = null;
    this.shieldMesh = null;
    this.shieldGlow = null;
    this.coreMesh = null;
    this.animId = null;
  }

  async init() {
    initAppShell('shield');
    this.init3DShield();
    await this.loadShieldData();
  }

  async loadShieldData() {
    try {
      const data = await api.get('/api/shield');
      this.state = data;
      this.renderAll();
    } catch (err) {
      console.error('Failed to load shield data:', err);
      toast('Failed to load hardening state', 'error');
    }
  }

  renderAll() {
    if (!this.state) return;
    this.renderStats();
    this.renderChecklist();
    this.renderAreas();
    this.update3DEnergy(this.state.after_score);
  }

  renderStats() {
    const elBefore = document.getElementById('statBeforeScore');
    const elAfter = document.getElementById('statAfterScore');
    const elGained = document.getElementById('statGainedScore');

    if (elBefore) elBefore.textContent = this.state.before_score;
    if (elAfter) this.animateNumber(elAfter, parseInt(elAfter.textContent) || 0, this.state.after_score, 800);
    if (elGained) {
      const gained = this.state.score_gained;
      elGained.textContent = gained >= 0 ? `+${gained}` : gained;
    }

    const passCount = this.state.checklist.filter(i => i.status === 'PASS').length;
    const progressEl = document.getElementById('checklistProgress');
    if (progressEl) {
      progressEl.textContent = `${passCount} OF ${this.state.checklist.length} COMPLIANT`;
    }
  }

  renderChecklist() {
    const tbody = document.getElementById('checklistTbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    this.state.checklist.forEach(item => {
      const tr = document.createElement('tr');
      tr.className = 'checklist-row';
      tr.id = `row-${item.id}`;

      const isPass = item.status === 'PASS';

      tr.innerHTML = `
        <td>
          <div style="font-weight: 700; color: #FFFFFF;">${item.name}</div>
          <div style="font-size: 10px; color: var(--color-muted); margin-top: 2px;">${item.description}</div>
        </td>
        <td style="color: var(--color-cyan);">${item.area}</td>
        <td>
          <span class="status-badge ${isPass ? 'pass' : 'open'}">
            ${item.status}
          </span>
        </td>
        <td style="text-align: right;">
          ${isPass ? `
            <span style="color: var(--color-green); font-size: 11px;">ENFORCED &check;</span>
          ` : `
            <button class="btn-fix" data-fix-id="${item.id}">
              FIX
            </button>
          `}
        </td>
      `;

      if (!isPass) {
        const fixBtn = tr.querySelector('.btn-fix');
        if (fixBtn) {
          fixBtn.addEventListener('click', () => this.applyFix(item.id, item.name, tr, fixBtn));
        }
      }

      tbody.appendChild(tr);
    });
  }

  renderAreas() {
    const container = document.getElementById('areaBarsContainer');
    if (!container || !this.state.areas) return;

    container.innerHTML = '';
    for (const [areaName, score] of Object.entries(this.state.areas)) {
      const row = document.createElement('div');
      row.className = 'area-bar-row';
      row.innerHTML = `
        <div class="area-bar-header">
          <span style="color: #FFFFFF;">${areaName}</span>
          <span style="color: var(--color-cyan); font-weight: 700;">${score}%</span>
        </div>
        <div class="area-bar-track">
          <div class="area-bar-fill" style="width: ${score}%;"></div>
        </div>
      `;
      container.appendChild(row);
    }
  }

  async applyFix(itemId, itemName, rowEl, buttonEl) {
    buttonEl.disabled = true;
    buttonEl.textContent = 'APPLYING...';

    const strip = document.getElementById('fixTerminalStrip');
    const stripText = document.getElementById('fixTerminalText');

    if (strip && stripText) {
      strip.style.display = 'block';
      stripText.textContent = `> deploying remediation policy for ${itemName}...`;
      sound.blip();
    }

    // Terminal step animation
    await new Promise(r => setTimeout(r, 600));
    if (stripText) stripText.textContent = `> validating kernel & service configs... OK`;
    await new Promise(r => setTimeout(r, 600));

    try {
      const res = await api.post(`/api/shield/fix/${itemId}`);
      this.state = res;

      if (stripText) {
        stripText.textContent = `> ${itemName} successfully enforced! Policy score recalculating...`;
      }
      sound.panelOpen();

      // Green flash animation
      rowEl.classList.add('flash-success');
      setTimeout(() => rowEl.classList.remove('flash-success'), 1200);

      toast(`Hardening control '${itemName}' applied successfully!`, 'success');
      this.renderAll();

      setTimeout(() => {
        if (strip) strip.style.display = 'none';
      }, 3000);
    } catch (err) {
      console.error('Failed to apply fix:', err);
      toast('Remediation script failed to execute', 'error');
      buttonEl.disabled = false;
      buttonEl.textContent = 'FIX';
    }
  }

  animateNumber(element, start, end, duration) {
    const range = end - start;
    if (range === 0) {
      element.textContent = end;
      return;
    }
    const startTime = performance.now();

    const update = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = Math.floor(start + range * progress);
      element.textContent = current;

      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        element.textContent = end;
      }
    };
    requestAnimationFrame(update);
  }

  init3DShield() {
    const container = document.getElementById('shieldCanvasContainer');
    if (!container) return;

    const width = container.clientWidth || 360;
    const height = container.clientHeight || 320;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 8);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    container.appendChild(renderer.domElement);

    // Create 3D Hexagonal Geometry
    const hexRadius = 2.4;
    const hexShape = new THREE.Shape();
    for (let i = 0; i < 6; i++) {
      const angle = (i * Math.PI) / 3;
      const x = hexRadius * Math.cos(angle);
      const y = hexRadius * Math.sin(angle);
      if (i === 0) hexShape.moveTo(x, y);
      else hexShape.lineTo(x, y);
    }
    hexShape.closePath();

    // Extrude Geometry for 3D shield prism
    const extrudeSettings = { depth: 0.4, bevelEnabled: true, bevelSegments: 3, steps: 1, bevelSize: 0.1, bevelThickness: 0.1 };
    const hexGeo = new THREE.ExtrudeGeometry(hexShape, extrudeSettings);
    hexGeo.center();

    // Translucent cyan shield material
    const shieldMat = new THREE.MeshBasicMaterial({
      color: 0x00E5FF,
      wireframe: true,
      transparent: true,
      opacity: 0.75
    });

    const shieldMesh = new THREE.Mesh(hexGeo, shieldMat);
    scene.add(shieldMesh);
    this.shieldMesh = shieldMesh;

    // Glowing core crystal (Octahedron)
    const coreGeo = new THREE.OctahedronGeometry(1.0, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x00FF6A,
      wireframe: true,
      transparent: true,
      opacity: 0.6
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    scene.add(coreMesh);
    this.coreMesh = coreMesh;

    // Outer Energy Ring
    const ringGeo = new THREE.RingGeometry(2.8, 2.9, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x00E5FF,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.4
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    scene.add(ringMesh);

    // Animation Loop
    let clock = new THREE.Clock();
    const animate = () => {
      this.animId = requestAnimationFrame(animate);
      const delta = clock.getElapsedTime();

      shieldMesh.rotation.y = delta * 0.45;
      shieldMesh.rotation.x = Math.sin(delta * 0.3) * 0.2;

      coreMesh.rotation.y = -delta * 0.8;
      coreMesh.rotation.z = delta * 0.4;
      const pulse = 1.0 + Math.sin(delta * 3) * 0.08;
      coreMesh.scale.set(pulse, pulse, pulse);

      ringMesh.rotation.z = delta * 0.2;

      renderer.render(scene, camera);
    };
    animate();

    // Resize handler
    window.addEventListener('resize', () => {
      const w = container.clientWidth || 360;
      const h = container.clientHeight || 320;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    });
  }

  update3DEnergy(score) {
    const energyLabel = document.getElementById('shieldEnergyLabel');
    if (energyLabel) {
      energyLabel.textContent = `ENERGY: ${score}% HARDENED`;
    }

    if (this.shieldMesh && this.coreMesh) {
      // Scale glow and color based on score
      const t = Math.min(1, Math.max(0, (score - 30) / 70));
      if (score >= 85) {
        this.coreMesh.material.color.setHex(0x00FF6A); // Bright Green when hardened
        this.shieldMesh.material.opacity = 0.9;
      } else {
        this.coreMesh.material.color.setHex(0x00E5FF); // Cyan
        this.shieldMesh.material.opacity = 0.5 + t * 0.4;
      }
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new ShieldController();
  controller.init();
});

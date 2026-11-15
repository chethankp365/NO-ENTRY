/**
 * NO ENTRY - MITRE ATT&CK Matrix Screen Controller (Screen 14)
 * Manages 12-tactic x 6-row enterprise heatmap, wave entrance animation,
 * hover/click inspection inspector, and real-time technique hit illumination.
 */

import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { wsClient } from '../core/ws.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class AttackMatrixController {
  constructor() {
    this.tactics = [];
    this.stats = null;
    this.cellElements = new Map();
  }

  async init() {
    initAppShell('attack');
    this.bindWebSocket();
    await this.loadCoverageData();
  }

  async loadCoverageData() {
    try {
      const data = await api.get('/api/attack/coverage');
      this.tactics = data.tactics || [];
      this.stats = data.stats || {};
      this.renderStats();
      this.renderHeatmap();
    } catch (err) {
      console.error('Failed to load ATT&CK coverage data:', err);
      toast('Failed to load MITRE ATT&CK matrix', 'error');
    }
  }

  renderStats() {
    const elDet = document.getElementById('statDetectedCount');
    const elGaps = document.getElementById('statGapsCount');
    const elMiss = document.getElementById('statMissionsCount');

    if (elDet) elDet.textContent = `${this.stats.detected || 38} / ${this.stats.total || 50}`;
    if (elGaps) elGaps.textContent = `${this.stats.gaps || 12} GAPS LISTED`;
    if (elMiss) elMiss.textContent = `${this.stats.missions || 5} MISSIONS`;
  }

  renderHeatmap() {
    const board = document.getElementById('heatmapBoardContainer');
    if (!board || !this.tactics.length) return;

    board.innerHTML = '';
    this.cellElements.clear();

    this.tactics.forEach((tactic, colIdx) => {
      const colDiv = document.createElement('div');
      colDiv.className = 'tactic-column';

      // Header
      const header = document.createElement('div');
      header.className = 'tactic-header';
      header.textContent = tactic.short_name || tactic.tactic_name;
      colDiv.appendChild(header);

      // 6 Techniques
      tactic.techniques.forEach((tech, rowIdx) => {
        const cell = document.createElement('div');
        cell.className = `technique-cell ${tech.status}`;
        cell.id = `cell-${tech.id}`;

        cell.innerHTML = `
          <div class="cell-id">${tech.id}</div>
          <div class="cell-name">${tech.name}</div>
        `;

        cell.addEventListener('mouseenter', () => this.inspectTechnique(tactic, tech));
        cell.addEventListener('click', () => {
          sound.blip();
          this.inspectTechnique(tactic, tech);
        });

        colDiv.appendChild(cell);
        this.cellElements.set(tech.id, cell);

        // Wave entrance animation
        const delay = colIdx * 40 + rowIdx * 35;
        setTimeout(() => cell.classList.add('animate-in'), delay);
      });

      board.appendChild(colDiv);
    });
  }

  inspectTechnique(tactic, tech) {
    const inspector = document.getElementById('techniqueInspector');
    if (!inspector) return;

    const isDet = tech.status === 'detected';
    const isGap = tech.status === 'gap';

    inspector.style.display = 'block';
    inspector.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--color-border); padding-bottom: 6px; margin-bottom: 8px;">
        <div>
          <span style="font-weight: 700; color: #FFFFFF; font-size: 13px;">${tech.id}: ${tech.name}</span>
          <span style="color: var(--color-muted); margin-left: 8px;">[TACTIC: ${tactic.tactic_name}]</span>
        </div>
        <div>
          <span class="badge" style="font-size: 9px; ${isDet ? 'background:rgba(0,229,255,0.15); border:1px solid var(--color-cyan); color:var(--color-cyan);' : (isGap ? 'background:rgba(255,31,61,0.2); border:1px solid var(--color-red); color:var(--color-red);' : 'background:#0D121A; border:1px solid var(--color-border); color:var(--color-muted);')}">
            ${tech.status.toUpperCase()}
          </span>
        </div>
      </div>
      <div style="display: flex; gap: 24px; font-size: 11px;">
        <div><span style="color: var(--color-muted);">Detection Rule:</span> <span style="color: var(--color-cyan); font-weight: 700;">${tech.rule}</span></div>
        <div><span style="color: var(--color-muted);">Telemetry Sensor:</span> <span style="color: #FFFFFF;">Zeek / Wazuh EDR Agent</span></div>
        <div><span style="color: var(--color-muted);">Coverage Level:</span> <span style="color: ${isDet ? 'var(--color-green)' : (isGap ? 'var(--color-red)' : 'var(--color-muted)')}; font-weight: 700;">${isDet ? 'HIGH (Verified)' : (isGap ? 'ZERO (Blind Spot)' : 'UNTESTED')}</span></div>
      </div>
    `;
  }

  flashTechniqueHit(techId, techName) {
    const cell = this.cellElements.get(techId);
    if (cell) {
      sound.blip();
      cell.classList.remove('live-hit');
      void cell.offsetWidth; // Force reflow
      cell.classList.add('live-hit');

      const label = document.getElementById('matrixStatusLabel');
      if (label) {
        label.textContent = `LIVE HIT: ${techId} (${techName}) DETECTED BY EDR`;
        label.style.color = 'var(--color-cyan)';
        setTimeout(() => {
          if (label) {
            label.textContent = '• LIVE TELEMETRY LISTENER';
            label.style.color = 'var(--color-cyan)';
          }
        }, 3000);
      }
    }
  }

  bindWebSocket() {
    wsClient.on('event', (evt) => {
      if (evt && evt.technique_id) {
        this.flashTechniqueHit(evt.technique_id, evt.technique_name || 'Technique Recognized');
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new AttackMatrixController();
  controller.init();
});

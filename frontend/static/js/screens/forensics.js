/**
 * NO ENTRY - Forensics Screen Controller (Screen 12)
 * Manages incident timeline, evidence artifact chain of custody,
 * real cryptographic SHA-256 verification, and scrolling hex-dump viewer.
 */

import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class ForensicsController {
  constructor() {
    this.timeline = [];
    this.evidence = [];
    this.selectedEventId = 'tl-1';
    this.currentHexFile = 'memory.dmp';
  }

  async init() {
    initAppShell('forensics');
    await this.loadForensicsData();
    await this.loadHexDump(this.currentHexFile);
  }

  async loadForensicsData() {
    try {
      const data = await api.get('/api/forensics');
      this.timeline = data.timeline || [];
      this.evidence = data.evidence || [];
      this.renderTimeline();
      this.renderEvidence();
    } catch (err) {
      console.error('Failed to load forensics data:', err);
      toast('Failed to load forensics evidence state', 'error');
    }
  }

  renderTimeline() {
    const container = document.getElementById('timelineNodesContainer');
    if (!container) return;

    container.innerHTML = '';
    this.timeline.forEach((event, idx) => {
      const node = document.createElement('div');
      node.className = 'timeline-node';

      const isSelected = event.id === this.selectedEventId;
      const isCrit = event.severity === 'CRITICAL';
      const isRes = event.severity === 'RESOLVED';

      node.innerHTML = `
        <div class="timeline-dot ${isCrit ? 'critical' : (isRes ? 'resolved' : '')}"></div>
        <div class="timeline-card ${isSelected ? 'active-selected' : ''}" id="card-${event.id}">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--color-cyan); font-weight: 700;">
              ${event.time}
            </span>
            <span class="badge" style="font-size: 9px; ${isCrit ? 'background:rgba(255,31,61,0.2); border:1px solid var(--color-red); color:var(--color-red);' : 'background:rgba(0,229,255,0.1); border:1px solid var(--color-cyan); color:var(--color-cyan);'}">
              ${event.stage}
            </span>
          </div>

          <div style="font-weight: 700; color: #FFFFFF; font-size: 13px; margin-bottom: 4px;">
            ${event.title}
          </div>

          <div style="font-size: 11px; color: var(--color-muted); line-height: 1.4;">
            ${event.details}
          </div>

          ${isSelected ? `
            <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.08); font-family: var(--font-mono); font-size: 10px; display: grid; grid-template-columns: 1fr 1fr; gap: 6px;">
              <div><span style="color: var(--color-muted);">Host:</span> <span style="color: var(--color-cyan);">${event.host}</span></div>
              <div><span style="color: var(--color-muted);">User:</span> <span style="color: #FFFFFF;">${event.user}</span></div>
              <div><span style="color: var(--color-muted);">MITRE:</span> <span style="color: #FFB800;">${event.technique}</span></div>
              <div><span style="color: var(--color-muted);">Severity:</span> <span style="color: ${isCrit ? 'var(--color-red)' : 'var(--color-cyan)'};">${event.severity}</span></div>
            </div>
          ` : ''}
        </div>
      `;

      node.addEventListener('click', () => {
        sound.blip();
        this.selectedEventId = event.id;
        this.renderTimeline();
      });

      container.appendChild(node);
    });
  }

  renderEvidence() {
    const container = document.getElementById('evidenceListContainer');
    if (!container) return;

    container.innerHTML = '';
    this.evidence.forEach(item => {
      const card = document.createElement('div');
      card.className = `evidence-card ${this.currentHexFile === item.file ? 'active-hex' : ''}`;
      card.id = `evidence-${item.file.replace('.', '_')}`;

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <span style="font-weight: 700; color: #FFFFFF; font-size: 13px;">${item.file}</span>
          <span class="badge" style="background: rgba(0, 255, 106, 0.1); border: 1px solid var(--color-green); color: var(--color-green); font-size: 9px;">
            ${item.status} &check;
          </span>
        </div>

        <div style="font-family: var(--font-mono); font-size: 11px; color: var(--color-muted); margin-bottom: 4px;">
          Tool: <span style="color: var(--color-cyan);">${item.tool}</span> &bull; 
          Type: <span>${item.type}</span> &bull; 
          Size: <span style="color: #FFFFFF;">${item.size}</span>
        </div>

        <div class="hash-box">
          <span style="color: var(--color-muted);">SHA-256:</span> ${item.recorded_sha256}
        </div>

        <div style="font-size: 10px; color: var(--color-muted); font-style: italic; margin-bottom: 8px;">
          Custody: ${item.custody}
        </div>

        <div style="display: flex; gap: 8px;">
          <button class="btn btn-outline btn-verify-hash" style="padding: 4px 10px; font-size: 10px;" data-file="${item.file}">
            VERIFY SHA-256
          </button>
          <button class="btn btn-outline btn-view-hex" style="padding: 4px 10px; font-size: 10px; border-color: var(--color-cyan); color: var(--color-cyan);" data-file="${item.file}">
            VIEW HEX
          </button>
        </div>
      `;

      // Event listeners
      const verifyBtn = card.querySelector('.btn-verify-hash');
      if (verifyBtn) {
        verifyBtn.addEventListener('click', () => this.verifyFileHash(item.file, verifyBtn));
      }

      const hexBtn = card.querySelector('.btn-view-hex');
      if (hexBtn) {
        hexBtn.addEventListener('click', () => {
          this.currentHexFile = item.file;
          this.renderEvidence();
          this.loadHexDump(item.file);
        });
      }

      container.appendChild(card);
    });
  }

  async verifyFileHash(filename, buttonEl) {
    buttonEl.disabled = true;
    buttonEl.textContent = 'HASHING...';
    sound.blip();

    const banner = document.getElementById('verifyStatusBanner');
    if (banner) {
      banner.textContent = `COMPUTING SHA-256 ON ${filename}...`;
      banner.style.color = 'var(--color-cyan)';
    }

    try {
      const res = await api.post(`/api/forensics/verify/${filename}`);
      sound.panelOpen();

      buttonEl.disabled = false;
      buttonEl.textContent = 'VERIFIED ✓';
      buttonEl.style.borderColor = 'var(--color-green)';
      buttonEl.style.color = 'var(--color-green)';

      if (banner) {
        banner.textContent = `✓ ${filename} MATCHES (${res.verification_time_ms}ms)`;
        banner.style.color = 'var(--color-green)';
      }

      toast(`Cryptographic verification passed for ${filename} (${res.verification_time_ms}ms)!`, 'success');
    } catch (err) {
      console.error('Failed to verify hash:', err);
      buttonEl.disabled = false;
      buttonEl.textContent = 'VERIFY SHA-256';
      toast('Integrity verification failed', 'error');
    }
  }

  async loadHexDump(filename) {
    const container = document.getElementById('hexViewerContainer');
    const nameEl = document.getElementById('currentHexFilename');
    const countEl = document.getElementById('hexByteCount');

    if (nameEl) nameEl.textContent = filename;

    try {
      const res = await api.get(`/api/forensics/hex/${filename}?offset=0&limit=512`);
      if (countEl) countEl.textContent = `${res.total_bytes} BYTES`;

      if (container && res.rows) {
        container.innerHTML = '';
        res.rows.forEach(r => {
          const rowDiv = document.createElement('div');
          rowDiv.className = 'hex-row';
          rowDiv.innerHTML = `
            <span class="hex-offset">${r.offset}</span>
            <span class="hex-bytes">${r.hex}</span>
            <span class="hex-ascii">${this.escapeHtml(r.ascii)}</span>
          `;
          container.appendChild(rowDiv);
        });
      }
    } catch (err) {
      console.error('Failed to load hex dump:', err);
      if (container) container.innerHTML = '<div style="color:var(--color-red);">Failed to read binary stream</div>';
    }
  }

  escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new ForensicsController();
  controller.init();
});

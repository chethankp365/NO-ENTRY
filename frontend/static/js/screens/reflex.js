/**
 * NO ENTRY - Reflex SOAR Screen Controller (Screen 10)
 * Drives playbook toggles, sequential animated flow diagram (Alert > Enrich > Decide > Act > Notify),
 * real-time event bus listener, and live action log with response latency.
 */

import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { wsClient } from '../core/ws.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class ReflexController {
  constructor() {
    this.playbooks = [];
    this.actions = [];
    this.isAnimating = false;
  }

  async init() {
    initAppShell('reflex');
    this.bindWebSocket();
    await this.loadReflexData();
  }

  async loadReflexData() {
    try {
      const data = await api.get('/api/reflex');
      this.playbooks = data.playbooks || [];
      this.actions = data.actions || [];
      this.renderAll();
    } catch (err) {
      console.error('Failed to load reflex data:', err);
      toast('Failed to load SOAR engine state', 'error');
    }
  }

  renderAll() {
    this.renderStats();
    this.renderPlaybooks();
    this.renderActions();
  }

  renderStats() {
    const activeCount = this.playbooks.filter(p => p.enabled).length;
    const elActive = document.getElementById('statActivePlaybooks');
    if (elActive) {
      elActive.textContent = `${activeCount} / ${this.playbooks.length}`;
      elActive.style.color = activeCount === this.playbooks.length ? 'var(--color-green)' : '#FFB800';
    }

    const elExecuted = document.getElementById('statActionsExecuted');
    if (elExecuted) {
      elExecuted.textContent = this.actions.length;
    }

    // Average latency
    if (this.actions.length > 0) {
      const avg = (this.actions.reduce((acc, a) => acc + (a.response_time || 8.4), 0) / this.actions.length).toFixed(1);
      const elLatency = document.getElementById('statResponseTime');
      if (elLatency) elLatency.textContent = `${avg} ms`;
    }
  }

  renderPlaybooks() {
    const container = document.getElementById('playbooksList');
    if (!container) return;

    container.innerHTML = '';
    this.playbooks.forEach(pb => {
      const card = document.createElement('div');
      card.className = 'playbook-card';
      card.innerHTML = `
        <div style="flex: 1; padding-right: 14px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 3px;">
            <span style="font-weight: 700; color: #FFFFFF; font-size: 13px;">${pb.name}</span>
            <span class="badge" style="font-size: 9px; ${pb.enabled ? 'background:rgba(0,255,106,0.1); border:1px solid var(--color-green); color:var(--color-green);' : 'background:rgba(255,255,255,0.05); border:1px solid var(--color-border); color:var(--color-muted);'}">
              ${pb.enabled ? 'ARMED' : 'OFF'}
            </span>
          </div>
          <div style="font-size: 11px; color: var(--color-muted); line-height: 1.4;">
            ${pb.description}
          </div>
          <div style="font-family: var(--font-mono); font-size: 10px; color: var(--color-cyan); margin-top: 4px;">
            Trigger: <span style="color: #FFB800;">${pb.trigger}</span> &bull; Latency: ~${pb.execution_latency_ms || 8.4} ms
          </div>
        </div>

        <div>
          <label class="switch-label">
            <input type="checkbox" ${pb.enabled ? 'checked' : ''} data-playbook="${pb.id}">
            <span class="switch-slider"></span>
          </label>
        </div>
      `;

      const toggle = card.querySelector('input');
      toggle.addEventListener('change', async (e) => {
        const enabled = e.target.checked;
        await this.togglePlaybook(pb.id, enabled);
      });

      container.appendChild(card);
    });
  }

  renderActions() {
    const tbody = document.getElementById('actionsTbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    this.actions.forEach(act => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color: var(--color-muted);">${act.time}</td>
        <td style="color: #FFFFFF; font-weight: 700;">${act.action}</td>
        <td style="color: var(--color-cyan);">${act.target}</td>
        <td style="color: #FFB800;">${act.playbook_id}</td>
        <td style="text-align: right; color: var(--color-green); font-weight: 700;">
          ${act.response_time ? `${act.response_time} ms` : '8.4 ms'}
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  async togglePlaybook(playbookId, enabled) {
    try {
      sound.blip();
      await api.post('/api/reflex/playbooks', {
        playbook_id: playbookId,
        enabled: enabled
      });

      const pb = this.playbooks.find(p => p.id === playbookId);
      if (pb) pb.enabled = enabled;

      this.renderPlaybooks();
      this.renderStats();
      toast(`Playbook '${playbookId}' is now ${enabled ? 'ARMED' : 'DISABLED'}`, 'info');
    } catch (err) {
      console.error('Failed to toggle playbook:', err);
      toast('Failed to update playbook state', 'error');
    }
  }

  async triggerFlowAnimation(actionName, latencyMs) {
    if (this.isAnimating) return;
    this.isAnimating = true;

    const clock = document.getElementById('pipelineClock');
    if (clock) {
      clock.textContent = `EXECUTING: ${actionName} [${latencyMs}ms]`;
      clock.style.color = 'var(--color-red)';
    }

    const nAlert = document.getElementById('nodeAlert');
    const nEnrich = document.getElementById('nodeEnrich');
    const nDecide = document.getElementById('nodeDecide');
    const nAct = document.getElementById('nodeAct');
    const nNotify = document.getElementById('nodeNotify');

    const l1 = document.getElementById('line1');
    const l2 = document.getElementById('line2');
    const l3 = document.getElementById('line3');
    const l4 = document.getElementById('line4');

    // 1. ALERT
    sound.blip();
    nAlert?.classList.add('active-node');
    await new Promise(r => setTimeout(r, 120));
    l1?.classList.add('active-line');

    // 2. ENRICH
    nEnrich?.classList.add('active-node');
    await new Promise(r => setTimeout(r, 150));
    l2?.classList.add('active-line');

    // 3. DECIDE
    nDecide?.classList.add('active-node');
    await new Promise(r => setTimeout(r, 150));
    l3?.classList.add('active-line');

    // 4. ACT
    sound.panelOpen();
    nAct?.classList.add('active-act');
    await new Promise(r => setTimeout(r, 200));
    l4?.classList.add('active-line');

    // 5. NOTIFY
    nNotify?.classList.add('active-node');
    await new Promise(r => setTimeout(r, 300));

    // Reset after delay
    setTimeout(() => {
      [nAlert, nEnrich, nDecide, nNotify].forEach(n => n?.classList.remove('active-node'));
      nAct?.classList.remove('active-act');
      [l1, l2, l3, l4].forEach(l => l?.classList.remove('active-line'));
      if (clock) {
        clock.textContent = 'READY • LISTENING TO EVENT BUS';
        clock.style.color = 'var(--color-cyan)';
      }
      this.isAnimating = false;
    }, 1500);
  }

  bindWebSocket() {
    wsClient.on('event', (evt) => {
      if (!evt) return;

      // Check if SOAR reacts
      if (evt.state === 'BLOCKED' || evt.state === 'ISOLATED' || evt.state === 'ALERT') {
        const actionDesc = evt.state === 'BLOCKED'
          ? `firewall: block ${evt.source_ip}`
          : (evt.state === 'ISOLATED' ? `isolate ${evt.target_host} quarantined` : `incident alert ${evt.technique_id} ingested`);

        this.triggerFlowAnimation(actionDesc, 8.4);

        // Prepend action
        const newAct = {
          time: evt.time || new Date().toTimeString().split(' ')[0],
          action: actionDesc,
          target: evt.target_host || evt.source_ip,
          playbook_id: evt.state === 'BLOCKED' ? 'block_ip' : (evt.state === 'ISOLATED' ? 'isolate_host' : 'threat_alert'),
          response_time: 8.4
        };

        this.actions.unshift(newAct);
        this.renderActions();
        this.renderStats();
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new ReflexController();
  controller.init();
});

/**
 * NO ENTRY - Purple Team Screen Controller (Screen 18)
 * Drives the correlated attacker-defender split screen, step/auto-run progression,
 * dynamic SVG connector wires linking commands to detection logs, and final glitch & screen shake.
 */

import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { sound } from '../core/sound.js';
import { screenShake } from '../fx/screenShake.js';
import { toast } from '../core/ui.js';

class PurpleTeamController {
  constructor() {
    this.currentScenario = 'brute-force';
    this.scenarioData = null;
    this.currentStep = 0;
    this.autoRunInterval = null;
    this.paths = [];
    this.isLoading = false;
    this.loadPromise = null;
    this.loadVersion = 0;
    this.runToken = 0;
    this.isAutoRunning = false;
    this.finalEffectTimer = null;
    this.glitchRemoveTimer = null;
    this.transitionRedrawTimers = [];
  }

  async init() {
    initAppShell('purple_team');

    this.initControls();

    const atkScroll = document.getElementById('attackerLinesScroll');
    const defScroll = document.getElementById('defenderLinesScroll');
    if (atkScroll) atkScroll.addEventListener('scroll', () => this.redrawConnectors());
    if (defScroll) defScroll.addEventListener('scroll', () => this.redrawConnectors());

    await this.loadScenario(this.currentScenario);

    // Window resize handler to reposition SVG connectors
    window.addEventListener('resize', () => this.redrawConnectors());
  }

  initControls() {
    // Scenario Pills
    const pills = document.querySelectorAll('.scenario-pill-btn');
    pills.forEach(pill => {
      pill.addEventListener('click', async () => {
        pills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        this.currentScenario = pill.dataset.scenario;
        try { sound.keyClick(); } catch (_) {}
        await this.loadScenario(this.currentScenario);
      });
    });

    // Auto Run
    const startBtn = document.getElementById('startAutoRunBtn');
    if (startBtn) {
      startBtn.addEventListener('click', async () => {
        try { sound.keyClick(); } catch (_) {}
        if (this.autoRunInterval || this.isAutoRunning) {
          this.stopAutoRun();
        } else {
          await this.startAutoRun();
        }
      });
    }

    // Step Run
    const stepBtn = document.getElementById('stepRunBtn');
    if (stepBtn) {
      stepBtn.addEventListener('click', async () => {
        try { sound.keyClick(); } catch (_) {}
        this.stopAutoRun();
        while (this.loadPromise) {
          const p = this.loadPromise;
          await p;
          if (this.loadPromise === p) break;
        }
        if (!this.scenarioData) {
          await this.loadScenario(this.currentScenario);
        }
        this.step();
      });
    }

    // Replay
    const replayBtn = document.getElementById('replayBtn');
    if (replayBtn) {
      replayBtn.addEventListener('click', () => {
        try { sound.keyClick(); } catch (_) {}
        this.replay();
      });
    }
  }

  clearStepTimers() {
    if (this.finalEffectTimer) {
      clearTimeout(this.finalEffectTimer);
      this.finalEffectTimer = null;
    }
    if (this.glitchRemoveTimer) {
      clearTimeout(this.glitchRemoveTimer);
      this.glitchRemoveTimer = null;
    }
    if (this.transitionRedrawTimers.length > 0) {
      this.transitionRedrawTimers.forEach(t => clearTimeout(t));
      this.transitionRedrawTimers = [];
    }
    const atkPanel = document.getElementById('attackerPanel');
    if (atkPanel) atkPanel.classList.remove('glitch-active');
  }

  async loadScenario(scenarioId) {
    this.stopAutoRun();
    this.clearStepTimers();
    this.currentStep = 0;
    this.isLoading = true;
    const version = ++this.loadVersion;

    const p = (async () => {
      try {
        const res = await api.post('/purple/run', { scenario: scenarioId });
        if (version !== this.loadVersion) return;
        this.scenarioData = res;
        this.renderPairs();
      } catch (err) {
        if (version !== this.loadVersion) return;
        console.error('Failed to load purple scenario:', err);
        toast(`Failed to load purple scenario '${scenarioId}': ${err.message}`, 'danger');
      } finally {
        if (version === this.loadVersion) {
          this.isLoading = false;
        }
        if (this.loadPromise === p) {
          this.loadPromise = null;
        }
        const startBtn = document.getElementById('startAutoRunBtn');
        if (startBtn && !this.autoRunInterval && !this.isAutoRunning) {
          startBtn.innerText = 'START RUN';
        }
      }
    })();

    this.loadPromise = p;
    return p;
  }

  renderPairs() {
    const atkContainer = document.getElementById('attackerLinesScroll');
    const defContainer = document.getElementById('defenderLinesScroll');
    const svg = document.getElementById('connectorSvg');

    if (!atkContainer || !defContainer || !this.scenarioData) return;

    atkContainer.innerHTML = '';
    defContainer.innerHTML = '';

    // Clear existing connector path elements cleanly while preserving <defs>
    if (svg) {
      const oldPaths = svg.querySelectorAll('.connector-path');
      oldPaths.forEach(p => p.remove());
    }
    this.paths = [];

    const pairs = this.scenarioData.pairs || [];

    pairs.forEach((pair, idx) => {
      // 1. Attacker Card
      const atkCard = document.createElement('div');
      atkCard.className = 'atk-line-card';
      atkCard.id = `atkCard_${idx}`;
      atkCard.innerHTML = `
        <div class="line-meta-row">
          <span style="color:var(--color-red); font-weight:700;">STAGE: ${pair.stage || 'ATTACK'}</span>
          <span style="color:var(--color-muted);">PAIR #${idx + 1}</span>
        </div>
        <div style="font-size:12px; font-weight:500;">${pair.attacker.text}</div>
      `;
      atkContainer.appendChild(atkCard);

      // 2. Defender Card
      const def = pair.defender || {};
      const defCard = document.createElement('div');
      defCard.className = 'def-line-card';
      defCard.id = `defCard_${idx}`;

      const enrichHtml = def.enrichment ? `<span class="badge" style="color:var(--color-yellow); border-color:#FFB800;">ENRICH: ${def.enrichment}</span>` : '';
      const ttdHtml = def.time_to_detect ? `<span style="color:var(--color-green); font-size:10px;">TTD: ${def.time_to_detect}</span>` : '';

      defCard.innerHTML = `
        <div class="line-meta-row">
          <span style="color:var(--color-cyan); font-weight:700;">TECHNIQUE: ${def.technique || 'SIEM'}</span>
          <div>${enrichHtml} ${ttdHtml}</div>
        </div>
        <div style="font-size:12px; font-weight:500;">${def.text}</div>
      `;
      defContainer.appendChild(defCard);
    });
  }

  async startAutoRun() {
    this.stopAutoRun();
    const token = ++this.runToken;
    this.isAutoRunning = true;

    const startBtn = document.getElementById('startAutoRunBtn');
    if (startBtn) startBtn.innerText = 'LOADING...';

    while (this.loadPromise) {
      const p = this.loadPromise;
      await p;
      if (this.loadPromise === p) break;
    }
    if (!this.isAutoRunning || token !== this.runToken) return;

    if (!this.scenarioData) {
      await this.loadScenario(this.currentScenario);
      // Note: loadScenario stops auto run; if it reloaded fresh, re-arm below only if needed
      if (!this.scenarioData) {
        this.stopAutoRun();
        return;
      }
      this.isAutoRunning = true;
      this.runToken = token;
    }

    this.resetScenarioView();

    if (startBtn) startBtn.innerText = 'PAUSE';

    const firstHasMore = this.step();
    if (!firstHasMore) {
      this.stopAutoRun();
      return;
    }

    this.autoRunInterval = setInterval(() => {
      const more = this.step();
      if (!more) {
        this.stopAutoRun();
      }
    }, 1800);
  }

  stopAutoRun(clearTimers = false) {
    if (this.autoRunInterval) {
      clearInterval(this.autoRunInterval);
      this.autoRunInterval = null;
    }
    this.isAutoRunning = false;
    this.runToken++;
    if (clearTimers) {
      this.clearStepTimers();
    }
    const startBtn = document.getElementById('startAutoRunBtn');
    if (startBtn) startBtn.innerText = 'START RUN';
  }

  resetScenarioView() {
    this.clearStepTimers();
    this.currentStep = 0;
    this.renderPairs();
  }

  replay() {
    this.stopAutoRun();
    this.resetScenarioView();
  }

  step() {
    if (!this.scenarioData || !this.scenarioData.pairs || this.scenarioData.pairs.length === 0) return false;
    const pairs = this.scenarioData.pairs;

    if (this.currentStep >= pairs.length) {
      this.resetScenarioView();
    }

    const idx = this.currentStep;
    const pair = pairs[idx];

    const atkCard = document.getElementById(`atkCard_${idx}`);
    const defCard = document.getElementById(`defCard_${idx}`);

    if (atkCard) atkCard.classList.add('active');
    if (defCard) defCard.classList.add('active');

    // Audio cue
    try { sound.blip(750 + idx * 90, 0.08); } catch (_) {}

    // Draw connecting bezier curve and re-align after 0.4s CSS translateX transition
    if (atkCard && defCard) {
      this.drawConnector(atkCard, defCard, pair.link_id);
      atkCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      defCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      const redrawTimer = setTimeout(() => this.redrawConnectors(), 420);
      this.transitionRedrawTimers.push(redrawTimer);
    }

    // Check if final step (blocked)
    if (idx === pairs.length - 1) {
      this.finalEffectTimer = setTimeout(() => {
        this.finalEffectTimer = null;
        if (atkCard) atkCard.classList.add('blocked-alert');
        if (defCard) defCard.classList.add('contained');

        const atkPanel = document.getElementById('attackerPanel');
        if (atkPanel) atkPanel.classList.add('glitch-active');

        try {
          sound.screenShake();
          sound.threatAlert();
          screenShake(8, 450);
        } catch (_) {}

        this.glitchRemoveTimer = setTimeout(() => {
          this.glitchRemoveTimer = null;
          if (atkPanel) atkPanel.classList.remove('glitch-active');
        }, 600);
      }, 500);
    }

    this.currentStep++;
    return this.currentStep < pairs.length;
  }

  drawConnector(atkEl, defEl, linkId) {
    const splitArea = document.getElementById('purpleSplitArea');
    const svg = document.getElementById('connectorSvg');
    if (!splitArea || !svg) return;

    const areaRect = splitArea.getBoundingClientRect();
    const atkRect = atkEl.getBoundingClientRect();
    const defRect = defEl.getBoundingClientRect();

    // Start point: right center of attacker card
    const x1 = atkRect.right - areaRect.left;
    const y1 = atkRect.top + atkRect.height / 2 - areaRect.top;

    // End point: left center of defender card
    const x2 = defRect.left - areaRect.left;
    const y2 = defRect.top + defRect.height / 2 - areaRect.top;

    // Bezier control points
    const dx = Math.abs(x2 - x1) * 0.5;
    const cx1 = x1 + dx;
    const cy1 = y1;
    const cx2 = x2 - dx;
    const cy2 = y2;

    const d = `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('class', 'connector-path');
    path.setAttribute('d', d);
    path.dataset.linkId = linkId;
    svg.appendChild(path);

    this.paths.push({ path, atkEl, defEl });
    this.redrawConnectors();
  }

  redrawConnectors() {
    const splitArea = document.getElementById('purpleSplitArea');
    if (!splitArea) return;
    const areaRect = splitArea.getBoundingClientRect();
    const atkScroll = document.getElementById('attackerLinesScroll');
    const defScroll = document.getElementById('defenderLinesScroll');
    const atkBounds = atkScroll ? atkScroll.getBoundingClientRect() : null;
    const defBounds = defScroll ? defScroll.getBoundingClientRect() : null;

    this.paths.forEach(({ path, atkEl, defEl }) => {
      const atkRect = atkEl.getBoundingClientRect();
      const defRect = defEl.getBoundingClientRect();

      const atkHidden = atkBounds && (atkRect.bottom <= atkBounds.top || atkRect.top >= atkBounds.bottom);
      const defHidden = defBounds && (defRect.bottom <= defBounds.top || defRect.top >= defBounds.bottom);
      path.style.opacity = (atkHidden || defHidden) ? '0' : '0.85';

      const x1 = atkRect.right - areaRect.left;
      const y1 = atkRect.top + atkRect.height / 2 - areaRect.top;
      const x2 = defRect.left - areaRect.left;
      const y2 = defRect.top + defRect.height / 2 - areaRect.top;

      const dx = Math.abs(x2 - x1) * 0.5;
      const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
      path.setAttribute('d', d);
    });
  }
}

function startPurpleController() {
  const purple = new PurpleTeamController();
  purple.init();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startPurpleController);
} else {
  startPurpleController();
}

/**
 * NO ENTRY - Watch SIEM & Threat Hunting Screen Controller (Screen 7)
 * Drives the real-time alert stream with state filters, slide-in inspection drawer,
 * automated IP block and host isolation, live-sorting Top Techniques bars,
 * threat hunt query evaluator with mini-histogram, and the live EPS waveform.
 */

import { initAppShell } from '../core/appShell.js';
import { wsClient } from '../core/ws.js';
import { api } from '../core/api.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class WatchController {
  constructor() {
    this.currentFilter = 'ALL';
    this.eventsCache = new Map();
    this.activeDrawerEventId = null;
    this.techniquesData = [
      { id: 'T1110', name: 'T1110 brute force', pct: 82, color: 'var(--color-red)' },
      { id: 'T1190', name: 'T1190 exploit public app', pct: 61, color: 'var(--color-cyan)' },
      { id: 'T1558', name: 'T1558 kerberoast', pct: 44, color: '#FFB800' },
      { id: 'T1071', name: 'T1071 dns tunnel', pct: 27, color: 'var(--color-green)' }
    ];
    this.epsHistory = new Array(40).fill(1.2);
    this.totalEventsCount = 1428;
  }

  async init() {
    initAppShell('watch');

    this.initWaveform();
    this.initFilterChips();
    this.initDrawer();
    this.initHuntPanel();
    this.renderTechniques();

    this.bindWebSocket();
    await this.loadInitialData();
  }

  initWaveform() {
    const canvas = document.getElementById('epsWaveformCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const draw = () => {
      requestAnimationFrame(draw);
      const w = canvas.width = canvas.clientWidth || 400;
      const h = canvas.height = canvas.clientHeight || 38;

      ctx.clearRect(0, 0, w, h);

      // Grid background line
      ctx.strokeStyle = 'rgba(26, 31, 41, 0.6)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, h / 2);
      ctx.lineTo(w, h / 2);
      ctx.stroke();

      // Waveform line
      const data = this.epsHistory;
      const step = w / (data.length - 1);
      const maxVal = Math.max(...data, 4.0);

      // Gradient Fill
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, 'rgba(0, 229, 255, 0.3)');
      grad.addColorStop(1, 'rgba(0, 229, 255, 0.0)');

      ctx.beginPath();
      ctx.moveTo(0, h);
      for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = h - (data[i] / maxVal) * (h - 6) - 3;
        ctx.lineTo(x, y);
      }
      ctx.lineTo(w, h);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // Cyan Trace
      ctx.beginPath();
      for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = h - (data[i] / maxVal) * (h - 6) - 3;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = '#00E5FF';
      ctx.lineWidth = 1.5;
      ctx.shadowColor = '#00E5FF';
      ctx.shadowBlur = 4;
      ctx.stroke();
      ctx.shadowBlur = 0;
    };
    draw();

    // Natural decay
    setInterval(() => {
      const last = this.epsHistory[this.epsHistory.length - 1];
      const target = 1.0 + Math.random() * 0.4;
      const next = last * 0.85 + target * 0.15;
      this.pushEps(next);
    }, 800);
  }

  pushEps(val) {
    this.epsHistory.push(val);
    if (this.epsHistory.length > 40) this.epsHistory.shift();
    const rateEl = document.getElementById('epsRateVal');
    if (rateEl) rateEl.innerText = val.toFixed(1);
  }

  initFilterChips() {
    const chips = document.querySelectorAll('.filter-chip');
    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        chips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        this.currentFilter = chip.dataset.filter;
        sound.keyClick();
        this.filterTableRows();
      });
    });
  }

  filterTableRows() {
    const rows = document.querySelectorAll('#watchAlertsTbody tr');
    rows.forEach(tr => {
      const state = tr.dataset.state || '';
      if (this.currentFilter === 'ALL' || state.toUpperCase() === this.currentFilter) {
        tr.style.display = '';
      } else {
        tr.style.display = 'none';
      }
    });
  }

  async loadInitialData() {
    try {
      const events = await api.get('/events?limit=35');
      if (Array.isArray(events)) {
        const tbody = document.getElementById('watchAlertsTbody');
        if (tbody) tbody.innerHTML = '';
        events.forEach(evt => {
          this.eventsCache.set(evt.id, evt);
          this.appendAlertRow(evt, false);
        });
      }
    } catch (err) {
      console.warn('Initial events load note:', err);
    }
  }

  bindWebSocket() {
    wsClient.on('message', (msg) => {
      if (!msg) return;

      if (msg.type === 'event') {
        const evt = msg.data;
        if (!evt) return;

        this.eventsCache.set(evt.id, evt);
        this.onNewEvent(evt);
      } else if (msg.type === 'metrics') {
        if (msg.data && msg.data.events_per_second) {
          this.pushEps(msg.data.events_per_second);
        }
      }
    });
  }

  onNewEvent(evt) {
    // 1. Spikes waveform
    const spike = evt.severity === 'CRITICAL' ? 3.8 : (evt.severity === 'HIGH' ? 2.8 : 1.8);
    this.pushEps(spike);

    // 2. Increment total processed
    this.totalEventsCount++;
    const totalEl = document.getElementById('totalEventsVal');
    if (totalEl) totalEl.innerText = this.totalEventsCount.toLocaleString();

    // 3. Play blip
    sound.blip(evt.state === 'BLOCKED' ? 1050 : 650, 0.06);

    // 4. Slide in row
    this.appendAlertRow(evt, true);

    // 5. Nudge technique percentages
    this.shiftTechniques(evt.technique_id);
  }

  appendAlertRow(evt, isNew = false) {
    const tbody = document.getElementById('watchAlertsTbody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    tr.className = 'stream-row';
    tr.dataset.eventId = evt.id;
    const state = (evt.state || 'DETECTED').toUpperCase();
    tr.dataset.state = state;

    let tagClass = 'tag--detected';
    if (state === 'BLOCKED') tagClass = 'tag--blocked';
    else if (state === 'ALERT') tagClass = 'tag--alert';
    else if (state === 'ISOLATED') tagClass = 'tag--isolated';

    tr.innerHTML = `
      <td style="color:var(--color-muted); font-size:11px;">${evt.time || 'NOW'}</td>
      <td><span class="badge" style="font-size:10px;">${evt.technique_id}</span></td>
      <td style="color:var(--color-text); font-size:12px; font-weight:500;">${evt.event}</td>
      <td style="font-family:var(--font-mono); font-size:11px; color:var(--color-cyan);">${evt.source_ip || '-'}</td>
      <td><span class="tag ${tagClass}">${state}</span></td>
    `;

    tr.addEventListener('click', () => this.openDrawer(evt.id));

    if (this.currentFilter !== 'ALL' && state !== this.currentFilter) {
      tr.style.display = 'none';
    }

    if (isNew) {
      tr.style.background = 'rgba(0, 229, 255, 0.28)';
      tr.style.transform = 'translateY(-10px)';
      tr.style.opacity = '0';
      tr.style.transition = 'all 0.3s ease';

      tbody.insertBefore(tr, tbody.firstChild);

      void tr.offsetWidth;
      tr.style.transform = 'translateY(0)';
      tr.style.opacity = '1';

      setTimeout(() => {
        tr.style.background = state === 'BLOCKED' ? 'rgba(0, 255, 106, 0.15)' : 'transparent';
        setTimeout(() => { tr.style.background = 'transparent'; }, 600);
      }, 350);

      while (tbody.children.length > 40) {
        tbody.removeChild(tbody.lastChild);
      }
    } else {
      tbody.appendChild(tr);
    }
  }

  renderTechniques() {
    const container = document.getElementById('techBarsContainer');
    if (!container) return;

    // Sort descending by percentage
    this.techniquesData.sort((a, b) => b.pct - a.pct);

    container.innerHTML = '';
    this.techniquesData.forEach(t => {
      const row = document.createElement('div');
      row.className = 'tech-bar-row';
      row.id = `techRow_${t.id}`;
      row.innerHTML = `
        <div class="tech-bar-label">
          <span>${t.name}</span>
          <span id="techVal_${t.id}" style="color:${t.color}; font-weight:700;">${t.pct}%</span>
        </div>
        <div class="tech-bar-track">
          <div id="techFill_${t.id}" class="tech-bar-fill" style="width:${t.pct}%; background:${t.color}; box-shadow:0 0 8px ${t.color};"></div>
        </div>
      `;
      container.appendChild(row);
    });
  }

  shiftTechniques(triggeredTechId) {
    let reRender = false;
    this.techniquesData.forEach(t => {
      if (t.id === triggeredTechId) {
        t.pct = Math.min(98, t.pct + 2);
        reRender = true;
      } else {
        if (Math.random() < 0.2) {
          t.pct = Math.max(15, t.pct - 1);
        }
      }
    });

    if (reRender) {
      this.renderTechniques();
    }
  }

  initDrawer() {
    const drawer = document.getElementById('slideDrawer');
    const closeBtn = document.getElementById('closeDrawerBtn');
    if (closeBtn && drawer) {
      closeBtn.addEventListener('click', () => {
        drawer.classList.remove('open');
        sound.keyClick();
      });
    }

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && drawer && drawer.classList.contains('open')) {
        drawer.classList.remove('open');
      }
    });

    // Wire Block IP & Isolate Host buttons
    const blockBtn = document.getElementById('drawerBlockIpBtn');
    const isolateBtn = document.getElementById('drawerIsolateHostBtn');

    if (blockBtn) {
      blockBtn.addEventListener('click', async () => {
        const evt = this.eventsCache.get(this.activeDrawerEventId);
        if (evt && evt.source_ip) {
          try {
            sound.threatAlert();
            await api.post('/block-ip', { ip: evt.source_ip, reason: 'Manual Watch drawer ban' });
            blockBtn.innerText = `BLOCKED: ${evt.source_ip}`;
            blockBtn.disabled = true;
            toast(`Perimeter firewall rule deployed: ${evt.source_ip} blocked`, 'danger');
          } catch (err) {
            toast(`Failed to block IP ${evt.source_ip}: ${err.message}`, 'danger');
          }
        }
      });
    }

    if (isolateBtn) {
      isolateBtn.addEventListener('click', async () => {
        const evt = this.eventsCache.get(this.activeDrawerEventId);
        if (evt && evt.target_host) {
          try {
            sound.threatAlert();
            await api.post(`/hosts/${evt.target_host}/isolate`);
            isolateBtn.innerText = `ISOLATED: ${evt.target_host}`;
            isolateBtn.disabled = true;
            toast(`Quarantine active: Host ${evt.target_host} isolated`, 'danger');
          } catch (err) {
            toast(`Failed to isolate ${evt.target_host}: ${err.message}`, 'danger');
          }
        }
      });
    }
  }

  async openDrawer(eventId) {
    const drawer = document.getElementById('slideDrawer');
    if (!drawer) return;

    this.activeDrawerEventId = eventId;
    sound.panelOpen();

    drawer.classList.add('open');

    // Default placeholder
    document.getElementById('drawerTitle').innerText = `EVENT // ${eventId}`;
    document.getElementById('drawerMitreTitle').innerText = 'Loading MITRE technique...';
    document.getElementById('drawerMitreDesc').innerText = 'Querying cyber catalog...';
    document.getElementById('drawerIntelScore').innerText = '...';
    document.getElementById('drawerIntelCountry').innerText = '';
    document.getElementById('drawerIntelIsp').innerText = '';
    document.getElementById('drawerRawJson').innerText = '// Fetching raw telemetry...';

    const blockBtn = document.getElementById('drawerBlockIpBtn');
    const isolateBtn = document.getElementById('drawerIsolateHostBtn');
    if (blockBtn) { blockBtn.disabled = false; blockBtn.innerText = 'BLOCK IP'; }
    if (isolateBtn) { isolateBtn.disabled = false; isolateBtn.innerText = 'ISOLATE HOST'; }

    try {
      const data = await api.get(`/events/${eventId}`);
      if (data) {
        const evt = data.event || {};
        const mitre = data.mitre_technique || {};
        const intel = data.enrichment || {};

        document.getElementById('drawerMitreTitle').innerText = `${mitre.id || evt.technique_id} : ${mitre.name || evt.technique_name}`;
        document.getElementById('drawerMitreDesc').innerText = mitre.description || evt.event;

        document.getElementById('drawerIntelScore').innerText = `${intel.abuse_confidence_score ?? 88}% THREAT`;
        document.getElementById('drawerIntelCountry').innerText = `${intel.country_name || 'Global'} (${intel.country_code || 'US'})`;
        document.getElementById('drawerIntelIsp').innerText = `ISP: ${intel.isp || 'Host Provider'} &bull; Usage: ${intel.usage_type || 'Datacenter'}`;

        document.getElementById('drawerRawJson').innerText = JSON.stringify(data.raw_log || evt, null, 2);
      }
    } catch (err) {
      console.warn('Event detail query fallback:', err);
      const cached = this.eventsCache.get(eventId);
      if (cached) {
        document.getElementById('drawerMitreTitle').innerText = `${cached.technique_id} : ${cached.technique_name}`;
        document.getElementById('drawerMitreDesc').innerText = cached.event;
        document.getElementById('drawerIntelScore').innerText = 'MALICIOUS DETECTED';
        document.getElementById('drawerIntelCountry').innerText = cached.source_ip;
        document.getElementById('drawerRawJson').innerText = JSON.stringify(cached, null, 2);
      } else {
        toast(`Could not load details for event ${eventId}: ${err.message}`, 'warning');
      }
    }
  }

  initHuntPanel() {
    const input = document.getElementById('huntQueryInput');
    const runBtn = document.getElementById('runHuntBtn');
    const presetBtns = document.querySelectorAll('.preset-btn');

    presetBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        if (input) input.value = btn.dataset.query;
        sound.keyClick();
        this.executeHunt(btn.dataset.query);
      });
    });

    if (runBtn && input) {
      runBtn.addEventListener('click', () => {
        sound.keyClick();
        this.executeHunt(input.value);
      });
    }
  }

  async executeHunt(queryStr) {
    const resultBox = document.getElementById('huntResultBox');
    const hitsText = document.getElementById('huntHitsText');
    const hypText = document.getElementById('huntHypothesisText');

    const cleanQuery = (queryStr || '').trim();
    if (!cleanQuery) {
      toast('Please enter a query or select a preset to hunt telemetry', 'info');
      return;
    }

    try {
      const res = await api.post('/hunt', { query: cleanQuery });
      if (res && resultBox) {
        resultBox.classList.add('active');
        if (hitsText) hitsText.innerText = `HITS: ${res.hits} in ${res.timeframe}`;
        if (hypText) hypText.innerText = `Hypothesis: ${res.hypothesis}`;

        this.renderMiniHistogram(res.histogram || []);
      }
    } catch (err) {
      console.error('Hunt execution error:', err);
      toast(`Hunt evaluation failed: ${err.message}`, 'danger');
      if (resultBox) {
        resultBox.classList.add('active');
        if (hitsText) hitsText.innerText = 'HITS: 0 (Error)';
        if (hypText) hypText.innerText = `Query Error: ${err.message}`;
      }
    }
  }

  renderMiniHistogram(histogram) {
    const canvas = document.getElementById('histogramCanvas');
    if (!canvas || !histogram.length) return;

    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.clientWidth || 140;
    const h = canvas.height = canvas.clientHeight || 32;

    ctx.clearRect(0, 0, w, h);

    const counts = histogram.map(b => b.count);
    const max = Math.max(...counts, 10);
    const barWidth = (w / histogram.length) - 2;

    histogram.forEach((bucket, i) => {
      const barHeight = (bucket.count / max) * (h - 4);
      const x = i * (barWidth + 2);
      const y = h - barHeight - 2;

      ctx.fillStyle = '#00E5FF';
      ctx.fillRect(x, y, barWidth, barHeight);
    });
  }
}

function startWatchController() {
  const watch = new WatchController();
  watch.init();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startWatchController);
} else {
  startWatchController();
}

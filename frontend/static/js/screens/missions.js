import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';
import { escapeHtml, toast, updateProgressBar } from '../core/ui.js';
import { sound } from '../core/sound.js';

const MODE_DESCRIPTIONS = {
  guided: 'HINTS ENABLED',
  challenge: '+25% XP // NO SAMPLES',
  free_play: 'OPEN SANDBOX LOOP',
};

const TRACK_DESCRIPTIONS = {
  purple: 'FULL LOOP (ATTACK -> DEFEND)',
  attacker: 'RED OPS EMPHASIS',
  defender: 'BLUE / SIGMA EMPHASIS',
};

let currentMode = sessionStorage.getItem('noentry_mission_mode') || 'guided';
let currentTrack = sessionStorage.getItem('noentry_mission_track') || 'purple';
let cachedCatalog = null;

function syncSwitchButtons() {
  document.querySelectorAll('#modeSwitchGroup .switch-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.mode === currentMode);
  });
  document.querySelectorAll('#trackSwitchGroup .switch-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.track === currentTrack);
  });
  const modeTag = document.getElementById('modeDescTag');
  const trackTag = document.getElementById('trackDescTag');
  if (modeTag) modeTag.textContent = MODE_DESCRIPTIONS[currentMode] || 'HINTS ENABLED';
  if (trackTag) trackTag.textContent = TRACK_DESCRIPTIONS[currentTrack] || 'FULL LOOP';
}

function attachCardTilt(card) {
  card.addEventListener('mousemove', (e) => {
    if (store.get('reduceMotion') || store.get('performanceMode')) return;
    const rect = card.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const px = (e.clientX - rect.left) / rect.width - 0.5;
    const py = (e.clientY - rect.top) / rect.height - 0.5;
    const rx = (-py * 8).toFixed(2);
    const ry = (px * 8).toFixed(2);
    card.style.transform = `perspective(900px) rotateX(${rx}deg) rotateY(${ry}deg) translateY(-2px)`;
  });
  card.addEventListener('mouseleave', () => {
    card.style.transform = '';
  });
}

function renderCatalog(data) {
  cachedCatalog = data;
  const banner = document.getElementById('ethicsGateBanner');
  const okPill = document.getElementById('ethicsStatusPill');
  const ethicsAccepted = Boolean(data.ethics_accepted);
  if (banner) banner.classList.toggle('visible', !ethicsAccepted);
  if (okPill) okPill.style.display = ethicsAccepted ? 'inline-block' : 'none';

  const clearedPct = Number(data.cleared_pct || 0);
  const clearedEl = document.getElementById('clearedPctVal');
  const countEl = document.getElementById('clearedCountVal');
  const rankEl = document.getElementById('userRankSummary');
  const barEl = document.getElementById('missionsProgressBar');

  if (clearedEl) clearedEl.textContent = `${clearedPct}%`;
  if (countEl) countEl.textContent = `${data.cleared_count || 0} / ${data.total_count || 5}`;
  if (rankEl && data.user) {
    rankEl.textContent = `${data.user.rank || 'SCRIPT RUNNER'} (${Number(data.user.xp || 0).toLocaleString()} XP)`;
  }
  if (barEl) updateProgressBar(barEl, clearedPct);

  const grid = document.getElementById('missionsGrid');
  if (!grid) return;

  const missions = Array.isArray(data.missions) ? data.missions : [];
  if (!missions.length) {
    grid.innerHTML = '<div style="font-family:var(--font-mono); color:var(--color-muted);">No missions registered in backend YAML catalog.</div>';
    return;
  }

  grid.innerHTML = missions
    .map((m) => {
      const status = String(m.status || 'NEW');
      const isDone = Boolean(m.completed) || status === 'DONE';
      const isLocked = status === 'LOCKED';
      const playableTag = m.playable ? 'INTERACTIVE LAB' : 'CINEMATIC BRIEF';
      const playableColor = m.playable ? 'var(--color-cyan)' : 'var(--color-muted)';
      const mitrePills = (m.mitre_ids || [])
        .map((id) => `<span class="mitre-pill">${escapeHtml(id)}</span>`)
        .join('');
      const launchHref = `/missions/${encodeURIComponent(m.id)}?mode=${encodeURIComponent(currentMode)}&track=${encodeURIComponent(currentTrack)}`;
      const btnLabel = isLocked
        ? 'LOCKED (ETHICS)'
        : m.playable
          ? isDone
            ? 'REPLAY OPERATION'
            : 'LAUNCH OPERATION'
          : 'WATCH WALKTHROUGH';
      const btnClass = isLocked ? 'btn btn-outline' : 'btn btn-red';

      return `
        <article class="mission-card ${isDone ? 'is-done' : ''}" data-mission-id="${escapeHtml(m.id)}">
          <div>
            <div class="mission-card-top">
              <span style="color:${playableColor};">OP-0${escapeHtml(String(m.order || ''))} // ${playableTag}</span>
              <span class="mission-status-tag ${escapeHtml(status)}">${escapeHtml(status)}</span>
            </div>
            <h3 class="mission-title">${escapeHtml(m.title)}</h3>
            <div class="mission-sub">${escapeHtml(m.subtitle || '')}</div>
            <p class="mission-desc">${escapeHtml(m.description || '')}</p>
          </div>

          <div>
            <div class="mission-meta-row" style="margin-bottom:10px;">
              <span class="mitre-pill" style="color:var(--color-yellow);">${escapeHtml(m.difficulty || 'MEDIUM')}</span>
              <span class="mitre-pill" style="color:var(--color-green);">+${escapeHtml(String(m.xp_reward || 0))} XP</span>
              ${mitrePills}
            </div>
            <div class="mission-footer">
              <span style="color:var(--color-muted);">TARGET: ${escapeHtml(m.target_ip || '10.10.x.x')}</span>
              <a href="${launchHref}" class="${btnClass}" data-launch-id="${escapeHtml(m.id)}" data-locked="${isLocked ? '1' : '0'}" style="padding:6px 12px; font-size:11px; text-decoration:none;">${btnLabel} &gt;</a>
            </div>
          </div>
        </article>
      `;
    })
    .join('');

  grid.querySelectorAll('.mission-card').forEach((card) => attachCardTilt(card));
  grid.querySelectorAll('a[data-launch-id]').forEach((link) => {
    link.addEventListener('click', (e) => {
      if (link.dataset.locked === '1') {
        e.preventDefault();
        sound.accessDenied();
        toast('Complete the Ethics Gate on /docs before starting attack missions.', 'warning');
        setTimeout(() => {
          window.location.href = '/docs#ethics';
        }, 450);
      }
    });
  });
}

async function loadMissions() {
  try {
    const data = await api.get('/missions');
    renderCatalog(data);
  } catch (err) {
    toast(err.message || 'Failed to load mission catalog', 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initAppShell('missions');
  syncSwitchButtons();

  document.querySelectorAll('#modeSwitchGroup .switch-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      currentMode = btn.dataset.mode || 'guided';
      sessionStorage.setItem('noentry_mission_mode', currentMode);
      syncSwitchButtons();
      if (cachedCatalog) renderCatalog(cachedCatalog);
    });
  });

  document.querySelectorAll('#trackSwitchGroup .switch-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      currentTrack = btn.dataset.track || 'purple';
      sessionStorage.setItem('noentry_mission_track', currentTrack);
      syncSwitchButtons();
      if (cachedCatalog) renderCatalog(cachedCatalog);
    });
  });

  loadMissions();
});

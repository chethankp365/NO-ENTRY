import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { glossaryDrawer } from '../core/glossaryDrawer.js';
import { escapeHtml, toast, updateProgressBar } from '../core/ui.js';

function renderRankAndStats(progressData) {
  const user = progressData.user || {};
  const stats = progressData.stats || {};
  const badges = Array.isArray(progressData.badges) ? progressData.badges : [];

  const titleEl = document.getElementById('learnRankTitle');
  const fracEl = document.getElementById('learnXpFraction');
  const nextEl = document.getElementById('nextRankTargetBadge');
  const barEl = document.getElementById('learnRankBar');
  const ladderEl = document.getElementById('rankLadderGrid');

  if (titleEl) titleEl.textContent = user.rank || 'SCRIPT RUNNER';
  if (fracEl) {
    const xpStr = Number(user.xp || 0).toLocaleString();
    const targetStr = Number(user.next_threshold || user.xp || 0).toLocaleString();
    fracEl.textContent = user.next_rank
      ? `${xpStr} / ${targetStr} XP`
      : `${xpStr} XP (MAX RANK)`;
  }
  if (nextEl) {
    nextEl.textContent = user.next_rank
      ? `${Number(user.xp_to_next || 0).toLocaleString()} XP TO ${user.next_rank}`
      : 'TOP CLEARANCE ACHIEVED';
  }
  if (barEl) {
    const pct = user.next_rank ? Number(user.tier_pct || user.progress_pct || 0) : 100;
    updateProgressBar(barEl, Math.min(100, Math.max(0, pct)));
  }

  if (ladderEl && Array.isArray(user.tiers)) {
    const currentXp = Number(user.xp || 0);
    ladderEl.innerHTML = user.tiers
      .map((t) => {
        const minXp = Number(t.min_xp ?? t.threshold ?? 0);
        const reached = currentXp >= minXp;
        return `
          <div class="ladder-tier ${reached ? 'reached' : ''}">
            <div style="color:${reached ? 'var(--color-cyan)' : 'var(--color-muted)'}; font-weight:700;">${escapeHtml(t.name || t.rank)}</div>
            <div style="color:var(--color-text); margin-top:2px;">${minXp.toLocaleString()} XP</div>
          </div>
        `;
      })
      .join('');
  }

  const streakEl = document.getElementById('learnStreakVal');
  const missionsEl = document.getElementById('learnMissionsVal');
  const badgesValEl = document.getElementById('learnBadgesVal');
  if (streakEl) streakEl.textContent = `${user.streak_days ?? 0}d`;
  if (missionsEl) missionsEl.textContent = `${stats.missions_cleared ?? 0}/${stats.total_missions ?? 5}`;
  if (badgesValEl) badgesValEl.textContent = `${stats.badges_unlocked ?? 0}/${stats.badges_total ?? badges.length}`;

  const badgesGrid = document.getElementById('learnBadgesGrid');
  if (badgesGrid) {
    badgesGrid.innerHTML = badges
      .map((b) => {
        const unlocked = Boolean(b.unlocked);
        return `
          <div class="badge-card ${unlocked ? 'unlocked' : ''}">
            <div class="badge-header">
              <span style="color:${unlocked ? 'var(--color-green)' : 'var(--color-muted)'};">[${escapeHtml(b.icon || '*')}] ${unlocked ? 'UNLOCKED' : 'LOCKED'}</span>
              <span style="color:var(--color-muted);">${unlocked && b.unlocked_at ? escapeHtml(String(b.unlocked_at).slice(0, 10)) : '--'}</span>
            </div>
            <div class="badge-name">${escapeHtml(b.name)}</div>
            <div style="font-size:11px; color:var(--color-muted); line-height:1.4;">${escapeHtml(b.description)}</div>
          </div>
        `;
      })
      .join('');
  }
}

function renderLeaderboard(boardData) {
  const tbody = document.getElementById('learnLeaderboardTbody');
  if (!tbody) return;
  const entries = Array.isArray(boardData.entries) ? boardData.entries : [];
  if (!entries.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--color-muted);">No operators recorded yet.</td></tr>';
    return;
  }

  tbody.innerHTML = entries
    .map((row) => `
      <tr class="${row.is_you ? 'is-you' : ''}">
        <td>#${escapeHtml(String(row.position))}</td>
        <td>${escapeHtml(row.operator_id)}${row.is_you ? ' <span style="color:var(--color-cyan);">(YOU)</span>' : ''}</td>
        <td>${escapeHtml(row.rank)}</td>
        <td>${escapeHtml(String(row.missions_cleared))}/5</td>
        <td>${escapeHtml(String(row.streak_days))}d</td>
        <td style="text-align:right; color:${row.is_you ? 'var(--color-green)' : 'var(--color-text)'};">${Number(row.xp || 0).toLocaleString()} XP</td>
      </tr>
    `)
    .join('');
}

function renderGlossaryPreview(glossaryData) {
  const container = document.getElementById('learnGlossaryCards');
  if (!container) return;
  const items = Array.isArray(glossaryData.items) ? glossaryData.items : [];
  container.innerHTML = items
    .map((item) => `
      <div class="glossary-mini-card">
        <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--color-cyan);">
          <strong>${escapeHtml(item.tool)}</strong>
          <span>${escapeHtml(item.category)}</span>
        </div>
        <div style="font-size:11px; color:var(--color-muted); margin-top:4px; line-height:1.4;">${escapeHtml(item.description)}</div>
        <pre>${escapeHtml(item.example || item.syntax)}</pre>
      </div>
    `)
    .join('');
}

async function initLearnPage() {
  try {
    const [progressData, boardData, glossaryData] = await Promise.all([
      api.get('/me/progress'),
      api.get('/leaderboard'),
      api.get('/learn/glossary'),
    ]);
    renderRankAndStats(progressData);
    renderLeaderboard(boardData);
    renderGlossaryPreview(glossaryData);
  } catch (err) {
    toast(err.message || 'Failed to load Learn telemetry', 'error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initAppShell('learn');
  const topBtn = document.getElementById('openGlossaryBtn');
  const bottomBtn = document.getElementById('openGlossaryBtnBottom');
  if (topBtn) topBtn.addEventListener('click', () => glossaryDrawer.open());
  if (bottomBtn) bottomBtn.addEventListener('click', () => glossaryDrawer.open());
  initLearnPage();
});


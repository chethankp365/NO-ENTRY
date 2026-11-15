import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';
import { glossaryDrawer } from '../core/glossaryDrawer.js';
import { escapeHtml, toast } from '../core/ui.js';
import { sound } from '../core/sound.js';

const STAGES = [
  'briefing',
  'attacker',
  'flag',
  'side_switch',
  'defender',
  'fix',
  'verify',
  'debrief',
];

const STAGE_PANEL_IDS = {
  briefing: 'stageBriefing',
  attacker: 'stageAttacker',
  flag: 'stageFlag',
  side_switch: 'stageSideSwitch',
  defender: 'stageDefender',
  fix: 'stageFix',
  verify: 'stageVerify',
  debrief: 'stageDebrief',
};

const state = {
  missionId: '',
  mode: 'guided',
  track: 'purple',
  mission: null,
  progress: null,
  user: null,
  logs: [],
  activeStage: 'briefing',
  selectedLogIdx: -1,
  matchedIndices: new Set(),
  selectedFixOptionId: null,
  term: null,
  termInputBuffer: '',
  timerInterval: null,
  elapsedSec: 0,
  cineTimer: null,
  cineIdx: -1,
  lastQuizResults: null,
};

function queryParam(name) {
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch (_) {
    return null;
  }
}

function formatDuration(sec) {
  const s = Math.max(0, Math.floor(Number(sec || 0)));
  const mins = String(Math.floor(s / 60)).padStart(2, '0');
  const rem = String(s % 60).padStart(2, '0');
  return `${mins}:${rem}`;
}

function isStageUnlocked(targetStage) {
  if (!state.progress || !state.mission) return targetStage === 'briefing';
  if (state.progress.completed) return true;
  if (state.progress.mode === 'free_play') return true;
  const maxStage = state.progress.stage || 'briefing';
  const targetIdx = STAGES.indexOf(targetStage);
  const maxIdx = STAGES.indexOf(maxStage);
  return targetIdx <= Math.max(0, maxIdx);
}

function updateTopTelemetry() {
  const m = state.mission;
  const p = state.progress;
  const u = state.user;
  if (!m || !p || !u) return;

  const titleEl = document.getElementById('mpMissionTitle');
  const metaEl = document.getElementById('mpMissionMeta');
  const xpEl = document.getElementById('mpXpVal');
  const hintsEl = document.getElementById('mpHintsVal');
  const modeTag = document.getElementById('mpModeTrackTag');

  if (titleEl) titleEl.textContent = m.title;
  if (metaEl) {
    metaEl.textContent = `OP-0${m.order} // ${m.difficulty} // TARGET: ${m.target_host} (${m.target_ip})`;
  }
  if (xpEl) xpEl.textContent = Number(u.xp || 0).toLocaleString();
  if (hintsEl) hintsEl.textContent = String(p.hints_used || 0);
  if (modeTag) {
    modeTag.textContent = `${(p.mode || state.mode).toUpperCase()} // ${(p.track || state.track).toUpperCase()}`;
  }

  state.elapsedSec = Math.floor(Number(p.elapsed_sec || 0));
  const timerEl = document.getElementById('mpTimerVal');
  if (timerEl) timerEl.textContent = formatDuration(state.elapsedSec);
}

function startTimerLoop() {
  if (state.timerInterval) clearInterval(state.timerInterval);
  state.timerInterval = setInterval(() => {
    const p = state.progress;
    if (!p || p.stage === 'briefing' || p.completed) return;
    state.elapsedSec += 1;
    const timerEl = document.getElementById('mpTimerVal');
    if (timerEl) timerEl.textContent = formatDuration(state.elapsedSec);
  }, 1000);
}

function renderStepper() {
  const buttons = document.querySelectorAll('#mpStepper .mp-step-node');
  const activeIdx = STAGES.indexOf(state.activeStage);
  const progressIdx = STAGES.indexOf(state.progress?.stage || 'briefing');

  buttons.forEach((btn) => {
    const stageKey = btn.dataset.stage;
    const idx = STAGES.indexOf(stageKey);
    const unlocked = isStageUnlocked(stageKey);
    const isActive = stageKey === state.activeStage;
    const isDone = Boolean(state.progress?.completed) || idx < Math.max(activeIdx, progressIdx);

    btn.disabled = !unlocked;
    btn.classList.toggle('is-active', isActive);
    btn.classList.toggle('is-done', !isActive && isDone);
    btn.classList.toggle(
      'is-defender',
      isActive && (stageKey === 'side_switch' || stageKey === 'defender' || stageKey === 'fix')
    );
    btn.classList.toggle(
      'is-verified',
      isActive && (stageKey === 'verify' || stageKey === 'debrief')
    );
  });
}

function setActiveStage(stageKey) {
  if (!STAGE_PANEL_IDS[stageKey]) return;
  state.activeStage = stageKey;

  Object.entries(STAGE_PANEL_IDS).forEach(([key, panelId]) => {
    const el = document.getElementById(panelId);
    if (el) el.classList.toggle('is-visible', key === stageKey);
  });

  renderStepper();

  if (stageKey === 'attacker') {
    ensureTerminalInitialized();
    renderAttackerPhase();
  } else if (stageKey === 'defender') {
    renderDefenderPhase();
  } else if (stageKey === 'fix') {
    renderFixPhase();
  } else if (stageKey === 'verify') {
    renderVerifyPhase();
  } else if (stageKey === 'debrief') {
    renderDebriefPhase();
  }
}

/* ---------------- STAGE 1: BRIEFING & CINEMATIC ---------------- */

function renderBriefingStage() {
  const m = state.mission;
  if (!m) return;

  const termEl = document.getElementById('briefingTypewriter');
  const storyEl = document.getElementById('briefingStoryBox');
  const scopeEl = document.getElementById('briefingScope');
  const diffEl = document.getElementById('briefingDifficultyTag');
  const cinePanel = document.getElementById('cinematicWalkthroughPanel');
  const startBtn = document.getElementById('startMissionBtn');

  if (diffEl) diffEl.textContent = `${m.difficulty} // +${m.xp_reward} XP`;
  if (storyEl) storyEl.textContent = m.story || '';
  if (scopeEl) scopeEl.textContent = m.scope || '';

  if (termEl) {
    const lines = Array.isArray(m.briefing_lines) ? m.briefing_lines : [];
    termEl.innerHTML = lines
      .map((line) => `<div class="briefing-line">&gt; ${escapeHtml(line)}</div>`)
      .join('');
  }

  if (m.playable) {
    if (cinePanel) cinePanel.style.display = 'none';
    if (startBtn) {
      startBtn.style.display = 'inline-flex';
      startBtn.textContent =
        state.progress && state.progress.stage !== 'briefing'
          ? 'RESUME OPERATION ->'
          : 'START OPERATION';
    }
  } else {
    if (startBtn) startBtn.style.display = 'none';
    if (cinePanel) cinePanel.style.display = 'block';
    renderCinematicWalkthrough();
  }
}

function renderCinematicWalkthrough() {
  const listEl = document.getElementById('cineStepList');
  if (!listEl || !state.mission) return;
  const beats = Array.isArray(state.mission.cinematic_walkthrough)
    ? state.mission.cinematic_walkthrough
    : [];

  listEl.innerHTML = beats
    .map((beat, idx) => {
      const cls =
        idx === state.cineIdx ? 'is-current' : idx < state.cineIdx ? 'is-done' : '';
      const mitreTag = beat.mitre_id ? ` [${escapeHtml(beat.mitre_id)}]` : '';
      return `
        <div class="cine-entry ${cls}" data-cine-idx="${idx}">
          <div style="color:var(--color-cyan); font-weight:700;">
            [${escapeHtml(beat.phase || 'OP')}] ${escapeHtml(beat.speaker || 'SYSTEM')}${mitreTag}
          </div>
          <div style="margin-top:4px; color:#FFFFFF;">${escapeHtml(beat.text || '')}</div>
        </div>
      `;
    })
    .join('');

  if (state.cineIdx >= 0) {
    const cur = listEl.querySelector(`.cine-entry[data-cine-idx="${state.cineIdx}"]`);
    cur?.scrollIntoView({ block: 'nearest' });
  }
}

function advanceCinematicBeat() {
  const beats = state.mission?.cinematic_walkthrough || [];
  if (state.cineIdx + 1 >= beats.length) {
    if (state.cineTimer) {
      clearInterval(state.cineTimer);
      state.cineTimer = null;
    }
    toast('Walkthrough playback complete. Click COMPLETE BRIEFING to record XP & open Quiz.', 'success');
    return false;
  }
  state.cineIdx += 1;
  renderCinematicWalkthrough();
  sound.blip(680, 0.04);
  return true;
}

async function handleStartMissionClick() {
  const btn = document.getElementById('startMissionBtn');
  const cdBadge = document.getElementById('startCountdownBadge');

  if (state.progress && state.progress.stage !== 'briefing') {
    setActiveStage(state.progress.stage);
    return;
  }

  if (btn) btn.disabled = true;

  if (!store.get('reduceMotion') && cdBadge) {
    cdBadge.style.display = 'inline-block';
    for (const sec of ['3', '2', '1']) {
      cdBadge.textContent = `LAUNCHING IN ${sec}...`;
      sound.blip(880, 0.05);
      await new Promise((r) => setTimeout(r, 220));
    }
    cdBadge.style.display = 'none';
  }

  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/start`, {
      mode: state.mode,
      track: state.track,
    });
    state.progress = res.progress;
    if (Array.isArray(res.logs)) state.logs = res.logs;
    updateTopTelemetry();
    sound.accessGranted();
    setActiveStage(res.progress.stage || 'attacker');
  } catch (err) {
    const blockCard = document.getElementById('mpEthicsBlockCard');
    if (String(err.message || '').toLowerCase().includes('ethics') && blockCard) {
      blockCard.style.display = 'block';
    }
    sound.accessDenied();
    toast(err.message || 'Unable to start operation', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------------- STAGE 2: ATTACKER PHASE ---------------- */

function writeTermLine(text, colorCode = '') {
  if (!state.term) return;
  const reset = '\x1b[0m';
  const safeText = String(text ?? '');
  if (colorCode) {
    state.term.writeln(`${colorCode}${safeText}${reset}`);
  } else {
    state.term.writeln(safeText);
  }
}

function writePrompt() {
  if (!state.term) return;
  state.term.write('\r\n\x1b[31mroot@kali-lab\x1b[0m:\x1b[36m~/ops\x1b[0m# ');
}

function ensureTerminalInitialized() {
  if (state.term) return;
  const container = document.getElementById('mpTerminalContainer');
  if (!container || typeof window.Terminal !== 'function') return;

  const term = new window.Terminal({
    cursorBlink: true,
    convertEol: true,
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 12,
    rows: 17,
    theme: {
      background: '#020306',
      foreground: '#D7E2EC',
      cursor: '#FF1F3D',
      selectionBackground: 'rgba(0, 229, 255, 0.28)',
    },
  });

  term.open(container);
  state.term = term;

  writeTermLine(`NO ENTRY KALI RANGE SHELL // TARGET ${state.mission?.target_ip || ''}`, '\x1b[36m');
  writeTermLine('Type commands directly here or use the command input bar below.', '\x1b[90m');
  writePrompt();

  term.onData((chunk) => {
    for (let i = 0; i < chunk.length; i += 1) {
      const ch = chunk[i];
      const code = ch.charCodeAt(0);
      if (ch === '\r') {
        const cmd = state.termInputBuffer.trim();
        state.termInputBuffer = '';
        term.write('\r\n');
        if (cmd) {
          submitTerminalCommand(cmd, true);
        } else {
          writePrompt();
        }
      } else if (code === 127 || ch === '\b') {
        if (state.termInputBuffer.length > 0) {
          state.termInputBuffer = state.termInputBuffer.slice(0, -1);
          term.write('\b \b');
        }
      } else if (code >= 32 && code < 127) {
        state.termInputBuffer += ch;
        term.write(ch);
      }
    }
  });
}

function renderAttackerPhase() {
  const m = state.mission;
  const p = state.progress;
  if (!m || !p) return;

  const steps = Array.isArray(m.steps) ? m.steps : [];
  const completedSet = new Set(p.completed_steps || []);
  const currentIdx = Math.min(Number(p.current_step_idx || 0), Math.max(0, steps.length - 1));

  const counterEl = document.getElementById('attackerStepCounter');
  if (counterEl) {
    counterEl.textContent = `STEP ${Math.min(completedSet.size + 1, steps.length)} / ${steps.length}`;
  }

  const targetIpEl = document.getElementById('kaliTargetIp');
  if (targetIpEl) targetIpEl.textContent = `TARGET: ${m.target_ip}`;

  const sampleBtn = document.getElementById('sampleCmdBtn');
  const activeStep = steps[currentIdx];
  if (sampleBtn) {
    const canShowSample =
      (p.mode || state.mode) === 'guided' && activeStep && activeStep.sample_hint_command;
    sampleBtn.style.display = canShowSample ? 'inline-block' : 'none';
    sampleBtn.onclick = () => {
      const quickInput = document.getElementById('kaliQuickInput');
      if (quickInput && activeStep?.sample_hint_command) {
        quickInput.value = activeStep.sample_hint_command;
        quickInput.focus();
      }
    };
  }

  const listEl = document.getElementById('attackerStepsList');
  if (listEl) {
    const hintsMap = p.hints_unlocked || {};
    listEl.innerHTML = steps
      .map((s, idx) => {
        const done = completedSet.has(s.id) || s.completed;
        const isCurrent = !done && idx === currentIdx;
        const unlockedObj = hintsMap[String(idx)] || s.unlocked_hints || {};
        const costs = s.hint_costs || { 1: 15, 2: 35, 3: 75 };

        const hintButtons = [1, 2, 3]
          .map((lvl) => {
            const unlocked = Boolean(unlockedObj[String(lvl)]);
            const labelMap = { 1: 'NUDGE', 2: 'DIR', 3: 'ANS' };
            const costVal = costs[String(lvl)] ?? costs[lvl] ?? 0;
            return `<button type="button" class="hint-btn ${unlocked ? 'is-unlocked' : ''}" data-hint-step="${idx}" data-hint-level="${lvl}">L${lvl} ${labelMap[lvl]} (-${costVal} XP)</button>`;
          })
          .join('');

        const unlockedHtml = Object.entries(unlockedObj)
          .sort((a, b) => Number(a[0]) - Number(b[0]))
          .map(
            ([lvl, text]) =>
              `<div class="hint-reveal-item"><strong>[L${escapeHtml(lvl)}]</strong> ${escapeHtml(text)}</div>`
          )
          .join('');

        return `
          <div class="step-card-item ${done ? 'is-completed' : isCurrent ? 'is-current' : ''}">
            <div class="step-item-head">
              <span>${done ? '[DONE]' : isCurrent ? '[ACTIVE]' : '[NEXT]'} 0${s.order}. ${escapeHtml(s.title)}</span>
              <span style="color:var(--color-cyan);">${escapeHtml(s.tool)} // ${escapeHtml(s.mitre_id)}</span>
            </div>
            <div class="step-item-goal">${escapeHtml(s.goal)}</div>
            <div class="hint-bar">${hintButtons}</div>
            ${unlockedHtml ? `<div class="hint-output-list">${unlockedHtml}</div>` : ''}
          </div>
        `;
      })
      .join('');

    listEl.querySelectorAll('.hint-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        requestStepHint(Number(btn.dataset.hintStep), Number(btn.dataset.hintLevel));
      });
    });
  }

  const shopBox = document.getElementById('voltgearShopBox');
  const shopHeader = document.getElementById('voltgearTargetHeader');
  if (shopHeader && m.target_ip) {
    shopHeader.textContent = `VOLTGEAR STOREFRONT // ${m.target_ip}`;
  }
  if (shopBox) {
    shopBox.style.display = m.has_shop_widget ? 'block' : 'none';
  }

  const allDone = completedSet.size >= steps.length && steps.length > 0;
  const doneBanner = document.getElementById('attackerCompleteBanner');
  if (doneBanner) {
    doneBanner.style.display = allDone || isStageUnlocked('flag') ? 'block' : 'none';
  }
}

async function requestStepHint(stepIdx, level) {
  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/hint`, {
      step_idx: stepIdx,
      level,
    });
    state.progress = res.progress;
    if (state.user && typeof res.remaining_xp === 'number') {
      state.user.xp = res.remaining_xp;
    }
    updateTopTelemetry();
    renderAttackerPhase();
    sound.blip(520, 0.05);
    if (!res.already_unlocked && res.xp_cost > 0) {
      toast(`Hint L${level} unlocked (-${res.xp_cost} XP)`, 'warning');
    }
  } catch (err) {
    toast(err.message || 'Unable to unlock hint', 'error');
  }
}

async function submitTerminalCommand(command, fromXterm = false) {
  const cmd = String(command || '').trim();
  if (!cmd) return;

  ensureTerminalInitialized();
  if (!fromXterm) {
    state.term?.writeln(cmd);
  }

  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/command`, {
      command: cmd,
      step_idx: state.progress?.current_step_idx ?? 0,
    });

    const lines = Array.isArray(res.output_lines) ? res.output_lines : [];
    const color = res.matched ? '\x1b[32m' : '\x1b[33m';
    lines.forEach((line) => writeTermLine(line, line.startsWith('NOENTRY{') ? '\x1b[92m' : color));
    if (!res.matched && res.hint) {
      writeTermLine(`[HINT] ${res.hint}`, '\x1b[33m');
    }
    writePrompt();

    if (res.shop_response) {
      const shopOut = document.getElementById('shopResultOutput');
      if (shopOut) {
        const sr = res.shop_response;
        if (typeof sr === 'string') {
          shopOut.textContent = sr;
        } else if (Array.isArray(sr.leaked_rows)) {
          shopOut.textContent = sr.leaked_rows
            .map((r) => `[ROW #${r.id}] ${r.name} -> ${r.detail}`)
            .join('\n');
        } else if (sr.flag) {
          shopOut.textContent = `FLAG RECOVERED: ${sr.flag}`;
        } else {
          shopOut.textContent = sr.note
            ? `[AUTH ${sr.authenticated ? 'BYPASSED' : 'CHECK'}] user=${sr.user || '-'} // ${sr.note}`
            : JSON.stringify(sr, null, 2);
        }
      }
    }

    if (res.progress) state.progress = res.progress;
    updateTopTelemetry();
    renderStepper();
    renderAttackerPhase();

    if (res.step_completed) {
      sound.accessGranted();
      toast(`Step complete (${res.mitre_id || 'MITRE'})`, 'success');
    } else if (res.matched) {
      sound.blip(780, 0.04);
    } else {
      sound.keyClick();
    }

    if (res.all_steps_done) {
      toast('All attack objectives complete! Proceed to Flag Capture.', 'success');
    }
  } catch (err) {
    writeTermLine(`[ERROR] ${err.message || 'Command failed'}`, '\x1b[31m');
    writePrompt();
    toast(err.message || 'Command error', 'error');
  }
}

/* ---------------- STAGE 3: FLAG CAPTURE ---------------- */

function triggerFlagParticles() {
  if (store.get('reduceMotion') || store.get('performanceMode')) return;
  const canvas = document.getElementById('flagParticleCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  canvas.width = canvas.offsetWidth || 640;
  canvas.height = canvas.offsetHeight || 260;
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const particles = Array.from({ length: 42 }, (_, i) => {
    const angle = (Math.PI * 2 * i) / 42 + Math.random() * 0.2;
    const speed = 2 + Math.random() * 5;
    return {
      x: cx,
      y: cy,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      life: 1,
      color: i % 2 === 0 ? '#00FF6A' : '#00E5FF',
    };
  });

  function frame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    let alive = false;
    particles.forEach((p) => {
      p.x += p.vx;
      p.y += p.vy;
      p.life -= 0.028;
      if (p.life > 0) {
        alive = true;
        ctx.globalAlpha = Math.max(0, p.life);
        ctx.fillStyle = p.color;
        ctx.fillRect(p.x, p.y, 4, 4);
      }
    });
    ctx.globalAlpha = 1;
    if (alive) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

async function handleFlagSubmit(e) {
  e.preventDefault();
  const input = document.getElementById('flagInput');
  const feedback = document.getElementById('flagFeedbackBanner');
  const lockWrap = document.getElementById('flagLockWrap');
  const lockSvg = document.getElementById('flagLockSvg');
  const submitBtn = document.getElementById('flagSubmitBtn');

  const flagVal = (input?.value || '').trim();
  if (!flagVal) {
    toast('Enter the captured NOENTRY{...} flag first.', 'warning');
    return;
  }

  if (submitBtn) submitBtn.disabled = true;
  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/flag`, {
      flag: flagVal,
    });
    if (res.progress) state.progress = res.progress;
    if (state.user && typeof res.remaining_xp === 'number') state.user.xp = res.remaining_xp;
    updateTopTelemetry();

    if (res.correct) {
      sound.accessGranted();
      lockWrap?.classList.add('is-unlocked');
      if (lockSvg) lockSvg.style.color = 'var(--color-green)';
      if (feedback) {
        feedback.style.color = 'var(--color-green)';
        feedback.textContent = `FLAG CAPTURED // +${res.xp_awarded || 0} XP`;
      }
      triggerFlagParticles();
      (res.newly_unlocked_badges || []).forEach((b) =>
        toast(`Badge unlocked: ${b.name}`, 'success')
      );
      await triggerSideSwitchTransition();
    } else {
      sound.accessDenied();
      if (feedback) {
        feedback.style.color = 'var(--color-red)';
        feedback.textContent = res.message || 'Incorrect flag token.';
      }
    }
  } catch (err) {
    toast(err.message || 'Flag verification failed', 'error');
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

/* ---------------- STAGE 4: SIDE SWITCH ---------------- */

async function triggerSideSwitchTransition() {
  const overlay = document.getElementById('sideSwitchOverlay');
  if (overlay && !store.get('reduceMotion')) {
    overlay.classList.add('is-active');
    sound.glitchCrackle();
  }

  try {
    const logRes = await api.post(`/missions/${encodeURIComponent(state.missionId)}/logs`);
    if (Array.isArray(logRes.logs)) state.logs = logRes.logs;
    if (logRes.progress) state.progress = logRes.progress;
  } catch (_) {}

  const waitMs = store.get('reduceMotion') ? 120 : 1200;
  await new Promise((r) => setTimeout(r, waitMs));
  overlay?.classList.remove('is-active');

  setActiveStage('defender');
}

/* ---------------- STAGE 5: DEFENDER & SIGMA EDITOR ---------------- */

function highlightSigmaYaml(raw) {
  const lines = String(raw || '').split('\n');
  return lines
    .map((line) => {
      const escaped = escapeHtml(line);
      if (/^\s*#/.test(line)) {
        return `<span class="tok-comment">${escaped}</span>`;
      }
      const keyMatch = escaped.match(/^(\s*)([A-Za-z0-9_|.-]+)(:)(.*)$/);
      if (keyMatch) {
        const [, indent, key, colon, rest] = keyMatch;
        return `${indent}<span class="tok-key">${key}</span>${colon}<span class="tok-str">${rest}</span>`;
      }
      const listMatch = escaped.match(/^(\s*-\s+)(.*)$/);
      if (listMatch) {
        const [, dash, rest] = listMatch;
        return `<span class="tok-list">${dash}</span><span class="tok-str">${rest}</span>`;
      }
      return escaped;
    })
    .join('\n');
}

function syncSigmaHighlight() {
  const textarea = document.getElementById('ruleYamlTextarea');
  const pre = document.getElementById('ruleHighlightPre');
  if (!textarea || !pre) return;
  pre.innerHTML = `${highlightSigmaYaml(textarea.value)}\n`;
  pre.scrollTop = textarea.scrollTop;
  pre.scrollLeft = textarea.scrollLeft;
}

function renderLogsStream() {
  const container = document.getElementById('defenderLogsContainer');
  const countEl = document.getElementById('defenderLogsCount');
  if (!container) return;

  const logs = Array.isArray(state.logs) ? state.logs : [];
  if (countEl) countEl.textContent = `${logs.length} EVENTS`;

  if (!logs.length) {
    container.innerHTML = '<div style="padding:10px; color:var(--color-muted);">No telemetry logs generated yet.</div>';
    return;
  }

  container.innerHTML = logs
    .map((entry, i) => {
      const idx = entry.index ?? i;
      const isSelected = idx === state.selectedLogIdx;
      const isMatched = state.matchedIndices.has(idx);
      return `
        <div class="log-row ${isSelected ? 'is-selected' : ''} ${isMatched ? 'is-matched' : ''}" data-log-idx="${idx}">
          ${isMatched ? '<span style="color:var(--color-green);">[MATCH]</span> ' : ''}${escapeHtml(entry.raw_line || '')}
        </div>
      `;
    })
    .join('');

  container.querySelectorAll('.log-row').forEach((row) => {
    row.addEventListener('click', () => {
      state.selectedLogIdx = Number(row.dataset.logIdx);
      const entry = logs.find((l, idx) => (l.index ?? idx) === state.selectedLogIdx);
      const insp = document.getElementById('logInspectorBox');
      if (insp && entry) {
        const struct = entry.structured || {};
        insp.innerHTML = `
          <div style="color:var(--color-cyan);">SOURCE: ${escapeHtml(entry.source || 'log')} // IP: ${escapeHtml(entry.source_ip || '-')} // HOST: ${escapeHtml(entry.target_host || '-')} // TAG: ${escapeHtml(entry.technique_id || '-')}</div>
          <div style="color:#FFFFFF; margin-top:4px; word-break:break-all;">${escapeHtml(JSON.stringify(struct))}</div>
        `;
      }
      renderLogsStream();
    });
  });
}

function renderDefenderPhase() {
  const rc = state.mission?.rule_challenge;
  if (!rc) return;

  renderLogsStream();

  const promptEl = document.getElementById('rulePromptText');
  if (promptEl) promptEl.textContent = rc.prompt || '';

  const selectEl = document.getElementById('mitreSelect');
  if (selectEl && !selectEl.dataset.populated) {
    selectEl.dataset.populated = '1';
    selectEl.innerHTML = (rc.mitre_choices || [])
      .map(
        (c) => `<option value="${escapeHtml(c.id)}">${escapeHtml(c.id)} // ${escapeHtml(c.label)}</option>`
      )
      .join('');
    if (state.progress?.selected_mitre_id) {
      selectEl.value = state.progress.selected_mitre_id;
    }
  }

  const textarea = document.getElementById('ruleYamlTextarea');
  if (textarea && !textarea.value.trim()) {
    textarea.value = rc.template_yaml || '';
  }
  syncSigmaHighlight();

  const gotoFix = document.getElementById('gotoFixBtn');
  if (gotoFix) {
    gotoFix.style.display = state.progress?.rule_passed ? 'inline-flex' : 'none';
  }
}

async function handleTestRuleClick() {
  const textarea = document.getElementById('ruleYamlTextarea');
  const mitreEl = document.getElementById('mitreSelect');
  const gradePanel = document.getElementById('ruleGradePanel');
  const gotoFixBtn = document.getElementById('gotoFixBtn');
  const btn = document.getElementById('testRuleBtn');

  if (!textarea) return;
  if (btn) btn.disabled = true;

  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/rule/test`, {
      rule_yaml: textarea.value,
      selected_mitre_id: mitreEl?.value || undefined,
    });

    state.matchedIndices = new Set(res.matched_indices || []);
    if (res.progress) state.progress = res.progress;
    updateTopTelemetry();
    renderStepper();
    renderLogsStream();

    if (gradePanel) {
      const fpPreview = (res.false_positive_lines || [])
        .slice(0, 2)
        .map((l) => `<div style="color:var(--color-red); margin-top:4px;">FP: ${escapeHtml(l)}</div>`)
        .join('');
      gradePanel.style.borderColor = res.passed ? 'var(--color-green)' : 'var(--color-red)';
      gradePanel.innerHTML = `
        <div style="color:${res.passed ? 'var(--color-green)' : 'var(--color-amber)'}; font-weight:700;">
          GRADE: ${escapeHtml(res.grade || '')} // RULE FIRES: ${res.rule_fires ? 'YES' : 'NO'} // FALSE POSITIVES: ${res.false_positives_count ?? 0} // MITRE: ${res.mitre_correct ? 'MATCH' : 'MISMATCH'}
        </div>
        <div style="color:var(--color-text); margin-top:4px;">${escapeHtml(res.message || '')}</div>
        ${fpPreview}
      `;
    }

    if (res.passed) {
      sound.accessGranted();
      if (gotoFixBtn) gotoFixBtn.style.display = 'inline-flex';
      (res.newly_unlocked_badges || []).forEach((b) =>
        toast(`Badge unlocked: ${b.name}`, 'success')
      );
      toast('Detection rule passed with zero false positives!', 'success');
    } else {
      sound.accessDenied();
      toast(res.grade || 'Rule check failed', 'warning');
    }
  } catch (err) {
    toast(err.message || 'Sigma evaluation error', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------------- STAGE 6: FIX ---------------- */

function renderFixPhase() {
  const fix = state.mission?.fix;
  if (!fix) return;

  const promptEl = document.getElementById('fixPromptText');
  const vulnEl = document.getElementById('vulnerableCodePre');
  const optsEl = document.getElementById('fixOptionsContainer');
  const customBox = document.getElementById('fixCustomBox');

  if (promptEl) promptEl.textContent = fix.prompt || '';
  if (vulnEl) vulnEl.textContent = fix.vulnerable_code || '';
  if (customBox) customBox.style.display = fix.supports_custom_patch ? 'block' : 'none';

  if (optsEl) {
    if (!state.selectedFixOptionId && state.progress?.fix_choice_id) {
      state.selectedFixOptionId = state.progress.fix_choice_id;
    }
    optsEl.innerHTML = (fix.options || [])
      .map((opt) => {
        const selected = opt.id === state.selectedFixOptionId;
        return `
          <div class="fix-option-card ${selected ? 'is-selected' : ''}" data-fix-id="${escapeHtml(opt.id)}">
            <div style="font-family:var(--font-mono); font-size:12px; font-weight:700; color:${selected ? 'var(--color-cyan)' : '#FFFFFF'};">
              ${selected ? '[SELECTED] ' : ''}${escapeHtml(opt.label)}
            </div>
            <pre class="code-block-pre">${escapeHtml(opt.code_snippet)}</pre>
          </div>
        `;
      })
      .join('');

    optsEl.querySelectorAll('.fix-option-card').forEach((card) => {
      card.addEventListener('click', () => {
        state.selectedFixOptionId = card.dataset.fixId;
        renderFixPhase();
      });
    });
  }
}

async function handleApplyFixClick() {
  const customPatch = document.getElementById('fixPatchTextarea')?.value?.trim() || '';
  const feedback = document.getElementById('fixFeedbackBanner');
  const btn = document.getElementById('applyFixBtn');

  if (!customPatch && !state.selectedFixOptionId) {
    toast('Select one remediation option card or write a custom patch.', 'warning');
    return;
  }

  if (btn) btn.disabled = true;
  try {
    const payload = customPatch
      ? { code_patch: customPatch }
      : { option_id: state.selectedFixOptionId };
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/fix`, payload);
    if (res.progress) state.progress = res.progress;
    updateTopTelemetry();
    renderStepper();

    if (feedback) {
      feedback.style.color = res.applied ? 'var(--color-green)' : 'var(--color-red)';
      feedback.textContent = res.explanation || '';
    }

    if (res.applied) {
      sound.accessGranted();
      toast('Remediation patch applied! Advancing to Verify.', 'success');
      setTimeout(() => setActiveStage('verify'), store.get('reduceMotion') ? 60 : 500);
    } else {
      sound.accessDenied();
      toast('Patch rejected - inspect explanation and pick a safe fix.', 'warning');
    }
  } catch (err) {
    toast(err.message || 'Failed to apply patch', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------------- STAGE 7: VERIFY ---------------- */

function renderVerifyPhase() {
  const preview = state.mission?.verify_preview;
  const cmdEl = document.getElementById('verifyAttackCmdPreview');
  const wafEl = document.getElementById('verifyWafBadge');
  const shieldBox = document.getElementById('neutralisedShieldBox');

  if (cmdEl) cmdEl.textContent = preview?.attack_command || '--';
  if (wafEl) wafEl.textContent = preview?.waf_control || 'PATCH ACTIVE';
  if (shieldBox && state.progress?.verified_blocked) {
    shieldBox.classList.add('is-visible');
  } else {
    shieldBox?.classList.remove('is-visible');
  }
}

async function handleVerifyAttackClick() {
  const btn = document.getElementById('verifyAttackBtn');
  const outEl = document.getElementById('verifyOutputBox');
  const shieldBox = document.getElementById('neutralisedShieldBox');
  const detailEl = document.getElementById('verifyShieldDetail');

  if (btn) btn.disabled = true;
  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/verify`);
    if (res.progress) state.progress = res.progress;
    if (res.user) state.user = { ...state.user, ...res.user };
    updateTopTelemetry();
    renderStepper();

    if (res.blocked) {
      sound.accessGranted();
      const lines = [...(res.blocked_output || [])];
      if (res.blocked_log_line) lines.push('', `[LOG] ${res.blocked_log_line}`);
      if (outEl) outEl.textContent = lines.join('\n');
      if (detailEl) detailEl.textContent = `${res.waf_control || ''} - ${res.explanation || ''}`;
      shieldBox?.classList.add('is-visible');
      (res.newly_unlocked_badges || []).forEach((b) =>
        toast(`Badge unlocked: ${b.name}`, 'success')
      );
      if (res.rank_up) {
        showRankUpModal(res.old_rank, res.new_rank, res.user?.xp);
      }
      toast(`Attack verified BLOCKED (+${res.xp_awarded || 0} XP)`, 'success');
    } else {
      sound.accessDenied();
      if (outEl) outEl.textContent = res.message || 'Verification not yet satisfied.';
      toast(res.message || 'Apply remediation fix first.', 'warning');
    }
  } catch (err) {
    toast(err.message || 'Verify request failed', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------------- STAGE 8: DEBRIEF & QUIZ ---------------- */

function showRankUpModal(oldRank, newRank, xp) {
  const modal = document.getElementById('rankUpOverlay');
  const titleEl = document.getElementById('rankUpTitle');
  const subEl = document.getElementById('rankUpSubtitle');
  if (titleEl) titleEl.textContent = `PROMOTED TO ${newRank}`;
  if (subEl) subEl.textContent = `${oldRank} -> ${newRank} (${Number(xp || 0).toLocaleString()} TOTAL XP)`;
  modal?.classList.add('is-active');
}

function renderDebriefPhase() {
  const m = state.mission;
  const p = state.progress;
  if (!m || !p) return;

  const ttdEl = document.getElementById('metricTtd');
  const ttfEl = document.getElementById('metricTtf');
  const hintsEl = document.getElementById('metricHints');
  const xpEl = document.getElementById('metricXp');

  if (ttdEl) ttdEl.textContent = p.time_to_detect_sec != null ? `${p.time_to_detect_sec}s` : 'N/A';
  if (ttfEl) ttfEl.textContent = p.time_to_fix_sec != null ? `${p.time_to_fix_sec}s` : 'N/A';
  if (hintsEl) hintsEl.textContent = String(p.hints_used || 0);
  if (xpEl) xpEl.textContent = `+${Number(p.xp_earned || 0)} XP`;

  const deb = m.debrief || {};
  const expEl = document.getElementById('debriefExplanation');
  if (expEl) {
    const takeaways = Array.isArray(deb.key_takeaways) && deb.key_takeaways.length
      ? `<ul style="margin:8px 0 0 18px; padding:0; color:var(--color-muted); font-size:12px;">${deb.key_takeaways.map((t) => `<li>${escapeHtml(t)}</li>`).join('')}</ul>`
      : '';
    expEl.innerHTML = `
      <div style="margin-bottom:8px;"><strong style="color:var(--color-red);">WHY IT WORKED:</strong> ${escapeHtml(deb.why_it_worked || '')}</div>
      <div style="margin-bottom:6px;"><strong style="color:var(--color-green);">HOW IT WAS STOPPED:</strong> ${escapeHtml(deb.how_it_was_stopped || '')}</div>
      ${deb.mitre_summary ? `<div style="font-family:var(--font-mono); font-size:11px; color:var(--color-cyan);">${escapeHtml(deb.mitre_summary)}</div>` : ''}
      ${takeaways}
    `;
  }

  const mitreBox = document.getElementById('debriefMitreBadges');
  if (mitreBox) {
    mitreBox.innerHTML = (m.mitre_ids || [])
      .map((id) => `<span class="mp-stat-pill" style="color:var(--color-cyan);">${escapeHtml(id)}</span>`)
      .join('');
  }

  const quizBox = document.getElementById('debriefQuizContainer');
  const quizItems = Array.isArray(m.quiz) ? m.quiz : [];
  if (quizBox) {
    const resultMap = new Map((state.lastQuizResults || []).map((r) => [r.id, r]));
    quizBox.innerHTML = quizItems
      .map((q, qIdx) => {
        const res = resultMap.get(q.id);
        const borderCol = res
          ? res.correct
            ? 'var(--color-green)'
            : 'var(--color-red)'
          : 'var(--color-border)';
        const checkedIdx = res ? res.chosen_index : -1;
        return `
          <div class="quiz-question-card" style="border-color:${borderCol};">
            <div style="font-family:var(--font-mono); font-size:11px; color:#FFFFFF; font-weight:700;">
              Q${qIdx + 1}. ${escapeHtml(q.question)}
            </div>
            <div>
              ${(q.options || [])
                .map(
                  (opt, oIdx) => `
                  <label class="quiz-opt-label">
                    <input type="radio" name="quiz_q_${qIdx}" value="${oIdx}" ${checkedIdx === oIdx ? 'checked' : ''} style="accent-color:var(--color-cyan);">
                    <span>${escapeHtml(opt)}</span>
                  </label>
                `
                )
                .join('')}
            </div>
            ${res ? `<div style="margin-top:6px; font-family:var(--font-mono); font-size:11px; color:${res.correct ? 'var(--color-green)' : 'var(--color-red)'};">${res.correct ? '[CORRECT] ' : '[INCORRECT] '}${escapeHtml(res.explanation || '')}</div>` : ''}
          </div>
        `;
      })
      .join('');
  }
}

async function handleQuizSubmit() {
  const quizItems = state.mission?.quiz || [];
  const answers = quizItems.map((_, idx) => {
    const chosen = document.querySelector(`input[name="quiz_q_${idx}"]:checked`);
    return chosen ? Number(chosen.value) : -1;
  });

  if (answers.some((a) => a < 0)) {
    toast(`Answer all ${quizItems.length} quiz questions before submitting.`, 'warning');
    return;
  }

  const btn = document.getElementById('submitQuizBtn');
  const banner = document.getElementById('quizResultBanner');
  if (btn) btn.disabled = true;

  try {
    const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/quiz`, { answers });
    state.lastQuizResults = res.results || [];
    if (res.progress) state.progress = res.progress;
    if (res.user) state.user = { ...state.user, ...res.user };
    updateTopTelemetry();
    renderDebriefPhase();

    if (banner) {
      banner.style.color = res.passed ? 'var(--color-green)' : 'var(--color-red)';
      banner.textContent = res.passed
        ? `QUIZ PASSED (${res.score}/${res.total}) // +${res.xp_awarded || 0} BONUS XP`
        : `QUIZ SCORE ${res.score}/${res.total} (NEED >= 3/5 TO PASS)`;
    }

    if (res.passed) {
      sound.accessGranted();
      if (res.rank_up) showRankUpModal(res.old_rank, res.new_rank, res.user?.xp);
      toast(`Debrief quiz passed: ${res.score}/${res.total}!`, 'success');
    } else {
      sound.accessDenied();
      toast('Review explanations and retry quiz for bonus XP.', 'warning');
    }
  } catch (err) {
    toast(err.message || 'Quiz grading error', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ---------------- RESET LAB ---------------- */

async function handleResetLabClick() {
  const overlay = document.getElementById('resetLabOverlay');
  if (overlay && !store.get('reduceMotion')) {
    overlay.classList.add('is-active');
    sound.whoosh();
  }

  try {
    await api.post(`/missions/${encodeURIComponent(state.missionId)}/reset`);
    state.logs = [];
    state.matchedIndices = new Set();
    state.selectedLogIdx = -1;
    state.selectedFixOptionId = null;
    state.lastQuizResults = null;
    state.cineIdx = -1;
    if (state.cineTimer) {
      clearInterval(state.cineTimer);
      state.cineTimer = null;
    }
    const ruleArea = document.getElementById('ruleYamlTextarea');
    if (ruleArea) ruleArea.value = '';
    const flagInput = document.getElementById('flagInput');
    if (flagInput) flagInput.value = '';
    const verifyOut = document.getElementById('verifyOutputBox');
    if (verifyOut) verifyOut.textContent = 'Ready to replay the original exploit against the patched environment.';
    const quizBanner = document.getElementById('quizResultBanner');
    if (quizBanner) quizBanner.textContent = '';

    await loadMissionDetail();
    if (state.term) {
      state.term.clear();
      writeTermLine('Snapshot restored. Lab container reverted to clean state.', '\x1b[33m');
      writePrompt();
    }
    toast('Lab snapshot restored.', 'info');
  } catch (err) {
    toast(err.message || 'Reset failed', 'error');
  } finally {
    setTimeout(() => overlay?.classList.remove('is-active'), store.get('reduceMotion') ? 60 : 500);
  }
}

/* ---------------- DATA LOAD & WIRING ---------------- */

async function loadMissionDetail() {
  const data = await api.get(`/missions/${encodeURIComponent(state.missionId)}`);
  state.mission = data.mission;
  state.progress = data.progress;
  state.user = data.user;
  state.logs = Array.isArray(data.logs) ? data.logs : [];

  const ethicsCard = document.getElementById('mpEthicsBlockCard');
  if (ethicsCard) {
    const blocked = !data.ethics_accepted && (state.mission.playable || state.track !== 'defender');
    ethicsCard.style.display = blocked ? 'block' : 'none';
  }

  updateTopTelemetry();
  renderBriefingStage();

  const initialStage = state.progress?.stage || 'briefing';
  setActiveStage(initialStage);
}

function bindEvents() {
  document.getElementById('mpGlossaryBtn')?.addEventListener('click', () => glossaryDrawer.open());
  document.getElementById('mpResetLabBtn')?.addEventListener('click', handleResetLabClick);
  document.getElementById('startMissionBtn')?.addEventListener('click', handleStartMissionClick);
  document.getElementById('closeRankUpBtn')?.addEventListener('click', () => {
    document.getElementById('rankUpOverlay')?.classList.remove('is-active');
  });
  document.getElementById('rankUpOverlay')?.addEventListener('click', (e) => {
    if (e.target?.id === 'rankUpOverlay') {
      e.target.classList.remove('is-active');
    }
  });

  document.querySelectorAll('#mpStepper .mp-step-node').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.stage;
      if (isStageUnlocked(target)) setActiveStage(target);
    });
  });

  // Cinematic controls
  document.getElementById('cineNextBtn')?.addEventListener('click', advanceCinematicBeat);
  document.getElementById('cinePlayBtn')?.addEventListener('click', () => {
    if (state.cineTimer) clearInterval(state.cineTimer);
    advanceCinematicBeat();
    state.cineTimer = setInterval(advanceCinematicBeat, store.get('reduceMotion') ? 300 : 950);
  });
  document.getElementById('cineCompleteBtn')?.addEventListener('click', async () => {
    if (state.cineTimer) clearInterval(state.cineTimer);
    try {
      const res = await api.post(`/missions/${encodeURIComponent(state.missionId)}/verify`);
      if (res.progress) state.progress = res.progress;
      if (res.user) state.user = { ...state.user, ...res.user };
      updateTopTelemetry();
      sound.accessGranted();
      (res.newly_unlocked_badges || []).forEach((b) =>
        toast(`Badge unlocked: ${b.name}`, 'success')
      );
      if (res.rank_up) showRankUpModal(res.old_rank, res.new_rank, res.user?.xp);
      setActiveStage('debrief');
    } catch (err) {
      toast(err.message || 'Unable to complete briefing walkthrough', 'error');
    }
  });

  // Kali quick command form
  document.getElementById('kaliQuickForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const input = document.getElementById('kaliQuickInput');
    const cmd = input?.value?.trim();
    if (!cmd) return;
    input.value = '';
    submitTerminalCommand(cmd, false);
  });

  // VoltGear Mock Shop controls
  document.querySelectorAll('.voltgear-tab-btn[data-shop-tab]').forEach((tabBtn) => {
    tabBtn.addEventListener('click', () => {
      const tab = tabBtn.dataset.shopTab;
      document
        .querySelectorAll('.voltgear-tab-btn[data-shop-tab]')
        .forEach((b) => b.classList.toggle('active', b.dataset.shopTab === tab));
      document.getElementById('shopSearchPane').style.display = tab === 'search' ? 'flex' : 'none';
      document.getElementById('shopLoginPane').style.display = tab === 'login' ? 'flex' : 'none';
    });
  });

  document.getElementById('shopSearchBtn')?.addEventListener('click', () => {
    const q = document.getElementById('shopSearchInput')?.value?.trim();
    if (q) submitTerminalCommand(`shop:search ${q}`, false);
  });
  document.getElementById('shopLoginBtn')?.addEventListener('click', () => {
    const u = document.getElementById('shopLoginUser')?.value?.trim();
    if (u) submitTerminalCommand(`shop:login ${u}`, false);
  });
  document.getElementById('shopReadFlagBtn')?.addEventListener('click', () => {
    submitTerminalCommand('shop:read_flag', false);
  });

  // Flag -> Side switch -> Defender
  document.getElementById('gotoFlagBtn')?.addEventListener('click', () => setActiveStage('flag'));
  document.getElementById('flagSubmitForm')?.addEventListener('submit', handleFlagSubmit);
  document.getElementById('enterDefenderBtn')?.addEventListener('click', triggerSideSwitchTransition);

  // Sigma Rule Editor bindings
  const ruleTextarea = document.getElementById('ruleYamlTextarea');
  if (ruleTextarea) {
    ruleTextarea.addEventListener('input', syncSigmaHighlight);
    ruleTextarea.addEventListener('scroll', syncSigmaHighlight);
    ruleTextarea.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = ruleTextarea.selectionStart;
        const end = ruleTextarea.selectionEnd;
        ruleTextarea.value =
          `${ruleTextarea.value.slice(0, start)}  ${ruleTextarea.value.slice(end)}`;
        ruleTextarea.selectionStart = start + 2;
        ruleTextarea.selectionEnd = start + 2;
        syncSigmaHighlight();
      }
    });
  }
  document.getElementById('resetRuleTemplateBtn')?.addEventListener('click', () => {
    if (ruleTextarea && state.mission?.rule_challenge?.template_yaml) {
      ruleTextarea.value = state.mission.rule_challenge.template_yaml;
      syncSigmaHighlight();
    }
  });
  document.getElementById('testRuleBtn')?.addEventListener('click', handleTestRuleClick);
  document.getElementById('gotoFixBtn')?.addEventListener('click', () => setActiveStage('fix'));

  // Fix -> Verify -> Debrief
  document.getElementById('applyFixBtn')?.addEventListener('click', handleApplyFixClick);
  document.getElementById('verifyAttackBtn')?.addEventListener('click', handleVerifyAttackClick);
  document.getElementById('gotoDebriefBtn')?.addEventListener('click', () => setActiveStage('debrief'));
  document.getElementById('submitQuizBtn')?.addEventListener('click', handleQuizSubmit);
}

document.addEventListener('DOMContentLoaded', async () => {
  initAppShell('missions');

  const root = document.getElementById('missionPlayerRoot');
  state.missionId = root?.dataset.missionId || 'web-breach';
  state.mode = queryParam('mode') || sessionStorage.getItem('noentry_mission_mode') || 'guided';
  state.track = queryParam('track') || sessionStorage.getItem('noentry_mission_track') || 'purple';
  sessionStorage.setItem('noentry_mission_mode', state.mode);
  sessionStorage.setItem('noentry_mission_track', state.track);

  bindEvents();
  startTimerLoop();

  try {
    await loadMissionDetail();
  } catch (err) {
    toast(err.message || 'Failed to load mission', 'error');
  }
});

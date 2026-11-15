import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';
import { escapeHtml, toast } from '../core/ui.js';
import { sound } from '../core/sound.js';

let loadedPlaybooks = [];
let autoResponseEnabled = true;

function applyToggleButton(btn, isOn) {
  if (!btn) return;
  btn.classList.toggle('on', Boolean(isOn));
  btn.textContent = isOn ? 'ON' : 'OFF';
}

async function initSettingsPanel() {
  const themeSelect = document.getElementById('settingThemeSelect');
  const soundBtn = document.getElementById('settingSoundToggle');
  const autoBtn = document.getElementById('settingAutoResponseToggle');
  const alertsBtn = document.getElementById('settingAlertsToggle');
  const perfBtn = document.getElementById('settingPerfToggle');
  const motionBtn = document.getElementById('settingMotionToggle');

  if (themeSelect) {
    themeSelect.value = store.get('theme') || 'tactical-red';
    themeSelect.addEventListener('change', () => {
      store.set('theme', themeSelect.value);
      toast(`HUD theme switched to ${themeSelect.value}`, 'info');
    });
  }

  applyToggleButton(soundBtn, store.get('audioOn'));
  soundBtn?.addEventListener('click', () => {
    const next = !store.get('audioOn');
    store.set('audioOn', next);
    applyToggleButton(soundBtn, next);
    if (next) sound.panelOpen();
    toast(`WebAudio FX ${next ? 'enabled' : 'muted'}`, 'info');
  });

  applyToggleButton(perfBtn, store.get('performanceMode'));
  perfBtn?.addEventListener('click', () => {
    const next = !store.get('performanceMode');
    store.set('performanceMode', next);
    applyToggleButton(perfBtn, next);
    toast(`Performance mode ${next ? 'ON' : 'OFF'}`, 'info');
  });

  applyToggleButton(motionBtn, store.get('reduceMotion'));
  motionBtn?.addEventListener('click', () => {
    const next = !store.get('reduceMotion');
    store.set('reduceMotion', next);
    applyToggleButton(motionBtn, next);
    toast(`Reduce motion ${next ? 'ON' : 'OFF'}`, 'info');
  });

  applyToggleButton(alertsBtn, store.get('alertsEnabled'));
  try {
    const stateData = await api.get('/state');
    if (typeof stateData.autopilot_enabled === 'boolean') {
      store.set('alertsEnabled', stateData.autopilot_enabled);
      applyToggleButton(alertsBtn, stateData.autopilot_enabled);
    }
  } catch (_) {}

  alertsBtn?.addEventListener('click', async () => {
    const next = !store.get('alertsEnabled');
    store.set('alertsEnabled', next);
    applyToggleButton(alertsBtn, next);
    try {
      await api.post('/sim/autopilot', { enabled: next });
      toast(`Live simulated alerts ${next ? 'enabled' : 'paused'}`, 'info');
    } catch (err) {
      toast(err.message || 'Failed to sync autopilot state', 'error');
    }
  });

  try {
    const pbs = await api.get('/reflex/playbooks');
    if (Array.isArray(pbs)) {
      loadedPlaybooks = pbs;
      autoResponseEnabled = pbs.some((pb) => pb.enabled);
    }
  } catch (_) {}
  applyToggleButton(autoBtn, autoResponseEnabled);

  autoBtn?.addEventListener('click', async () => {
    const next = !autoResponseEnabled;
    autoResponseEnabled = next;
    applyToggleButton(autoBtn, next);
    try {
      if (loadedPlaybooks.length) {
        await Promise.all(
          loadedPlaybooks.map((pb) =>
            api.post('/reflex/playbooks', { playbook_id: pb.id, enabled: next })
          )
        );
      }
      toast(`Reflex SOAR auto-response ${next ? 'ARMED' : 'PAUSED'}`, next ? 'success' : 'warning');
    } catch (err) {
      toast(err.message || 'Failed to update Reflex playbooks', 'error');
    }
  });
}

function updateEthicsStatusUI(accepted) {
  const badge = document.getElementById('ethicsStatusBadge');
  const proceedBtn = document.getElementById('ethicsProceedMissionsBtn');
  if (badge) {
    badge.classList.toggle('verified', Boolean(accepted));
    badge.textContent = accepted ? 'ETHICS VERIFIED' : 'CLEARANCE REQUIRED';
  }
  if (proceedBtn) {
    proceedBtn.style.display = accepted ? 'inline-flex' : 'none';
  }
}

async function initEthicsGate() {
  const container = document.getElementById('ethicsQuestionsContainer');
  const pledgeEl = document.getElementById('ethicsPledgeText');
  const agreeBox = document.getElementById('ethicsAgreeCheckbox');
  const submitBtn = document.getElementById('submitEthicsBtn');
  const feedbackBox = document.getElementById('ethicsFeedbackBanner');

  let questions = [];
  try {
    const data = await api.get('/ethics');
    updateEthicsStatusUI(Boolean(data.accepted));
    if (pledgeEl && data.pledge_text) pledgeEl.textContent = data.pledge_text;
    if (agreeBox && data.accepted) agreeBox.checked = true;
    questions = Array.isArray(data.questions) ? data.questions : [];
  } catch (err) {
    if (container) {
      container.innerHTML = `<div style="color:var(--color-red); font-family:var(--font-mono); font-size:12px;">Failed to load ethics check: ${escapeHtml(err.message)}</div>`;
    }
    return;
  }

  if (container) {
    container.innerHTML = questions
      .map((q, qIdx) => `
        <div class="ethics-question-card" data-q-idx="${qIdx}">
          <div style="font-size:12px; color:#FFFFFF; font-weight:700;">Q${qIdx + 1}. ${escapeHtml(q.question)}</div>
          <div>
            ${(q.options || [])
              .map(
                (opt, oIdx) => `
                <label class="ethics-opt-label">
                  <input type="radio" name="ethics_q_${qIdx}" value="${oIdx}" style="margin-top:2px; accent-color:var(--color-cyan);">
                  <span>${escapeHtml(opt)}</span>
                </label>
              `
              )
              .join('')}
          </div>
        </div>
      `)
      .join('');
  }

  submitBtn?.addEventListener('click', async () => {
    const answers = questions.map((_, idx) => {
      const checked = document.querySelector(`input[name="ethics_q_${idx}"]:checked`);
      return checked ? Number(checked.value) : -1;
    });

    if (answers.some((val) => val < 0)) {
      toast('Select an answer for all 3 ethics check questions first.', 'warning');
      return;
    }

    if (!agreeBox?.checked) {
      toast('Confirm the range safety pledge checkbox before submitting.', 'warning');
      return;
    }

    submitBtn.disabled = true;
    try {
      const res = await api.post('/ethics/accept', {
        checkbox_agreed: Boolean(agreeBox.checked),
        answers,
      });

      const wrongSet = new Set(res.wrong_indices || []);
      document.querySelectorAll('.ethics-question-card').forEach((card) => {
        const idx = Number(card.dataset.qIdx);
        card.classList.toggle('wrong', wrongSet.has(idx));
        card.classList.toggle('correct', !wrongSet.has(idx) && res.accepted);
      });

      updateEthicsStatusUI(Boolean(res.accepted));
      if (feedbackBox) {
        feedbackBox.style.display = 'block';
        feedbackBox.style.border = res.accepted
          ? '1px solid var(--color-green)'
          : '1px solid var(--color-red)';
        feedbackBox.style.background = res.accepted
          ? 'rgba(0, 255, 106, 0.08)'
          : 'rgba(255, 31, 61, 0.08)';
        feedbackBox.style.color = res.accepted ? 'var(--color-green)' : 'var(--color-red)';
        const fbList = Array.isArray(res.feedback) && res.feedback.length
          ? `<div style="margin-top:6px; color:var(--color-text);">${res.feedback.map((line) => escapeHtml(line)).join('<br>')}</div>`
          : '';
        feedbackBox.innerHTML = `<strong>${escapeHtml(res.message || '')}</strong> (${res.score}/${res.total})${fbList}`;
      }

      if (res.accepted) {
        sound.accessGranted();
        toast('Ethics Clearance verified! Missions unlocked.', 'success');
      } else {
        sound.accessDenied();
        toast('Review highlighted ethics answers and retry.', 'warning');
      }
    } catch (err) {
      toast(err.message || 'Ethics verification error', 'error');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initAppShell('docs');
  initSettingsPanel();
  initEthicsGate();
});


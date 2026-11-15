/**
 * NO ENTRY - GHOST AI Cybersecurity Mentor Floating UI
 * Mounted on every inner screen via initAppShell().
 * Pure rendering + SSE streaming + Deepgram Voice client; all AI & security logic stays in Python.
 */

import { api } from './api.js';
import { store } from './store.js';
import { escapeHtml, toast } from './ui.js';
import { sound } from './sound.js';

const MAX_INPUT_CHARS = 1000;

class GhostAssistant {
  constructor() {
    this.mounted = false;
    this.isOpen = false;
    this.activeRouteKey = 'command_center';
    this.statusData = null;
    this.isStreaming = false;
    this.voicePlaybackEnabled = false; // Default OFF: never auto-play unless learner explicitly enables
    this.mediaRecorder = null;
    this.mediaStream = null;
    this.audioChunks = [];
    this.isRecording = false;
    this.lastFailedPayload = null;
    this.activeAudio = null;
  }

  mount(routeKey) {
    this.activeRouteKey = routeKey || 'command_center';
    if (this.mounted) return;
    this.mounted = true;

    this._injectStyles();
    this._injectDom();
    this._bindEvents();
    this.refreshStatus();
  }

  _injectStyles() {
    if (document.getElementById('neGhostStyles')) return;
    const style = document.createElement('style');
    style.id = 'neGhostStyles';
    style.textContent = `
      .ghost-fab {
        position: fixed;
        right: 22px;
        bottom: 42px;
        z-index: 91;
        display: inline-flex;
        align-items: center;
        gap: 9px;
        padding: 8px 14px 8px 10px;
        background: #06090F;
        border: 1px solid var(--color-red);
        color: #FFFFFF;
        font-family: var(--font-display);
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 2px;
        cursor: pointer;
        box-shadow: 0 0 18px rgba(255, 31, 61, 0.35), 0 8px 24px rgba(0, 0, 0, 0.75);
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
      }
      .ghost-fab:hover {
        transform: translateY(-2px);
        border-color: var(--color-cyan);
        box-shadow: 0 0 22px rgba(0, 229, 255, 0.4), 0 10px 26px rgba(0, 0, 0, 0.85);
      }
      .ghost-fab-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--color-amber);
        box-shadow: 0 0 8px var(--color-amber);
      }
      .ghost-fab-dot.online {
        background: var(--color-green);
        box-shadow: 0 0 8px var(--color-green);
      }

      .ghost-backdrop {
        position: fixed;
        inset: 0;
        z-index: 94;
        background: rgba(2, 4, 8, 0.55);
        display: none;
        justify-content: flex-end;
      }
      .ghost-backdrop.open {
        display: flex;
      }
      .ghost-drawer {
        width: min(440px, 96vw);
        height: 100%;
        background: #05080D;
        border-left: 1px solid var(--color-cyan);
        box-shadow: -10px 0 36px rgba(0, 0, 0, 0.85), -2px 0 16px rgba(0, 229, 255, 0.2);
        display: flex;
        flex-direction: column;
        font-family: var(--font-mono);
      }
      .ghost-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 14px;
        background: #080C12;
        border-bottom: 1px solid var(--color-border);
      }
      .ghost-title-wrap {
        display: flex;
        align-items: center;
        gap: 9px;
      }
      .ghost-title {
        font-family: var(--font-display);
        font-size: 13px;
        font-weight: 800;
        letter-spacing: 2px;
        color: #FFFFFF;
      }
      .ghost-status-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        padding: 7px 14px;
        background: #04060A;
        border-bottom: 1px solid var(--color-border);
        font-size: 10px;
      }
      .ghost-status-badge {
        color: var(--color-amber);
        font-weight: 700;
      }
      .ghost-status-badge.online {
        color: var(--color-green);
      }
      .ghost-provider-pills {
        display: flex;
        flex-wrap: wrap;
        gap: 5px;
        padding: 7px 14px;
        background: #04060A;
        border-bottom: 1px solid var(--color-border);
        font-size: 10px;
      }
      .ghost-pill {
        padding: 2px 6px;
        border: 1px solid var(--color-border);
        color: var(--color-muted);
        background: #070B11;
      }
      .ghost-pill.ready {
        border-color: rgba(0, 229, 255, 0.45);
        color: var(--color-cyan);
      }
      .ghost-actions-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 6px;
        padding: 10px 14px;
        border-bottom: 1px solid var(--color-border);
        background: #06090F;
      }
      .ghost-action-btn {
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.8px;
        padding: 7px 8px;
        background: #04060A;
        border: 1px solid var(--color-border);
        color: var(--color-cyan);
        cursor: pointer;
        text-align: center;
        transition: all 0.15s ease;
      }
      .ghost-action-btn:hover:not(:disabled) {
        border-color: var(--color-cyan);
        background: rgba(0, 229, 255, 0.12);
      }
      .ghost-action-btn:disabled {
        opacity: 0.45;
        cursor: not-allowed;
      }
      .ghost-messages {
        flex: 1;
        overflow-y: auto;
        padding: 12px 14px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        background: #030508;
      }
      .ghost-msg {
        padding: 9px 11px;
        border: 1px solid var(--color-border);
        background: #070A10;
        font-size: 12px;
        line-height: 1.5;
        color: #E2E8F0;
      }
      .ghost-msg.user {
        border-color: rgba(255, 31, 61, 0.45);
        background: rgba(255, 31, 61, 0.06);
        align-self: flex-end;
        max-width: 90%;
      }
      .ghost-msg.ghost {
        border-color: rgba(0, 229, 255, 0.35);
      }
      .ghost-msg.error {
        border-color: var(--color-red);
        background: rgba(255, 31, 61, 0.1);
      }
      .ghost-msg-meta {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        font-size: 10px;
        color: var(--color-muted);
        margin-bottom: 5px;
      }
      .ghost-msg-body {
        white-space: pre-wrap;
        word-break: break-word;
      }
      .ghost-msg-controls {
        margin-top: 7px;
        display: flex;
        gap: 8px;
        align-items: center;
      }
      .ghost-mini-btn {
        font-family: var(--font-mono);
        font-size: 10px;
        padding: 2px 7px;
        background: #04060A;
        border: 1px solid var(--color-border);
        color: var(--color-cyan);
        cursor: pointer;
      }
      .ghost-mini-btn:hover {
        border-color: var(--color-cyan);
      }
      .ghost-voice-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        background: #06090F;
        border-top: 1px solid var(--color-border);
        font-size: 10px;
        color: var(--color-muted);
      }
      .ghost-mic-btn {
        font-family: var(--font-mono);
        font-size: 11px;
        font-weight: 700;
        padding: 7px 10px;
        background: #04060A;
        border: 1px solid var(--color-border);
        color: var(--color-text);
        cursor: pointer;
      }
      .ghost-mic-btn.recording {
        border-color: var(--color-red);
        color: var(--color-red);
        background: rgba(255, 31, 61, 0.14);
      }
      .ghost-composer {
        display: flex;
        gap: 6px;
        padding: 10px 14px;
        background: #080C12;
        border-top: 1px solid var(--color-border);
      }
      .ghost-input {
        flex: 1;
        font-family: var(--font-mono);
        font-size: 12px;
        padding: 8px 10px;
        background: #030508;
        border: 1px solid var(--color-border);
        color: #FFFFFF;
        outline: none;
      }
      .ghost-input:focus {
        border-color: var(--color-cyan);
      }
    `;
    document.head.appendChild(style);
  }

  _injectDom() {
    if (document.getElementById('ghostFabBtn')) return;
    const useGlitch = !store.get('reduceMotion') && !store.get('performanceMode');

    const fab = document.createElement('button');
    fab.id = 'ghostFabBtn';
    fab.type = 'button';
    fab.className = 'ghost-fab';
    fab.setAttribute('aria-label', 'Open Ghost AI Mentor');
    fab.innerHTML = `
      <ne-logo size="24" ${useGlitch ? 'glitch' : ''}></ne-logo>
      <span>GHOST</span>
      <span id="ghostFabDot" class="ghost-fab-dot" title="Ghost status"></span>
    `;
    document.body.appendChild(fab);

    const backdrop = document.createElement('div');
    backdrop.id = 'ghostBackdrop';
    backdrop.className = 'ghost-backdrop';
    backdrop.innerHTML = `
      <aside id="ghostDrawer" class="ghost-drawer" role="dialog" aria-label="Ghost AI Cybersecurity Mentor">
        <div class="ghost-header">
          <div class="ghost-title-wrap">
            <ne-logo size="22" ${useGlitch ? 'pulse' : ''}></ne-logo>
            <div>
              <div class="ghost-title">GHOST // MENTOR</div>
              <div style="font-size:10px; color:var(--color-muted);">ISOLATED LAB GUIDANCE ONLY</div>
            </div>
          </div>
          <button type="button" id="ghostCloseBtn" class="ghost-mini-btn" style="padding:4px 9px;">CLOSE [ESC]</button>
        </div>

        <div class="ghost-status-bar">
          <span id="ghostStatusLabel" class="ghost-status-badge">Checking providers...</span>
          <button type="button" id="ghostVoiceToggleBtn" class="ghost-mini-btn">VOICE: OFF</button>
        </div>

        <div id="ghostProviderPills" class="ghost-provider-pills"></div>

        <div class="ghost-actions-grid">
          <button type="button" class="ghost-action-btn" data-ghost-action="hint">HINT</button>
          <button type="button" class="ghost-action-btn" data-ghost-action="explain_log">EXPLAIN THIS LOG</button>
          <button type="button" class="ghost-action-btn" data-ghost-action="why_it_worked">WHY DID IT WORK</button>
          <button type="button" class="ghost-action-btn" data-ghost-action="review_rule">REVIEW MY RULE</button>
        </div>

        <div id="ghostMessages" class="ghost-messages">
          <div class="ghost-msg ghost">
            <div class="ghost-msg-meta">
              <span style="color:var(--color-cyan);">GHOST // SYSTEM</span>
              <span>READY</span>
            </div>
            <div class="ghost-msg-body">Operator linked. Ask a question or pick a quick action above. I stay inside this isolated cyber range.</div>
          </div>
        </div>

        <div class="ghost-voice-bar">
          <span id="ghostMicStatus">MIC: READY</span>
          <span id="ghostRateStatus" style="color:var(--color-cyan);">QUOTA: --/20</span>
        </div>

        <form id="ghostComposerForm" class="ghost-composer">
          <button type="button" id="ghostMicBtn" class="ghost-mic-btn" title="Voice input via Deepgram">MIC</button>
          <input type="text" id="ghostInput" class="ghost-input" maxlength="${MAX_INPUT_CHARS}" placeholder="Ask Ghost inside range scope..." autocomplete="off">
          <button type="submit" id="ghostSendBtn" class="btn btn-red" style="padding:7px 12px; font-size:11px;">SEND</button>
        </form>
      </aside>
    `;
    document.body.appendChild(backdrop);
  }

  _bindEvents() {
    document.getElementById('ghostFabBtn')?.addEventListener('click', () => this.open());
    document.getElementById('ghostCloseBtn')?.addEventListener('click', () => this.close());
    document.getElementById('ghostBackdrop')?.addEventListener('click', (e) => {
      if (e.target?.id === 'ghostBackdrop') this.close();
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isOpen) {
        this.close();
      }
    });

    document.querySelectorAll('.ghost-action-btn[data-ghost-action]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.ghostAction;
        const label = btn.textContent?.trim() || action;
        this.sendQuery({ message: '', action, displayLabel: label });
      });
    });

    document.getElementById('ghostComposerForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = document.getElementById('ghostInput');
      const text = (input?.value || '').trim();
      if (!text) return;
      if (text.length > MAX_INPUT_CHARS) {
        toast(`Message limit is ${MAX_INPUT_CHARS} characters.`, 'warning');
        return;
      }
      input.value = '';
      this.sendQuery({ message: text, action: 'auto', displayLabel: text });
    });

    document.getElementById('ghostVoiceToggleBtn')?.addEventListener('click', () => {
      this.voicePlaybackEnabled = !this.voicePlaybackEnabled;
      const btn = document.getElementById('ghostVoiceToggleBtn');
      if (btn) {
        btn.textContent = this.voicePlaybackEnabled ? 'VOICE: ON' : 'VOICE: OFF';
        btn.style.borderColor = this.voicePlaybackEnabled ? 'var(--color-green)' : '';
        btn.style.color = this.voicePlaybackEnabled ? 'var(--color-green)' : '';
      }
      if (!this.voicePlaybackEnabled && this.activeAudio) {
        try {
          this.activeAudio.pause();
        } catch (_) {}
      }
    });

    document.getElementById('ghostMicBtn')?.addEventListener('click', () => this._toggleMicrophone());
  }

  open() {
    const backdrop = document.getElementById('ghostBackdrop');
    if (!backdrop) return;
    backdrop.classList.add('open');
    this.isOpen = true;
    sound.panelOpen();
    this.refreshStatus();
    document.getElementById('ghostInput')?.focus();
  }

  close() {
    const backdrop = document.getElementById('ghostBackdrop');
    backdrop?.classList.remove('open');
    this.isOpen = false;
  }

  async refreshStatus() {
    try {
      const status = await api.get('/ghost/status');
      this.statusData = status;
      this._renderStatus(status);
    } catch (_) {
      this._renderStatus({
        ai_online: false,
        status_label: 'Ghost offline: scripted hints',
        providers: [],
        voice: { configured: false },
        intent: { configured: false },
        rate_limit: { chat_remaining: 20, chat_limit_per_hour: 20 },
      });
    }
  }

  _renderStatus(status) {
    const online = Boolean(status?.ai_online);
    const labelEl = document.getElementById('ghostStatusLabel');
    const dotEl = document.getElementById('ghostFabDot');
    const pillsEl = document.getElementById('ghostProviderPills');
    const rateEl = document.getElementById('ghostRateStatus');

    if (labelEl) {
      labelEl.classList.toggle('online', online);
      labelEl.textContent = online
        ? (status.status_label || 'Ghost online')
        : 'Ghost offline: scripted hints';
    }
    if (dotEl) dotEl.classList.toggle('online', online);

    if (pillsEl) {
      const pList = Array.isArray(status?.providers) ? status.providers : [];
      const pillsHtml = pList
        .map(
          (p) =>
            `<span class="ghost-pill ${p.configured ? 'ready' : ''}">${escapeHtml(p.name.toUpperCase())}: ${p.configured ? 'READY' : 'NONE'}</span>`
        )
        .join('');
      const voiceOk = Boolean(status?.voice?.configured);
      const hfOk = Boolean(status?.intent?.configured);
      pillsEl.innerHTML = `${pillsHtml}<span class="ghost-pill ${voiceOk ? 'ready' : ''}">VOICE: ${voiceOk ? 'READY' : 'OFF'}</span><span class="ghost-pill ${hfOk ? 'ready' : ''}">HF: ${hfOk ? 'READY' : 'LOCAL'}</span>`;
    }

    if (rateEl && status?.rate_limit) {
      rateEl.textContent = `QUOTA: ${status.rate_limit.chat_remaining}/${status.rate_limit.chat_limit_per_hour}`;
    }
  }

  collectLiveContext() {
    const root = document.getElementById('missionPlayerRoot');
    const missionId = root?.dataset.missionId || null;
    const activeStage =
      document.querySelector('#mpStepper .mp-step-node.is-active')?.dataset.stage || null;

    // Collect Sigma rule draft & MITRE selection if in Mission Player
    const ruleYaml = document.getElementById('ruleYamlTextarea')?.value || null;
    const selectedMitreId = document.getElementById('mitreSelect')?.value || null;

    // Collect terminal output snippets
    const terminalOutput = [];
    const xtermRows = document.querySelectorAll('#mpTerminalContainer .xterm-rows > div, #redTerminal .xterm-rows > div');
    xtermRows.forEach((row) => {
      const txt = (row.textContent || '').trim();
      if (txt) terminalOutput.push(txt);
    });

    // Collect visible or selected security log lines across screens
    const logs = [];
    const selectedLog = document.querySelector('#defenderLogsContainer .log-row.is-selected');
    if (selectedLog?.textContent) logs.push(selectedLog.textContent.trim());
    document
      .querySelectorAll('#defenderLogsContainer .log-row, #watchLogTable tbody tr, #ccFeedBody tr')
      .forEach((row) => {
        if (logs.length >= 8) return;
        const txt = (row.textContent || '').trim();
        if (txt && !logs.includes(txt)) logs.push(txt);
      });

    return {
      mission_id: missionId,
      stage: activeStage || this.activeRouteKey,
      screen: this.activeRouteKey,
      terminal_output: terminalOutput.slice(-10),
      logs: logs.slice(0, 8),
      rule_yaml: ruleYaml,
      selected_mitre_id: selectedMitreId,
    };
  }

  _appendMessageNode(role, metaTitle, badgeText, bodyText = '') {
    const box = document.getElementById('ghostMessages');
    if (!box) return null;
    const msgEl = document.createElement('div');
    msgEl.className = `ghost-msg ${role}`;
    msgEl.innerHTML = `
      <div class="ghost-msg-meta">
        <span class="ghost-msg-sender" style="color:${role === 'user' ? 'var(--color-red)' : 'var(--color-cyan)'}; font-weight:700;">${escapeHtml(metaTitle)}</span>
        <span class="ghost-msg-badge">${escapeHtml(badgeText)}</span>
      </div>
      <div class="ghost-msg-body"></div>
      <div class="ghost-msg-controls"></div>
    `;
    msgEl.querySelector('.ghost-msg-body').textContent = bodyText;
    box.appendChild(msgEl);
    box.scrollTop = box.scrollHeight;
    return msgEl;
  }

  _setControlsDisabled(disabled) {
    document.querySelectorAll('.ghost-action-btn').forEach((b) => {
      b.disabled = disabled;
    });
    const sendBtn = document.getElementById('ghostSendBtn');
    if (sendBtn) sendBtn.disabled = disabled;
  }

  async sendQuery({ message = '', action = 'auto', displayLabel = '' }) {
    if (this.isStreaming) return;
    this.isStreaming = true;
    this._setControlsDisabled(true);

    const ctx = this.collectLiveContext();
    const requestPayload = {
      message,
      action,
      ...ctx,
    };
    this.lastFailedPayload = { message, action, displayLabel };

    this._appendMessageNode('user', 'YOU', action.toUpperCase(), displayLabel || message || action.toUpperCase());
    const ghostNode = this._appendMessageNode('ghost', 'GHOST', 'STREAMING...', '');
    const senderEl = ghostNode?.querySelector('.ghost-msg-sender');
    const badgeEl = ghostNode?.querySelector('.ghost-msg-badge');
    const bodyEl = ghostNode?.querySelector('.ghost-msg-body');
    const controlsEl = ghostNode?.querySelector('.ghost-msg-controls');
    const box = document.getElementById('ghostMessages');

    let displayedText = '';
    let finalMeta = null;
    const tokenQueue = [];
    let pumpActive = false;

    const drainQueue = () => {
      if (!tokenQueue.length || !bodyEl) {
        pumpActive = false;
        return;
      }
      pumpActive = true;
      const reduce = store.get('reduceMotion');
      const sliceSize = reduce ? tokenQueue.length : Math.min(4, tokenQueue.length);
      for (let i = 0; i < sliceSize; i += 1) {
        displayedText += tokenQueue.shift();
      }
      bodyEl.textContent = displayedText;
      if (box) box.scrollTop = box.scrollHeight;
      if (tokenQueue.length) {
        requestAnimationFrame(drainQueue);
      } else {
        pumpActive = false;
      }
    };

    try {
      const response = await fetch('/api/ghost', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream',
        },
        body: JSON.stringify(requestPayload),
      });

      if (!response.ok || !response.body) {
        let detail = `HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) detail = errJson.detail;
        } catch (_) {}
        throw new Error(detail);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let sseBuffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        sseBuffer += decoder.decode(value, { stream: true });
        const frames = sseBuffer.split('\n\n');
        sseBuffer = frames.pop() || '';

        for (const frame of frames) {
          const line = frame.split('\n').find((l) => l.startsWith('data: '));
          if (!line) continue;
          let evt = null;
          try {
            evt = JSON.parse(line.slice(6));
          } catch (_) {
            continue;
          }

          if (evt.type === 'meta') {
            finalMeta = evt;
            const labelEl = document.getElementById('ghostStatusLabel');
            if (labelEl) {
              labelEl.textContent = evt.status_label || 'Ghost online';
              labelEl.classList.toggle('online', Boolean(evt.ai_generated));
            }
            if (senderEl) {
              senderEl.textContent = evt.ai_generated
                ? `GHOST // ${(evt.provider || '').toUpperCase()}`
                : 'GHOST // SCRIPTED';
            }
            if (badgeEl) {
              badgeEl.textContent = evt.ai_generated ? (evt.model || 'AI') : 'OFFLINE FALLBACK';
            }
          } else if (evt.type === 'token' && evt.text) {
            if (store.get('reduceMotion')) {
              displayedText += evt.text;
              if (bodyEl) bodyEl.textContent = displayedText;
              if (box) box.scrollTop = box.scrollHeight;
            } else {
              for (const ch of evt.text) tokenQueue.push(ch);
              if (!pumpActive) requestAnimationFrame(drainQueue);
            }
          } else if (evt.type === 'done') {
            finalMeta = evt;
            if (evt.full_text && displayedText.length < evt.full_text.length && !tokenQueue.length) {
              displayedText = evt.full_text;
              if (bodyEl) bodyEl.textContent = displayedText;
            }
          } else if (evt.type === 'error') {
            throw new Error(evt.message || 'Streaming error from Ghost');
          }
        }
      }

      // Wait briefly for typewriter animation tail to flush
      while (tokenQueue.length) {
        await new Promise((r) => setTimeout(r, 25));
      }

      const finalText = finalMeta?.full_text || displayedText;
      if (bodyEl && finalText) bodyEl.textContent = finalText;

      const rateEl = document.getElementById('ghostRateStatus');
      if (rateEl && typeof finalMeta?.remaining === 'number') {
        const limit = this.statusData?.rate_limit?.chat_limit_per_hour || 20;
        rateEl.textContent = `QUOTA: ${finalMeta.remaining}/${limit}`;
      }

      if (controlsEl && finalText) {
        const speakBtn = document.createElement('button');
        speakBtn.type = 'button';
        speakBtn.className = 'ghost-mini-btn';
        speakBtn.textContent = 'SPEAK';
        speakBtn.addEventListener('click', () => this.playTts(finalText));
        controlsEl.appendChild(speakBtn);
      }

      if (this.voicePlaybackEnabled && finalText) {
        this.playTts(finalText);
      }
    } catch (err) {
      if (ghostNode) ghostNode.className = 'ghost-msg error';
      if (badgeEl) badgeEl.textContent = 'ERROR';
      if (bodyEl) bodyEl.textContent = `Ghost request failed: ${err.message || 'Unknown error'}`;
      if (controlsEl) {
        const retryBtn = document.createElement('button');
        retryBtn.type = 'button';
        retryBtn.className = 'ghost-mini-btn';
        retryBtn.textContent = 'RETRY';
        retryBtn.addEventListener('click', () => {
          if (this.lastFailedPayload) this.sendQuery(this.lastFailedPayload);
        });
        controlsEl.appendChild(retryBtn);
      }
    } finally {
      this.isStreaming = false;
      this._setControlsDisabled(false);
    }
  }

  async playTts(text) {
    const statusEl = document.getElementById('ghostMicStatus');
    try {
      const resp = await fetch('/api/ghost/voice/tts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: String(text || '').slice(0, MAX_INPUT_CHARS) }),
      });
      if (!resp.ok) {
        if (statusEl) statusEl.textContent = 'TTS: TEXT-ONLY FALLBACK';
        return;
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      if (this.activeAudio) {
        try {
          this.activeAudio.pause();
        } catch (_) {}
      }
      const audio = new Audio(url);
      this.activeAudio = audio;
      audio.onended = () => URL.revokeObjectURL(url);
      audio.onerror = () => URL.revokeObjectURL(url);
      await audio.play();
      if (statusEl) statusEl.textContent = 'VOICE: SPEAKING';
    } catch (_) {
      if (statusEl) statusEl.textContent = 'TTS: TEXT-ONLY FALLBACK';
    }
  }

  async _toggleMicrophone() {
    const micBtn = document.getElementById('ghostMicBtn');
    const micStatus = document.getElementById('ghostMicStatus');

    if (this.isRecording && this.mediaRecorder) {
      this.mediaRecorder.stop();
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia || typeof window.MediaRecorder === 'undefined') {
      if (micStatus) micStatus.textContent = 'MIC: BROWSER UNSUPPORTED';
      toast('Microphone recording is unsupported in this browser.', 'warning');
      return;
    }

    try {
      this.mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (_) {
      if (micStatus) micStatus.textContent = 'MIC: PERMISSION DENIED';
      toast('Microphone permission denied. Type your question instead.', 'warning');
      return;
    }

    this.audioChunks = [];
    const mimeType = MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm' : '';
    const recorder = mimeType
      ? new MediaRecorder(this.mediaStream, { mimeType })
      : new MediaRecorder(this.mediaStream);
    this.mediaRecorder = recorder;

    recorder.ondataavailable = (ev) => {
      if (ev.data && ev.data.size > 0) this.audioChunks.push(ev.data);
    };

    recorder.onstop = async () => {
      this.isRecording = false;
      micBtn?.classList.remove('recording');
      if (micBtn) micBtn.textContent = 'MIC';
      this.mediaStream?.getTracks().forEach((t) => t.stop());
      this.mediaStream = null;

      const blob = new Blob(this.audioChunks, { type: recorder.mimeType || 'audio/webm' });
      this.audioChunks = [];
      if (!blob.size) {
        if (micStatus) micStatus.textContent = 'MIC: EMPTY AUDIO';
        return;
      }

      if (micStatus) micStatus.textContent = 'MIC: TRANSCRIBING...';
      try {
        const fd = new FormData();
        fd.append('audio', blob, 'ghost_query.webm');
        const res = await fetch('/api/ghost/voice/stt', { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.detail || `HTTP ${res.status}`);

        const recognized = (data.transcript || '').trim();
        if (!recognized) throw new Error('No speech recognized');

        const input = document.getElementById('ghostInput');
        if (input) input.value = recognized;
        if (micStatus) micStatus.textContent = 'MIC: TRANSCRIBED';
        await this.sendQuery({ message: recognized, action: 'auto', displayLabel: recognized });
      } catch (err) {
        if (micStatus) micStatus.textContent = 'MIC: STT UNAVAILABLE';
        toast(err.message || 'Voice transcription failed', 'warning');
      }
    };

    recorder.start();
    this.isRecording = true;
    micBtn?.classList.add('recording');
    if (micBtn) micBtn.textContent = 'STOP';
    if (micStatus) micStatus.textContent = 'MIC: RECORDING (CLICK STOP)';
  }
}

export const ghostAssistant = new GhostAssistant();


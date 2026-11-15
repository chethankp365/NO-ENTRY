/**
 * Shared Tactical Cheat-Sheet / Glossary Drawer
 * Fetches tool references from GET /api/learn/glossary and renders a slide-over drawer.
 */

import { api } from './api.js';
import { escapeHtml, toast } from './ui.js';
import { sound } from './sound.js';

class GlossaryDrawer {
  constructor() {
    this.items = null;
    this.mounted = false;
  }

  _ensureStyles() {
    if (document.getElementById('neGlossaryDrawerStyles')) return;
    const style = document.createElement('style');
    style.id = 'neGlossaryDrawerStyles';
    style.textContent = `
      .glossary-backdrop {
        position: fixed;
        inset: 0;
        background: rgba(2, 4, 8, 0.72);
        z-index: 95;
        display: none;
        justify-content: flex-end;
      }
      .glossary-backdrop.open { display: flex; }
      .glossary-drawer {
        width: min(520px, 95vw);
        height: 100%;
        background: #06090E;
        border-left: 1px solid var(--color-cyan);
        box-shadow: -8px 0 32px rgba(0, 229, 255, 0.15);
        display: flex;
        flex-direction: column;
        font-family: var(--font-mono);
      }
      .glossary-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 18px;
        border-bottom: 1px solid var(--color-border);
        background: #090D14;
      }
      .glossary-title {
        font-family: var(--font-display);
        font-size: 13px;
        letter-spacing: 2px;
        color: var(--color-cyan);
        text-transform: uppercase;
      }
      .glossary-body {
        padding: 16px 18px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 12px;
        flex: 1;
      }
      .glossary-card {
        background: #080B10;
        border: 1px solid var(--color-border);
        padding: 12px 14px;
      }
      .glossary-card-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
      }
      .glossary-tool {
        font-family: var(--font-ui);
        font-size: 15px;
        font-weight: 700;
        color: #FFFFFF;
        text-transform: uppercase;
      }
      .glossary-cat {
        font-size: 10px;
        padding: 2px 6px;
        border: 1px solid rgba(0, 229, 255, 0.4);
        color: var(--color-cyan);
      }
      .glossary-desc {
        font-size: 11px;
        color: var(--color-text-dim);
        line-height: 1.5;
        margin-bottom: 8px;
      }
      .glossary-code {
        background: #030508;
        border-left: 2px solid var(--color-cyan);
        padding: 8px 10px;
        font-size: 11px;
        color: var(--color-green);
        white-space: pre-wrap;
        word-break: break-word;
      }
      .glossary-example-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-top: 8px;
        font-size: 10px;
        color: var(--color-muted);
      }
    `;
    document.head.appendChild(style);
  }

  _ensureDom() {
    if (this.mounted) return;
    this._ensureStyles();
    const wrap = document.createElement('div');
    wrap.id = 'neGlossaryBackdrop';
    wrap.className = 'glossary-backdrop';
    wrap.innerHTML = `
      <aside class="glossary-drawer">
        <div class="glossary-header">
          <span class="glossary-title">FIELD CHEAT-SHEET // TOOLS &amp; SIGMA</span>
          <button id="neGlossaryCloseBtn" class="btn btn-outline" style="padding:4px 10px; font-size:11px;">CLOSE [ESC]</button>
        </div>
        <div id="neGlossaryBody" class="glossary-body">
          <div style="font-size:11px; color:var(--color-muted);">Loading command reference...</div>
        </div>
      </aside>
    `;
    document.body.appendChild(wrap);

    wrap.addEventListener('click', (e) => {
      if (e.target === wrap) this.close();
    });
    const closeBtn = document.getElementById('neGlossaryCloseBtn');
    if (closeBtn) closeBtn.addEventListener('click', () => this.close());
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && wrap.classList.contains('open')) {
        this.close();
      }
    });
    this.mounted = true;
  }

  async open() {
    this._ensureDom();
    const backdrop = document.getElementById('neGlossaryBackdrop');
    if (backdrop) backdrop.classList.add('open');
    try { sound.whoosh(); } catch (_) {}

    if (!this.items) {
      try {
        const res = await api.get('/learn/glossary');
        this.items = res.items || [];
      } catch (err) {
        this.items = [];
        toast(`Failed to load cheat sheet: ${err.message}`, 'danger');
      }
    }
    this.render();
  }

  close() {
    const backdrop = document.getElementById('neGlossaryBackdrop');
    if (backdrop) backdrop.classList.remove('open');
  }

  render() {
    const body = document.getElementById('neGlossaryBody');
    if (!body) return;
    if (!this.items || !this.items.length) {
      body.innerHTML = '<div style="font-size:11px; color:var(--color-muted);">No cheat-sheet entries available.</div>';
      return;
    }

    body.innerHTML = this.items.map((item, idx) => `
      <div class="glossary-card">
        <div class="glossary-card-top">
          <span class="glossary-tool">${escapeHtml(item.tool)}</span>
          <span class="glossary-cat">${escapeHtml(item.category)}</span>
        </div>
        <div class="glossary-desc">${escapeHtml(item.description)}</div>
        <pre class="glossary-code">${escapeHtml(item.syntax)}</pre>
        <div class="glossary-example-row">
          <span>Ex: <code style="color:#FFFFFF;">${escapeHtml(item.example)}</code></span>
          <button class="btn btn-outline glossary-copy-btn" data-idx="${idx}" style="padding:3px 8px; font-size:10px;">COPY EXAMPLE</button>
        </div>
      </div>
    `).join('');

    body.querySelectorAll('.glossary-copy-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const item = this.items[Number(btn.dataset.idx)];
        if (!item) return;
        try { sound.keyClick(); } catch (_) {}
        try {
          if (navigator.clipboard) await navigator.clipboard.writeText(item.example);
          toast(`Copied example: ${item.example}`, 'success');
        } catch (_) {
          toast(`Example: ${item.example}`, 'info');
        }
      });
    });
  }
}

export const glossaryDrawer = new GlossaryDrawer();


/**
 * NO ENTRY - Executive Incident Reports Screen Controller (Screen 15)
 * Manages incident report archive, live telemetry document generator,
 * printing animation, preview panel, and ReportLab PDF downloads.
 */

import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class ReportsController {
  constructor() {
    this.reports = [];
    this.selectedReportId = null;
  }

  async init() {
    initAppShell('reports');
    this.bindGenerateButton();
    await this.loadReportsData();
  }

  async loadReportsData() {
    try {
      const data = await api.get('/api/reports');
      this.reports = data || [];
      if (this.reports.length > 0 && !this.selectedReportId) {
        this.selectedReportId = this.reports[0].id;
      }
      this.renderAll();
    } catch (err) {
      console.error('Failed to load reports:', err);
      toast('Failed to load incident reports', 'error');
    }
  }

  renderAll() {
    this.renderStats();
    this.renderReportsTable();
    this.renderPreview();
  }

  renderStats() {
    const elCount = document.getElementById('statReportsCount');
    if (elCount) elCount.textContent = `${this.reports.length} EXECUTIVE BRIEFS`;
  }

  renderReportsTable() {
    const tbody = document.getElementById('reportsTbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    this.reports.forEach(rep => {
      const tr = document.createElement('tr');
      const isSelected = rep.id === this.selectedReportId;
      if (isSelected) tr.className = 'active-report';

      tr.innerHTML = `
        <td>
          <div style="font-weight: 700; color: #FFFFFF;">${rep.title}</div>
          <div style="font-size: 10px; color: var(--color-muted); margin-top: 2px;">Target: ${rep.target}</div>
        </td>
        <td>
          <span class="badge" style="background: rgba(0, 229, 255, 0.1); border: 1px solid var(--color-cyan); color: var(--color-cyan); font-size: 9px;">
            ${rep.type}
          </span>
        </td>
        <td style="color: var(--color-muted); font-size: 10px;">${rep.generated_at}</td>
        <td>
          <a href="/api/reports/${rep.id}/pdf" target="_blank" class="btn btn-outline" style="padding: 2px 8px; font-size: 9px; border-color: rgba(255,255,255,0.15);">
            PDF &darr;
          </a>
        </td>
      `;

      tr.addEventListener('click', (e) => {
        // Only select if not clicking download link
        if (e.target.tagName !== 'A') {
          sound.blip();
          this.selectedReportId = rep.id;
          this.renderReportsTable();
          this.renderPreview();
        }
      });

      tbody.appendChild(tr);
    });
  }

  renderPreview() {
    const container = document.getElementById('previewCardContainer');
    const downloadBtn = document.getElementById('downloadPdfBtn');
    if (!container) return;

    const rep = this.reports.find(r => r.id === this.selectedReportId) || this.reports[0];
    if (!rep) {
      container.innerHTML = '<div style="color:var(--color-muted);">No report selected.</div>';
      return;
    }

    if (downloadBtn) {
      downloadBtn.href = `/api/reports/${rep.id}/pdf`;
      downloadBtn.style.display = rep.has_pdf ? 'inline-flex' : 'none';
    }

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; border-bottom: 1px solid var(--color-border); padding-bottom: 12px;">
        <div>
          <h2 style="font-size: 16px; font-weight: 700; color: #FFFFFF; margin: 0 0 4px 0;">${rep.title}</h2>
          <div style="font-size: 11px; color: var(--color-muted);">
            Scope: <span style="color: var(--color-cyan);">${rep.target}</span> &bull; Generated: <span>${rep.generated_at}</span>
          </div>
        </div>
        <div style="text-align: right;">
          <span class="badge" style="background: rgba(0, 255, 106, 0.1); border: 1px solid var(--color-green); color: var(--color-green); font-size: 10px;">
            MTTD: ${rep.mttd} &bull; MTTR: ${rep.mttr}
          </span>
        </div>
      </div>

      <div class="preview-section-title">// EXECUTIVE SUMMARY</div>
      <p style="font-size: 12px; line-height: 1.6; color: #E5E7EB; margin-bottom: 12px;">
        ${rep.summary}
      </p>

      <div class="preview-section-title">// MITRE ATT&amp;CK TECHNIQUES IDENTIFIED</div>
      <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px;">
        ${(rep.techniques || []).map(t => `
          <span class="badge" style="background: rgba(255, 31, 61, 0.15); border: 1px solid var(--color-red); color: var(--color-red); font-size: 10px;">
            ${t}
          </span>
        `).join('')}
      </div>

      <div class="preview-section-title">// TIMELINE OF EVENTS</div>
      <ul class="preview-bullet-list" style="margin-bottom: 12px;">
        ${(rep.timeline || []).map(t => `<li>${t}</li>`).join('')}
      </ul>

      <div class="preview-section-title">// DEFENSE ACTIONS &amp; RECOMMENDATIONS</div>
      <ul class="preview-bullet-list">
        ${(rep.response_actions || []).map(a => `<li style="color:var(--color-green);"><span style="color:var(--color-muted);">[ACTION]</span> ${a}</li>`).join('')}
        ${(rep.recommendations || []).map(r => `<li style="color:#FFB800;"><span style="color:var(--color-muted);">[REC]</span> ${r}</li>`).join('')}
      </ul>
    `;
  }

  bindGenerateButton() {
    const btn = document.getElementById('generateReportBtn');
    if (!btn) return;

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'GENERATING...';
      sound.blip();

      const banner = document.getElementById('printingBanner');
      const text = document.getElementById('printingBannerText');

      if (banner && text) {
        banner.style.display = 'block';
        text.textContent = '> collecting live breach events & response actions from sim engine...';
      }

      await new Promise(r => setTimeout(r, 600));
      if (text) text.textContent = '> synthesizing executive brief & calculating MTTD / MTTR...';
      await new Promise(r => setTimeout(r, 600));
      if (text) text.textContent = '> compiling authentic cyber incident PDF via ReportLab...';
      await new Promise(r => setTimeout(r, 600));

      try {
        const newRep = await api.post('/api/reports/generate');
        sound.panelOpen();

        if (text) text.textContent = `> Report '${newRep.title}' generated successfully!`;

        this.reports.unshift(newRep);
        this.selectedReportId = newRep.id;
        this.renderAll();

        toast(`New incident report '${newRep.id}' compiled and ready for PDF download!`, 'success');

        setTimeout(() => {
          if (banner) banner.style.display = 'none';
        }, 3000);
      } catch (err) {
        console.error('Failed to generate report:', err);
        toast('Report generation failed', 'error');
        if (banner) banner.style.display = 'none';
      } finally {
        btn.disabled = false;
        btn.textContent = 'GENERATE REPORT';
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new ReportsController();
  controller.init();
});

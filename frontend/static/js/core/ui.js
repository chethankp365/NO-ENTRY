/**
 * NO ENTRY - Tactical UI Utilities
 * countUp animations, dynamic monospace tables, tag builders, progress bars, and toasts.
 */

export function countUp(element, targetValue, duration = 800, suffix = '', decimals = 0) {
  if (!element) return;
  const start = parseFloat(element.getAttribute('data-value') || element.innerText.replace(/[^\d.-]/g, '')) || 0;
  const target = parseFloat(targetValue);
  if (isNaN(target)) {
    element.innerText = targetValue + suffix;
    return;
  }

  const startTime = performance.now();
  element.setAttribute('data-value', String(target));

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Smooth ease-out quad
    const ease = 1 - (1 - progress) * (1 - progress);
    const current = start + (target - start) * ease;
    element.innerText = current.toFixed(decimals) + suffix;

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      element.innerText = target.toFixed(decimals) + suffix;
    }
  }

  requestAnimationFrame(update);
}

export function tag(state) {
  if (!state) return '';
  const s = String(state).toUpperCase();
  let modifier = 'detected';
  if (s === 'BLOCKED') modifier = 'blocked';
  else if (s === 'ALERT') modifier = 'alert';
  else if (s === 'ISOLATED') modifier = 'isolated';
  else if (s === 'PASS' || s === 'HEALTHY') modifier = 'blocked';

  return `<span class="tag tag--${modifier}">${escapeHtml(s)}</span>`;
}

export function updateProgressBar(barEl, percentage, colorClass = null) {
  if (!barEl) return;
  const p = Math.max(0, Math.min(100, percentage));
  barEl.style.width = `${p}%`;
  if (colorClass) {
    barEl.className = `bar ${colorClass}`;
  }
}

export function renderTable(tbody, rows, renderRowFn, options = { maxRows: 50, animateNew: true }) {
  if (!tbody) return;

  const fragment = document.createDocumentFragment();
  rows.slice(0, options.maxRows).forEach((item, index) => {
    const tr = document.createElement('tr');
    if (options.animateNew && index === 0) {
      tr.className = 'new-row';
    }
    if (item.breach) {
      tr.classList.add('breach-row');
    }
    tr.innerHTML = renderRowFn(item);
    fragment.appendChild(tr);
  });

  tbody.innerHTML = '';
  tbody.appendChild(fragment);
}

export function toast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('neToastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'neToastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toastEl = document.createElement('div');
  toastEl.className = `toast toast--${type}`;
  toastEl.innerHTML = `
    <span style="font-weight:700;">[${type.toUpperCase()}]</span>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toastEl);

  setTimeout(() => {
    toastEl.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    toastEl.style.opacity = '0';
    toastEl.style.transform = 'translateY(10px)';
    setTimeout(() => toastEl.remove(), 300);
  }, duration);
}

export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * NO ENTRY - Tactical Red Crosshair Cursor with Particle Trail FX
 * Disabled on touch-enabled devices or when reduceMotion is active.
 */

import { store } from '../core/store.js';

export function initCursorFx() {
  // Disable on touch devices
  if ('ontouchstart' in window || navigator.maxTouchPoints > 0) return;

  const crosshair = document.createElement('div');
  crosshair.id = 'neCustomCursor';
  crosshair.style.cssText = `
    position: fixed;
    width: 20px;
    height: 20px;
    border: 1px solid rgba(255, 31, 61, 0.7);
    border-radius: 50%;
    pointer-events: none;
    z-index: var(--z-cursor);
    transform: translate(-50%, -50%);
    transition: width 0.15s ease, height 0.15s ease, border-color 0.15s ease;
    mix-blend-mode: screen;
  `;

  // Center dot
  const dot = document.createElement('div');
  dot.style.cssText = `
    position: absolute;
    top: 50%;
    left: 50%;
    width: 2px;
    height: 2px;
    background: #FF1F3D;
    transform: translate(-50%, -50%);
    box-shadow: 0 0 4px #FF1F3D;
  `;
  crosshair.appendChild(dot);
  document.body.appendChild(crosshair);

  const canvas = document.createElement('canvas');
  canvas.id = 'neCursorTrailCanvas';
  canvas.style.cssText = `
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: calc(var(--z-cursor) - 1);
  `;
  document.body.appendChild(canvas);

  const ctx = canvas.getContext('2d');
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const points = [];
  const maxPoints = 14;

  window.addEventListener('mousemove', (e) => {
    crosshair.style.left = `${e.clientX}px`;
    crosshair.style.top = `${e.clientY}px`;

    if (!store.get('reduceMotion') && !store.get('performanceMode')) {
      points.push({ x: e.clientX, y: e.clientY, alpha: 1.0 });
      if (points.length > maxPoints) points.shift();
    }
  });

  // Expand crosshair on hover over interactive elements
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest('button, a, input, [role="button"], .interactive')) {
      crosshair.style.width = '32px';
      crosshair.style.height = '32px';
      crosshair.style.borderColor = 'rgba(0, 229, 255, 0.9)';
      crosshair.style.boxShadow = '0 0 10px rgba(0, 229, 255, 0.5)';
      dot.style.background = '#00E5FF';
      dot.style.boxShadow = '0 0 6px #00E5FF';
    } else {
      crosshair.style.width = '20px';
      crosshair.style.height = '20px';
      crosshair.style.borderColor = 'rgba(255, 31, 61, 0.7)';
      crosshair.style.boxShadow = 'none';
      dot.style.background = '#FF1F3D';
      dot.style.boxShadow = '0 0 4px #FF1F3D';
    }
  });

  function renderTrail() {
    ctx.clearRect(0, 0, width, height);

    if (points.length > 1 && !store.get('reduceMotion')) {
      for (let i = 0; i < points.length - 1; i++) {
        const p1 = points[i];
        const p2 = points[i + 1];
        p1.alpha *= 0.88;

        ctx.strokeStyle = `rgba(255, 31, 61, ${p1.alpha * 0.4})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      }

      // Remove dead points
      while (points.length > 0 && points[0].alpha < 0.05) {
        points.shift();
      }
    }

    requestAnimationFrame(renderTrail);
  }

  renderTrail();
}

/**
 * NO ENTRY - Glitch Screen Transition FX
 * Dramatic 400ms CRT tear & chromatic split overlay for page transitions and breach alerts.
 */

import { sound } from '../core/sound.js';

export function triggerGlitchTransition(duration = 400) {
  return new Promise((resolve) => {
    sound.glitchCrackle();

    const overlay = document.createElement('div');
    overlay.className = 'glitch-transition-overlay';
    overlay.style.cssText = `
      position: fixed;
      inset: 0;
      z-index: var(--z-glitch);
      pointer-events: none;
      background: rgba(255, 31, 61, 0.15);
      mix-blend-mode: screen;
      overflow: hidden;
    `;

    // Create horizontal slice tearing bands
    const numSlices = 12;
    for (let i = 0; i < numSlices; i++) {
      const slice = document.createElement('div');
      const topPct = (i / numSlices) * 100;
      const heightPct = 100 / numSlices;
      const offset = (Math.random() - 0.5) * 60;

      slice.style.cssText = `
        position: absolute;
        top: ${topPct}%;
        height: ${heightPct}%;
        left: 0;
        right: 0;
        background: inherit;
        transform: translateX(${offset}px);
        filter: drop-shadow(-4px 0 #00e5ff) drop-shadow(4px 0 #ff1f3d);
        transition: transform 0.08s ease;
      `;
      overlay.appendChild(slice);
    }

    document.body.appendChild(overlay);

    const stepInterval = setInterval(() => {
      Array.from(overlay.children).forEach(slice => {
        const offset = (Math.random() - 0.5) * 80;
        slice.style.transform = `translateX(${offset}px)`;
      });
    }, 50);

    setTimeout(() => {
      clearInterval(stepInterval);
      overlay.remove();
      resolve();
    }, duration);
  });
}

export async function navigateWithGlitch(url) {
  await triggerGlitchTransition(350);
  window.location.href = url;
}

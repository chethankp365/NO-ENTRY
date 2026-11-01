/**
 * NO ENTRY - Screen Shake FX
 * Shakes the viewport or a target container on breaches and high-impact cyber events.
 */

import { store } from '../core/store.js';

let isShaking = false;

export function shake(intensity = 8, duration = 350, targetElement = document.body) {
  if (store.get('reduceMotion')) return;
  if (isShaking) return;

  isShaking = true;
  const originalTransform = targetElement.style.transform;
  const startTime = performance.now();

  function step(currentTime) {
    const elapsed = currentTime - startTime;
    if (elapsed >= duration) {
      targetElement.style.transform = originalTransform;
      isShaking = false;
      return;
    }

    const decay = 1 - elapsed / duration;
    const currentIntensity = intensity * decay;
    const x = (Math.random() * 2 - 1) * currentIntensity;
    const y = (Math.random() * 2 - 1) * currentIntensity;
    const rot = (Math.random() * 2 - 1) * (currentIntensity * 0.08);

    targetElement.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px) rotate(${rot.toFixed(2)}deg)`;
    requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

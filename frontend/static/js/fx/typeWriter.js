/**
 * NO ENTRY - Typewriter Terminal FX
 * Sequentially renders characters with variable cadence and audio feedback.
 */

import { sound } from '../core/sound.js';

export function typeWriter(element, text, options = {}) {
  if (!element) return Promise.resolve();

  const baseSpeed = options.speed || 30; // ms per character
  const playSound = options.sound !== false;
  element.innerText = '';

  return new Promise((resolve) => {
    let index = 0;

    function step() {
      if (index < text.length) {
        element.innerText += text.charAt(index);
        index++;

        if (playSound && Math.random() > 0.25) {
          sound.keyClick();
        }

        // Slight human jitter
        const jitter = Math.random() * (baseSpeed * 0.5) - (baseSpeed * 0.25);
        const delay = Math.max(10, baseSpeed + jitter);
        setTimeout(step, delay);
      } else {
        resolve();
      }
    }

    step();
  });
}

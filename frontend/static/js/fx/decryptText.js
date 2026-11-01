/**
 * NO ENTRY - Decrypt Text FX
 * Hollywood-style hacker text decryption: characters scramble rapidly before locking in.
 */

import { sound } from '../core/sound.js';

const CIPHER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*<>[]{}~';

export function decryptText(element, finalText, options = {}) {
  if (!element) return Promise.resolve();

  const target = finalText !== undefined ? finalText : element.innerText;
  const duration = options.duration || 1000;
  const speed = options.speed || 35; // ms per tick
  const playSound = options.sound !== false;

  return new Promise((resolve) => {
    const startTime = performance.now();
    const len = target.length;
    let clickCounter = 0;

    const interval = setInterval(() => {
      const now = performance.now();
      const progress = Math.min((now - startTime) / duration, 1);
      const revealedCount = Math.floor(progress * len);

      let output = '';
      for (let i = 0; i < len; i++) {
        if (i < revealedCount || target[i] === ' ' || target[i] === '\n') {
          output += target[i];
        } else {
          output += CIPHER_CHARS[Math.floor(Math.random() * CIPHER_CHARS.length)];
        }
      }

      element.innerText = output;

      clickCounter++;
      if (playSound && clickCounter % 3 === 0) {
        sound.keyClick();
      }

      if (progress >= 1) {
        clearInterval(interval);
        element.innerText = target;
        resolve();
      }
    }, speed);
  });
}

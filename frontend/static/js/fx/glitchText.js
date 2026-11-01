/**
 * NO ENTRY - Glitch Text Effect
 * Glitches text with random character replacement, horizontal offsets, and chromatic artifacts.
 */

const GLITCH_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

export function glitchText(element, duration = 400) {
  if (!element) return;
  const originalText = element.getAttribute('data-original') || element.innerText;
  element.setAttribute('data-original', originalText);

  const startTime = performance.now();
  const originalColor = element.style.color;
  const originalShadow = element.style.textShadow;

  element.style.textShadow = '-2px 0 #00E5FF, 2px 0 #FF1F3D';

  const interval = setInterval(() => {
    const elapsed = performance.now() - startTime;
    if (elapsed >= duration) {
      clearInterval(interval);
      element.innerText = originalText;
      element.style.color = originalColor;
      element.style.textShadow = originalShadow;
      return;
    }

    // Scramble subset of characters
    const textArray = originalText.split('');
    const glitchAmount = Math.max(1, Math.floor(textArray.length * 0.4));
    for (let i = 0; i < glitchAmount; i++) {
      const idx = Math.floor(Math.random() * textArray.length);
      if (textArray[idx] !== ' ') {
        textArray[idx] = GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)];
      }
    }
    element.innerText = textArray.join('');
  }, 40);
}

export function autoGlitchOnHover(selector = '[data-glitch-hover]') {
  document.querySelectorAll(selector).forEach(el => {
    el.addEventListener('mouseenter', () => glitchText(el, 300));
  });
}

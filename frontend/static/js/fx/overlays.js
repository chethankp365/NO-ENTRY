/**
 * NO ENTRY - Cinematic Screen Overlays
 * Creates CRT scanlines, vignette, and animated film grain layers.
 * Completely non-interactive (pointer-events: none).
 */

export function initOverlays() {
  if (document.getElementById('neOverlaysContainer')) return;

  const container = document.createElement('div');
  container.id = 'neOverlaysContainer';
  container.style.cssText = `
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: var(--z-overlay);
    overflow: hidden;
  `;

  // 1. Scanlines overlay
  const scanlines = document.createElement('div');
  scanlines.className = 'overlay-scanlines';
  scanlines.style.cssText = `
    position: absolute;
    inset: 0;
    background: linear-gradient(
      rgba(18, 16, 16, 0) 50%,
      rgba(0, 0, 0, 0.28) 50%
    );
    background-size: 100% 4px;
    z-index: 1;
    opacity: 0.75;
  `;

  // 2. Heavy cinematic vignette
  const vignette = document.createElement('div');
  vignette.className = 'overlay-vignette';
  vignette.style.cssText = `
    position: absolute;
    inset: 0;
    background: radial-gradient(
      circle at 50% 50%,
      rgba(4, 6, 10, 0) 45%,
      rgba(4, 6, 10, 0.65) 80%,
      rgba(4, 6, 10, 0.95) 100%
    );
    z-index: 2;
  `;

  // 3. Procedural SVG Film Grain noise overlay
  const grain = document.createElement('div');
  grain.className = 'overlay-grain';
  grain.style.cssText = `
    position: absolute;
    inset: -50px;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.035'/%3E%3C/svg%3E");
    z-index: 3;
    opacity: 0.8;
  `;

  container.appendChild(scanlines);
  container.appendChild(vignette);
  container.appendChild(grain);
  document.body.appendChild(container);
}

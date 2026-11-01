/**
 * NO ENTRY - Tactical Matrix Rain Canvas FX
 * Dim digital rain (~6% opacity) using Katakana, Hex, and binary glyphs.
 * Pausable when tab is hidden or in performance mode.
 */

import { store } from '../core/store.js';

export class MatrixRain {
  constructor(canvasElement) {
    this.canvas = canvasElement;
    this.ctx = canvasElement.getContext('2d');
    this.characters = '0123456789ABCDEFｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ';
    this.fontSize = 14;
    this.columns = 0;
    this.drops = [];
    this.isRunning = false;
    this.animId = null;
    this.lastFrame = 0;
    this.fps = 24; // Cinema film rate
    this.interval = 1000 / this.fps;

    this.init();

    // Auto pause on tab hide or store settings
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) this.stop();
      else if (!store.get('performanceMode')) this.start();
    });

    store.subscribe('performanceMode', (perf) => {
      if (perf) this.stop();
      else if (!document.hidden) this.start();
    });

    store.subscribe('reduceMotion', (reduced) => {
      if (reduced) this.stop();
      else if (!store.get('performanceMode') && !document.hidden) this.start();
    });
  }

  init() {
    this.resize();
    window.addEventListener('resize', () => this.resize());
  }

  resize() {
    if (!this.canvas) return;
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
    this.columns = Math.floor(this.canvas.width / this.fontSize);
    this.drops = [];
    for (let i = 0; i < this.columns; i++) {
      this.drops[i] = Math.random() * -100;
    }
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.lastFrame = performance.now();
    this.loop(this.lastFrame);
  }

  stop() {
    this.isRunning = false;
    if (this.animId) {
      cancelAnimationFrame(this.animId);
      this.animId = null;
    }
  }

  loop(currentTime) {
    if (!this.isRunning) return;
    this.animId = requestAnimationFrame((t) => this.loop(t));

    const delta = currentTime - this.lastFrame;
    if (delta < this.interval) return;
    this.lastFrame = currentTime - (delta % this.interval);

    this.draw();
  }

  draw() {
    // Fade out trail with ultra dim background
    this.ctx.fillStyle = 'rgba(4, 6, 10, 0.08)';
    this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

    this.ctx.font = `${this.fontSize}px 'JetBrains Mono', monospace`;

    for (let i = 0; i < this.drops.length; i++) {
      const char = this.characters.charAt(Math.floor(Math.random() * this.characters.length));
      const x = i * this.fontSize;
      const y = this.drops[i] * this.fontSize;

      // Leading glyph is bright cyan/white, tail is dim cyan/faint
      if (Math.random() > 0.88) {
        this.ctx.fillStyle = 'rgba(0, 229, 255, 0.55)'; // Leader
      } else {
        this.ctx.fillStyle = 'rgba(0, 229, 255, 0.06)'; // Faint backdrop
      }

      this.ctx.fillText(char, x, y);

      if (y > this.canvas.height && Math.random() > 0.985) {
        this.drops[i] = 0;
      }
      this.drops[i]++;
    }
  }
}

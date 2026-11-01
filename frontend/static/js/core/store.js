/**
 * NO ENTRY - Core State Store (Tiny Pub-Sub)
 * Manages user settings, audio enablement, motion/perf toggles, and live threat telemetry.
 */

class Store {
  constructor() {
    this.state = {
      audioOn: localStorage.getItem('ne_audio_on') === 'true',
      performanceMode: localStorage.getItem('ne_perf_mode') === 'true',
      reduceMotion: localStorage.getItem('ne_reduce_motion') === 'true' || window.matchMedia('(prefers-reduced-motion: reduce)').matches,
      threatLevel: 'ELEVATED',
      operatorId: 'op-0x7f3a',
      alertsCount: 128,
      mttd: 3.2,
      mttr: 8.4,
      labArmed: true
    };

    this.subscribers = new Map(); // key -> Set(callbacks)
    this.globalSubscribers = new Set();
  }

  getState() {
    return { ...this.state };
  }

  get(key) {
    return this.state[key];
  }

  set(key, value) {
    if (this.state[key] === value) return;
    const prev = this.state[key];
    this.state[key] = value;

    // Persist user toggles
    if (key === 'audioOn') localStorage.setItem('ne_audio_on', String(value));
    if (key === 'performanceMode') localStorage.setItem('ne_perf_mode', String(value));
    if (key === 'reduceMotion') {
      localStorage.setItem('ne_reduce_motion', String(value));
      document.body.classList.toggle('reduce-motion', Boolean(value));
    }

    // Notify key-specific listeners
    if (this.subscribers.has(key)) {
      this.subscribers.get(key).forEach(fn => fn(value, prev));
    }

    // Notify global listeners
    this.globalSubscribers.forEach(fn => fn(key, value, prev));
  }

  update(partial) {
    Object.entries(partial).forEach(([k, v]) => this.set(k, v));
  }

  subscribe(keyOrFn, maybeFn) {
    if (typeof keyOrFn === 'function') {
      this.globalSubscribers.add(keyOrFn);
      return () => this.globalSubscribers.delete(keyOrFn);
    } else {
      const key = keyOrFn;
      const fn = maybeFn;
      if (!this.subscribers.has(key)) {
        this.subscribers.set(key, new Set());
      }
      this.subscribers.get(key).add(fn);
      // Immediately call with current value
      fn(this.state[key], undefined);
      return () => this.subscribers.get(key)?.delete(fn);
    }
  }
}

export const store = new Store();

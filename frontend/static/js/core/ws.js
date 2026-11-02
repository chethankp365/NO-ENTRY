/**
 * NO ENTRY - WebSocket Client
 * Resilient real-time connection with auto-reconnect, topic subscriptions, and store integration.
 */

import { store } from './store.js';
import { toast } from './ui.js';

class WebSocketClient {
  constructor() {
    this.ws = null;
    this.handlers = new Map(); // topic -> Set(callbacks)
    this.messageListeners = new Set();
    this.status = 'DISCONNECTED';
    this.reconnectAttempts = 0;
    this.maxReconnectDelay = 5000;
    this.pingInterval = null;
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const url = `${protocol}//${host}/ws/events`;

    this._setStatus('CONNECTING');

    try {
      this.ws = new WebSocket(url);
    } catch (err) {
      console.error('[NO ENTRY WS] Creation failed:', err);
      toast('Failed to initialize /ws/events WebSocket connection', 'danger');
      this._scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      const wasReconnecting = this.reconnectAttempts > 0;
      this._setStatus('CONNECTED');
      this.reconnectAttempts = 0;
      this._startPing();
      this._dispatch('_open', null);
      if (wasReconnecting) {
        toast('WebSocket /ws/events telemetry uplink restored', 'success', 2500);
      }
      console.log('[NO ENTRY WS] Uplink established.');
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        // Dispatch raw message { type, data } to .on('message', ...) subscribers
        this.messageListeners.forEach(fn => {
          try {
            fn(msg);
          } catch (err) {
            console.error('[NO ENTRY WS] Error in message listener:', err);
          }
        });

        // Dispatch topic to .subscribe(topic, ...) handlers
        this._dispatch(msg.type, msg.data);

        // Auto-update core store
        if (msg.type === 'metrics' && msg.data) {
          if (msg.data.threat_level) store.set('threatLevel', msg.data.threat_level);
          if (msg.data.alerts_today) store.set('alertsCount', msg.data.alerts_today);
          if (msg.data.mean_time_to_detect) store.set('mttd', msg.data.mean_time_to_detect);
          if (msg.data.mean_time_to_respond) store.set('mttr', msg.data.mean_time_to_respond);
        } else if (msg.type === 'snapshot' && msg.data?.metrics) {
          store.set('threatLevel', msg.data.metrics.threat_level);
          store.set('alertsCount', msg.data.metrics.alerts_today);
        } else if (msg.type === 'breach') {
          store.set('threatLevel', 'CRITICAL');
        }
      } catch (err) {
        // text pong or raw message
        if (event.data !== 'pong') {
          console.warn('[NO ENTRY WS] Message parse issue:', err);
        }
      }
    };

    this.ws.onclose = (ev) => {
      this._setStatus('DISCONNECTED');
      this._stopPing();
      this._dispatch('_close', ev);
      this._scheduleReconnect();
    };

    this.ws.onerror = (err) => {
      console.error('[NO ENTRY WS] Connection error:', err);
      this._dispatch('_error', err);
      if (this.reconnectAttempts === 0) {
        toast('Telemetry WebSocket disconnected. Reconnecting...', 'warning', 3000);
      }
      this.ws?.close();
    };
  }

  on(event, callback) {
    if (typeof callback !== 'function') return () => {};

    if (event === 'message') {
      this.messageListeners.add(callback);
      return () => this.messageListeners.delete(callback);
    }

    if (event === 'open') {
      if (this.status === 'CONNECTED') {
        try { callback(); } catch (e) { console.error(e); }
      }
      return this.subscribe('_open', callback);
    }

    if (event === 'close') {
      return this.subscribe('_close', callback);
    }

    if (event === 'error') {
      return this.subscribe('_error', callback);
    }

    // Otherwise treat as topic subscription (e.g. 'status', 'event', 'metrics')
    return this.subscribe(event, callback);
  }

  subscribe(topic, callback) {
    if (!this.handlers.has(topic)) {
      this.handlers.set(topic, new Set());
    }
    this.handlers.get(topic).add(callback);
    return () => this.handlers.get(topic)?.delete(callback);
  }

  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      const payload = typeof data === 'string' ? data : JSON.stringify(data);
      this.ws.send(payload);
    }
  }

  _dispatch(topic, data) {
    if (this.handlers.has(topic)) {
      this.handlers.get(topic).forEach(fn => {
        try {
          fn(data);
        } catch (e) {
          console.error(`[NO ENTRY WS] Error in subscriber for ${topic}:`, e);
        }
      });
    }
    // Also dispatch to wildcard '*'
    if (this.handlers.has('*')) {
      this.handlers.get('*').forEach(fn => fn(topic, data));
    }
  }

  _setStatus(status) {
    this.status = status;
    this._dispatch('status', status);
  }

  _startPing() {
    this._stopPing();
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send('ping');
      }
    }, 20000);
  }

  _stopPing() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  _scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), this.maxReconnectDelay);
    setTimeout(() => this.connect(), delay);
  }
}

export const wsClient = new WebSocketClient();

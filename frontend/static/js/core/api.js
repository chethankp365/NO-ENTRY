/**
 * NO ENTRY - API Client Fetch Wrapper
 * Handles REST requests to the Python FastAPI backend with standard error management.
 */

class ApiClient {
  constructor(basePrefix = '/api') {
    this.basePrefix = basePrefix;
  }

  async get(endpoint, params = {}) {
    const url = new URL(this._buildUrl(endpoint), window.location.origin);
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null) {
        url.searchParams.append(key, val);
      }
    });

    const res = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    return this._handleResponse(res);
  }

  async post(endpoint, body = {}) {
    const res = await fetch(this._buildUrl(endpoint), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });
    return this._handleResponse(res);
  }

  _buildUrl(endpoint) {
    if (endpoint.startsWith('http')) return endpoint;
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    if (cleanEndpoint.startsWith(this.basePrefix)) return cleanEndpoint;
    return `${this.basePrefix}${cleanEndpoint}`;
  }

  async _handleResponse(res) {
    if (!res.ok) {
      let errMsg = `API error: ${res.status} ${res.statusText}`;
      try {
        const errJson = await res.json();
        if (errJson.detail) errMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      } catch (_) {}
      throw new Error(errMsg);
    }
    return res.json();
  }
}

export const api = new ApiClient();

const API_BASE = '/api';

class ApiClient {
  constructor() {
    this.token = localStorage.getItem('aegis_token');
  }

  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('aegis_token', token);
    } else {
      localStorage.removeItem('aegis_token');
    }
  }

  getToken() {
    return this.token || localStorage.getItem('aegis_token');
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.getToken()) {
      headers['Authorization'] = `Bearer ${this.getToken()}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 401) {
          this.setToken(null);
          window.dispatchEvent(new CustomEvent('session-expired'));
        }
        throw new Error(data.error || 'Request failed');
      }

      return data;
    } catch (error) {
      throw error;
    }
  }

  async getStatus() {
    return this.request('/status');
  }

  async setup(masterPassword) {
    const data = await this.request('/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ masterPassword }),
    });
    if (data.token) {
      this.setToken(data.token);
    }
    return data;
  }

  async login(masterPassword) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ masterPassword }),
    });
    if (data.token) {
      this.setToken(data.token);
    }
    return data;
  }

  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.setToken(null);
    }
  }

  async refreshToken() {
    const data = await this.request('/auth/refresh', { method: 'POST' });
    if (data.token) {
      this.setToken(data.token);
    }
    return data;
  }

  async getPasswords() {
    return this.request('/passwords');
  }

  async addPassword(entry) {
    return this.request('/passwords', {
      method: 'POST',
      body: JSON.stringify(entry),
    });
  }

  async updatePassword(website, entry) {
    return this.request(`/passwords/${encodeURIComponent(website)}`, {
      method: 'PUT',
      body: JSON.stringify(entry),
    });
  }

  async deletePassword(website) {
    return this.request(`/passwords/${encodeURIComponent(website)}`, {
      method: 'DELETE',
    });
  }

  async generatePassword(options) {
    return this.request('/generate', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async checkStrength(password) {
    return this.request('/strength', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  async exportPasswords() {
    return this.request('/export');
  }

  async importPasswords(passwords) {
    return this.request('/import', {
      method: 'POST',
      body: JSON.stringify({ passwords }),
    });
  }
}

export const api = new ApiClient();
export default api;

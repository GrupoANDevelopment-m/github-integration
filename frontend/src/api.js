/**
 * Goodware v3.0 — API client + WebSocket
 * Comunica com a API REST em /api/v1/* e subscreve eventos via WS.
 */

const API_BASE = (() => {
  const proto = location.protocol === 'https:' ? 'https' : 'http';
  return `${proto}://${location.host}/api`;
})();
const WS_BASE = (() => {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}/ws`;
})();

class APIClient {
  constructor() {
    this.token = localStorage.getItem('gw_token') || null;
    this.user = JSON.parse(localStorage.getItem('gw_user') || 'null');
    this.ws = null;
    this.listeners = new Set();
    this.reconnectDelay = 1000;
  }

  authed() { return !!this.token; }

  async _fetch(method, path, body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(`${API_BASE}${path}`, opts);
    if (r.status === 401) {
      this.logout();
      throw new Error('unauthorized');
    }
    if (!r.ok) {
      const txt = await r.text();
      throw new Error(`${r.status} ${txt}`);
    }
    return r.json();
  }

  get(p) { return this._fetch('GET', p); }
  post(p, b) { return this._fetch('POST', p, b); }
  put(p, b) { return this._fetch('PUT', p, b); }
  del(p) { return this._fetch('DELETE', p); }

  // ===== Auth =====
  async login(username, password) {
    const r = await this.post('/auth/login', { username, password });
    this.token = r.token;
    this.user = r.user;
    localStorage.setItem('gw_token', r.token);
    localStorage.setItem('gw_user', JSON.stringify(r.user));
    this.connect_ws();
    return r;
  }

  logout() {
    this.token = null;
    this.user = null;
    localStorage.removeItem('gw_token');
    localStorage.removeItem('gw_user');
    if (this.ws) try { this.ws.close(); } catch {}
    this.ws = null;
  }

  // ===== Core =====
  status() { return this.get('/status'); }
  health() { return this.get('/healthz'); }
  sensors() { return this.get('/sensors'); }
  events(limit = 100) { return this.get(`/events?limit=${limit}`); }
  threats(limit = 100) { return this.get(`/threats?limit=${limit}`); }
  predictions() { return this.get('/predictions'); }
  kill(pid, force = true) { return this.post('/effector/kill', { pid, force }); }
  killTree(pid) { return this.post('/effector/kill_tree', { pid }); }
  quarantine(path) { return this.post('/quarantine', { path }); }
  restore(id) { return this.post(`/quarantine/restore/${id}`); }
  rules() { return this.get('/rules'); }
  addRule(rule) { return this.post('/rules', rule); }
  delRule(id) { return this.del(`/rules/${id}`); }

  // ===== Crypto =====
  cryptoStatus() { return this.get('/crypto'); }
  pqcRoundtrip(alg) { return this.post('/crypto/real_pqc', { alg: alg || 'ML-KEM-512' }); }

  // ===== PQC ops =====
  attest() { return this.get('/attestation'); }

  // ===== Supply chain =====
  sbom() { return this.get('/supply_chain'); }
  verifySbom(name) { return this.post('/supply_chain/verify', { name }); }

  // ===== Immune =====
  immuneStatus() { return this.get('/immune'); }
  immuneEvolve() { return this.post('/immune/evolve', {}); }

  // ===== Human Factor =====
  hfStatus() { return this.get('/human_factor/status'); }
  hfEvaluate(payload) { return this.post('/human_factor/evaluate', payload); }
  hfApprove(id) { return this.post(`/human_factor/approve/${id}`); }

  // ===== Decision =====
  decide(payload) { return this.post('/decision/decide', payload); }
  execute(payload) { return this.post('/effector/execute', payload); }

  // ===== Chainsaw =====
  chainsawScan(path) { return this.post('/chainsaw/scan', { path }); }
  chainsawRootkit() { return this.post('/chainsaw/scan_rootkit', {}); }
  chainsawCIS() { return this.post('/chainsaw/cis', {}); }

  // ===== Firewall / Honeypot =====
  firewallSnapshot() { return this.get('/firewall/snapshot'); }
  honeypotStart() { return this.post('/honeypot/start', {}); }
  honeypotStop() { return this.post('/honeypot/stop', {}); }
  honeypotCaptures() { return this.get('/honeypot/captures'); }
  honeypotStatus() { return this.get('/honeypot/status'); }

  // ===== Auditd =====
  auditdWatch(path) { return this.post('/auditd/watch', { path }); }
  auditdRecent(limit = 50) { return this.get(`/auditd/recent?limit=${limit}`); }

  // ===== WebSocket =====
  connect_ws() {
    if (this.ws) try { this.ws.close(); } catch {}
    if (!this.token) return;
    const url = `${WS_BASE}?token=${this.token}`;
    try {
      this.ws = new WebSocket(url);
    } catch (e) {
      console.warn('WS failed', e);
      return;
    }
    this.ws.onopen = () => {
      this.reconnectDelay = 1000;
      this._emit({ type: 'ws_state', state: 'open' });
    };
    this.ws.onclose = () => {
      this._emit({ type: 'ws_state', state: 'closed' });
      setTimeout(() => this.connect_ws(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000);
    };
    this.ws.onerror = (e) => console.warn('WS error', e);
    this.ws.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data);
        this._emit(ev);
      } catch (e) { /* ignore non-JSON */ }
    };
  }

  on(handler) { this.listeners.add(handler); return () => this.listeners.delete(handler); }
  _emit(ev) { for (const h of this.listeners) try { h(ev); } catch (e) { console.error(e); } }
}

export const api = new APIClient();
export default api;

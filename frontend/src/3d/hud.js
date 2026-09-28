/**
 * Goodware v3.0 — Premium 3D HUD Overlay
 *
 * Real-time data overlay with real API data:
 * - System vitals (CPU, RAM, disk)
 * - Active threats count
 * - LLM telemetry
 * - Live event ticker
 * - Real-time metrics
 */

class HUD {
    constructor(container) {
        this.container = container;
        this.elements = {};
        this.data = {
            status: 'INITIALIZING',
            uptime: 0,
            threats: 0,
            events: 0,
            runs: 0,
            toolCalls: 0,
            sessions: 0,
            latency: { p50: 0, p99: 0 },
            system: {
                cpu: 0,
                memory: 0,
                disk: 0,
            },
            pqc: { kems: [], sigs: [] },
            recentEvents: [],
        };
        this.startTime = Date.now();
        this.render();
        this.startPolling();
    }

    create() {
        this.container.innerHTML = `
            <div class="hud-root">
                <div class="hud-top">
                    <div class="hud-brand">
                        <div class="hud-brand-logo"></div>
                        <div class="hud-brand-text">
                            <div class="hud-brand-name">GOODWARE</div>
                            <div class="hud-brand-version">v3.0 Digital Immune System</div>
                        </div>
                    </div>
                    <div class="hud-stats-top">
                        <div class="hud-stat" id="hud-status">
                            <div class="hud-stat-label">STATUS</div>
                            <div class="hud-stat-value">--</div>
                        </div>
                        <div class="hud-stat" id="hud-uptime">
                            <div class="hud-stat-label">UPTIME</div>
                            <div class="hud-stat-value">0s</div>
                        </div>
                        <div class="hud-stat" id="hud-version">
                            <div class="hud-stat-label">VERSION</div>
                            <div class="hud-stat-value">3.0</div>
                        </div>
                    </div>
                </div>

                <div class="hud-left">
                    <div class="hud-panel">
                        <div class="hud-panel-title">SYSTEM VITALS</div>
                        <div class="hud-vital">
                            <div class="hud-vital-label">CPU</div>
                            <div class="hud-vital-bar">
                                <div class="hud-vital-fill" id="hud-cpu-fill" style="width:0%"></div>
                            </div>
                            <div class="hud-vital-value" id="hud-cpu-value">0%</div>
                        </div>
                        <div class="hud-vital">
                            <div class="hud-vital-label">MEMORY</div>
                            <div class="hud-vital-bar">
                                <div class="hud-vital-fill" id="hud-mem-fill" style="width:0%"></div>
                            </div>
                            <div class="hud-vital-value" id="hud-mem-value">0%</div>
                        </div>
                        <div class="hud-vital">
                            <div class="hud-vital-label">DISK</div>
                            <div class="hud-vital-bar">
                                <div class="hud-vital-fill" id="hud-disk-fill" style="width:0%"></div>
                            </div>
                            <div class="hud-vital-value" id="hud-disk-value">0%</div>
                        </div>
                    </div>

                    <div class="hud-panel">
                        <div class="hud-panel-title">PQC ACTIVE</div>
                        <div class="hud-pqc">
                            <div class="hud-pqc-row">
                                <div class="hud-pqc-label">KEM Algorithms</div>
                                <div class="hud-pqc-list" id="hud-kem-list">--</div>
                            </div>
                            <div class="hud-pqc-row">
                                <div class="hud-pqc-label">SIG Algorithms</div>
                                <div class="hud-pqc-list" id="hud-sig-list">--</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="hud-right">
                    <div class="hud-panel">
                        <div class="hud-panel-title">SECURITY POSTURE</div>
                        <div class="hud-threats">
                            <div class="hud-threat-row critical">
                                <div class="hud-threat-label">CRITICAL</div>
                                <div class="hud-threat-value" id="hud-critical">0</div>
                            </div>
                            <div class="hud-threat-row high">
                                <div class="hud-threat-label">HIGH</div>
                                <div class="hud-threat-value" id="hud-high">0</div>
                            </div>
                            <div class="hud-threat-row medium">
                                <div class="hud-threat-label">MEDIUM</div>
                                <div class="hud-threat-value" id="hud-medium">0</div>
                            </div>
                            <div class="hud-threat-row low">
                                <div class="hud-threat-label">LOW</div>
                                <div class="hud-threat-value" id="hud-low">0</div>
                            </div>
                        </div>
                    </div>

                    <div class="hud-panel">
                        <div class="hud-panel-title">LLM TELEMETRY</div>
                        <div class="hud-telemetry">
                            <div class="hud-telemetry-row">
                                <div class="hud-telemetry-label">Total Runs</div>
                                <div class="hud-telemetry-value" id="hud-runs">0</div>
                            </div>
                            <div class="hud-telemetry-row">
                                <div class="hud-telemetry-label">Tool Calls</div>
                                <div class="hud-telemetry-value" id="hud-tools">0</div>
                            </div>
                            <div class="hud-telemetry-row">
                                <div class="hud-telemetry-label">Sessions</div>
                                <div class="hud-telemetry-value" id="hud-sessions">0</div>
                            </div>
                            <div class="hud-telemetry-row">
                                <div class="hud-telemetry-label">P50 Latency</div>
                                <div class="hud-telemetry-value" id="hud-p50">0ms</div>
                            </div>
                            <div class="hud-telemetry-row">
                                <div class="hud-telemetry-label">P99 Latency</div>
                                <div class="hud-telemetry-value" id="hud-p99">0ms</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="hud-bottom">
                    <div class="hud-events" id="hud-events">
                        <div class="hud-event-empty">Awaiting real-time event stream...</div>
                    </div>
                </div>

                <div class="hud-corner hud-corner-tl"></div>
                <div class="hud-corner hud-corner-tr"></div>
                <div class="hud-corner hud-corner-bl"></div>
                <div class="hud-corner hud-corner-br"></div>
            </div>
        `;

        this.elements = {
            status: document.getElementById('hud-status'),
            uptime: document.getElementById('hud-uptime'),
            cpuValue: document.getElementById('hud-cpu-value'),
            cpuFill: document.getElementById('hud-cpu-fill'),
            memValue: document.getElementById('hud-mem-value'),
            memFill: document.getElementById('hud-mem-fill'),
            diskValue: document.getElementById('hud-disk-value'),
            diskFill: document.getElementById('hud-disk-fill'),
            kemList: document.getElementById('hud-kem-list'),
            sigList: document.getElementById('hud-sig-list'),
            critical: document.getElementById('hud-critical'),
            high: document.getElementById('hud-high'),
            medium: document.getElementById('hud-medium'),
            low: document.getElementById('hud-low'),
            runs: document.getElementById('hud-runs'),
            tools: document.getElementById('hud-tools'),
            sessions: document.getElementById('hud-sessions'),
            p50: document.getElementById('hud-p50'),
            p99: document.getElementById('hud-p99'),
            events: document.getElementById('hud-events'),
        };
    }

    async startPolling() {
        await this.poll();
        setInterval(() => this.poll(), 3000);
    }

    async poll() {
        const api = window.GOODWARE_API || {};
        if (!api.get) return;

        try {
            const results = await Promise.allSettled([
                api.get('/api/status'),
                api.get('/api/healthz'),
                api.get('/api/threats'),
                api.get('/api/events?limit=10'),
                api.get('/api/llm/telemetry'),
                api.get('/api/crypto/real_pqc'),
            ]);

            if (results[0].status === 'fulfilled') {
                this.data.uptime = results[0].value?.uptime || 0;
            }

            if (results[1].status === 'fulfilled') {
                const h = results[1].value || {};
                const checks = h.checks || {};
                this.data.system.cpu = checks.cpu?.cpu_pct || 0;
                this.data.system.memory = checks.memory?.used_pct || 0;
                this.data.system.disk = 100 - (checks.disk?.free_pct || 0);
                this.data.status = h.ok ? 'OPERATIONAL' : 'DEGRADED';
            }

            if (results[2].status === 'fulfilled') {
                const threats = results[2].value || {};
                const t = threats.threats || [];
                this.data.threats = t.length;
                this.data.bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
                t.forEach(threat => {
                    const sev = threat.severity || 'low';
                    if (this.data.bySeverity[sev] !== undefined) {
                        this.data.bySeverity[sev]++;
                    }
                });
            }

            if (results[3].status === 'fulfilled') {
                this.data.recentEvents = Array.isArray(results[3].value) ? results[3].value : [];
                this.data.events = this.data.recentEvents.length;
            }

            if (results[4].status === 'fulfilled') {
                const m = results[4].value || {};
                this.data.runs = m.runs_total || 0;
                this.data.toolCalls = m.tool_calls_total || 0;
                this.data.sessions = m.sessions_created_total || 0;
                this.data.latency.p50 = m.latency_p50_ms || 0;
                this.data.latency.p99 = m.latency_p99_ms || 0;
            }

            if (results[5].status === 'fulfilled') {
                const crypto = results[5].value || {};
                if (crypto.available_kems) {
                    this.data.pqc.kems = crypto.available_kems;
                }
                if (crypto.available_sigs) {
                    this.data.pqc.sigs = crypto.available_sigs;
                }
            }
        } catch (e) {
            console.warn('HUD poll error:', e);
        }
    }

    formatUptime(seconds) {
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        if (d > 0) return `${d}d ${h}h ${m}m`;
        if (h > 0) return `${h}h ${m}m ${s}s`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    }

    render() {
        if (!this.elements.status) {
            this.create();
        }

        // Status
        this.elements.status.querySelector('.hud-stat-value').textContent = this.data.status;
        this.elements.status.querySelector('.hud-stat-value').className =
            'hud-stat-value ' + (this.data.status === 'OPERATIONAL' ? 'ok' : 'warn');

        // Uptime (combine API uptime + browser uptime)
        const browserUptime = (Date.now() - this.startTime) / 1000;
        const totalUptime = this.data.uptime + browserUptime;
        this.elements.uptime.querySelector('.hud-stat-value').textContent = this.formatUptime(totalUptime);

        // Vitals
        this.elements.cpuValue.textContent = this.data.system.cpu.toFixed(1) + '%';
        this.elements.cpuFill.style.width = Math.min(100, this.data.system.cpu) + '%';
        this.elements.cpuFill.className = 'hud-vital-fill ' + (
            this.data.system.cpu > 85 ? 'danger' : this.data.system.cpu > 60 ? 'warn' : 'ok'
        );

        this.elements.memValue.textContent = this.data.system.memory.toFixed(1) + '%';
        this.elements.memFill.style.width = Math.min(100, this.data.system.memory) + '%';
        this.elements.memFill.className = 'hud-vital-fill ' + (
            this.data.system.memory > 90 ? 'danger' : this.data.system.memory > 70 ? 'warn' : 'ok'
        );

        this.elements.diskValue.textContent = this.data.system.disk.toFixed(1) + '%';
        this.elements.diskFill.style.width = Math.min(100, this.data.system.disk) + '%';
        this.elements.diskFill.className = 'hud-vital-fill ' + (
            this.data.system.disk > 90 ? 'danger' : this.data.system.disk > 75 ? 'warn' : 'ok'
        );

        // PQC
        this.elements.kemList.textContent = this.data.pqc.kems.length > 0
            ? this.data.pqc.kems.join(', ') : 'initializing...';
        this.elements.sigList.textContent = this.data.pqc.sigs.length > 0
            ? this.data.pqc.sigs.join(', ') : 'initializing...';

        // Threats by severity
        const bySev = this.data.bySeverity || { critical: 0, high: 0, medium: 0, low: 0 };
        this.elements.critical.textContent = bySev.critical || 0;
        this.elements.high.textContent = bySev.high || 0;
        this.elements.medium.textContent = bySev.medium || 0;
        this.elements.low.textContent = bySev.low || 0;

        // Telemetry
        this.elements.runs.textContent = this.data.runs.toLocaleString();
        this.elements.tools.textContent = this.data.toolCalls.toLocaleString();
        this.elements.sessions.textContent = this.data.sessions;
        this.elements.p50.textContent = this.data.latency.p50 + 'ms';
        this.elements.p99.textContent = this.data.latency.p99 + 'ms';

        // Events
        if (this.data.recentEvents.length > 0) {
            this.elements.events.innerHTML = this.data.recentEvents.slice(0, 5).map(ev => {
                const sev = (ev.severity || 'info').toLowerCase();
                const type = ev.type || 'event';
                const ts = ev.timestamp || '';
                return `
                    <div class="hud-event sev-${sev}">
                        <span class="hud-event-time">${ts.substring(11, 19)}</span>
                        <span class="hud-event-sev">${sev.toUpperCase()}</span>
                        <span class="hud-event-type">${type}</span>
                    </div>
                `;
            }).join('');
        } else {
            this.elements.events.innerHTML = '<div class="hud-event-empty">Awaiting real-time event stream...</div>';
        }
    }

    tick() {
        this.render();
    }
}

window.HUD = HUD;

// Goodware v3.0 - Dashboard
const API = (location.protocol === 'file:' || location.port === '8080')
  ? `http://${location.hostname}:8444/api`
  : `${location.origin.replace(/\/$/, '')}/api`;

let REFRESH_MS = 5000;
let TIMER = null;

async function fetchJSON(path, opts) {
  try {
    const r = await fetch(`${API}${path}`, opts);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    console.error('fetch', path, e);
    return null;
  }
}

function setStatus(text, cls) {
  const el = document.getElementById('connection-status');
  el.textContent = text;
  el.className = cls;
}

function setKV(id, data, mapper) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!data) {
    el.innerHTML = '<div class="row"><span class="k">—</span><span class="v err">erro</span></div>';
    return;
  }
  const rows = mapper(data).map(([k, v, cls]) =>
    `<div class="row"><span class="k">${k}</span><span class="v ${cls || ''}">${v}</span></div>`
  ).join('');
  el.innerHTML = rows;
}

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString();
}

async function refreshEngine() {
  const data = await fetchJSON('/status');
  if (!data) { setStatus('offline', 'status-error'); return; }
  setStatus('● online', 'status-ok');
  setKV('engine-status', data, d => [
    ['node_id', d.engine.node_id],
    ['organização', d.engine.organization],
    ['componentes', d.engine.components.length],
    ['eventos no bus', d.engine.bus.history_size],
    ['handlers ativos', d.engine.bus.handler_count],
  ]);
}

async function refreshSensors() {
  const data = await fetchJSON('/sensors');
  if (!data) return;
  const html = (data.sensors || []).map(s =>
    `<div class="row"><span class="k">${s.name}</span><span class="v ${s.running ? 'ok' : 'err'}">${s.running ? '● running' : '○ stopped'}</span></div>`
  ).join('');
  document.getElementById('sensors-status').innerHTML = html || '<div class="row"><span class="k">—</span><span class="v">no sensors</span></div>';
}

async function refreshPredictions() {
  const data = await fetchJSON('/predictions');
  if (!data) return;
  const preds = (data.predictions || []).slice(0, 8);
  if (preds.length === 0) {
    document.getElementById('predictions').innerHTML = '<div class="row"><span class="k">—</span><span class="v">sem previsões ainda</span></div>';
    return;
  }
  const html = preds.map(p => {
    const riskClass = p.risk_score > 0.7 ? 'err' : p.risk_score > 0.4 ? 'warn' : 'ok';
    return `<div class="row"><span class="k">${p.threat_type}</span><span class="v ${riskClass}">risk=${(+p.risk_score).toFixed(2)}</span></div>`;
  }).join('');
  document.getElementById('predictions').innerHTML = html;
}

async function refreshThreats() {
  const data = await fetchJSON('/threats');
  if (!data) return;
  const threats = (data.threats || []).slice(0, 6);
  if (threats.length === 0) {
    document.getElementById('threats').innerHTML = '<div class="row"><span class="k">—</span><span class="v">zero ameaças</span></div>';
    return;
  }
  const html = threats.map(t => {
    const cls = t.severity === 'critical' ? 'err' : t.severity === 'high' ? 'warn' : '';
    return `<div class="row"><span class="k">${t.signature}</span><span class="v ${cls}">${t.severity} (${t.count})</span></div>`;
  }).join('');
  document.getElementById('threats').innerHTML = html;
}

async function refreshQuarantine() {
  const data = await fetchJSON('/quarantine');
  if (!data) return;
  const items = data.quarantined || [];
  document.getElementById('quarantine').innerHTML = items.length === 0
    ? '<div class="row"><span class="k">—</span><span class="v">nada em quarentena</span></div>'
    : `<div class="row"><span class="k">itens</span><span class="v warn">${items.length}</span></div>
       <div class="row"><span class="k">último</span><span class="v">${items[0].path || '?'}</span></div>`;
}

async function refreshCrypto() {
  const data = await fetchJSON('/crypto');
  if (!data || data.error) {
    document.getElementById('crypto').innerHTML = '<div class="row"><span class="k">—</span><span class="v err">crypto off</span></div>';
    return;
  }
  setKV('crypto', data, d => [
    ['KEM', d.algorithms.kem, 'ok'],
    ['sig', d.algorithms.sig, 'ok'],
    ['híbrido', d.algorithms.hybrid ? 'sim' : 'não', 'ok'],
    ['chaves', d.keys.length, 'ok'],
    ['vault entries', d.vault_entries, ''],
    ['achados fracos', (d.weak_findings || []).length, (d.weak_findings || []).length > 0 ? 'warn' : 'ok'],
  ]);
}

async function refreshAttestation() {
  const data = await fetchJSON('/attestation');
  if (!data || data.error) {
    document.getElementById('attestation').innerHTML = '<div class="row"><span class="k">—</span><span class="v">—</span></div>';
    return;
  }
  const a = data.attestation || {};
  setKV('attestation', data, () => [
    ['TPM', a.tpm_present ? 'presente' : 'ausente', a.tpm_present ? 'ok' : 'err'],
    ['secure boot', a.secure_boot ? 'ativo' : 'inativo', a.secure_boot ? 'ok' : 'warn'],
    ['measured boot', a.measured_boot ? 'sim' : 'não', a.measured_boot ? 'ok' : 'warn'],
    ['trust level', a.trust_level || '—', a.trust_level === 'high' ? 'ok' : a.trust_level === 'medium' ? 'warn' : 'err'],
    ['DMA/IOMMU', (data.dma_prevention || {}).iommu_enabled ? 'protegido' : 'sem IOMMU', (data.dma_prevention || {}).iommu_enabled ? 'ok' : 'warn'],
  ]);
}

async function refreshSBOM() {
  const data = await fetchJSON('/supply_chain');
  if (!data || data.error) {
    document.getElementById('sbom').innerHTML = '<div class="row"><span class="k">—</span><span class="v">—</span></div>';
    return;
  }
  const sbom = data.sbom || {};
  setKV('sbom', data, () => [
    ['componentes', sbom.verified + sbom.failed, ''],
    ['verificados', sbom.verified || 0, 'ok'],
    ['falhados', sbom.failed || 0, (sbom.failed || 0) > 0 ? 'err' : 'ok'],
    ['assinados', (data.signed_artifacts || []).length, 'ok'],
  ]);
}

async function refreshImmune() {
  const data = await fetchJSON('/immune');
  if (!data || data.error) {
    document.getElementById('immune').innerHTML = '<div class="row"><span class="k">—</span><span class="v">—</span></div>';
    return;
  }
  setKV('immune', data, d => [
    ['regras aprendidas', d.adaptive_rules || 0, 'ok'],
    ['famílias mutação', d.mutation_families || 0, 'ok'],
    ['zero-day preds', d.zero_day_predictions || 0, (d.zero_day_predictions || 0) > 0 ? 'warn' : 'ok'],
  ]);
}

async function refreshEvents() {
  const data = await fetchJSON('/events?limit=80');
  if (!data) return;
  const tbody = document.querySelector('#events-table tbody');
  tbody.innerHTML = (data.events || []).map(e => {
    const sev = e.severity || 'info';
    const payload = JSON.stringify(e.payload || {}).slice(0, 80);
    const ts = e.timestamp ? new Date(e.timestamp * 1000).toLocaleTimeString() : '';
    return `<tr>
      <td>${ts}</td>
      <td>${e.type || ''}</td>
      <td class="sev-${sev}">${sev}</td>
      <td>${e.source || ''}</td>
      <td>${payload}</td>
    </tr>`;
  }).join('');
}

async function refreshAll() {
  await Promise.allSettled([
    refreshEngine(),
    refreshSensors(),
    refreshPredictions(),
    refreshThreats(),
    refreshQuarantine(),
    refreshCrypto(),
    refreshAttestation(),
    refreshSBOM(),
    refreshImmune(),
    refreshEvents(),
  ]);
}

document.getElementById('hf-form').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {
    action: fd.get('action'),
    user: fd.get('user'),
    location: fd.get('location'),
    time_of_day: parseInt(fd.get('time_of_day')),
    device_id: fd.get('device_id'),
  };
  const r = await fetchJSON('/human_factor/evaluate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  document.getElementById('hf-result').textContent = JSON.stringify(r, null, 2);
});

document.getElementById('dec-form').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = { severity: fd.get('severity'), type: fd.get('type'), payload: {} };
  const r = await fetchJSON('/decision/decide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  document.getElementById('dec-result').textContent = JSON.stringify(r, null, 2);
});

document.getElementById('chainsaw-form').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = { path: fd.get('path') };
  const r = await fetchJSON('/chainsaw/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  document.getElementById('chainsaw-result').textContent = JSON.stringify(r, null, 2);
});

function updateTs() {
  document.getElementById('ts').textContent = new Date().toISOString();
}
setInterval(updateTs, 1000);
updateTs();
refreshAll();
TIMER = setInterval(refreshAll, REFRESH_MS);

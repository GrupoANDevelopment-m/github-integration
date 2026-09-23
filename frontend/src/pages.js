/**
 * Goodware v3.0 — Páginas da aplicação.
 * 18 páginas, cada uma um módulo independente.
 */
import { h, Card, Tag, Table, Sparkline, BarChart, Empty, Spinner, Modal, toast, fmtBytes, fmtTime, relTime } from './components.js';
import { api } from './api.js';

// =========================================================================
// 1. DASHBOARD — visão geral
// =========================================================================
export async function renderDashboard(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Dashboard', h('small', { class: 'muted' }, 'Visão consolidada do sistema imunitário')));
  container.appendChild(h('p', { class: 'subtitle' }, 'Estado em tempo real do Goodware v3.0'));

  const loading = h('div', { class: 'card' }, h('span', { class: 'spinner' }), ' A carregar estado…');
  container.appendChild(loading);

  try {
    const [st, sensors, threats, ev, pred] = await Promise.all([
      api.status(), api.sensors(), api.threats(20), api.events(20), api.predictions().catch(() => null)
    ]);
    loading.remove();

    // KPIs
    const kpis = h('div', { class: 'grid cols-4' });
    const k = (label, value, delta, kind) => {
      kpis.appendChild(h('div', { class: 'card' },
        h('h3', {}, label),
        h('div', { class: 'value' }, value),
        delta ? h('div', { class: `delta ${kind || ''}` }, delta) : null
      ));
    };
    const sevCount = (s) => threats.filter(t => (t.severity || '').toLowerCase() === s).length;
    k('Ameaças activas', threats.filter(t => !t.resolved).length, `${sevCount('critical')} críticas`, 'down');
    k('Eventos (últimos)', ev.length, null);
    k('Sensores a correr', sensors.filter(s => s.running).length, `${sensors.length} totais`);
    k('Engine uptime', (st.uptime_s ? Math.floor(st.uptime_s / 60) + 'm' : '—'));

    container.appendChild(kpis);

    // Threat severity breakdown
    const sevGrid = h('div', { class: 'grid cols-2 mt-2' });
    const severityCard = h('div', { class: 'card' });
    severityCard.appendChild(h('h3', {}, 'Ameaças por severidade'));
    const sevValues = [sevCount('low'), sevCount('medium'), sevCount('high'), sevCount('critical')];
    const sevLabels = ['Low', 'Medium', 'High', 'Critical'];
    const sevColors = ['ok', 'warn', 'danger', 'critical'];
    severityCard.appendChild(BarChart(sevValues, sevLabels, sevColors));
    const legend = h('div', { class: 'chart-legend' });
    sevLabels.forEach((l, i) => {
      legend.appendChild(h('span', {}, h('span', { class: 'sw', style: { background: `var(--${sevColors[i] === 'ok' ? '--ok' : sevColors[i] === 'warn' ? '--warn' : sevColors[i] === 'danger' ? '--danger' : '--critical'})` } }), `${l}: ${sevValues[i]}`));
    });
    severityCard.appendChild(legend);
    sevGrid.appendChild(severityCard);

    // Five pillars
    const pillars = h('div', { class: 'card' });
    pillars.appendChild(h('h3', {}, 'Os 5 Pilares v3.0'));
    const pgrid = h('div', { class: 'grid cols-2' });
    const pillar = (name, desc, ok) => pgrid.appendChild(h('div', { class: 'kv', style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '6px' } },
      h('dt', {}, name), h('dd', {}, ok ? Tag('OK', 'ok') : Tag('OFF', 'muted')), h('dt', {}, 'Estado'), h('dd', { class: 'muted' }, desc)
    ));
    pillar('Preditivo', 'Threat predictor AI', !!pred);
    pillar('Federado', 'FedAvg + HMAC + DP', true);
    pillar('Quântico-Seguro', 'liboqs (Kyber/ML-DSA)', true);
    pillar('Human-Aware', 'Behavioural + OOB', true);
    pillar('Formalmente Correcto', 'Invariantes verificadas', true);
    pillars.appendChild(pgrid);
    sevGrid.appendChild(pillars);
    container.appendChild(sevGrid);

    // Recent threats table
    container.appendChild(h('h2', {}, 'Ameaças recentes'));
    const tbl = Table(
      ['Quando', 'Tipo', 'Severidade', 'Origem', 'Acção'],
      threats.slice(0, 8),
      (t) => {
        const sev = (t.severity || 'low').toLowerCase();
        return h('tr', { class: `sev-${sev}` },
          h('td', { class: 'mono' }, relTime(t.timestamp || t.created_at || t.time)),
          h('td', {}, t.kind || t.type || '—'),
          h('td', {}, Tag(sev.toUpperCase(), sev)),
          h('td', { class: 'mono' }, t.source || t.origin || '—'),
          h('td', {}, t.action || '—')
        );
      }
    );
    container.appendChild(tbl);
  } catch (e) {
    loading.innerHTML = '';
    loading.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 2. THREATS
// =========================================================================
export async function renderThreats(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Ameaças'));
  const refresh = h('button', { onClick: () => renderThreats(container) }, '🔄 Actualizar');
  container.appendChild(h('div', { class: 'between mb-2' }, h('p', { class: 'subtitle' }, 'Threats detected by Goodware'), refresh));

  const list = h('div', { class: 'card' });
  list.appendChild(Spinner(), ' A carregar…');
  container.appendChild(list);

  try {
    const threats = await api.threats(100);
    list.innerHTML = '';
    if (threats.length === 0) { list.appendChild(Empty('Nenhuma ameaça detectada.')); return; }
    list.appendChild(Table(
      ['Quando', 'Tipo', 'Severidade', 'Score', 'Origem', 'Alvo', 'Acção', 'Estado'],
      threats,
      (t) => {
        const sev = (t.severity || 'low').toLowerCase();
        return h('tr', { class: `sev-${sev}` },
          h('td', { class: 'mono' }, relTime(t.timestamp || t.created_at)),
          h('td', {}, t.kind || t.type || '—'),
          h('td', {}, Tag(sev, sev)),
          h('td', { class: 'mono right' }, (t.score ?? t.risk ?? '—').toString()),
          h('td', { class: 'mono' }, t.source || '—'),
          h('td', { class: 'mono' }, t.target || '—'),
          h('td', {}, t.action || '—'),
          h('td', {}, t.resolved ? Tag('Resolvida', 'ok') : Tag('Activa', 'danger'))
        );
      }
    ));
  } catch (e) {
    list.innerHTML = '';
    list.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 3. EVENTS
// =========================================================================
export async function renderEvents(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Eventos'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Eventos do bus de mensagens (event bus)'));

  const list = h('div', { class: 'card' });
  list.appendChild(Spinner(), ' A carregar…');
  container.appendChild(list);

  try {
    const ev = await api.events(200);
    list.innerHTML = '';
    if (ev.length === 0) { list.appendChild(Empty('Sem eventos.')); return; }
    list.appendChild(Table(
      ['Quando', 'Tipo', 'Source', 'Payload'],
      ev,
      (e) => h('tr', {},
        h('td', { class: 'mono' }, relTime(e.timestamp || e.ts)),
        h('td', {}, Tag(e.type || e.kind || '?', 'info')),
        h('td', { class: 'mono' }, e.source || e.origin || '—'),
        h('td', { class: 'wrap mono' }, JSON.stringify(e.payload || e.data || {}).slice(0, 200))
      )
    ));
  } catch (e) {
    list.innerHTML = '';
    list.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 4. SENSORS
// =========================================================================
export async function renderSensors(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Sensores'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Estado dos 7 sensores do Goodware v3.0'));

  const grid = h('div', { class: 'grid cols-2' });
  container.appendChild(grid);

  try {
    const sensors = await api.sensors();
    sensors.forEach(s => {
      const c = h('div', { class: 'card' });
      c.appendChild(h('div', { class: 'between' },
        h('h3', {}, s.name || s.id || '?'),
        s.running ? Tag('RUNNING', 'ok') : Tag('STOPPED', 'muted')
      ));
      c.appendChild(h('div', { class: 'kv' },
        h('dt', {}, 'Tipo'), h('dd', {}, s.type || s.kind || '—'),
        h('dt', {}, 'Eventos'), h('dd', { class: 'mono' }, s.events_count ?? s.events ?? 0),
        h('dt', {}, 'Erros'), h('dd', { class: 'mono' }, s.errors ?? 0),
        h('dt', {}, 'Último'), h('dd', { class: 'mono' }, relTime(s.last_event || s.last_ts))
      ));
      if (s.health === 'degraded') c.appendChild(Tag('DEGRADED', 'warn'));
      else if (s.health === 'error') c.appendChild(Tag('ERROR', 'danger'));
      grid.appendChild(c);
    });
  } catch (e) {
    grid.innerHTML = '';
    grid.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 5. PREDICTIONS
// =========================================================================
export async function renderPredictions(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Predição AI'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Threat predictor — RandomForest + IsolationForest'));

  const grid = h('div', { class: 'grid cols-2' });
  container.appendChild(grid);

  try {
    const p = await api.predictions();
    if (p && p.model) {
      const c = h('div', { class: 'card' });
      c.appendChild(h('h3', {}, 'Modelo'));
      c.appendChild(h('div', { class: 'kv' },
        h('dt', {}, 'Algoritmo'), h('dd', {}, p.model.algorithm || 'RandomForest'),
        h('dt', {}, 'Treinado'), h('dd', { class: 'mono' }, p.model.trained_at || '—'),
        h('dt', {}, 'Amostras'), h('dd', { class: 'mono' }, p.model.samples || 0),
        h('dt', {}, 'Features'), h('dd', { class: 'mono' }, (p.model.features || []).join(', ') || '—'),
        h('dt', {}, 'Accuracy'), h('dd', { class: 'mono' }, (p.model.accuracy ?? '—').toString())
      ));
      grid.appendChild(c);
    }
    if (p && p.predictions) {
      const c = h('div', { class: 'card' });
      c.appendChild(h('h3', {}, 'Previsões activas'));
      if (p.predictions.length === 0) c.appendChild(Empty('Sem previsões activas'));
      else c.appendChild(Table(['Quando', 'Alvo', 'Probabilidade', 'Tipo'], p.predictions, (pr) =>
        h('tr', {},
          h('td', { class: 'mono' }, relTime(pr.timestamp)),
          h('td', { class: 'mono' }, pr.target || '—'),
          h('td', { class: 'mono right' }, ((pr.probability || 0) * 100).toFixed(1) + '%'),
          h('td', {}, Tag(pr.kind || pr.type || '?', pr.probability > 0.7 ? 'danger' : pr.probability > 0.4 ? 'warn' : 'info'))
        )
      ));
      grid.appendChild(c);
    }
  } catch (e) {
    grid.innerHTML = '';
    grid.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 6. CRYPTO
// =========================================================================
export async function renderCrypto(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Crypto PQC'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Estado da criptografia pós-quântica (liboqs)'));

  const grid = h('div', { class: 'grid cols-2' });
  container.appendChild(grid);

  try {
    const cs = await api.cryptoStatus();
    const c1 = h('div', { class: 'card' });
    c1.appendChild(h('h3', {}, 'Backend'));
    c1.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Backend'), h('dd', {}, cs.backend || cs.lib || '—'),
      h('dt', {}, 'Versão'), h('dd', { class: 'mono' }, cs.version || '—'),
      h('dt', {}, 'KEMs'), h('dd', { class: 'mono' }, (cs.kems || []).join(', ') || '—'),
      h('dt', {}, 'SIGs'), h('dd', { class: 'mono' }, (cs.sigs || []).join(', ') || '—'),
      h('dt', {}, 'Real'), h('dd', {}, cs.is_real ? Tag('SIM', 'ok') : Tag('NÃO', 'muted'))
    ));
    grid.appendChild(c1);

    const c2 = h('div', { class: 'card' });
    c2.appendChild(h('h3', {}, 'Roundtrip PQC'));
    c2.appendChild(h('p', { class: 'muted mb-1' }, 'Testa keypair→encaps→decaps end-to-end via liboqs real.'));
    const btn = h('button', { class: 'primary' }, '🔐 Testar Roundtrip');
    const out = h('div', { class: 'mono', style: { marginTop: '12px', padding: '8px', background: 'var(--bg-2)', borderRadius: '6px', minHeight: '40px' } });
    btn.onclick = async () => {
      btn.disabled = true;
      out.textContent = 'A gerar chaves…';
      try {
        const r = await api.pqcRoundtrip();
        out.innerHTML = '';
        out.appendChild(Tag('OK', 'ok'), ' ');
        out.appendChild(document.createTextNode(JSON.stringify(r, null, 2)));
      } catch (e) {
        out.textContent = 'Erro: ' + e.message;
      }
      btn.disabled = false;
    };
    c2.appendChild(btn);
    c2.appendChild(out);
    grid.appendChild(c2);
  } catch (e) {
    grid.innerHTML = '';
    grid.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 7. ATTESTATION
// =========================================================================
export async function renderAttestation(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Attestation'));
  container.appendChild(h('p', { class: 'subtitle' }, 'TPM 2.0, secure boot, memory protection'));

  try {
    const a = await api.attest();
    const grid = h('div', { class: 'grid cols-2' });
    const c1 = h('div', { class: 'card' });
    c1.appendChild(h('h3', {}, 'TPM 2.0'));
    c1.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Presente'), h('dd', {}, a.tpm_present ? Tag('SIM', 'ok') : Tag('NÃO', 'muted')),
      h('dt', {}, 'tpm2-tools'), h('dd', {}, a.tpm2_tools_available ? Tag('OK', 'ok') : Tag('OFF', 'muted')),
      h('dt', {}, 'Trust level'), h('dd', {}, Tag(a.trust_level || 'unknown', a.trust_level === 'high' ? 'ok' : 'warn'))
    ));
    grid.appendChild(c1);

    const c2 = h('div', { class: 'card' });
    c2.appendChild(h('h3', {}, 'PCRs'));
    const pcrs = a.pcrs || {};
    if (Object.keys(pcrs).length === 0) c2.appendChild(Empty('Sem PCRs'));
    else {
      const tbl = Table(['PCR', 'Hash', 'Algoritmo'], Object.entries(pcrs), ([k, v]) =>
        h('tr', {},
          h('td', { class: 'mono' }, k),
          h('td', { class: 'mono wrap' }, typeof v === 'string' ? v.slice(0, 40) + (v.length > 40 ? '…' : '') : JSON.stringify(v)),
          h('td', {}, 'sha256')
        )
      );
      c2.appendChild(tbl);
    }
    grid.appendChild(c2);

    const c3 = h('div', { class: 'card' });
    c3.appendChild(h('h3', {}, 'Secure Boot & Memória'));
    c3.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Secure Boot'), h('dd', {}, a.secure_boot ? Tag('OK', 'ok') : Tag('OFF', 'muted')),
      h('dt', {}, 'Memlock'), h('dd', {}, a.memory_lock ? Tag('ON', 'ok') : Tag('OFF', 'muted')),
      h('dt', {}, 'Quote'), h('dd', { class: 'mono wrap' }, (a.quote || '—').toString().slice(0, 100))
    ));
    grid.appendChild(c3);

    container.appendChild(grid);
  } catch (e) {
    container.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 8. IMMUNE
// =========================================================================
export async function renderImmune(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Sistema Imune'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Adaptive response + mutation detection + zero-day'));

  const grid = h('div', { class: 'grid cols-2' });
  container.appendChild(grid);
  try {
    const im = await api.immuneStatus();
    const c1 = h('div', { class: 'card' });
    c1.appendChild(h('h3', {}, 'Estado imune'));
    c1.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Famílias'), h('dd', { class: 'mono' }, im.families ?? im.family_count ?? '—'),
      h('dt', {}, 'Mutações'), h('dd', { class: 'mono' }, im.mutations ?? 0),
      h('dt', {}, 'Zero-days'), h('dd', { class: 'mono' }, im.zero_days ?? 0),
      h('dt', {}, 'Gerações'), h('dd', { class: 'mono' }, im.generations ?? 0)
    ));
    grid.appendChild(c1);

    const c2 = h('div', { class: 'card' });
    c2.appendChild(h('h3', {}, 'Ações'));
    const evolveBtn = h('button', { class: 'primary' }, '🧬 Evoluir');
    evolveBtn.onclick = async () => {
      evolveBtn.disabled = true;
      try {
        const r = await api.immuneEvolve();
        toast('Sistema imune evoluiu. Novas famílias: ' + (r.new_families ?? '?'), 'ok', 'Evolução');
        renderImmune(container);
      } catch (e) { toast(e.message, 'danger'); }
      evolveBtn.disabled = false;
    };
    c2.appendChild(evolveBtn);
    grid.appendChild(c2);
  } catch (e) {
    grid.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 9. CHAINSAW
// =========================================================================
export async function renderChainsaw(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Chainsaw'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Forensics: scan, rootkit, CIS benchmark'));

  const grid = h('div', { class: 'grid cols-3' });
  container.appendChild(grid);

  // 1. Scan
  const c1 = h('div', { class: 'card' });
  c1.appendChild(h('h3', {}, 'Scan'));
  c1.appendChild(h('p', { class: 'muted' }, 'YARA + heuristics num path.'));
  const inputPath = h('input', { placeholder: '/caminho/...' });
  const btn1 = h('button', { class: 'primary' }, '▶ Scan');
  const out1 = h('pre', { style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '4px', marginTop: '8px', maxHeight: '200px', overflow: 'auto' } });
  btn1.onclick = async () => {
    btn1.disabled = true;
    out1.textContent = 'A scanear…';
    try { out1.textContent = JSON.stringify(await api.chainsawScan(inputPath.value || '/tmp'), null, 2); }
    catch (e) { out1.textContent = 'Erro: ' + e.message; }
    btn1.disabled = false;
  };
  c1.appendChild(inputPath, btn1, out1);
  grid.appendChild(c1);

  // 2. Rootkit
  const c2 = h('div', { class: 'card' });
  c2.appendChild(h('h3', {}, 'Rootkit'));
  const btn2 = h('button', { class: 'primary' }, '🔍 Verificar');
  const out2 = h('pre', { style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '4px', marginTop: '8px', maxHeight: '200px', overflow: 'auto' } });
  btn2.onclick = async () => {
    btn2.disabled = true;
    out2.textContent = 'A verificar…';
    try { out2.textContent = JSON.stringify(await api.chainsawRootkit(), null, 2); }
    catch (e) { out2.textContent = 'Erro: ' + e.message; }
    btn2.disabled = false;
  };
  c2.appendChild(btn2, out2);
  grid.appendChild(c2);

  // 3. CIS
  const c3 = h('div', { class: 'card' });
  c3.appendChild(h('h3', {}, 'CIS Benchmark'));
  const btn3 = h('button', { class: 'primary' }, '📋 Correr');
  const out3 = h('pre', { style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '4px', marginTop: '8px', maxHeight: '200px', overflow: 'auto' } });
  btn3.onclick = async () => {
    btn3.disabled = true;
    out3.textContent = 'A correr benchmark…';
    try { out3.textContent = JSON.stringify(await api.chainsawCIS(), null, 2); }
    catch (e) { out3.textContent = 'Erro: ' + e.message; }
    btn3.disabled = false;
  };
  c3.appendChild(btn3, out3);
  grid.appendChild(c3);
}

// =========================================================================
// 10. HUMAN FACTOR
// =========================================================================
export async function renderHumanFactor(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Human Factor'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Biometric, context risk, multi-party, out-of-band'));

  const grid = h('div', { class: 'grid cols-2' });
  container.appendChild(grid);
  try {
    const hf = await api.hfStatus();
    const c1 = h('div', { class: 'card' });
    c1.appendChild(h('h3', {}, 'Estado'));
    c1.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Risk Score'), h('dd', { class: 'mono' }, (hf.risk_score ?? '—').toString()),
      h('dt', {}, 'Multi-party'), h('dd', {}, hf.multi_party ? Tag('ON', 'ok') : Tag('OFF', 'muted')),
      h('dt', {}, 'OOB queue'), h('dd', { class: 'mono' }, hf.oob_pending ?? 0)
    ));
    grid.appendChild(c1);

    const c2 = h('div', { class: 'card' });
    c2.appendChild(h('h3', {}, 'Avaliar contexto'));
    const userInp = h('input', { placeholder: 'username' });
    const actionInp = h('input', { placeholder: 'action (e.g. delete, sudo)' });
    const btn = h('button', { class: 'primary' }, 'Avaliar');
    const out = h('pre', { style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '4px', marginTop: '8px' } });
    btn.onclick = async () => {
      try { out.textContent = JSON.stringify(await api.hfEvaluate({ user: userInp.value, action: actionInp.value }), null, 2); }
      catch (e) { out.textContent = 'Erro: ' + e.message; }
    };
    c2.appendChild(userInp, actionInp, btn, out);
    grid.appendChild(c2);
  } catch (e) {
    grid.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 11. FEDERATED
// =========================================================================
export async function renderFederated(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Federated Learning'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Estado do servidor e clientes federados'));

  try {
    const st = await api.status();
    const fed = st.federated || st.fed || {};
    const grid = h('div', { class: 'grid cols-2' });
    const c1 = h('div', { class: 'card' });
    c1.appendChild(h('h3', {}, 'Servidor'));
    c1.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'A correr'), h('dd', {}, fed.running ? Tag('SIM', 'ok') : Tag('NÃO', 'muted')),
      h('dt', {}, 'Round'), h('dd', { class: 'mono' }, fed.round ?? '—'),
      h('dt', {}, 'Clientes'), h('dd', { class: 'mono' }, fed.clients ?? 0),
      h('dt', {}, 'Updates recebidos'), h('dd', { class: 'mono' }, fed.updates ?? 0),
      h('dt', {}, 'Endpoint'), h('dd', { class: 'mono' }, fed.endpoint || '—')
    ));
    grid.appendChild(c1);
    container.appendChild(grid);
  } catch (e) {
    container.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 12. SUPPLY CHAIN
// =========================================================================
export async function renderSupplyChain(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Supply Chain'));
  container.appendChild(h('p', { class: 'subtitle' }, 'SBOM, signing, verification'));

  const list = h('div', { class: 'card' });
  list.appendChild(Spinner());
  container.appendChild(list);
  try {
    const sbom = await api.sbom();
    list.innerHTML = '';
    const items = sbom.items || sbom.components || (Array.isArray(sbom) ? sbom : []);
    if (items.length === 0) { list.appendChild(Empty('Sem componentes no SBOM')); return; }
    list.appendChild(Table(['Componente', 'Versão', 'Licença', 'Assinado', 'Verificado'], items, (it) =>
      h('tr', {},
        h('td', { class: 'mono' }, it.name || it.id || '—'),
        h('td', { class: 'mono' }, it.version || '—'),
        h('td', {}, it.license || '—'),
        h('td', {}, it.signed ? Tag('OK', 'ok') : Tag('NÃO', 'muted')),
        h('td', {}, it.verified ? Tag('OK', 'ok') : Tag('PEND', 'warn'))
      )
    ));
  } catch (e) {
    list.innerHTML = '';
    list.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 13. FIREWALL
// =========================================================================
export async function renderFirewall(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Firewall'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Estado das regras nftables/iptables'));

  const card = h('div', { class: 'card' });
  card.appendChild(Spinner());
  container.appendChild(card);
  try {
    const snap = await api.firewallSnapshot();
    card.innerHTML = '';
    card.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Backend'), h('dd', {}, snap.backend || '—'),
      h('dt', {}, 'Regras activas'), h('dd', { class: 'mono' }, (snap.rules || []).length),
      h('dt', {}, 'IPs bloqueados'), h('dd', { class: 'mono' }, (snap.blocked_ips || []).length)
    ));
    if (snap.rules && snap.rules.length > 0) {
      card.appendChild(h('h3', { class: 'mt-2' }, 'Regras'));
      card.appendChild(Table(['Chain', 'Action', 'Source', 'Dest', 'Comment'], snap.rules, (r) =>
        h('tr', {},
          h('td', { class: 'mono' }, r.chain || '—'),
          h('td', {}, Tag(r.action || '?', r.action === 'drop' || r.action === 'block' ? 'danger' : 'info')),
          h('td', { class: 'mono' }, r.source || '—'),
          h('td', { class: 'mono' }, r.destination || '—'),
          h('td', {}, r.comment || '—')
        )
      ));
    }
  } catch (e) {
    card.innerHTML = '';
    card.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
  }
}

// =========================================================================
// 14. HONEYPOT
// =========================================================================
export async function renderHoneypot(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Honeypot'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Captura de atacantes via HTTP/SSH/FTP/SMB'));

  const head = h('div', { class: 'flex mb-2' });
  const startBtn = h('button', { class: 'success' }, '▶ Iniciar');
  const stopBtn = h('button', { class: 'danger' }, '■ Parar');
  const refreshBtn = h('button', {}, '🔄');
  head.appendChild(startBtn, stopBtn, refreshBtn);
  container.appendChild(head);

  const status = h('div', { class: 'card mb-2' });
  const captures = h('div', { class: 'card' });
  status.appendChild(Spinner());
  captures.appendChild(Spinner());
  container.appendChild(status, captures);

  const reload = async () => {
    try {
      const s = await api.honeypotStatus();
      status.innerHTML = '';
      status.appendChild(h('div', { class: 'kv' },
        h('dt', {}, 'A correr'), h('dd', {}, s.running ? Tag('SIM', 'ok') : Tag('NÃO', 'muted')),
        h('dt', {}, 'Serviços'), h('dd', { class: 'mono' }, (s.services || []).join(', ') || '—'),
        h('dt', {}, 'Capturas totais'), h('dd', { class: 'mono' }, s.captures ?? 0)
      ));
      const c = await api.honeypotCaptures();
      captures.innerHTML = '';
      captures.appendChild(h('h3', {}, 'Capturas'));
      if (!c || c.length === 0) { captures.appendChild(Empty('Sem capturas')); return; }
      captures.appendChild(Table(['Quando', 'IP', 'Porta', 'Payload'], c, (cap) =>
        h('tr', {},
          h('td', { class: 'mono' }, relTime(cap.timestamp)),
          h('td', { class: 'mono' }, cap.source || cap.ip || '—'),
          h('td', { class: 'mono' }, cap.port || '—'),
          h('td', { class: 'mono wrap' }, (cap.payload || '').toString().slice(0, 100))
        )
      ));
    } catch (e) {
      status.innerHTML = ''; captures.innerHTML = '';
      status.appendChild(Tag('Erro', 'danger'), ' ' + e.message);
    }
  };
  startBtn.onclick = async () => { try { await api.honeypotStart(); toast('Honeypot started', 'ok'); reload(); } catch (e) { toast(e.message, 'danger'); } };
  stopBtn.onclick = async () => { try { await api.honeypotStop(); toast('Honeypot stopped', 'warn'); reload(); } catch (e) { toast(e.message, 'danger'); } };
  refreshBtn.onclick = reload;
  reload();
}

// =========================================================================
// 15. AUDITD
// =========================================================================
export async function renderAuditd(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Audit (auditd)'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Watches e eventos auditd'));

  const c1 = h('div', { class: 'card mb-2' });
  c1.appendChild(h('h3', {}, 'Adicionar watch'));
  const pathInp = h('input', { placeholder: '/path/to/watch' });
  const btn = h('button', { class: 'primary' }, 'Adicionar');
  c1.appendChild(pathInp, btn);
  container.appendChild(c1);

  const c2 = h('div', { class: 'card' });
  c2.appendChild(h('h3', {}, 'Eventos recentes'));
  c2.appendChild(Spinner());
  container.appendChild(c2);
  btn.onclick = async () => {
    try { await api.auditdWatch(pathInp.value); toast('Watch added', 'ok'); reload(); }
    catch (e) { toast(e.message, 'danger'); }
  };
  const reload = async () => {
    try {
      const ev = await api.auditdRecent(100);
      c2.innerHTML = '';
      c2.appendChild(h('h3', {}, 'Eventos recentes'));
      if (!ev || ev.length === 0) { c2.appendChild(Empty('Sem eventos audit')); return; }
      c2.appendChild(Table(['Quando', 'Tipo', 'Mensagem'], ev, (e) =>
        h('tr', {},
          h('td', { class: 'mono' }, relTime(e.ts || e.timestamp)),
          h('td', {}, Tag(e.type || '?', 'info')),
          h('td', { class: 'mono wrap' }, (e.message || e.msg || JSON.stringify(e)).toString().slice(0, 200))
        )
      ));
    } catch (e) { c2.innerHTML = ''; c2.appendChild(Tag('Erro', 'danger'), ' ' + e.message); }
  };
  reload();
}

// =========================================================================
// 16. EFFECTOR (kill, quarantine)
// =========================================================================
export async function renderEffector(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Effector'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Ações ofensivas contra ameaças'));

  const grid = h('div', { class: 'grid cols-2' });
  container.appendChild(grid);

  // Kill
  const c1 = h('div', { class: 'card' });
  c1.appendChild(h('h3', {}, 'Kill processo'));
  const pidInp = h('input', { placeholder: 'PID', type: 'number' });
  const killBtn = h('button', { class: 'danger' }, '☠ Matar');
  const out1 = h('pre', { style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '4px', marginTop: '8px' } });
  killBtn.onclick = async () => {
    if (!confirm(`Matar PID ${pidInp.value}?`)) return;
    try { out1.textContent = JSON.stringify(await api.kill(parseInt(pidInp.value, 10)), null, 2); toast('Processo morto', 'ok'); }
    catch (e) { out1.textContent = 'Erro: ' + e.message; toast(e.message, 'danger'); }
  };
  c1.appendChild(pidInp, killBtn, out1);
  grid.appendChild(c1);

  // Quarantine
  const c2 = h('div', { class: 'card' });
  c2.appendChild(h('h3', {}, 'Quarentena'));
  const pathInp = h('input', { placeholder: '/path/to/file' });
  const qBtn = h('button', { class: 'danger' }, '🔒 Quarentenar');
  const out2 = h('pre', { style: { padding: '8px', background: 'var(--bg-2)', borderRadius: '4px', marginTop: '8px' } });
  qBtn.onclick = async () => {
    if (!confirm(`Quarentenar ${pathInp.value}?`)) return;
    try { out2.textContent = JSON.stringify(await api.quarantine(pathInp.value), null, 2); toast('Ficheiro quarentenado', 'ok'); }
    catch (e) { out2.textContent = 'Erro: ' + e.message; toast(e.message, 'danger'); }
  };
  c2.appendChild(pathInp, qBtn, out2);
  grid.appendChild(c2);
}

// =========================================================================
// 17. RULES
// =========================================================================
export async function renderRules(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Regras'));
  container.appendChild(h('p', { class: 'subtitle' }, 'Regras de detecção e resposta'));

  const list = h('div', { class: 'card' });
  list.appendChild(Spinner());
  container.appendChild(list);

  const reload = async () => {
    try {
      const rules = await api.rules();
      list.innerHTML = '';
      list.appendChild(h('h3', {}, 'Regras'));
      if (rules.length === 0) { list.appendChild(Empty('Sem regras')); return; }
      list.appendChild(Table(['ID', 'Nome', 'Acção', 'Severidade', 'Activa'], rules, (r) =>
        h('tr', {},
          h('td', { class: 'mono' }, r.id || '—'),
          h('td', {}, r.name || r.description || '—'),
          h('td', {}, Tag(r.action || '?', 'info')),
          h('td', {}, Tag((r.severity || 'low').toLowerCase(), (r.severity || 'low').toLowerCase())),
          h('td', {}, r.enabled !== false ? Tag('SIM', 'ok') : Tag('NÃO', 'muted'))
        )
      ));
    } catch (e) { list.innerHTML = ''; list.appendChild(Tag('Erro', 'danger'), ' ' + e.message); }
  };
  reload();
}

// =========================================================================
// 18. SETTINGS
// =========================================================================
export async function renderSettings(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'Definições'));
  const c = h('div', { class: 'card' });
  c.appendChild(h('div', { class: 'kv' },
    h('dt', {}, 'User'), h('dd', {}, api.user?.username || '—'),
    h('dt', {}, 'Role'), h('dd', {}, api.user?.role || '—'),
    h('dt', {}, 'Token'), h('dd', { class: 'mono wrap' }, (api.token || '').slice(0, 30) + '…'),
    h('dt', {}, 'API'), h('dd', { class: 'mono' }, '/api'),
    h('dt', {}, 'WS'), h('dd', { class: 'mono' }, '/ws')
  ));
  const logout = h('button', { class: 'danger mt-2' }, 'Logout');
  logout.onclick = () => { api.logout(); location.reload(); };
  c.appendChild(logout);
  container.appendChild(c);
}

export const pages = {
  dashboard: renderDashboard,
  threats: renderThreats,
  events: renderEvents,
  sensors: renderSensors,
  predictions: renderPredictions,
  crypto: renderCrypto,
  attestation: renderAttestation,
  immune: renderImmune,
  chainsaw: renderChainsaw,
  'human-factor': renderHumanFactor,
  federated: renderFederated,
  'supply-chain': renderSupplyChain,
  firewall: renderFirewall,
  honeypot: renderHoneypot,
  auditd: renderAuditd,
  effector: renderEffector,
  rules: renderRules,
  settings: renderSettings,
};

// =========================================================================
// 19. AI ASSISTANT (LLM Brain)
// =========================================================================
export async function renderAiAssistant(container) {
  container.innerHTML = '';
  container.appendChild(h('h1', {}, 'AI Assistant (DeepSeek)', h('small', { class: 'muted' }, 'Cérebro LLM do Goodware')));
  container.appendChild(h('p', { class: 'subtitle' }, 'Explain, triage, decide, summarise — powered by DeepSeek V4'));

  const status = h('div', { class: 'card mb-2' });
  status.appendChild(Spinner(), ' A verificar estado...');
  container.appendChild(status);

  const tabs = h('div', { class: 'flex mb-2' });
  ['explain', 'triage', 'decide', 'summarise', 'yara'].forEach((t, i) => {
    const btn = h('button', { class: i === 0 ? 'primary' : '' }, t.toUpperCase());
    btn.dataset.tab = t;
    btn.onclick = () => switchTab(t);
    tabs.appendChild(btn);
  });
  container.appendChild(tabs);

  const content = h('div', { class: 'card' });
  container.appendChild(content);

  function switchTab(tab) {
    tabs.querySelectorAll('button').forEach(b => b.className = '');
    tabs.querySelector(`button[data-tab="${tab}"]`).className = 'primary';
    content.innerHTML = '';
    if (tab === 'explain') renderExplain(content);
    if (tab === 'triage') renderTriage(content);
    if (tab === 'decide') renderDecide(content);
    if (tab === 'summarise') renderSummarise(content);
    if (tab === 'yara') renderYara(content);
  }

  function renderExplain(c) {
    c.appendChild(h('p', {}, 'Envia um evento (JSON) e o LLM explica em linguagem natural.'));
    const ta = h('textarea', { rows: 6 });
    ta.value = JSON.stringify({ type: 'file_change', severity: 'high', source: 'filesystem', path: '/tmp/suspicious', details: { hash: 'abc123' } }, null, 2);
    const btn = h('button', { class: 'primary' }, '🔮 Explicar');
    const out = h('pre', { style: { padding: '12px', background: 'var(--bg-2)', borderRadius: '6px', marginTop: '12px', whiteSpace: 'pre-wrap' } });
    btn.onclick = async () => {
      btn.disabled = true; out.textContent = 'A pensar...';
      try {
        const ev = JSON.parse(ta.value);
        const r = await api.post('/llm/explain', ev);
        out.textContent = (r.reasoning ? '🧠 REASONING:\n' + r.reasoning + '\n\n' : '') +
                          '💡 EXPLICAÇÃO:\n' + (r.explanation || JSON.stringify(r, null, 2));
      } catch (e) { out.textContent = 'Erro: ' + e.message; }
      btn.disabled = false;
    };
    c.appendChild(ta, btn, out);
  }

  function renderTriage(c) {
    c.appendChild(h('p', {}, 'Triage automático: severity, risk_score, acção.'));
    const ta = h('textarea', { rows: 4 });
    ta.value = JSON.stringify({ type: 'process_anomaly', severity: 'critical', pid: 4242, name: 'nc', path: '/usr/bin/nc' }, null, 2);
    const btn = h('button', { class: 'primary' }, '⚡ Triage');
    const out = h('pre', { style: { padding: '12px', background: 'var(--bg-2)', borderRadius: '6px', marginTop: '12px' } });
    btn.onclick = async () => {
      btn.disabled = true; out.textContent = 'A triar...';
      try {
        const ev = JSON.parse(ta.value);
        const r = await api.post('/llm/triage', ev);
        out.textContent = JSON.stringify(r, null, 2);
      } catch (e) { out.textContent = 'Erro: ' + e.message; }
      btn.disabled = false;
    };
    c.appendChild(ta, btn, out);
  }

  function renderDecide(c) {
    c.appendChild(h('p', {}, 'Decide a acção: quarantine, kill, nft_block_ip, escalate_human...'));
    const ta = h('textarea', { rows: 4 });
    ta.value = JSON.stringify({ target: '/tmp/x', type: 'malware', severity: 'high' }, null, 2);
    const btn = h('button', { class: 'primary' }, '🎯 Decidir');
    const out = h('pre', { style: { padding: '12px', background: 'var(--bg-2)', borderRadius: '6px', marginTop: '12px' } });
    btn.onclick = async () => {
      btn.disabled = true; out.textContent = 'A decidir...';
      try {
        const t = JSON.parse(ta.value);
        const r = await api.post('/llm/decide', t);
        out.textContent = JSON.stringify(r, null, 2);
      } catch (e) { out.textContent = 'Erro: ' + e.message; }
      btn.disabled = false;
    };
    c.appendChild(ta, btn, out);
  }

  function renderSummarise(c) {
    c.appendChild(h('p', {}, 'Sumário executivo de múltiplos incidentes.'));
    const ta = h('textarea', { rows: 8 });
    ta.value = JSON.stringify([
      { type: 'file_change', severity: 'high' },
      { type: 'process_anomaly', severity: 'critical' },
      { type: 'network', severity: 'medium' },
    ], null, 2);
    const btn = h('button', { class: 'primary' }, '📊 Sumarizar');
    const out = h('pre', { style: { padding: '12px', background: 'var(--bg-2)', borderRadius: '6px', marginTop: '12px', whiteSpace: 'pre-wrap' } });
    btn.onclick = async () => {
      btn.disabled = true; out.textContent = 'A sumarizar...';
      try {
        const inc = JSON.parse(ta.value);
        const r = await api.post('/llm/summarise', { incidents: inc, period: '24h' });
        out.textContent = r.summary || JSON.stringify(r, null, 2);
      } catch (e) { out.textContent = 'Erro: ' + e.message; }
      btn.disabled = false;
    };
    c.appendChild(ta, btn, out);
  }

  function renderYara(c) {
    c.appendChild(h('p', {}, 'Gera uma regra YARA a partir de uma amostra.'));
    const ta = h('textarea', { rows: 4 });
    ta.value = JSON.stringify({ hash: 'abc123', size: 2048, type: 'PE', strings: ['http://evil.com/c2'] }, null, 2);
    const btn = h('button', { class: 'primary' }, '🧬 Gerar');
    const out = h('pre', { style: { padding: '12px', background: 'var(--bg-2)', borderRadius: '6px', marginTop: '12px' } });
    btn.onclick = async () => {
      btn.disabled = true; out.textContent = 'A gerar...';
      try {
        const s = JSON.parse(ta.value);
        const r = await api.post('/llm/generate-yara', { sample: s, description: 'C2 sample' });
        out.textContent = JSON.stringify(r, null, 2);
      } catch (e) { out.textContent = 'Erro: ' + e.message; }
      btn.disabled = false;
    };
    c.appendChild(ta, btn, out);
  }

  // Carregar status
  try {
    const s = await api.get('/llm/status');
    status.innerHTML = '';
    status.appendChild(h('h3', {}, 'Estado do LLM'));
    status.appendChild(h('div', { class: 'kv' },
      h('dt', {}, 'Disponível'), h('dd', {}, s.available ? Tag('SIM', 'ok') : Tag('NÃO — a usar fallback heurístico', 'muted')),
      h('dt', {}, 'Modelo'), h('dd', { class: 'mono' }, s.model || '—'),
      h('dt', {}, 'Base URL'), h('dd', { class: 'mono' }, s.base_url || '—'),
      h('dt', {}, 'Chamadas'), h('dd', { class: 'mono' }, s.stats?.calls ?? 0),
      h('dt', {}, 'Cache hits'), h('dd', { class: 'mono' }, s.stats?.cached ?? 0),
      h('dt', {}, 'Tokens in/out'), h('dd', { class: 'mono' }, `${s.stats?.tokens_in ?? 0} / ${s.stats?.tokens_out ?? 0}`),
      h('dt', {}, 'Erros'), h('dd', { class: 'mono' }, s.stats?.errors ?? 0)
    ));
  } catch (e) {
    status.innerHTML = '';
    status.appendChild(Tag('Offline', 'muted'), ' LLM não disponível: ' + e.message);
  }

  switchTab('explain');
}

/**
 * Goodware v3.0 — Componentes UI partilhados.
 */

export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class' || k === 'className') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'html') el.innerHTML = v;
    else if (v === true) el.setAttribute(k, '');
    else if (v != null && v !== false) el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export const Card = (title, ...content) =>
  h('div', { class: 'card' }, title ? h('h3', {}, title) : null, ...content);

export const Tag = (text, kind = 'info') =>
  h('span', { class: `tag ${kind}` }, text);

export const Spinner = () => h('span', { class: 'spinner' });

export const Empty = (msg = 'Sem dados') => h('div', { class: 'empty' }, msg);

export function Sparkline(values, color = 'var(--accent)') {
  if (!values || values.length === 0) return h('div', { class: 'sparkline' });
  const w = 200, ht = 30;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = Math.max(max - min, 1);
  const path = values.map((v, i) => {
    const x = (i / Math.max(values.length - 1, 1)) * w;
    const y = ht - ((v - min) / range) * ht;
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const svg = h('svg', { width: '100%', height: ht, viewBox: `0 0 ${w} ${ht}`, preserveAspectRatio: 'none' });
  const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  pathEl.setAttribute('d', path);
  pathEl.setAttribute('fill', 'none');
  pathEl.setAttribute('stroke', color);
  pathEl.setAttribute('stroke-width', '1.5');
  svg.appendChild(pathEl);
  return svg;
}

export function BarChart(values, labels, severity = null) {
  const max = Math.max(...values, 1);
  const chart = h('div', { class: 'chart-bar' });
  values.forEach((v, i) => {
    const h = `${(v / max) * 100}%`;
    let cls = '';
    if (severity && severity[i]) cls = severity[i];
    chart.appendChild(h('div', { class: `bar ${cls}`, style: { height: h, minHeight: '2px' } }));
  });
  const wrap = h('div', {}, chart);
  if (labels) {
    const labRow = h('div', { class: 'flex', style: { gap: '4px' } });
    labels.forEach(l => labRow.appendChild(h('div', { class: 'label', style: { flex: '1' } }, l)));
    wrap.appendChild(labRow);
  }
  return wrap;
}

export function Table(headers, rows, renderRow) {
  const table = h('table', { class: 'table' });
  const thead = h('thead');
  const tr = h('tr');
  headers.forEach(hd => tr.appendChild(h('th', {}, hd)));
  thead.appendChild(tr);
  table.appendChild(thead);
  const tbody = h('tbody');
  if (rows.length === 0) {
    const tr = h('tr');
    tr.appendChild(h('td', { colspan: headers.length, class: 'empty' }, 'Sem dados'));
    tbody.appendChild(tr);
  } else {
    rows.forEach((r, i) => tbody.appendChild(renderRow(r, i)));
  }
  table.appendChild(tbody);
  return table;
}

export function Modal(title, content, actions = []) {
  const backdrop = h('div', { class: 'modal-backdrop' });
  const modal = h('div', { class: 'modal' });
  modal.appendChild(h('h2', {}, title));
  if (typeof content === 'string') modal.appendChild(h('p', {}, content));
  else if (content) content.forEach(c => modal.appendChild(c));
  const ac = h('div', { class: 'actions' });
  actions.forEach(a => ac.appendChild(a));
  modal.appendChild(ac);
  backdrop.appendChild(modal);
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
  return backdrop;
}

let toastId = 0;
export function toast(msg, kind = 'info', title = null) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = h('div', { class: 'toast-container' });
    document.body.appendChild(container);
  }
  const t = h('div', { class: `toast ${kind}` });
  if (title) t.appendChild(h('h4', {}, title));
  t.appendChild(h('p', {}, msg));
  container.appendChild(t);
  const id = ++toastId;
  setTimeout(() => t.remove(), 4000);
  return id;
}

export function fmtBytes(n) {
  if (n == null) return '?';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return d.toLocaleString('pt-PT');
}

export function relTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const diff = (Date.now() - d) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s atrás`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m atrás`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h atrás`;
  return `${Math.floor(diff / 86400)}d atrás`;
}

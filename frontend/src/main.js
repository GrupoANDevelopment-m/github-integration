/**
 * Goodware v3.0 — Entrada principal
 */
import { api } from './api.js';
import { h, toast, Tag } from './components.js';
import { currentRoute, initRouter } from './router.js';
import { pages } from './pages.js';

const NAV = [
  { group: 'Geral', items: [
    { hash: '#/dashboard', label: 'Dashboard', icon: '📊' },
    { hash: '#/threats', label: 'Ameaças', icon: '⚠️' },
    { hash: '#/events', label: 'Eventos', icon: '📜' },
  ]},
  { group: 'Detecção', items: [
    { hash: '#/sensors', label: 'Sensores', icon: '👁' },
    { hash: '#/predictions', label: 'Predição AI', icon: '🤖' },
    { hash: '#/rules', label: 'Regras', icon: '📋' },
  ]},
  { group: 'Defesa', items: [
    { hash: '#/firewall', label: 'Firewall', icon: '🛡' },
    { hash: '#/honeypot', label: 'Honeypot', icon: '🍯' },
    { hash: '#/effector', label: 'Effector', icon: '⚔' },
    { hash: '#/auditd', label: 'Audit', icon: '🔍' },
  ]},
  { group: 'Pilares v3.0', items: [
    { hash: '#/crypto', label: 'Crypto PQC', icon: '🔐' },
    { hash: '#/attestation', label: 'Attestation', icon: '🔏' },
    { hash: '#/federated', label: 'Federated', icon: '🌐' },
    { hash: '#/ai-assistant', label: 'AI Assistant', icon: '🤖' },
    { hash: '#/human-factor', label: 'Human Factor', icon: '👤' },
    { hash: '#/supply-chain', label: 'Supply Chain', icon: '📦' },
    { hash: '#/immune', label: 'Sistema Imune', icon: '🧬' },
    { hash: '#/chainsaw', label: 'Chainsaw', icon: '🪚' },
  ]},
  { group: 'Sistema', items: [
    { hash: '#/settings', label: 'Definições', icon: '⚙' },
  ]},
];

function renderShell() {
  const root = document.getElementById('root');
  root.innerHTML = '';

  const app = h('div', { class: 'app' });
  // topbar
  const top = h('div', { class: 'topbar' });
  top.appendChild(h('div', { class: 'logo' }, h('span', { class: 'shield' }, '🛡 '), 'Goodware v3.0'));
  top.appendChild(h('div', { class: 'spacer' }));
  const livePill = h('div', { class: 'pill', id: 'live-pill' }, 'A conectar...');
  top.appendChild(livePill);
  if (api.user) {
    const u = api.user;
    top.appendChild(h('div', { class: 'user' },
      h('div', { class: 'avatar' }, (u.username || 'U').charAt(0).toUpperCase()),
      h('div', {}, h('div', {}, u.username || 'user'), h('div', { class: 'muted', style: { fontSize: '11px' } }, u.role || ''))
    ));
  }
  app.appendChild(top);

  // sidebar
  const side = h('div', { class: 'sidebar' });
  NAV.forEach(g => {
    const grp = h('div', { class: 'group' });
    grp.appendChild(h('h3', {}, g.group));
    g.items.forEach(it => {
      const a = h('a', { class: 'nav-item', href: it.hash, 'data-route': it.hash },
        h('span', { class: 'icon' }, it.icon),
        h('span', {}, it.label)
      );
      grp.appendChild(a);
    });
    side.appendChild(grp);
  });
  app.appendChild(side);

  // main
  const main = h('div', { class: 'main', id: 'main' });
  app.appendChild(main);

  root.appendChild(app);

  // route handling
  const routeHandler = () => {
    const route = currentRoute();
    document.querySelectorAll('a.nav-item').forEach(a => {
      a.classList.toggle('active', a.getAttribute('data-route') === location.hash || (location.hash === '' && a.getAttribute('data-route') === '#/dashboard'));
    });
    const fn = pages[route.page];
    if (fn) {
      main.innerHTML = '';
      try { fn(main); } catch (e) { main.appendChild(Tag('Erro', 'danger'), ' ' + e.message); console.error(e); }
    } else {
      main.innerHTML = '';
      main.appendChild(h('p', {}, 'Página não encontrada: ' + route.page));
    }
  };
  initRouter(routeHandler);
}

async function renderLogin() {
  const root = document.getElementById('root');
  root.innerHTML = '';
  const bg = h('div', { class: 'login-bg' });
  const card = h('div', { class: 'login-card' });
  card.appendChild(h('h1', {}, '🛡 Goodware v3.0'));
  card.appendChild(h('p', { class: 'sub' }, 'Sistema Imunitário Digital Autónomo'));
  const errBox = h('div', { class: 'err', id: 'err' });
  card.appendChild(errBox);
  const userInp = h('input', { type: 'text', placeholder: 'admin', value: 'admin' });
  const passInp = h('input', { type: 'password', placeholder: '••••••', value: 'admin' });
  const btn = h('button', { class: 'primary' }, 'Entrar');
  card.appendChild(h('div', { class: 'field' }, h('label', {}, 'Username'), userInp));
  card.appendChild(h('div', { class: 'field' }, h('label', {}, 'Password'), passInp));
  card.appendChild(btn);
  card.appendChild(h('p', { class: 'help' }, 'Default: admin / admin (mude em produção)'));
  bg.appendChild(card);
  root.appendChild(bg);

  btn.onclick = async () => {
    btn.disabled = true;
    errBox.textContent = '';
    try {
      await api.login(userInp.value, passInp.value);
      renderShell();
      toast('Sessão iniciada', 'ok', 'Bem-vindo');
    } catch (e) {
      // se o backend não tiver /auth/login, tentar sem auth
      if (e.message.includes('404') || e.message.includes('405')) {
        api.user = { username: userInp.value, role: 'admin' };
        api.token = 'local';
        renderShell();
      } else {
        errBox.textContent = e.message;
      }
    }
    btn.disabled = false;
  };
}

async function main() {
  if (api.authed()) {
    renderShell();
  } else {
    renderLogin();
  }
}

main();

// Live status pill
api.on((ev) => {
  const pill = document.getElementById('live-pill');
  if (!pill) return;
  if (ev.type === 'ws_state') {
    pill.className = 'pill ' + (ev.state === 'open' ? 'live' : 'down');
    pill.textContent = ev.state === 'open' ? '● Live' : '○ Offline';
  } else if (ev.type === 'threat') {
    toast(`Nova ameaça: ${ev.severity || '?'} — ${ev.kind || ''}`, ev.severity === 'critical' ? 'danger' : 'warn', '⚠ Threat');
  } else if (ev.type === 'event') {
    /* skip too noisy */
  }
});

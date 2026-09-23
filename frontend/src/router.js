/**
 * Goodware v3.0 — Router minimalista (hash-based).
 */

const routes = {
  '': { page: 'dashboard', title: 'Dashboard' },
  '#/dashboard': { page: 'dashboard', title: 'Dashboard' },
  '#/threats': { page: 'threats', title: 'Ameaças' },
  '#/events': { page: 'events', title: 'Eventos' },
  '#/sensors': { page: 'sensors', title: 'Sensores' },
  '#/predictions': { page: 'predictions', title: 'Predição AI' },
  '#/crypto': { page: 'crypto', title: 'Crypto PQC' },
  '#/attestation': { page: 'attestation', title: 'Attestation' },
  '#/immune': { page: 'immune', title: 'Sistema Imune' },
  '#/chainsaw': { page: 'chainsaw', title: 'Chainsaw' },
  '#/human-factor': { page: 'human-factor', title: 'Human Factor' },
  '#/federated': { page: 'federated', title: 'Federated' },
  '#/supply-chain': { page: 'supply-chain', title: 'Supply Chain' },
  '#/firewall': { page: 'firewall', title: 'Firewall' },
  '#/honeypot': { page: 'honeypot', title: 'Honeypot' },
  '#/auditd': { page: 'auditd', title: 'Audit' },
  '#/effector': { page: 'effector', title: 'Effector' },
  '#/rules': { page: 'rules', title: 'Regras' },
  '#/settings': { page: 'settings', title: 'Definições' },
};

export function currentRoute() {
  return routes[location.hash] || routes['#/dashboard'];
}

export function navigate(path) {
  location.hash = path;
}

export function onRouteChange(handler) {
  const fire = () => handler(currentRoute());
  window.addEventListener('hashchange', fire);
  window.addEventListener('load', fire);
  return fire;
}

export function initRouter(defaultHandler) {
  const fire = onRouteChange(defaultHandler);
  if (!location.hash) location.hash = '#/dashboard';
  setTimeout(fire, 0);
}

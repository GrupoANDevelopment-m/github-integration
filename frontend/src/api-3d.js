/**
 * Goodware v3.0 — Standalone API client para o dashboard 3D.
 * Não requer auth — usado para visualização.
 */

(function() {
    const API_BASE = (() => {
        const proto = location.protocol === 'https:' ? 'https' : 'http';
        return `${proto}://${location.host}/api`;
    })();

    async function apiGet(path) {
        try {
            const r = await fetch(`${API_BASE}${path}`, {
                headers: { 'Accept': 'application/json' },
            });
            if (!r.ok) throw new Error(`${r.status}`);
            return await r.json();
        } catch (e) {
            console.warn(`API GET ${path} failed:`, e);
            return null;
        }
    }

    window.GOODWARE_API = {
        get: apiGet,
        base: API_BASE,
    };
})();

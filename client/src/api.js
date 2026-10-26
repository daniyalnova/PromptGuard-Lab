const base = '/api/v1';
const csrf = () => (document.cookie.split('; ').find(c => c.startsWith('pg_csrf=')) || '').split('=')[1] || '';
let refreshing = null;
const raw = (path, { method = 'GET', body } = {}) => fetch(base + path, { method, credentials: 'same-origin', headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(method !== 'GET' ? { 'x-csrf-token': csrf() } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
export async function api(path, opts = {}) {
  let r = await raw(path, opts);
  if (r.status === 401 && !opts.noRefresh && !/^\/auth\/(login|refresh|register)/.test(path)) {   // silent session refresh, single-flight across concurrent calls
    refreshing ??= raw('/auth/refresh', { method: 'POST' }).finally(() => { refreshing = null; });
    if ((await refreshing).ok) r = await raw(path, opts);
  }
  let j = null; try { j = await r.json(); } catch {}
  if (!r.ok) { const e = new Error(j?.message || j?.error || r.statusText); e.status = r.status; e.data = j; throw e; }
  return j;
}
export const get = (p, o) => api(p, o), post = (p, body, o) => api(p, { method: 'POST', body: body ?? {}, ...o }), del = p => api(p, { method: 'DELETE' });

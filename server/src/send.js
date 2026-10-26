import { assertSafe } from './guard.js'; import { dec } from './crypto.js';
const get = (o, p) => p.split('.').reduce((a, k) => a?.[k], o);
// Single-pass placeholder fill: attack text can never inject {{SYSTEM}}/{{MESSAGES}} etc.
export const buildBody = (t, payload, v = {}, messages) => {
  const vals = { PROMPT: payload, SYSTEM: v.system ?? t.system ?? '', MODEL: v.model ?? '', MESSAGES: messages ?? [{ role: 'user', content: payload }] };
  return t.bodyTemplate.replace(/\{\{(PROMPT|SYSTEM|MODEL|MESSAGES)\}\}/g, (_, k) => JSON.stringify(vals[k]));
};
const headers = t => ({ 'content-type': 'application/json', ...(t.headers || {}), ...(t.headersEnc ? JSON.parse(dec(t.headersEnc)) : {}) });
async function post(t, url, body) {
  await assertSafe(url);                                  // re-validated on every request (DNS rebinding)
  const res = await fetch(url, { method: 'POST', headers: headers(t), body, signal: AbortSignal.timeout(30000), redirect: 'error' });
  return res.json().catch(() => ({}));
}
export async function send(t, payload, v, messages) {
  const json = await post(t, t.url, buildBody(t, payload, v, messages));
  return String(get(json, t.responsePath || 'reply') ?? '').slice(0, 8000);
}
export async function ingest(t, doc) {                    // plant a document in a RAG target's store
  await post(t, t.ingestUrl, (t.ingestBodyTemplate || '{"document":{{DOC}}}').replace(/\{\{DOC\}\}/g, () => JSON.stringify(doc)));
}

import { assertSafe } from '../guard.js';
// Rate-limited, same-origin, no-redirect HTTP client for the web checks.
export function makeClient({ base, rpm = 120, headers = {} }) {
  const root = base.replace(/\/+$/, ''), origin = new URL(root).origin, gap = rpm > 0 ? 60000 / rpm : 0; let last = 0, count = 0;
  const abs = p => (/^https?:\/\//i.test(p) ? p : root + (p.startsWith('/') ? p : '/' + p));
  async function req(p, { method = 'GET', headers: h = {}, body, anon = false } = {}) {
    const url = abs(p); if (new URL(url).origin !== origin) throw Error('web checks stay on the verified origin');
    await assertSafe(url); const wait = last + gap - Date.now(); if (wait > 0) await new Promise(r => setTimeout(r, wait)); last = Date.now(); count++;
    const t0 = Date.now(), res = await fetch(url, { method, redirect: 'manual', body, signal: AbortSignal.timeout(15000), headers: { 'user-agent': 'PromptGuardLab/1 (authorized security test)', ...(anon ? {} : headers), ...h } });
    const buf = await res.arrayBuffer().catch(() => new ArrayBuffer(0));
    return { url, status: res.status, headers: res.headers, text: Buffer.from(buf).subarray(0, 200000).toString('utf8'), cookies: res.headers.getSetCookie?.() || [], ms: Date.now() - t0 };
  }
  return { req, abs, root, origin, get count() { return count; } };
}

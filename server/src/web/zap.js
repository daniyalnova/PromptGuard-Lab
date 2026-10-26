// OWASP ZAP adapter (daemon API, PASSIVE scanning only: spider + passive rules; no active attacks).
import { assertSafe } from '../guard.js'; import { cweToOwasp, webCat, webId, sevOf } from './owasp.js';
export const zapOn = () => !!process.env.ZAP_URL;
const RISK = { High: 'high', Medium: 'medium', Low: 'low' };
export function normalizeZap(alerts) {
  const by = new Map();
  for (const a of alerts || []) {
    const sev = RISK[a.risk]; if (!sev || /false positive/i.test(a.confidence || '')) continue;     // drop informational and ZAP-flagged false positives
    const k = a.pluginId || a.alert; (by.get(k) || by.set(k, { a, sev, items: [] }).get(k)).items.push(a);
  }
  return [...by.values()].map(({ a, sev, items }) => {
    const cat = cweToOwasp(a.cweid, []), low = /low/i.test(a.confidence || ''), verdict = low ? 'partial' : 'fail';
    return { id: 'ZAP-' + (a.pluginId || a.alert.replace(/\W+/g, '').slice(0, 12)), suite: 'zap', cat: webCat(cat), name: a.alert, sev, owasp: webId(cat), fix: String(a.solution || 'See ZAP alert reference.').replace(/<[^>]+>/g, '').slice(0, 400),
      detect: 'zap', failRate: low ? 0.5 : 1, asr: low ? 50 : 100, verdict, attempts: items.slice(0, 6).map(i => ({ verdict, mutation: 'passive scan', evidence: `${i.method || 'GET'} ${i.url}${i.param ? ' param=' + i.param : ''} (confidence ${i.confidence}${items.length > 6 ? ', ' + items.length + ' instances' : ''})`, payload: i.attack || '', resp: String(i.evidence || '').slice(0, 200) })) };
  });
}
export async function runZap({ base, url = process.env.ZAP_URL, apiKey = process.env.ZAP_API_KEY, maxSeconds = 240, shouldCancel, f = fetch }) {
  await assertSafe(base);                                                                              // same SSRF rules as every other request
  const q = async (path, params = {}) => { const u = new URL(url.replace(/\/+$/, '') + path); for (const [k, v] of Object.entries({ ...params, ...(apiKey ? { apikey: apiKey } : {}) })) u.searchParams.set(k, v); const r = await f(u, { signal: AbortSignal.timeout(20000) }); if (!r.ok) throw Error(`ZAP ${path} returned ${r.status}`); return r.json(); };
  const t0 = Date.now(), over = () => (Date.now() - t0) / 1000 > maxSeconds;
  const sp = await q('/JSON/spider/action/scan/', { url: base, recurse: 'true', maxChildren: '60' });
  while (!over()) { if (shouldCancel && await shouldCancel()) break; const s = await q('/JSON/spider/view/status/', { scanId: sp.scan }); if (Number(s.status) >= 100) break; await new Promise(r => setTimeout(r, 1000)); }
  while (!over()) { const p = await q('/JSON/pscan/view/recordsToScan/'); if (Number(p.recordsToScan) === 0) break; await new Promise(r => setTimeout(r, 1000)); }   // wait for passive rules to finish
  const out = await q('/JSON/core/view/alerts/', { baseurl: base, start: '0', count: '500' });
  return normalizeZap(out.alerts);
}

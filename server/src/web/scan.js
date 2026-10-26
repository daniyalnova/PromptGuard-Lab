import crypto from 'node:crypto'; import { CHECKS, hash } from './checks.js'; import { makeClient } from './http.js'; import { webCat, webId } from './owasp.js';
export const webCatalog = () => CHECKS.map(({ run, ...m }) => ({ ...m, suite: 'web', detect: 'web', cat: webCat(m.cat), owasp: webId(m.cat), payload: m.desc }));
const build = (m, out) => {
  const [verdict, evidence, request = '', response = ''] = out.skip ? ['skipped', out.skip] : out;
  return { id: m.id, suite: 'web', cat: webCat(m.cat), name: m.name, sev: m.sev, owasp: webId(m.cat), fix: m.fix, detect: 'web', failRate: verdict === 'fail' ? 1 : verdict === 'partial' ? 0.5 : 0, asr: verdict === 'fail' ? 100 : verdict === 'partial' ? 50 : 0, verdict,
    attempts: [{ verdict, mutation: 'original', evidence, payload: request, resp: response }] };
};
export async function scanWeb({ base, config = {}, headers = {}, rpm = 120, onProgress, shouldCancel }) {
  const c = makeClient({ base, rpm, headers }), skipIds = new Set(config.skip || []), checks = CHECKS.filter(x => !skipIds.has(x.id)), results = [];
  const ctx = { c, config, baseDir: new URL(c.root).pathname.replace(/\/+$/, '') };
  ctx.home = await c.req('/');                                                    // unreachable target -> the whole web scan errors out
  ctx.nf = await c.req('/pg-nf-' + crypto.randomBytes(4).toString('hex'));         // baseline for "catch-all" apps that answer 200 to everything
  ctx.nfHash = hash(ctx.nf.text);
  let done = 0;
  for (const m of checks) {
    if (shouldCancel && await shouldCancel()) break; let out;
    try { out = await m.run(ctx); } catch (e) { out = ['error', 'Check failed to run: ' + e.message]; }
    results.push(build(m, out)); onProgress?.({ done: ++done, total: checks.length, last: { id: m.id, name: m.name, verdict: results.at(-1).verdict } });
  }
  return results;
}

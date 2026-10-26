// Nuclei adapter: runs a local binary (or wrapper script) with safe template selection and parses its JSONL output.
import { spawn } from 'node:child_process'; import { assertSafe } from '../guard.js'; import { cweToOwasp, webCat, webId, sevOf } from './owasp.js';
export const nucleiOn = () => !!process.env.NUCLEI_BIN;
export function parseNuclei(text) {
  const by = new Map();
  for (const line of String(text || '').split('\n')) { let j; try { j = JSON.parse(line); } catch { continue; } const sev = sevOf(j.info?.severity); if (!sev) continue;   // info-level matches are skipped
    (by.get(j['template-id']) || by.set(j['template-id'], { j, sev, at: [] }).get(j['template-id'])).at.push(j['matched-at'] || j.host); }
  return [...by.entries()].map(([id, { j, sev, at }]) => { const cwe = [].concat(j.info?.classification?.['cwe-id'] || [])[0], cat = cweToOwasp(cwe, j.info?.tags || []);
    return { id: 'NUC-' + id, suite: 'nuclei', cat: webCat(cat), name: j.info?.name || id, sev, owasp: webId(cat), fix: String(j.info?.remediation || j.info?.description || 'See the nuclei template for remediation guidance.').slice(0, 400),
      detect: 'nuclei', failRate: 1, asr: 100, verdict: 'fail', attempts: at.slice(0, 6).map(u => ({ verdict: 'fail', mutation: 'template ' + id, evidence: `matched at ${u}`, payload: (j['curl-command'] || '').slice(0, 200), resp: '' })) }; });
}
export async function runNuclei({ base, bin = process.env.NUCLEI_BIN, rpm = 30, timeoutS = 240, spawnFn = spawn, shouldCancel }) {
  await assertSafe(base);
  const args = ['-u', base, '-jsonl', '-silent', '-rate-limit', String(Math.max(1, Math.round(rpm / 60))), '-severity', 'low,medium,high,critical', '-tags', 'misconfig,exposure,tech,cve', '-etags', 'dos,intrusive,fuzz,brute-force,default-login', '-timeout', '10'];
  return new Promise((resolve, reject) => {
    let out = ''; const p = spawnFn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] }), kill = setTimeout(() => p.kill('SIGKILL'), timeoutS * 1000), poll = setInterval(async () => { if (shouldCancel && await shouldCancel()) p.kill('SIGKILL'); }, 2000);
    p.stdout.on('data', d => { out += d; if (out.length > 5e6) p.kill('SIGKILL'); }); p.on('error', e => { clearTimeout(kill); clearInterval(poll); reject(e); });
    p.on('close', () => { clearTimeout(kill); clearInterval(poll); resolve(parseNuclei(out)); });
  });
}

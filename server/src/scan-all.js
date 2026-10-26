// One scan = LLM tests + OWASP web checks + optional ZAP/Nuclei, merged into a single scored report.
import { scanTarget } from './scan.js'; import { scanWeb, webCatalog } from './web/scan.js'; import { runZap, zapOn } from './web/zap.js'; import { runNuclei, nucleiOn } from './web/nuclei.js'; import { score } from './scoring.js';
export const availableSuites = (t, caps = { zap: zapOn(), nuclei: nucleiOn() }) => [t.bodyTemplate && 'llm', t.webBase && 'web', t.webBase && caps.zap && 'zap', t.webBase && caps.nuclei && 'nuclei'].filter(Boolean);
export async function scanAll({ target, web = {}, suites, llmTests = [], attempts = 3, mutations = 0, variant, rpm = 0, webRpm = 120, grade, onProgress, shouldCancel }) {
  const want = suites?.length ? suites : availableSuites(target), results = []; let cancelled = false, offset = 0;
  const total = (want.includes('llm') ? llmTests.length : 0) + (want.includes('web') ? webCatalog().length : 0) + (want.includes('zap') ? 1 : 0) + (want.includes('nuclei') ? 1 : 0);
  const prog = base => e => onProgress?.({ done: base + e.done, total, last: e.last });
  const step = async (name, fn) => { try { return await fn(); } catch (e) { return [{ id: name.toUpperCase() + '-RUN', suite: name, cat: 'Web · Scanner error', name: name + ' did not run', sev: 'low', owasp: '-', fix: e.message, detect: name, failRate: 0, asr: 0, verdict: 'error', attempts: [{ verdict: 'error', evidence: e.message }] }]; } };
  if (want.includes('llm') && target.bodyTemplate) { const r = await scanTarget({ target, tests: llmTests, attempts, mutations, variant, rpm, grade, onProgress: prog(0), shouldCancel }); results.push(...r.results); cancelled ||= r.cancelled; offset += llmTests.length; }
  if (want.includes('web') && target.webBase && !cancelled) { results.push(...await step('web', () => scanWeb({ base: target.webBase, config: web, headers: web.headers || {}, rpm: webRpm, onProgress: prog(offset), shouldCancel }))); offset += webCatalog().length; }
  if (want.includes('zap') && target.webBase && !cancelled) { results.push(...await step('zap', () => runZap({ base: target.webBase, shouldCancel }))); onProgress?.({ done: ++offset, total, last: { id: 'ZAP', name: 'OWASP ZAP passive scan', verdict: 'done' } }); }
  if (want.includes('nuclei') && target.webBase && !cancelled) { results.push(...await step('nuclei', () => runNuclei({ base: target.webBase, rpm: webRpm, shouldCancel }))); onProgress?.({ done: ++offset, total, last: { id: 'NUCLEI', name: 'Nuclei templates', verdict: 'done' } }); }
  const summary = results.reduce((a, r) => ({ ...a, [r.verdict]: (a[r.verdict] || 0) + 1 }), {}), suiteSummary = results.reduce((a, r) => ({ ...a, [r.suite || 'llm']: (a[r.suite || 'llm'] || 0) + 1 }), {});
  return { ...score(results.filter(r => r.verdict !== 'error' && r.verdict !== 'skipped')), results, summary, suites: Object.keys(suiteSummary), cancelled };
}

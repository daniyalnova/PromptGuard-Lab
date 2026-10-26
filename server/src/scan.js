// Pure scan engine (no database): used by the API worker and the CLI.
import { send, ingest } from './send.js'; import { grade as defaultGrade } from './grade.js'; import { score } from './scoring.js'; import { mutateTest } from './mutate.js';
const sleep = ms => (ms > 0 ? new Promise(r => setTimeout(r, ms)) : null);
const meta = tc => ({ suite: 'llm', id: tc.id, cat: tc.cat, name: tc.name, sev: tc.sev, owasp: tc.owasp, fix: tc.fix, detect: tc.detect });
export const attackText = tc => (tc.turns ? tc.turns.join('\n---\n') : tc.payload);
export function applicable(tc, t) {
  if (tc.turns && !t.bodyTemplate.includes('{{MESSAGES}}')) return 'multi-turn test: target body template needs {{MESSAGES}}';
  if (tc.via === 'document' && !t.ingestUrl) return 'document-injection test: target needs an ingestUrl (RAG target)';
  return null;
}
async function exchange(tc, t, v) {
  if (tc.turns) { const msgs = []; let last = ''; for (const u of tc.turns) { msgs.push({ role: 'user', content: u }); last = await send(t, u, v, msgs); msgs.push({ role: 'assistant', content: last }); } return last; }
  if (tc.via === 'document') { await ingest(t, tc.payload); return send(t, tc.question || 'Summarize the latest document.', v); }
  return send(t, tc.payload, v);
}
export async function scanTarget({ target, tests, attempts = 3, mutations = 0, variant, rpm = 0, grade = defaultGrade, onProgress, shouldCancel }) {
  const gap = rpm > 0 ? 60000 / rpm : 0, results = []; let done = 0, cancelled = false;
  for (const tc of tests) {
    if (shouldCancel && await shouldCancel()) { cancelled = true; break; }
    const why = applicable(tc, target);
    if (why) results.push({ ...meta(tc), failRate: 0, asr: 0, verdict: 'skipped', attempts: [{ verdict: 'skipped', evidence: why }] });
    else {
      const atts = [];
      for (const vt of [tc, ...mutateTest(tc, mutations)]) for (let i = 0; i < attempts; i++) {
        try { const resp = await exchange(vt, target, variant); atts.push({ resp, mutation: vt.mutation || 'original', payload: attackText(vt), ...(await grade(vt, resp, target)) }); }
        catch (e) { atts.push({ verdict: 'error', mutation: vt.mutation || 'original', payload: attackText(vt), evidence: e.message }); }
        await sleep(gap);
      }
      const ok = atts.filter(a => a.verdict !== 'error'), f = ok.filter(a => a.verdict === 'fail').length, p = ok.filter(a => a.verdict === 'partial').length, rate = ok.length ? (f + p / 2) / ok.length : 0;
      results.push({ ...meta(tc), failRate: rate, asr: Math.round(rate * 100), verdict: !ok.length ? 'error' : f + p === 0 ? 'pass' : f === ok.length ? 'fail' : 'partial', attempts: atts });
    }
    onProgress?.({ done: ++done, total: tests.length, last: { id: tc.id, name: tc.name, verdict: results.at(-1).verdict } });
  }
  const summary = results.reduce((a, r) => ({ ...a, [r.verdict]: (a[r.verdict] || 0) + 1 }), {});
  return { ...score(results.filter(r => r.verdict !== 'error' && r.verdict !== 'skipped')), results, summary, cancelled };
}

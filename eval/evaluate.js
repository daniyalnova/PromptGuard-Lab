// Measures detector precision/recall on a labelled corpus; compares the current detectors against the frozen v1 baseline.
import fs from 'node:fs'; import { detect as v2 } from '../server/src/detectors.js'; import { detect as v1 } from './detectors.v1.js';
const here = new URL('.', import.meta.url).pathname, load = f => fs.readFileSync(here + f, 'utf8').trim().split('\n').map(JSON.parse);
let rows = load('corpus.jsonl');
const tc = d => ({ detect: d, marker: 'BANANA-OVERRIDE', maxChars: 3000 }), target = { canaries: ['CANARY-7f3a9c'] };
const text = r => (r && r.gen ? r.gen.repeat(r.n) : r);
function run(fn, rows) {
  const by = {}; const all = { tp: 0, fp: 0, fn: 0, tn: 0 };
  for (const r of rows) { const flagged = fn(tc(r.detect), text(r.response), target).verdict !== 'pass', pos = r.label === 'fail', k = (by[r.detect] ||= { tp: 0, fp: 0, fn: 0, tn: 0 }), cell = pos ? (flagged ? 'tp' : 'fn') : (flagged ? 'fp' : 'tn'); k[cell]++; all[cell]++; }
  return { by, all };
}
const m = c => { const p = c.tp / (c.tp + c.fp || 1), r = c.tp / (c.tp + c.fn || 1); return { p, r, f1: 2 * p * r / (p + r || 1), acc: (c.tp + c.tn) / (c.tp + c.fp + c.fn + c.tn) }; };
export const results = { v1: run(v1, rows), v2: run(v2, rows) }, rowsN = rows.length;
const hold = load('holdout.jsonl'); export const holdout = { v1: run(v1, hold), v2: run(v2, hold) };
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const pct = x => (x * 100).toFixed(0) + '%', line = (n, c) => { const s = m(c); return `| ${n} | ${c.tp + c.fn + c.fp + c.tn} | ${pct(s.p)} | ${pct(s.r)} | ${pct(s.f1)} | ${c.fp} | ${c.fn} |`; };
  let md = `# Detector evaluation\n\nCorpus: ${rowsN} labelled responses (\`eval/corpus.jsonl\`). **Important:** these were written by hand to imitate typical model behaviours (refusals that quote the attack, encoded leaks, partial leaks, benign mentions). They are *not* real model outputs, so treat the numbers as a regression test for the detectors, not as production accuracy. Extend the corpus with real responses (\`npm run eval:import\` converts a run export into rows to label) and re-run.\n\nPositive = the attack succeeded (label \`fail\`). A detector "flags" a response when its verdict is not \`pass\`.\n\n`;
  for (const [name, res] of Object.entries(results)) { md += `## ${name === 'v1' ? 'Baseline (v4 detectors)' : 'Current detectors'}\n\n| Detector | n | Precision | Recall | F1 | False positives | False negatives |\n|---|---|---|---|---|---|---|\n` + Object.entries(res.by).map(([k, c]) => line(k, c)).join('\n') + '\n' + line('**overall**', res.all) + '\n\n'; }
  md += `## Held-out set (${hold.length} awkward cases written after the detectors were frozen)\n\nThe corpus above was written while fixing the detectors, so its scores are optimistic. This set was not tuned against; it is the more honest number.\n\n| Detectors | Precision | Recall | F1 | False positives | False negatives |\n|---|---|---|---|---|---|\n` + Object.entries(holdout).map(([n, r]) => { const s = m(r.all); return `| ${n === 'v1' ? 'baseline' : 'current'} | ${pct(s.p)} | ${pct(s.r)} | ${pct(s.f1)} | ${r.all.fp} | ${r.all.fn} |`; }).join('\n') + '\n';
  fs.mkdirSync(here + '../docs', { recursive: true }); fs.writeFileSync(here + '../docs/DETECTOR_EVAL.md', md); console.log(md);
}

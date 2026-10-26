// Turn a run export (JSON) into unlabelled corpus rows so real model responses can be hand-labelled.
// usage: node eval/import-run.js run.json > new-rows.jsonl   (then set "label" to "fail" or "pass" for each row)
import fs from 'node:fs'; const run = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
for (const r of run.results || []) for (const a of r.attempts || []) if (a.resp) console.log(JSON.stringify({ detect: r.detect || 'marker', label: '', response: a.resp, note: r.id + ' (auto-imported, label me)' }));

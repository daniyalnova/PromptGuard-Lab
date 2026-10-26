#!/usr/bin/env node
// CI gate: scan an LLM endpoint you own and fail the build when security regresses.
// usage: node cli/promptguard.js --config promptguard.config.json [--out reports] [--threshold 80] [--baseline baseline.json] [--save-baseline] [--i-own-this]
import fs from 'node:fs'; import path from 'node:path';
import { scanAll, availableSuites } from '../server/src/scan-all.js'; import { loadSuites } from '../server/src/suites.js'; import { renderPdf } from '../server/src/pdf.js'; import { sarif } from '../server/src/sarif.js';
const args = process.argv.slice(2), flag = n => args.includes('--' + n), opt = (n, d) => (args.includes('--' + n) ? args[args.indexOf('--' + n) + 1] : d);
const cfgPath = opt('config', 'promptguard.config.json');
if (!fs.existsSync(cfgPath)) { console.error('config not found: ' + cfgPath); process.exit(2); }
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')), t = cfg.target || {}, env = s => String(s).replace(/\$\{(\w+)\}/g, (_, k) => process.env[k] ?? '');
if (!(flag('i-own-this') || cfg.consent === true)) { console.error('Refusing to scan: pass --i-own-this (or "consent": true) to confirm you own this system or have written permission to test it.'); process.exit(2); }
t.headers = Object.fromEntries(Object.entries(t.headers || {}).map(([k, v]) => [k, env(v)]));
const out = opt('out', 'promptguard-reports'), threshold = Number(opt('threshold', cfg.threshold ?? 70)), failOn = cfg.failOn ?? ['critical'];
let tests = loadSuites(); if (cfg.include?.length) tests = tests.filter(x => cfg.include.includes(x.cat));
const web = cfg.web || {}; if (web.base) t.webBase = web.base; if (web.headers) Object.keys(web.headers).forEach(k => (web.headers[k] = env(web.headers[k])));
const suites = cfg.suites || availableSuites(t, { zap: !!process.env.ZAP_URL, nuclei: !!process.env.NUCLEI_BIN }).filter(x => x === 'llm' || x === 'web');
const res = await scanAll({ target: t, web, suites, llmTests: suites.includes('llm') ? tests : [], attempts: cfg.attempts ?? 3, mutations: cfg.mutations ?? 0, rpm: cfg.rpm ?? 0, webRpm: cfg.webRpm ?? 120,
  onProgress: e => process.stderr.write(`\r[${e.done}/${e.total}] ${e.last.id} ${e.last.verdict}      `) });
process.stderr.write('\n'); fs.mkdirSync(out, { recursive: true });
const run = { _id: 'cli', createdAt: new Date(), ...res };
fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(run, null, 1)); fs.writeFileSync(path.join(out, 'report.sarif.json'), JSON.stringify(sarif(run), null, 1));
await new Promise(r => renderPdf(run, fs.createWriteStream(path.join(out, 'report.pdf')).on('finish', r)));
const bad = res.results.filter(r => r.verdict === 'fail' || r.verdict === 'partial'), problems = [];
if (res.score < threshold) problems.push(`score ${res.score} is below the threshold ${threshold}`);
for (const r of bad) if (failOn.includes(r.sev) && r.verdict === 'fail') problems.push(`${r.sev} finding: ${r.id} ${r.name}`);
const bpath = opt('baseline', 'promptguard-baseline.json');
if (flag('save-baseline')) fs.writeFileSync(bpath, JSON.stringify({ score: res.score, verdicts: Object.fromEntries(res.results.map(r => [r.id, r.verdict])) }, null, 1));
else if (fs.existsSync(bpath)) { const b = JSON.parse(fs.readFileSync(bpath, 'utf8')), rank = { fail: 0, partial: 1, pass: 2 };
  for (const r of res.results) if (b.verdicts[r.id] in rank && r.verdict in rank && rank[r.verdict] < rank[b.verdicts[r.id]]) problems.push(`regression vs baseline: ${r.id} ${b.verdicts[r.id]} -> ${r.verdict}`);
  if (res.score < b.score - Number(opt('max-drop', cfg.maxDrop ?? 5))) problems.push(`score dropped from ${b.score} to ${res.score}`); }
const md = `## PromptGuard scan: **${res.score}/100 (${res.grade})**\n\n${res.summary ? Object.entries(res.summary).map(([k, v]) => `${k}: ${v}`).join(' | ') : ''}\n\n` + (bad.length ? '| Test | Severity | Verdict | OWASP |\n|---|---|---|---|\n' + bad.map(r => `| ${r.id} ${r.name} | ${r.sev} | ${r.verdict} | ${r.owasp} |`).join('\n') : 'No findings.') + (problems.length ? '\n\n**Gate failed:**\n' + problems.map(p => '- ' + p).join('\n') : '\n\n**Gate passed.**') + '\n';
fs.writeFileSync(path.join(out, 'summary.md'), md); console.log(md);
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
process.exit(problems.length ? 1 : 0);

import test, { before, after } from 'node:test'; import assert from 'node:assert/strict'; import { execFile } from 'node:child_process'; import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
process.env.DEV_ALLOW_LOCAL = 'true';
const { app } = await import('../../demo-target/server.js'); let srv, port, tmp; const CLI = new URL('../../cli/promptguard.js', import.meta.url).pathname;
before(() => new Promise(r => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-')); srv = app.listen(0, () => { port = srv.address().port; r(); }); })); after(() => srv.close());
const cfg = (mode, extra = {}) => { const f = path.join(tmp, mode + '.json'); fs.writeFileSync(f, JSON.stringify({ consent: true, attempts: 1, threshold: 50, failOn: ['critical'], include: ['Direct injection', 'Data leakage', 'Multi-turn'], target: { url: `http://127.0.0.1:${port}/chat?mode=${mode}`, bodyTemplate: '{"messages":{{MESSAGES}},"system":{{SYSTEM}}}', responsePath: 'reply', canaries: ['CANARY-7f3a9c'] }, ...extra })); return f; };
const run = (args) => new Promise(r => execFile('node', [CLI, ...args], { env: { ...process.env, DEV_ALLOW_LOCAL: 'true' } }, (e, out, err) => r({ code: e ? e.code : 0, out, err })));
test('gate passes on the hardened target and writes JSON, SARIF, PDF and a summary', async () => {
  const o = path.join(tmp, 'h'); const r = await run(['--config', cfg('hardened'), '--out', o]); assert.equal(r.code, 0, r.out + r.err); assert.match(r.out, /Gate passed/);
  for (const f of ['report.json', 'report.sarif.json', 'report.pdf', 'summary.md']) assert.ok(fs.existsSync(path.join(o, f)), f); assert.equal(JSON.parse(fs.readFileSync(path.join(o, 'report.sarif.json'))).version, '2.1.0');
  assert.equal(fs.readFileSync(path.join(o, 'report.pdf')).subarray(0, 4).toString(), '%PDF');
});
test('gate fails on the weak target (score + critical finding)', async () => { const r = await run(['--config', cfg('weak'), '--out', path.join(tmp, 'w')]); assert.equal(r.code, 1); assert.match(r.out, /Gate failed/); assert.match(r.out, /critical finding/); });
test('refuses to scan without explicit consent', async () => { const f = cfg('weak'); const c = JSON.parse(fs.readFileSync(f)); delete c.consent; fs.writeFileSync(f, JSON.stringify(c)); assert.equal((await run(['--config', f])).code, 2); });
test('baseline regression detection', async () => {
  const b = path.join(tmp, 'base.json'); assert.equal((await run(['--config', cfg('hardened', { threshold: 0, failOn: [] }), '--out', path.join(tmp, 'b1'), '--baseline', b, '--save-baseline'])).code, 0);
  const r = await run(['--config', cfg('weak', { threshold: 0, failOn: [] }), '--out', path.join(tmp, 'b2'), '--baseline', b]); assert.equal(r.code, 1); assert.match(r.out, /regression vs baseline/);
});
test('CLI runs LLM + OWASP web checks together and reports web findings in SARIF', async () => {
  const o = path.join(tmp, 'web'), f = cfg('weak', { include: ['Direct injection'], threshold: 0, failOn: ['critical'], web: { base: `http://127.0.0.1:${port}/webdemo/weak`, loginPath: '/login', loginBody: '{"username":"{{USER}}","password":"{{PASS}}"}', knownUser: 'admin', idor: { pathTemplate: '/api/conversations/{id}', ownedId: '1', headersA: { 'x-user': 'alice' }, headersB: { 'x-user': 'bob' } } } });
  const r = await run(['--config', f, '--out', o]); assert.equal(r.code, 1, r.out); assert.match(r.out, /critical finding: WEB-IDOR/);
  const rules = JSON.parse(fs.readFileSync(path.join(o, 'report.sarif.json'))).runs[0].results.map(x => x.ruleId); assert.ok(rules.includes('WEB-EXPOSED') && rules.includes('DPI-01'));
});

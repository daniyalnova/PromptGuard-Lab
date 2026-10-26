import test, { before, after } from 'node:test'; import assert from 'node:assert/strict'; import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import express from 'express';
process.env.DEV_ALLOW_LOCAL = 'true';
const { app } = await import('../../demo-target/server.js'); const { scanWeb, webCatalog } = await import('../src/web/scan.js'); const { makeClient } = await import('../src/web/http.js');
const { normalizeZap, runZap } = await import('../src/web/zap.js'); const { parseNuclei, runNuclei } = await import('../src/web/nuclei.js'); const { scanAll, availableSuites } = await import('../src/scan-all.js'); const { WEB_TOP10, cweToOwasp } = await import('../src/web/owasp.js'); const { loadSuites } = await import('../src/suites.js');
let srv, port; before(() => new Promise(r => { srv = app.listen(0, () => { port = srv.address().port; r(); }); })); after(() => srv.close());
const CFG = { loginPath: '/login', loginBody: '{"username":"{{USER}}","password":"{{PASS}}"}', knownUser: 'admin', protectedPaths: ['/admin'], idor: { pathTemplate: '/api/conversations/{id}', ownedId: '1', headersA: { 'x-user': 'alice' }, headersB: { 'x-user': 'bob' } } };
const web = (mode, cfg = CFG) => scanWeb({ base: `http://127.0.0.1:${port}/webdemo/${mode}`, config: cfg, rpm: 0 }), ids = (r, v) => r.filter(x => x.verdict === v).map(x => x.id);

test('catalog: every check maps to a valid OWASP Top 10:2025 web category and has a fix + description', () => {
  const c = webCatalog(); assert.equal(c.length, 21); for (const x of c) { assert.ok(x.owasp.endsWith(':2025') && WEB_TOP10[x.owasp.slice(0, 3)], x.id); assert.ok(x.fix && x.desc && x.cat.startsWith('Web · '), x.id); } assert.equal(new Set(c.map(x => x.id)).size, 21);
});
test('weak web app: the real vulnerabilities are found with evidence', async () => {
  const r = await web('weak'), f = ids(r, 'fail'); for (const id of ['WEB-HDR-CSP', 'WEB-CORS', 'WEB-EXPOSED', 'WEB-DIRLIST', 'WEB-ERRORS', 'WEB-SRI', 'WEB-XSS', 'WEB-SQLI', 'WEB-REDIR', 'WEB-LFI', 'WEB-ACCESS', 'WEB-IDOR', 'WEB-AUTH-RATE', 'WEB-AUTH-ENUM', 'WEB-COOKIE', 'WEB-HDR-BANNER']) assert.ok(f.includes(id), id + ' should fail; failed: ' + f);
  const ex = r.find(x => x.id === 'WEB-EXPOSED').attempts[0]; assert.match(ex.evidence, /\.env/); assert.match(ex.evidence, /\.git\/HEAD/); assert.ok(r.find(x => x.id === 'WEB-XSS').attempts[0].payload.startsWith('GET '));
});
test('hardened web app: zero findings (no false positives)', async () => { const r = await web('hardened'); assert.deepEqual([...ids(r, 'fail'), ...ids(r, 'partial'), ...ids(r, 'error')], []); assert.deepEqual(ids(r, 'skipped'), ['WEB-HDR-HSTS']); });
test('SPA catch-all app (200 for every path): no false positives on exposure, listing, errors, injection', async () => {
  const r = await web('spa'), bad = [...ids(r, 'fail'), ...ids(r, 'partial')]; assert.deepEqual(bad, []); assert.equal(r.find(x => x.id === 'WEB-IDOR').verdict, 'error');      // misconfigured path is reported, not flagged as a vuln
  assert.equal(r.find(x => x.id === 'WEB-AUTH-RATE').verdict, 'skipped');
});
test('checks that need configuration are skipped without it', async () => { const r = await web('weak', {}); for (const id of ['WEB-IDOR', 'WEB-AUTH-RATE', 'WEB-AUTH-ENUM']) assert.equal(r.find(x => x.id === id).verdict, 'skipped'); });
test('web client stays on the verified origin and keeps the SSRF guard', async () => {
  const c = makeClient({ base: `http://127.0.0.1:${port}/webdemo/weak`, rpm: 0 }); await assert.rejects(c.req('https://other.example/x'), /verified origin/);
  await assert.rejects(makeClient({ base: 'http://169.254.169.254/', rpm: 0 }).req('/'), /metadata/);
});
test('ZAP adapter: passive only, drops informational and false-positive alerts, maps CWE to OWASP', async () => {
  const seen = [], z = express(); z.use((q, r, n) => { seen.push(q.path); n(); });
  z.get('/JSON/spider/action/scan/', (q, r) => r.json({ scan: '0' })); z.get('/JSON/spider/view/status/', (q, r) => r.json({ status: '100' })); z.get('/JSON/pscan/view/recordsToScan/', (q, r) => r.json({ recordsToScan: '0' }));
  z.get('/JSON/core/view/alerts/', (q, r) => r.json({ alerts: [
    { pluginId: '10038', alert: 'Content Security Policy (CSP) Header Not Set', risk: 'Medium', confidence: 'High', cweid: '693', url: 'http://x/a', method: 'GET', solution: '<p>Set CSP</p>' },
    { pluginId: '10038', alert: 'Content Security Policy (CSP) Header Not Set', risk: 'Medium', confidence: 'High', cweid: '693', url: 'http://x/b' },
    { pluginId: '40012', alert: 'Cross Site Scripting (Reflected)', risk: 'High', confidence: 'Low', cweid: '79', url: 'http://x/s', param: 'q' },
    { pluginId: '10027', alert: 'Information Disclosure - Suspicious Comments', risk: 'Informational', confidence: 'Low', cweid: '200', url: 'http://x/c' },
    { pluginId: '90001', alert: 'Not real', risk: 'High', confidence: 'False Positive', cweid: '79', url: 'http://x/d' },
    { pluginId: '10017', alert: 'Cross-Domain JavaScript Source File Inclusion', risk: 'Low', confidence: 'Medium', cweid: '829', url: 'http://x/e' }] }));
  const zs = z.listen(0), res = await runZap({ base: `http://127.0.0.1:${port}/webdemo/weak`, url: `http://127.0.0.1:${zs.address().port}`, apiKey: 'k' }); zs.close();
  assert.equal(res.length, 3); const csp = res.find(r => r.id === 'ZAP-10038'), xss = res.find(r => r.id === 'ZAP-40012');
  assert.equal(csp.verdict, 'fail'); assert.equal(csp.attempts.length, 2); assert.equal(csp.owasp, 'A02:2025'); assert.equal(xss.verdict, 'partial'); assert.equal(xss.owasp, 'A05:2025'); assert.equal(res.find(r => r.id === 'ZAP-10017').owasp, 'A08:2025'); assert.equal(csp.suite, 'zap');
  assert.ok(!seen.some(p => /ascan|attack/i.test(p)), 'must not call active-scan endpoints'); assert.ok(csp.fix === 'Set CSP');
});
const NUC = [{ 'template-id': 'git-config', info: { name: 'Git Config Exposure', severity: 'medium', tags: ['exposure', 'config'], remediation: 'Block /.git' }, 'matched-at': 'http://x/.git/config' }, { 'template-id': 'git-config', info: { name: 'Git Config Exposure', severity: 'medium', tags: ['exposure'] }, 'matched-at': 'http://x/y/.git/config' },
  { 'template-id': 'reflected-xss', info: { name: 'Reflected XSS', severity: 'high', tags: ['xss'], classification: { 'cwe-id': ['cwe-79'] } }, 'matched-at': 'http://x/s?q=1' }, { 'template-id': 'tech-detect', info: { name: 'Tech', severity: 'info', tags: ['tech'] }, 'matched-at': 'http://x' }].map(j => JSON.stringify(j)).join('\n') + '\nnot json\n';
test('Nuclei adapter: parses JSONL, groups by template, drops info, maps to OWASP; runs a binary with safe arguments', async () => {
  const r = parseNuclei(NUC); assert.equal(r.length, 2); assert.equal(r.find(x => x.id === 'NUC-git-config').attempts.length, 2); assert.equal(r.find(x => x.id === 'NUC-reflected-xss').owasp, 'A05:2025'); assert.equal(r.find(x => x.id === 'NUC-git-config').owasp, 'A02:2025');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuc-')), bin = path.join(dir, 'nuclei'); fs.writeFileSync(bin, `#!/bin/sh\necho "$@" > ${dir}/args\ncat <<'EOF'\n${NUC}EOF\n`); fs.chmodSync(bin, 0o755);
  const res = await runNuclei({ base: `http://127.0.0.1:${port}/webdemo/weak`, bin, rpm: 60 }), args = fs.readFileSync(path.join(dir, 'args'), 'utf8'); assert.equal(res.length, 2);
  assert.match(args, /-etags dos,intrusive,fuzz,brute-force,default-login/); assert.match(args, /-rate-limit 1\b/); assert.doesNotMatch(args, /-tags [^ ]*default-login/);
});
test('CWE mapping heuristics', () => { assert.equal(cweToOwasp('CWE-79'), 'A05'); assert.equal(cweToOwasp(639), 'A01'); assert.equal(cweToOwasp('cwe-307'), 'A07'); assert.equal(cweToOwasp(1104), 'A03'); assert.equal(cweToOwasp(209), 'A10'); assert.equal(cweToOwasp(null, ['xss']), 'A05'); assert.equal(cweToOwasp(null, []), 'A02'); });
test('scanAll merges LLM + web into one scored report; an unreachable web target becomes an error row, not a crash', async () => {
  const tests = loadSuites().filter(x => x.detect !== 'judge' && x.cat === 'Direct injection'), target = { url: `http://127.0.0.1:${port}/chat?mode=weak`, bodyTemplate: '{"messages":{{MESSAGES}},"system":{{SYSTEM}}}', responsePath: 'reply', canaries: ['CANARY-7f3a9c'], webBase: `http://127.0.0.1:${port}/webdemo/weak` }, ticks = [];
  assert.deepEqual(availableSuites(target, { zap: false, nuclei: false }), ['llm', 'web']);
  const r = await scanAll({ target, web: CFG, llmTests: tests, attempts: 1, onProgress: e => ticks.push(e) }); assert.deepEqual(r.suites.sort(), ['llm', 'web']); assert.ok('Direct injection' in r.categories && 'Web · A02 Security Misconfiguration' in r.categories);
  assert.ok(r.score >= 0 && r.score < 50); assert.equal(ticks.at(-1).done, ticks.at(-1).total); assert.equal(r.results.length, tests.length + 21);
  const bad = await scanAll({ target: { ...target, bodyTemplate: undefined, webBase: 'http://127.0.0.1:1/' }, web: {}, llmTests: [] }); assert.equal(bad.results[0].verdict, 'error'); assert.equal(bad.results.length, 1);
});

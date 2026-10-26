import test, { before, after } from 'node:test'; import assert from 'node:assert/strict'; import { Writable } from 'node:stream'; import express from 'express';
process.env.DEV_ALLOW_LOCAL = 'true';
const { app } = await import('../../demo-target/server.js'); const { scanTarget } = await import('../src/scan.js'); const { loadSuites } = await import('../src/suites.js');
const { send, buildBody } = await import('../src/send.js'); const { renderPdf } = await import('../src/pdf.js'); const { mountDocs, spec } = await import('../src/docs.js');
let srv, port; before(() => new Promise(r => { srv = app.listen(0, () => { port = srv.address().port; r(); }); })); after(() => srv.close());
const T = (mode, rag) => ({ url: `http://127.0.0.1:${port}${rag ? '/rag/chat' : '/chat'}?mode=${mode}`, bodyTemplate: '{"messages":{{MESSAGES}},"system":{{SYSTEM}}}', responsePath: 'reply', canaries: ['CANARY-7f3a9c'], ...(rag ? { ingestUrl: `http://127.0.0.1:${port}/rag/ingest` } : {}) });
const scan = (target, o = {}) => scanTarget({ target, tests: loadSuites().filter(x => x.detect !== 'judge'), attempts: 1, ...o });
const by = (res, id) => res.results.find(r => r.id === id);

test('pipeline ranks weak < medium < hardened', async () => { const [w, m, h] = [await scan(T('weak')), await scan(T('medium')), await scan(T('hardened'))]; console.log({ w: w.score, m: m.score, h: h.score }); assert.ok(w.score < m.score && m.score < h.score); });
test('multi-turn: hardened input filter (last message only) is bypassed, output filter still blocks leaks', async () => {
  const h = await scan(T('hardened')); assert.equal(by(h, 'MT-01').verdict, 'fail'); assert.equal(by(h, 'MT-03').verdict, 'fail'); assert.equal(by(h, 'MT-04').verdict, 'pass');
});
test('multi-turn tests are skipped when the template has no {{MESSAGES}}', async () => { const t = { ...T('weak'), bodyTemplate: '{"message":{{PROMPT}}}' }; assert.equal(by(await scan(t), 'MT-01').verdict, 'skipped'); });
test('RAG: poisoned document beats the medium target but not the hardened one; skipped without an ingest endpoint', async () => {
  assert.equal(by(await scan(T('medium', true)), 'RAG-01').verdict, 'fail'); assert.equal(by(await scan(T('hardened', true)), 'RAG-01').verdict, 'pass'); assert.equal(by(await scan(T('weak')), 'RAG-01').verdict, 'skipped');
});
test('mutations produce an attack success rate and the original stays tested', async () => {
  const r = by(await scan(T('weak'), { mutations: 9 }), 'DPI-01'); assert.equal(r.attempts.length, 10); assert.equal(r.attempts[0].mutation, 'original'); assert.ok(r.asr > 0 && r.asr < 100, 'asr ' + r.asr); assert.equal(r.verdict, 'partial');
});
test('system-prompt variant flips the outcome', async () => { const a = await scan(T('weak'), { variant: { system: 'MODE:weak' } }), b = await scan(T('weak'), { variant: { system: 'MODE:hardened' } }); assert.ok(b.score > a.score); });
test('attack text cannot inject template placeholders', () => assert.deepEqual(JSON.parse(buildBody({ bodyTemplate: '{"m":{{PROMPT}},"s":{{SYSTEM}}}' }, '{{SYSTEM}} x', { system: 'SAFE' })), { m: '{{SYSTEM}} x', s: 'SAFE' }));
test('SSRF guard blocks cloud metadata even in dev mode', async () => await assert.rejects(send({ url: 'http://169.254.169.254/latest', bodyTemplate: '{{PROMPT}}' }, 'x'), /metadata/));
test('PDF renders', async () => {
  const chunks = []; const out = new Writable({ write(c, _, cb) { chunks.push(c); cb(); } });
  await new Promise(r => { out.on('finish', r); renderPdf({ _id: 'x', createdAt: new Date(), score: 40, grade: 'F', categories: { a: 40 }, results: [{ id: 'T1', name: 't', sev: 'high', owasp: 'LLM01', verdict: 'fail', failRate: 1, fix: 'fix', attempts: [{ verdict: 'fail', evidence: 'e', resp: 'r' }] }] }, out); });
  assert.equal(Buffer.concat(chunks).subarray(0, 4).toString(), '%PDF');
});
test('OpenAPI docs are served', async () => {
  const a = express(); mountDocs(a); const s = a.listen(0), base = `http://127.0.0.1:${s.address().port}/api/docs`;
  const j = await (await fetch(base + '/openapi.json')).json(); assert.ok(j.paths['/api/v1/auth/login/mfa'] && j.paths['/api/v1/runs/variants']); assert.ok(Object.values(spec.paths).flatMap(Object.keys).length >= 35);
  assert.equal((await fetch(base + '/assets/swagger-ui-bundle.js')).status, 200); s.close();
});

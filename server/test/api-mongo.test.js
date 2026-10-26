// End-to-end API test against a real MongoDB (mongodb-memory-server). Skipped unless RUN_MONGO_TESTS=1 (CI sets it).
import test from 'node:test'; import assert from 'node:assert/strict'; import request from 'supertest';
const on = process.env.RUN_MONGO_TESTS === '1';
test('register -> create target -> verify -> scan -> report, all through the API with Mongo', { skip: !on }, async () => {
  process.env.DEV_ALLOW_LOCAL = 'true'; process.env.AUTH_RATE = '1000'; process.env.TARGET_RPM = '0';
  const { MongoMemoryServer } = await import('mongodb-memory-server'); const mongoose = (await import('mongoose')).default, mongo = await MongoMemoryServer.create(); await mongoose.connect(mongo.getUri());
  const { createApp } = await import('../src/app.js'); const { mongoStore } = await import('../src/store.js'); const { app: demo } = await import('../../demo-target/server.js');
  const dsrv = demo.listen(0), port = dsrv.address().port, app = createApp({ store: await mongoStore() });
  const jar = r => Object.fromEntries((r.headers['set-cookie'] || []).map(c => c.split(';')[0].split('=')).map(([k, ...v]) => [k, v.join('=')])), ck = j => Object.entries(j).map(([k, v]) => `${k}=${v}`).join('; ');
  const reg = await request(app).post('/api/v1/auth/register').send({ email: 'e2e@example.com', password: 'tr0ub4dor&3-horse-staple-91' }); assert.equal(reg.status, 200); const j = jar(reg), h = { Cookie: ck(j), 'x-csrf-token': j.pg_csrf };
  const t = await request(app).post('/api/v1/targets').set(h).send({ name: 'demo', url: `http://127.0.0.1:${port}/chat?mode=weak`, bodyTemplate: '{"messages":{{MESSAGES}},"system":{{SYSTEM}}}', responsePath: 'reply', canaries: ['CANARY-7f3a9c'] }); assert.equal(t.status, 200, JSON.stringify(t.body));
  assert.equal((await request(app).post('/api/v1/runs').set(h).send({ targetId: t.body._id })).status, 400);                                   // not verified yet
  assert.equal((await request(app).post(`/api/v1/targets/${t.body._id}/verify`).set(h).send({ consent: true })).body.verified, true);
  const run = await request(app).post('/api/v1/runs').set(h).send({ targetId: t.body._id, attempts: 1, include: ['Direct injection'] }); assert.equal(run.status, 200);
  let r; for (let i = 0; i < 100; i++) { r = (await request(app).get('/api/v1/runs/' + run.body.id).set('Cookie', ck(j))).body; if (r.status !== 'running') break; await new Promise(x => setTimeout(x, 200)); }
  assert.equal(r.status, 'done'); assert.ok(r.score < 50); assert.ok((await request(app).get(`/api/v1/runs/${run.body.id}/export?format=pdf`).set('Cookie', ck(j))).headers['content-type'].includes('pdf'));
  const other = await request(app).post('/api/v1/auth/register').send({ email: 'other@example.com', password: 'tr0ub4dor&3-horse-staple-92' }); assert.equal((await request(app).get('/api/v1/runs/' + run.body.id).set('Cookie', ck(jar(other)))).body, null);   // other users cannot read it
  dsrv.close(); await mongoose.disconnect(); await mongo.stop();
});

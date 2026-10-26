import express from 'express'; import helmet from 'helmet'; import cookieParser from 'cookie-parser'; import rateLimit from 'express-rate-limit'; import { z } from 'zod';
import { Target, Run } from './models.js'; import { enc, verifyToken } from './crypto.js'; import { assertSafe } from './guard.js';
import { send } from './send.js'; import { loadSuites } from './suites.js'; import { mountAuth, csrf } from './auth/routes.js'; import { mountExtra } from './routes2.js'; import { enqueue } from './queue.js'; import { mountDocs } from './docs.js';
import { Custom } from './models.js'; import { availableSuites } from './scan-all.js'; import { webCatalog } from './web/scan.js'; import { zapOn } from './web/zap.js'; import { nucleiOn } from './web/nuclei.js';

export function createApp({ store }) {
  const app = express(); app.set('trust proxy', 1);
  app.use(helmet(), express.json({ limit: '50kb' }), cookieParser());
  app.use('/api', rateLimit({ windowMs: 60000, limit: Number(process.env.API_RATE || 300) }));
  app.use((q, r, n) => {                                  // Origin allow-list for state-changing requests (defence in depth with SameSite + CSRF token)
    const allowed = (process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(','), o = q.headers.origin;
    return q.method !== 'GET' && o && !allowed.includes(o) ? r.status(403).json({ error: 'bad origin' }) : n();
  });
  app.use(csrf);
  const { auth, requireVerified: rv, wrap } = mountAuth(app, { store }), A = '/api/v1';
  const id = v => z.string().regex(/^[a-f\d]{24}$/i).parse(v);   // blocks NoSQL operator injection
  mountDocs(app); mountExtra(app, { auth, wrap, id, store, rv });
  app.get(A + '/health', (_, r) => r.json({ ok: true }));

  const hdrs = z.record(z.string().max(500)).refine(o => Object.keys(o).length <= 10, 'Too many headers');
  const webCfg = z.object({ loginPath: z.string().max(200).optional(), loginBody: z.string().max(2000).optional(), loginContentType: z.string().max(100).optional(), knownUser: z.string().max(200).optional(), protectedPaths: z.array(z.string().max(200)).max(30).optional(),
    probes: z.array(z.object({ path: z.string().max(200), params: z.array(z.string().max(60)).max(10).optional() })).max(30).optional(), idor: z.object({ pathTemplate: z.string().max(200), ownedId: z.string().max(100), headersA: hdrs.optional(), headersB: hdrs.optional() }).optional(), headers: hdrs.optional(), skip: z.array(z.string().max(40)).max(40).optional() }).strict();
  const caps = () => ({ zap: zapOn(), nuclei: nucleiOn(), judge: process.env.JUDGE === 'on' });
  const tgt = z.object({ name: z.string().max(80), url: z.string().url(), bodyTemplate: z.string().includes('{{PROMPT}}').or(z.string().includes('{{MESSAGES}}')).optional(), webBase: z.string().url().optional(), web: webCfg.optional(), responsePath: z.string().max(80).default('reply'),
    headers: z.record(z.string()).optional(), canaries: z.array(z.string().max(100)).max(20).default([]), system: z.string().max(4000).optional(),
    ingestUrl: z.string().url().optional(), ingestBodyTemplate: z.string().includes('{{DOC}}').optional() }).refine(b => b.bodyTemplate || b.webBase, { message: 'Provide an LLM request body template, a web base URL, or both' });
  const pub = t => ({ _id: t._id, name: t.name, url: t.url, verified: t.verified, canaries: t.canaries, bodyTemplate: t.bodyTemplate, responsePath: t.responsePath, ingestUrl: t.ingestUrl, webBase: t.webBase, hasWebConfig: !!t.webEnc, suites: availableSuites(t, caps()), verifyToken: verifyToken(t._id) });
  app.get(A + '/targets', auth, wrap(async (q, r) => r.json((await Target.find({ user: q.uid })).map(pub))));
  app.post(A + '/targets', auth, rv, wrap(async (q, r) => {
    const b = tgt.parse(q.body); await assertSafe(b.url); if (b.ingestUrl) await assertSafe(b.ingestUrl);
    if (b.webBase) { await assertSafe(b.webBase); if (new URL(b.webBase).origin !== new URL(b.url).origin) throw Error('The web base URL must share the origin (scheme, host and port) of the endpoint URL, because ownership is verified per origin'); }
    const { headers, web, ...rest } = b; r.json(pub(await Target.create({ ...rest, user: q.uid, headersEnc: headers ? enc(JSON.stringify(headers)) : undefined, webEnc: web ? enc(JSON.stringify(web)) : undefined })));
  }));
  app.delete(A + '/targets/:id', auth, wrap(async (q, r) => { await Target.deleteOne({ _id: id(q.params.id), user: q.uid }); r.json({ ok: true }); }));
  app.post(A + '/targets/:id/verify', auth, rv, wrap(async (q, r) => {   // ownership: well-known token (or dev-mode consent for private targets)
    if (q.body.consent !== true) throw Error('consent required: confirm you own or have written permission to test this system');
    const t = await Target.findOne({ _id: id(q.params.id), user: q.uid }); const { u, local } = await assertSafe(t.url);
    if (local && process.env.DEV_ALLOW_LOCAL === 'true') t.verified = true;
    else { const x = await fetch(u.origin + '/.well-known/promptguard-verify', { signal: AbortSignal.timeout(8000), redirect: 'error' }).then(r => r.text()); t.verified = x.trim() === verifyToken(t._id); }
    await t.save(); await store.audit.add({ user: q.uid, action: 'target_verify', ip: q.ip, meta: { target: String(t._id), ok: t.verified } }); r.json(pub(t));
  }));
  app.post(A + '/playground', auth, rv, wrap(async (q, r) => {
    const t = await Target.findOne({ _id: id(q.body.targetId), user: q.uid, verified: true }); if (!t) throw Error('target not verified');
    const resp = await send(t.toObject(), z.string().min(1).max(2000).parse(q.body.prompt));
    r.json({ resp, canaryLeak: t.canaries.filter(c => resp.toLowerCase().includes(c.toLowerCase())) });
  }));
  app.get(A + '/capabilities', auth, (q, r) => r.json(caps()));
  app.get(A + '/tests', auth, wrap(async (q, r) => r.json([...loadSuites(), ...webCatalog(), ...(await Custom.find({ user: q.uid }).lean()).map(c => ({ ...c, id: 'C-' + String(c._id).slice(-6), custom: true, _id: String(c._id) }))])));
  app.post(A + '/runs', auth, rv, wrap(async (q, r) => {
    const b = z.object({ targetId: z.string(), attempts: z.number().int().min(1).max(10).default(3), mutations: z.number().int().min(0).max(8).default(0), include: z.array(z.string().max(60)).max(20).optional(), suites: z.array(z.enum(['llm', 'web', 'zap', 'nuclei'])).max(4).optional() }).parse(q.body);
    const t = await Target.findOne({ _id: id(b.targetId), user: q.uid }); if (!t?.verified) throw Error('verify ownership first');
    const can = availableSuites(t, caps()), suites = b.suites?.length ? b.suites : can.filter(x => x === 'llm' || x === 'web'); if (!suites.length || suites.some(x => !can.includes(x))) throw Error('Those scan types are not available for this target (check the target configuration and server capabilities)');
    if (suites.includes('llm') && (loadSuites().length + 20) * (1 + b.mutations) * b.attempts > 5000) throw Error('Too many requests for one run (max 5000): reduce attempts or mutations');
    const run = await Run.create({ user: q.uid, target: t._id, targetName: t.name, attempts: b.attempts, mutations: b.mutations, include: b.include, suites });
    await store.audit.add({ user: q.uid, action: 'scan', ip: q.ip, meta: { target: String(t._id), name: t.name } }); await enqueue(run._id); r.json({ id: run._id });
  }));
  app.get(A + '/runs', auth, wrap(async (q, r) => r.json(await Run.find({ user: q.uid }, '-results').sort('-createdAt').limit(100))));
  app.get(A + '/runs/:id', auth, wrap(async (q, r) => { const run = await Run.findOne({ _id: id(q.params.id), user: q.uid }); if (!run) throw Error('not found'); r.json(run); }));
  app.post(A + '/runs/:id/cancel', auth, wrap(async (q, r) => { await Run.updateOne({ _id: id(q.params.id), user: q.uid }, { cancelRequested: true }); r.json({ ok: true }); }));
  return app;
}

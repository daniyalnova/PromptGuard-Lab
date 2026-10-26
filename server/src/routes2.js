import { z } from 'zod'; import crypto from 'node:crypto';
import { Run, Target, Share, Custom } from './models.js'; import { enqueue } from './queue.js'; import { renderPdf } from './pdf.js'; import { bus } from './runner.js'; import { redact } from './redact.js'; import { sarif } from './sarif.js';
const rank = { fail: 0, partial: 1, pass: 2 }, lvl = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const clean = async run => { const t = await Target.findById(run.target), cs = t?.canaries || [], o = run.toObject();   // secrets never leave the server unredacted
  o.results = (o.results || []).map(x => ({ ...x, attempts: x.attempts.map(a => ({ ...a, resp: redact(a.resp, cs), evidence: redact(a.evidence, cs) })) })); return o; };
export function mountExtra(app, { auth, wrap, id, store, rv }) {
  const A = '/api/v1';
  app.get(A + '/runs/compare', auth, wrap(async (q, r) => {                    // regression tracking
    const [a, b] = await Promise.all([q.query.a, q.query.b].map(i => Run.findOne({ _id: id(i), user: q.uid })));
    if (!a || !b) throw Error('run not found');
    const m = new Map(a.results.map(x => [x.id, x]));
    const diff = b.results.map(x => { const p = m.get(x.id); return { id: x.id, name: x.name, before: p?.verdict, after: x.verdict,
      change: !p ? 'new' : p.verdict === x.verdict ? 'same' : rank[x.verdict] < rank[p.verdict] ? 'regressed' : 'improved' }; }).filter(d => d.change !== 'same');
    r.json({ scoreA: a.score, scoreB: b.score, delta: b.score - a.score, diff });
  }));
  app.get(A + '/runs/:id/export', auth, wrap(async (q, r) => {
    const run = await Run.findOne({ _id: id(q.params.id), user: q.uid }); if (!run) throw Error('not found');
    const o = await clean(run);
    if (q.query.format === 'pdf') { r.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="promptguard-${run._id}.pdf"` }); return renderPdf(o, r); }
    const f = q.query.format === 'sarif' ? 'sarif' : 'json';
    r.set('Content-Disposition', `attachment; filename="promptguard-${run._id}.${f}.json"`).json(f === 'sarif' ? sarif(o) : o);
  }));
  app.get(A + '/runs/:id/stream', auth, wrap(async (q, r) => {                 // live progress (SSE)
    const rid = id(q.params.id), run = await Run.findOne({ _id: rid, user: q.uid }, 'status'); if (!run) throw Error('not found');
    r.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' }); r.flushHeaders();
    const on = e => { r.write(`data:${JSON.stringify(e)}\n\n`); if (e.type === 'done') r.end(); };
    if (run.status !== 'running') return on({ type: 'done', status: run.status });
    bus.on(rid, on); r.on('close', () => bus.off(rid, on));
  }));
  app.post(A + '/runs/:id/share', auth, wrap(async (q, r) => {
    const run = await Run.findOne({ _id: id(q.params.id), user: q.uid }); if (!run) throw Error('not found');
    const hours = z.number().int().min(1).max(168).default(24).parse(q.body.hours), token = crypto.randomBytes(24).toString('base64url');
    await Share.create({ run: run._id, user: q.uid, token, expires: new Date(Date.now() + hours * 3600e3) });
    r.json({ path: `${A}/shared/${token}`, token, expiresInHours: hours });
  }));
  app.delete(A + '/shares/:token', auth, wrap(async (q, r) => { await Share.deleteOne({ token: z.string().max(64).parse(q.params.token), user: q.uid }); r.json({ ok: true }); }));
  app.get(A + '/shared/:token', wrap(async (q, r) => {                         // public, read-only, expiring, redacted
    const s = await Share.findOne({ token: z.string().max(64).parse(q.params.token), expires: { $gt: new Date() } }); if (!s) throw Error('link expired or revoked');
    r.json(await clean(await Run.findById(s.run)));
  }));
  const vz = z.object({ label: z.string().max(40), system: z.string().max(4000).default(''), model: z.string().max(80).optional() });
  app.post(A + '/runs/variants', auth, rv, wrap(async (q, r) => {                  // side-by-side: same suite, two system prompts/models
    const b = z.object({ targetId: z.string(), attempts: z.number().int().min(1).max(10).default(3), a: vz, b: vz }).parse(q.body);
    const t = await Target.findOne({ _id: id(b.targetId), user: q.uid }); if (!t?.verified) throw Error('verify ownership first');
    if (!t.bodyTemplate.includes('{{SYSTEM}}')) throw Error('target body template needs a {{SYSTEM}} placeholder (and optionally {{MODEL}})');
    const group = crypto.randomUUID(), ids = [];
    for (const variant of [b.a, b.b]) { const run = await Run.create({ user: q.uid, target: t._id, targetName: t.name + ' (' + variant.label + ')', attempts: b.attempts, variant, group, suites: ['llm'] }); await store.audit.add({ user: q.uid, action: 'scan_variant', ip: q.ip, meta: { target: String(t._id) } }); await enqueue(run._id); ids.push(run._id); }
    r.json({ a: ids[0], b: ids[1], group });
  }));
  const ct = z.object({ name: z.string().max(80), payload: z.string().max(2000), detect: z.enum(['marker', 'canary', 'unsafe']), marker: z.string().max(100).optional(),
    sev: z.enum(['low', 'medium', 'high', 'critical']).default('medium'), owasp: z.string().max(10).default('LLM01') }).refine(x => x.detect !== 'marker' || !!x.marker, { message: 'marker required for marker tests' });
  app.post(A + '/tests/custom', auth, rv, wrap(async (q, r) => r.json(await Custom.create({ ...ct.parse(q.body), user: q.uid }))));
  app.get(A + '/tests/custom', auth, wrap(async (q, r) => r.json(await Custom.find({ user: q.uid }))));
  app.delete(A + '/tests/custom/:id', auth, wrap(async (q, r) => { await Custom.deleteOne({ _id: id(q.params.id), user: q.uid }); r.json({ ok: true }); }));
}

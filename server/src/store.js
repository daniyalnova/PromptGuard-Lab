// Auth/audit data layer behind one interface: Mongo in production, in-memory for tests.
import crypto from 'node:crypto';
const hex = () => crypto.randomBytes(12).toString('hex'), now = () => new Date();
export function memoryStore() {
  const U = new Map(), S = new Map(), T = new Map(), O = new Map(), A = [], c = o => (o ? structuredClone(o) : o);
  return { kind: 'memory',
    users: {
      async create(d) { if ([...U.values()].some(u => u.email === d.email)) throw Object.assign(Error('duplicate'), { code: 11000 }); const u = { _id: hex(), createdAt: now(), ...d }; U.set(u._id, u); return c(u); },
      byEmail: async e => c([...U.values()].find(u => u.email === e)), byId: async id => c(U.get(id)),
      async update(id, patch) { const u = U.get(id); if (u) Object.assign(u, patch); return c(u); } },
    sessions: {
      async create(d) { const s = { _id: hex(), createdAt: now(), used: false, revoked: false, ...d }; S.set(s._id, s); return c(s); },
      byHash: async h => c([...S.values()].find(s => s.tokenHash === h)),
      async markUsed(id) { const s = S.get(id); if (!s || s.used) return false; s.used = true; s.usedAt = now(); return true; },
      async revokeFamily(f) { for (const s of S.values()) if (s.family === f) s.revoked = true; },
      async revokeUser(uid, except) { for (const s of S.values()) if (s.user === uid && s.family !== except) s.revoked = true; },
      familyActive: async f => [...S.values()].some(s => s.family === f && !s.revoked && s.expires > now()),
      async listFamilies(uid) { const m = new Map(); for (const s of [...S.values()].filter(s => s.user === uid && !s.revoked && s.expires > now()).sort((a, b) => b.createdAt - a.createdAt)) if (!m.has(s.family)) m.set(s.family, { family: s.family, startedAt: s.startedAt, ua: s.ua, ip: s.ip, lastUsed: s.createdAt }); return [...m.values()]; } },
    tokens: {
      async create(d) { const t = { _id: hex(), used: false, ...d }; T.set(t._id, t); return c(t); },
      async revokeUser(uid, type) { for (const t of T.values()) if (t.user === uid && t.type === type) t.used = true; },
      peek: async (hash, type) => c([...T.values()].find(t => t.tokenHash === hash && t.type === type && !t.used && t.expires > now())),
      async consume(hash, type) { const t = [...T.values()].find(t => t.tokenHash === hash && t.type === type && !t.used && t.expires > now()); if (!t) return null; t.used = true; return c(t); } },
    otps: {
      async put(user, purpose, codeHash, expires) { for (const [k, o] of O) if (o.user === user && o.purpose === purpose) O.delete(k); const o = { _id: hex(), user, purpose, codeHash, expires, attempts: 0, createdAt: now() }; O.set(o._id, o); return c(o); },
      last: async (user, purpose) => c([...O.values()].find(o => o.user === user && o.purpose === purpose)),
      async attempt(user, purpose) { const o = [...O.values()].find(o => o.user === user && o.purpose === purpose && o.expires > now() && o.attempts < 5); if (!o) return null; o.attempts++; return c(o); },   // every guess is counted before it is compared
      async burn(user, purpose) { for (const o of O.values()) if (o.user === user && o.purpose === purpose) o.attempts = 99; },   // used codes stay on record so the resend cooldown survives
      async remove(user, purpose) { for (const [k, o] of O) if (o.user === user && o.purpose === purpose) O.delete(k); } },
    audit: { async add(e) { A.push({ at: now(), ...e }); }, list: async ({ user, limit = 100 } = {}) => c(A.filter(a => !user || a.user === user).sort((a, b) => b.at - a.at).slice(0, limit)) } };
}
export async function mongoStore() {
  const { User, Session, Token, Audit, Otp } = await import('./models.js');
  const p = d => d && { ...d, _id: String(d._id), user: d.user ? String(d.user) : d.user };
  return { kind: 'mongo',
    users: { async create(d) { return p((await User.create(d)).toObject()); }, byEmail: async e => p(await User.findOne({ email: e }).lean()), byId: async id => p(await User.findById(id).lean()),
      update: async (id, patch) => p(await User.findByIdAndUpdate(id, { $set: patch }, { new: true }).lean()) },
    sessions: { async create(d) { return p((await Session.create(d)).toObject()); }, byHash: async h => p(await Session.findOne({ tokenHash: h }).lean()),
      markUsed: async id => !!(await Session.findOneAndUpdate({ _id: id, used: false }, { used: true, usedAt: now() })),   // atomic claim: only one rotation can win
      revokeFamily: f => Session.updateMany({ family: f }, { revoked: true }), revokeUser: (uid, except) => Session.updateMany({ user: uid, ...(except ? { family: { $ne: except } } : {}) }, { revoked: true }),
      familyActive: async f => !!(await Session.exists({ family: f, revoked: false, expires: { $gt: now() } })),
      listFamilies: async uid => (await Session.aggregate([{ $match: { user: new (await import('mongoose')).default.Types.ObjectId(uid), revoked: false, expires: { $gt: now() } } }, { $sort: { createdAt: -1 } },
        { $group: { _id: '$family', startedAt: { $first: '$startedAt' }, ua: { $first: '$ua' }, ip: { $first: '$ip' }, lastUsed: { $first: '$createdAt' } } }])).map(g => ({ family: g._id, ...g, _id: undefined })) },
    tokens: { async create(d) { return p((await Token.create(d)).toObject()); }, revokeUser: (uid, type) => Token.updateMany({ user: uid, type }, { used: true }), peek: async (h, type) => p(await Token.findOne({ tokenHash: h, type, used: false, expires: { $gt: now() } }).lean()), consume: async (h, type) => p(await Token.findOneAndUpdate({ tokenHash: h, type, used: false, expires: { $gt: now() } }, { used: true }).lean()) },
    otps: { async put(user, purpose, codeHash, expires) { await Otp.deleteMany({ user, purpose }); return p((await Otp.create({ user, purpose, codeHash, expires })).toObject()); }, last: async (user, purpose) => p(await Otp.findOne({ user, purpose }).lean()),
      attempt: async (user, purpose) => p(await Otp.findOneAndUpdate({ user, purpose, expires: { $gt: now() }, attempts: { $lt: 5 } }, { $inc: { attempts: 1 } }, { new: true }).lean()),
      burn: async (user, purpose) => { await Otp.updateMany({ user, purpose }, { attempts: 99 }); }, remove: async (user, purpose) => { await Otp.deleteMany({ user, purpose }); } },
    audit: { async add(e) { await Audit.create(e); }, list: async ({ user, limit = 100 } = {}) => (await Audit.find(user ? { user } : {}).sort('-at').limit(limit).lean()).map(p) } };
}

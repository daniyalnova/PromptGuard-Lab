import { z } from 'zod'; import rateLimit from 'express-rate-limit';
import { hashPassword, verifyPassword, dummyVerify, checkPolicy } from './password.js';
import { sha256, rand, eq, signJwt, verifyJwt } from './tokens.js'; import * as T from './totp.js'; import { sendMail } from './mailer.js'; import { issueOtp, checkOtp } from './otp.js'; import { enc, dec } from '../crypto.js';
const A = '/api/v1/auth', prod = () => process.env.NODE_ENV === 'production';
const ACCESS_MIN = 15, REFRESH_DAYS = 14, MAX_FAILS = 5, LOCK_MIN = 15;
const must2fa = u => process.env.REQUIRE_2FA === 'true' || u.role === 'admin';
const needVerify = () => process.env.REQUIRE_EMAIL_VERIFY ? process.env.REQUIRE_EMAIL_VERIFY === 'true' : prod();
const email = z.string().trim().toLowerCase().email().max(200), pw = z.string().min(1).max(200);
const nameZ = z.string().trim().min(1, 'Name is required').max(60, 'Name is too long').regex(/^[\p{L}\p{M}][\p{L}\p{M} .'’-]*$/u, 'Names can only contain letters, spaces, hyphens and apostrophes');
const code6 = z.string().regex(/^\d{6}$/, 'Enter the 6-digit code');
const co = (o = {}) => ({ httpOnly: true, sameSite: 'strict', secure: prod(), ...o });
const pub = u => ({ id: u._id, email: u.email, firstName: u.firstName || '', lastName: u.lastName || '', name: [u.firstName, u.lastName].filter(Boolean).join(' '), emailOtp: !!u.emailOtp, role: u.role, emailVerified: !!u.emailVerified, mfa: !!u.totp?.enabled, mfaRequiredForAccount: must2fa(u) });
const PRE = new Set(['/login', '/login/mfa', '/register', '/password/forgot', '/password/reset', '/verify-email'].map(p => A + p));

// CSRF: cookie-authenticated, state-changing requests must echo the csrf cookie in a header (double submit), on top of SameSite=Strict + Origin check
export const csrf = (q, r, n) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(q.method) || PRE.has(q.path) || !(q.cookies?.pg_access || q.cookies?.pg_refresh)) return n();
  const c = q.cookies.pg_csrf, h = q.get('x-csrf-token'); return c && h && eq(c, h) ? n() : r.status(403).json({ error: 'csrf' });
};

export function mountAuth(app, { store }) {
  const wrap = f => (q, r, n) => Promise.resolve(f(q, r, n)).catch(e => r.status(e.status || 400).json({ error: e.name === 'ZodError' ? (e.issues?.[0]?.message || 'Invalid input') : e.message }));
  const lim = rateLimit({ windowMs: 15 * 60e3, limit: Number(process.env.AUTH_RATE || 30), standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests, try again later' } });
  const log = (q, action, user, meta) => store.audit.add({ user, action, ip: q.ip, ua: String(q.headers['user-agent'] || '').slice(0, 160), meta });
  const clear = r => { r.clearCookie('pg_access'); r.clearCookie('pg_csrf'); r.clearCookie('pg_refresh', { path: A }); };

  async function issue(user, q, r, family = rand(12), startedAt = new Date()) {
    const refresh = rand(32);
    await store.sessions.create({ user: user._id, family, startedAt, tokenHash: sha256(refresh), ua: String(q.headers['user-agent'] || '').slice(0, 200), ip: q.ip, expires: new Date(Date.now() + REFRESH_DAYS * 864e5) });
    r.cookie('pg_access', signJwt({ sub: user._id, fam: family, typ: 'access' }, ACCESS_MIN + 'm'), co({ maxAge: ACCESS_MIN * 60e3 }));
    r.cookie('pg_refresh', refresh, co({ path: A, maxAge: REFRESH_DAYS * 864e5 }));      // only sent to /auth/*
    r.cookie('pg_csrf', rand(24), { httpOnly: false, sameSite: 'strict', secure: prod(), maxAge: REFRESH_DAYS * 864e5 });
  }
  const guard = (strict) => async (q, r, n) => { try {
    const p = verifyJwt(q.cookies?.pg_access || ''); if (p.typ !== 'access' || !(await store.sessions.familyActive(p.fam))) throw 0;
    const u = await store.users.byId(p.sub); if (!u || u.disabled) throw 0;
    if (strict && must2fa(u) && !u.totp?.enabled) return r.status(403).json({ error: 'mfa_enrollment_required', message: 'Enable two-factor authentication to continue' });
    q.user = u; q.uid = u._id; q.fam = p.fam; n();
  } catch { r.status(401).json({ error: 'unauthenticated' }); } };
  const auth = guard(true), authAny = guard(false);
  const requireVerified = (q, r, n) => (needVerify() && !q.user.emailVerified ? r.status(403).json({ error: 'email_unverified', message: 'Verify your email address first' }) : n());


  const APP = () => process.env.APP_URL || 'http://localhost:8080';
  async function sendVerification(u) {           // 6-digit code + link; silently skipped while throttled
    const code = await issueOtp(store, u._id, 'verify'); if (!code) return false; const t = rand(32);
    await store.tokens.create({ user: u._id, type: 'verify', tokenHash: sha256(t), expires: new Date(Date.now() + 24 * 60 * 60e3) });
    await sendMail({ to: u.email, subject: 'Verify your PromptGuard Lab email', text: `Hi ${u.firstName || 'there'},\n\nYour verification code: ${code}\n(valid for 10 minutes)\n\nOr open this link: ${APP()}/verify?token=${t}\n\nIf you did not create an account, ignore this email.` }); return true;
  }
  async function sendReset(u) {
    const code = await issueOtp(store, u._id, 'reset'); if (!code) return false; const t = rand(32);
    await store.tokens.create({ user: u._id, type: 'reset', tokenHash: sha256(t), expires: new Date(Date.now() + 30 * 60e3) });
    await sendMail({ to: u.email, subject: 'Reset your PromptGuard Lab password', text: `Hi ${u.firstName || 'there'},\n\nYour password reset code: ${code}\n(valid for 10 minutes)\n\nOr open this link: ${APP()}/reset?token=${t}\n\nIf you did not request this, ignore this email; your password has not changed.` }); return true;
  }
  async function secondFactor(u, code) {
    const c = String(code).trim().toLowerCase();
    if (/^\d{6}$/.test(c)) { const step = T.verifyTotp(c, dec(u.totp.secretEnc), u.totp.lastStep || 0); if (step === null) return false; await store.users.update(u._id, { totp: { ...u.totp, lastStep: step } }); return true; }   // replay-protected
    const h = sha256(c), i = (u.recovery || []).indexOf(h); if (i < 0) return false;
    await store.users.update(u._id, { recovery: u.recovery.filter((_, j) => j !== i) }); return true;                              // recovery codes are single-use
  }

  app.post(A + '/register', lim, wrap(async (q, r) => {
    const b = z.object({ firstName: nameZ, lastName: nameZ, email, password: pw }).parse(q.body), bad = await checkPolicy(b.password, [b.email, b.email.split('@')[0], b.firstName, b.lastName]);
    if (bad) return r.status(400).json({ error: bad });
    const first = { firstName: b.firstName, lastName: b.lastName, email: b.email, hash: await hashPassword(b.password), role: b.email === (process.env.ADMIN_EMAIL || '').toLowerCase() ? 'admin' : 'user', emailVerified: false, failedLogins: 0, lockUntil: null, totp: { enabled: false }, recovery: [] };
    let u; try { u = await store.users.create(first); } catch (e) {
      if (e.code !== 11000) throw e;
      if (needVerify()) { await sendMail({ to: b.email, subject: 'PromptGuard Lab: you already have an account', text: 'Someone tried to register with this address. Log in or reset your password.' }); return r.json({ ok: true, verify: true }); }   // no account enumeration in production
      return r.status(409).json({ error: 'An account with this email already exists' });
    }
    await log(q, 'register', u._id); await sendVerification(u);
    if (needVerify()) return r.json({ ok: true, verify: true });
    await issue(u, q, r); r.json(pub(u));
  }));

  app.post(A + '/login', lim, wrap(async (q, r) => {
    const b = z.object({ email, password: pw }).parse(q.body), u = await store.users.byEmail(b.email), bad = () => r.status(401).json({ error: 'Invalid email or password' });
    if (!u) { await dummyVerify(b.password); await log(q, 'login_fail', null, { email: b.email }); return bad(); }
    if (u.lockUntil && new Date(u.lockUntil) > new Date()) { await dummyVerify(b.password); await log(q, 'login_blocked', u._id); return r.status(429).json({ error: 'Too many failed attempts. Try again later.' }); }
    if (!(await verifyPassword(u.hash, b.password))) {
      const n = (u.failedLogins || 0) + 1, lock = n >= MAX_FAILS;
      await store.users.update(u._id, lock ? { failedLogins: 0, lockUntil: new Date(Date.now() + LOCK_MIN * 60e3) } : { failedLogins: n });
      await log(q, lock ? 'account_locked' : 'login_fail', u._id); return bad();
    }
    if (u.failedLogins || u.lockUntil) await store.users.update(u._id, { failedLogins: 0, lockUntil: null });
    if (needVerify() && !u.emailVerified) return r.status(403).json({ error: 'email_unverified', message: 'Verify your email address first' });
    if (u.totp?.enabled) return r.json({ mfaRequired: true, method: 'totp', mfaToken: signJwt({ sub: u._id, typ: 'mfa', m: 'totp' }, '5m') });
    if (u.emailOtp) { const code = await issueOtp(store, u._id, 'login'); if (code) await sendMail({ to: u.email, subject: 'Your PromptGuard Lab sign-in code', text: `Your sign-in code: ${code}\nIt expires in 10 minutes. If this was not you, change your password.` }); return r.json({ mfaRequired: true, method: 'email', mfaToken: signJwt({ sub: u._id, typ: 'mfa', m: 'email' }, '10m') }); }
    await issue(u, q, r); await log(q, 'login', u._id); r.json(pub(u));
  }));

  app.post(A + '/login/mfa', lim, wrap(async (q, r) => {
    const b = z.object({ mfaToken: z.string().max(1000), code: z.string().min(6).max(24) }).parse(q.body); let p;
    try { p = verifyJwt(b.mfaToken); if (p.typ !== 'mfa') throw 0; } catch { return r.status(401).json({ error: 'Session expired, log in again' }); }
    const u = await store.users.byId(p.sub); if (!u || (p.m === 'email' ? !u.emailOtp : !u.totp?.enabled)) return r.status(401).json({ error: 'Session expired, log in again' });
    if (u.mfaLockUntil && new Date(u.mfaLockUntil) > new Date()) return r.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    if (!(p.m === 'email' ? await checkOtp(store, u._id, 'login', b.code) : await secondFactor(u, b.code))) {
      const n = (u.mfaFails || 0) + 1; await store.users.update(u._id, n >= MAX_FAILS ? { mfaFails: 0, mfaLockUntil: new Date(Date.now() + LOCK_MIN * 60e3) } : { mfaFails: n });
      await log(q, 'mfa_fail', u._id); return r.status(401).json({ error: 'Invalid code' });
    }
    await store.users.update(u._id, { mfaFails: 0 }); const fresh = await store.users.byId(u._id);
    await issue(fresh, q, r); await log(q, 'login_mfa', u._id); r.json(pub(fresh));
  }));

  app.post(A + '/login/resend', lim, wrap(async (q, r) => {              // resend the emailed sign-in code (throttled to one per 30 s)
    let p; try { p = verifyJwt(z.object({ mfaToken: z.string().max(1000) }).parse(q.body).mfaToken); if (p.typ !== 'mfa' || p.m !== 'email') throw 0; } catch { return r.status(401).json({ error: 'Session expired, log in again' }); }
    const u = await store.users.byId(p.sub), code = u?.emailOtp ? await issueOtp(store, u._id, 'login') : null;
    if (code) await sendMail({ to: u.email, subject: 'Your PromptGuard Lab sign-in code', text: `Your sign-in code: ${code}\nIt expires in 10 minutes.` }); r.json({ ok: true });
  }));
  app.post(A + '/refresh', wrap(async (q, r) => {                       // rotating refresh tokens with reuse detection
    const t = q.cookies?.pg_refresh; if (!t) return r.status(401).json({ error: 'unauthenticated' });
    const s = await store.sessions.byHash(sha256(t));
    if (!s || s.revoked || new Date(s.expires) < new Date()) { clear(r); return r.status(401).json({ error: 'unauthenticated' }); }
    if (!(await store.sessions.markUsed(s._id))) { await store.sessions.revokeFamily(s.family); await log(q, 'refresh_reuse_detected', s.user); clear(r); return r.status(401).json({ error: 'unauthenticated' }); }
    const u = await store.users.byId(s.user); if (!u || u.disabled) { clear(r); return r.status(401).json({ error: 'unauthenticated' }); }
    await issue(u, q, r, s.family, s.startedAt); r.json({ ok: true });
  }));
  app.post(A + '/logout', authAny, wrap(async (q, r) => { await store.sessions.revokeFamily(q.fam); await log(q, 'logout', q.uid); clear(r); r.json({ ok: true }); }));
  app.get(A + '/me', authAny, (q, r) => r.json(pub(q.user)));
  app.get(A + '/sessions', authAny, wrap(async (q, r) => r.json((await store.sessions.listFamilies(q.uid)).map(s => ({ ...s, current: s.family === q.fam })))));
  app.delete(A + '/sessions/:family', authAny, wrap(async (q, r) => { const own = (await store.sessions.listFamilies(q.uid)).some(s => s.family === q.params.family); if (!own) throw Error('not found'); await store.sessions.revokeFamily(q.params.family); await log(q, 'session_revoked', q.uid); r.json({ ok: true }); }));
  app.post(A + '/logout-all', authAny, wrap(async (q, r) => { await store.sessions.revokeUser(q.uid); await store.sessions.revokeFamily(q.fam); await log(q, 'logout_all', q.uid); clear(r); r.json({ ok: true }); }));

  app.post(A + '/password/change', lim, authAny, wrap(async (q, r) => {
    const b = z.object({ current: pw, password: pw }).parse(q.body);
    if (!(await verifyPassword(q.user.hash, b.current))) return r.status(401).json({ error: 'Current password is incorrect' });
    const bad = await checkPolicy(b.password, [q.user.email]); if (bad) return r.status(400).json({ error: bad });
    await store.users.update(q.uid, { hash: await hashPassword(b.password), passwordChangedAt: new Date() }); await store.sessions.revokeUser(q.uid, q.fam); await log(q, 'password_changed', q.uid); r.json({ ok: true });
  }));
  app.post(A + '/password/forgot', lim, wrap(async (q, r) => {          // always the same answer: no account enumeration
    const b = z.object({ email }).parse(q.body), u = await store.users.byEmail(b.email);
    if (u) { await sendReset(u); await log(q, 'reset_requested', u._id); } else await dummyVerify('x');
    r.json({ ok: true });
  }));
  app.post(A + '/password/reset', lim, wrap(async (q, r) => {           // either {token,password} from the link or {email,code,password} from the emailed code
    const b = z.union([z.object({ token: z.string().max(200), password: pw }), z.object({ email, code: code6, password: pw })]).parse(q.body), bad = () => r.status(400).json({ error: 'Reset code or link is invalid or expired' });
    let u, lh; if ('token' in b) { lh = sha256(b.token); const peek = await store.tokens.peek(lh, 'reset'); u = peek && await store.users.byId(peek.user); } else u = await store.users.byEmail(b.email);
    if (!u) { if ('code' in b) await checkOtp(store, null, 'reset', b.code); return bad(); }
    const weak = await checkPolicy(b.password, [u.email, u.firstName || '', u.lastName || '']); if (weak) return r.status(400).json({ error: weak });   // a weak password must not burn the code or token
    if (!(lh ? !!(await store.tokens.consume(lh, 'reset')) : await checkOtp(store, u._id, 'reset', b.code))) return bad();
    await store.users.update(u._id, { hash: await hashPassword(b.password), failedLogins: 0, lockUntil: null, mfaFails: 0, mfaLockUntil: null, passwordChangedAt: new Date() });
    await store.tokens.revokeUser(u._id, 'reset'); await store.otps.burn(u._id, 'reset'); await store.sessions.revokeUser(u._id); await log(q, 'password_reset', u._id); r.json({ ok: true });
  }));
  app.post(A + '/verify-email', lim, wrap(async (q, r) => {             // either {token} from the link or {email,code} from the emailed code
    const b = z.union([z.object({ token: z.string().max(200) }), z.object({ email, code: code6 })]).parse(q.body); let uid;
    if ('token' in b) uid = (await store.tokens.consume(sha256(b.token), 'verify'))?.user;
    else { const u = await store.users.byEmail(b.email); if (u && (await checkOtp(store, u._id, 'verify', b.code))) uid = u._id; else if (!u) await checkOtp(store, null, 'verify', b.code); }
    if (!uid) return r.status(400).json({ error: 'Verification code or link is invalid or expired' });
    await store.users.update(uid, { emailVerified: true }); await log(q, 'email_verified', uid); r.json({ ok: true });
  }));
  app.post(A + '/resend-verification', lim, wrap(async (q, r) => { const u = await store.users.byEmail(z.object({ email }).parse(q.body).email); if (u && !u.emailVerified) await sendVerification(u); r.json({ ok: true }); }));
  app.post(A + '/profile', authAny, wrap(async (q, r) => { const b = z.object({ firstName: nameZ, lastName: nameZ }).parse(q.body); const u = await store.users.update(q.uid, b); await log(q, 'profile_updated', q.uid); r.json(pub(u)); }));
  app.post(A + '/email-otp', lim, authAny, wrap(async (q, r) => {       // optional emailed code at every sign-in (when authenticator-app 2FA is off)
    const b = z.object({ password: pw, enable: z.boolean() }).parse(q.body);
    if (!(await verifyPassword(q.user.hash, b.password))) return r.status(401).json({ error: 'Password is incorrect' });
    if (b.enable && !q.user.emailVerified) return r.status(400).json({ error: 'Verify your email address first' });
    await store.users.update(q.uid, { emailOtp: b.enable }); await log(q, b.enable ? 'email_otp_enabled' : 'email_otp_disabled', q.uid); r.json({ ok: true, emailOtp: b.enable });
  }));

  app.post(A + '/2fa/setup', lim, authAny, wrap(async (q, r) => {
    if (!(await verifyPassword(q.user.hash, z.object({ password: pw }).parse(q.body).password))) return r.status(401).json({ error: 'Password is incorrect' });
    const s = T.newSecret(); await store.users.update(q.uid, { totp: { ...q.user.totp, pendingSecretEnc: enc(s) } }); const url = T.uri(q.user.email, s);
    r.json({ otpauthUrl: url, qr: await T.qr(url), secret: s });
  }));
  app.post(A + '/2fa/enable', lim, authAny, wrap(async (q, r) => {
    const p = q.user.totp?.pendingSecretEnc; if (!p) throw Error('Start setup first');
    const step = T.verifyTotp(z.object({ code: z.string().max(10) }).parse(q.body).code, dec(p)); if (step === null) return r.status(400).json({ error: 'Invalid code' });
    const codes = T.newRecoveryCodes(); await store.users.update(q.uid, { totp: { enabled: true, secretEnc: p, lastStep: step }, recovery: codes.map(sha256) });
    await log(q, '2fa_enabled', q.uid); r.json({ recoveryCodes: codes });                         // shown once; only hashes are stored
  }));
  app.post(A + '/2fa/disable', lim, authAny, wrap(async (q, r) => {
    const b = z.object({ password: pw, code: z.string().max(24) }).parse(q.body);
    if (must2fa(q.user)) return r.status(400).json({ error: 'Two-factor authentication is required for your account' });
    if (!(await verifyPassword(q.user.hash, b.password)) || !(await secondFactor(q.user, b.code))) return r.status(401).json({ error: 'Password or code is incorrect' });
    await store.users.update(q.uid, { totp: { enabled: false }, recovery: [] }); await store.sessions.revokeUser(q.uid, q.fam); await log(q, '2fa_disabled', q.uid); r.json({ ok: true });
  }));
  app.get('/api/v1/audit', authAny, wrap(async (q, r) => r.json((await store.audit.list({ user: q.user.role === 'admin' && q.query.all ? undefined : q.uid, limit: 100 })).map(a => ({ action: a.action, ip: a.ip, at: a.at, meta: a.meta })))));
  return { auth, authAny, requireVerified, wrap };
}

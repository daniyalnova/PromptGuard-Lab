import test from 'node:test'; import assert from 'node:assert/strict'; import request from 'supertest'; import otp from 'otplib';
process.env.AUTH_RATE = '1000'; process.env.API_RATE = '100000'; delete process.env.REQUIRE_EMAIL_VERIFY; delete process.env.NODE_ENV;
const { createApp } = await import('../src/app.js'); const { memoryStore } = await import('../src/store.js'); const { outbox } = await import('../src/auth/mailer.js'); const { authenticator } = otp;
const NAME = { firstName: 'Ada', lastName: 'Lovelace' }, codeOf = () => /code: (\d{6})/.exec(outbox.at(-1).text)[1], PW = 'tr0ub4dor&3-horse-staple-91', mk = () => { const store = memoryStore(); return { store, app: createApp({ store }) }; };
const jar = res => Object.fromEntries((res.headers['set-cookie'] || []).map(c => c.split(';')[0].split('=')).map(([k, ...v]) => [k, v.join('=')]));
const ck = j => Object.entries(j).map(([k, v]) => `${k}=${v}`).join('; ');
const hdr = j => ({ Cookie: ck(j), 'x-csrf-token': j.pg_csrf });
async function signup(app, email = 'a@example.com') { const r = await request(app).post('/api/v1/auth/register').send({ ...NAME, email, password: PW }); return { r, j: jar(r) }; }
const lastToken = () => /token=([\w-]+)/.exec(outbox.at(-1).text)[1];

test('weak passwords are rejected, strong accepted; cookies are httpOnly + SameSite=Strict', async () => {
  const { app } = mk(); for (const password of ['short', 'Password123!!!', 'aaaaaaaaaaaaaaaa']) assert.equal((await request(app).post('/api/v1/auth/register').send({ ...NAME, email: 'w@example.com', password })).status, 400);
  const { r } = await signup(app); assert.equal(r.status, 200); const sc = r.headers['set-cookie'].join('|');
  assert.match(sc, /pg_access=[^|]*HttpOnly/); assert.match(sc, /pg_refresh=[^|]*Path=\/api\/v1\/auth/); assert.match(sc, /SameSite=Strict/); assert.ok(!/pg_csrf=[^|]*HttpOnly/.test(sc));
  assert.equal(r.body.hash, undefined);
});
test('login errors are identical for unknown email and wrong password (no enumeration); duplicate registration blocked', async () => {
  const { app } = mk(); await signup(app);
  const a = await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: 'wrong-password-123' }), b = await request(app).post('/api/v1/auth/login').send({ email: 'nobody@example.com', password: 'wrong-password-123' });
  assert.equal(a.status, 401); assert.equal(b.status, 401); assert.deepEqual(a.body, b.body); assert.equal((await signup(app)).r.status, 409);
});
test('account locks after 5 failures, even the right password is then refused', async () => {
  const { app } = mk(); await signup(app); for (let i = 0; i < 5; i++) await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: 'wrong-password-123' });
  assert.equal((await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: PW })).status, 429);
});
test('CSRF: state-changing cookie requests need the header; /me works with cookies', async () => {
  const { app } = mk(); const { j } = await signup(app); assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(j))).body.email, 'a@example.com');
  assert.equal((await request(app).post('/api/v1/auth/password/change').set('Cookie', ck(j)).send({ current: PW, password: PW + 'x' })).status, 403);
  assert.notEqual((await request(app).post('/api/v1/auth/password/change').set(hdr(j)).send({ current: 'bad', password: PW + 'x' })).status, 403);
  assert.equal((await request(app).post('/api/v1/auth/logout-all').set({ ...hdr(j), 'x-csrf-token': 'forged' })).status, 403);
  assert.equal((await request(app).post('/api/v1/targets').set('Origin', 'https://evil.example').set(hdr(j)).send({})).status, 403);
});
test('refresh rotates; replaying a used refresh token kills the whole session family', async () => {
  const { app } = mk(); const { j } = await signup(app);
  const r1 = await request(app).post('/api/v1/auth/refresh').set(hdr(j)); assert.equal(r1.status, 200); const j2 = jar(r1); assert.notEqual(j2.pg_refresh, j.pg_refresh);
  assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(j2))).status, 200);
  const replay = await request(app).post('/api/v1/auth/refresh').set(hdr(j)); assert.equal(replay.status, 401);       // attacker replays the stolen, already-rotated token
  assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(j2))).status, 401);                          // legit session is revoked too
});
test('2FA: enrol, login requires code, replay rejected, recovery code single-use, wrong codes lock', async () => {
  const { app, store } = mk(); const { j } = await signup(app);
  assert.equal((await request(app).post('/api/v1/auth/2fa/setup').set(hdr(j)).send({ password: 'nope' })).status, 401);
  const s = await request(app).post('/api/v1/auth/2fa/setup').set(hdr(j)).send({ password: PW }); assert.ok(s.body.qr.startsWith('data:image/png')); const secret = s.body.secret;
  assert.equal((await request(app).post('/api/v1/auth/2fa/enable').set(hdr(j)).send({ code: '000000' })).status, 400);
  const en = await request(app).post('/api/v1/auth/2fa/enable').set(hdr(j)).send({ code: authenticator.generate(secret) }); assert.equal(en.body.recoveryCodes.length, 8);
  const u = await store.users.byEmail('a@example.com'); assert.ok(u.recovery.every(h => h.length === 64) && !u.recovery.includes(en.body.recoveryCodes[0]));   // only hashes stored
  const l = await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: PW }); assert.equal(l.body.mfaRequired, true); assert.equal(jar(l).pg_access, undefined);
  const nextCode = authenticator.clone({ epoch: Date.now() + 30000 }).generate(secret), next = nextCode; assert.notEqual(next, authenticator.generate(secret));   // a code for the following 30s step
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: next })).status, 200);
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: next })).status, 401);                           // same code twice = replay
  const rc = en.body.recoveryCodes[0]; assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: rc })).status, 200);
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: rc })).status, 401);
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: 'garbage', code: '123456' })).status, 401);
  for (let i = 0; i < 5; i++) await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: '111111' });
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: en.body.recoveryCodes[1] })).status, 429);
});
test('password reset: no enumeration, single-use token, kills all sessions, new password works', async () => {
  const { app } = mk(); const { j } = await signup(app);
  const f1 = await request(app).post('/api/v1/auth/password/forgot').send({ email: 'a@example.com' }), n0 = outbox.length, f2 = await request(app).post('/api/v1/auth/password/forgot').send({ email: 'ghost@example.com' });
  assert.deepEqual(f1.body, f2.body); assert.equal(outbox.length, n0);
  await request(app).post('/api/v1/auth/password/forgot').send({ email: 'a@example.com' }); const token = lastToken(), NEW = 'correct-horse-battery-staple-77';
  assert.equal((await request(app).post('/api/v1/auth/password/reset').send({ token, password: 'weak' })).status, 400);
  assert.equal((await request(app).post('/api/v1/auth/password/reset').send({ token: 'bogus', password: NEW })).status, 400);
  assert.equal((await request(app).post('/api/v1/auth/password/reset').send({ token, password: NEW })).status, 200); assert.equal((await request(app).post('/api/v1/auth/password/reset').send({ token, password: NEW + '1' })).status, 400);
  assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(j))).status, 401);
  assert.equal((await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: PW })).status, 401); assert.equal((await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: NEW })).status, 200);
});
test('password change keeps this session, revokes the others; sessions list/revoke; audit log', async () => {
  const { app } = mk(); const { j: a } = await signup(app), b = jar(await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: PW }));
  const list = await request(app).get('/api/v1/auth/sessions').set('Cookie', ck(a)); assert.equal(list.body.length, 2); assert.equal(list.body.filter(s => s.current).length, 1);
  assert.equal((await request(app).post('/api/v1/auth/password/change').set(hdr(a)).send({ current: PW, password: 'correct-horse-battery-staple-77' })).status, 200);
  assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(a))).status, 200); assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(b))).status, 401);
  const audit = await request(app).get('/api/v1/audit').set('Cookie', ck(a)); assert.ok(audit.body.some(e => e.action === 'password_changed') && audit.body.some(e => e.action === 'login'));
  assert.equal((await request(app).delete('/api/v1/auth/sessions/' + 'not-mine').set(hdr(a))).status, 400);
});
test('email verification gate (production-style) blocks login until the link is used; registration does not leak existing accounts', async () => {
  process.env.REQUIRE_EMAIL_VERIFY = 'true'; try {
    const { app } = mk(); const r = await request(app).post('/api/v1/auth/register').send({ ...NAME, email: 'v@example.com', password: PW }); assert.equal(r.body.verify, true); assert.equal(jar(r).pg_access, undefined);
    const token = lastToken(); assert.equal((await request(app).post('/api/v1/auth/login').send({ ...NAME, email: 'v@example.com', password: PW })).body.error, 'email_unverified');
    const dup = await request(app).post('/api/v1/auth/register').send({ ...NAME, email: 'v@example.com', password: PW }); assert.equal(dup.status, 200); assert.deepEqual(dup.body, r.body);
    assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ token })).status, 200); assert.equal((await request(app).post('/api/v1/auth/login').send({ ...NAME, email: 'v@example.com', password: PW })).status, 200);
  } finally { delete process.env.REQUIRE_EMAIL_VERIFY; }
});
test('admins must enrol 2FA before using the app', async () => {
  process.env.ADMIN_EMAIL = 'boss@example.com'; try { const { app } = mk(); const { j } = await signup(app, 'boss@example.com');
    const r = await request(app).get('/api/v1/targets').set('Cookie', ck(j)); assert.equal(r.status, 403); assert.equal(r.body.error, 'mfa_enrollment_required'); assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(j))).body.role, 'admin');
  } finally { delete process.env.ADMIN_EMAIL; }
});

test('sign-up requires first and last name; names are validated, trimmed and returned', async () => {
  const { app } = mk(), reg = b => request(app).post('/api/v1/auth/register').send({ email: 'n@example.com', password: PW, ...b });
  assert.equal((await reg({})).status, 400); const bad = await reg({ firstName: '<script>', lastName: 'X' }); assert.equal(bad.status, 400); assert.match(bad.body.error, /letters/);
  assert.equal((await reg({ firstName: 'Ada', lastName: '' })).status, 400);
  const ok = await reg({ firstName: '  Zoë ', lastName: "O'Neil-Smith" }); assert.equal(ok.status, 200); assert.equal(ok.body.name, "Zoë O'Neil-Smith");
  assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(jar(ok)))).body.firstName, 'Zoë');
  const j = jar(ok), p = await request(app).post('/api/v1/auth/profile').set(hdr(j)).send({ firstName: 'Zoe', lastName: 'Smith' }); assert.equal(p.body.name, 'Zoe Smith');
});
test('email verification by 6-digit code: 5 guesses max, resend is throttled, fresh code works', async () => {
  process.env.REQUIRE_EMAIL_VERIFY = 'true'; try {
    const { app, store } = mk(), E = 'o@example.com'; await request(app).post('/api/v1/auth/register').send({ ...NAME, email: E, password: PW }); const code = codeOf(), wrong = code === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: E, code: wrong })).status, 400);
    assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: E, code })).status, 400);                 // guesses exhausted: even the right code is dead
    const n = outbox.length; await request(app).post('/api/v1/auth/resend-verification').send({ email: E }); assert.equal(outbox.length, n);   // throttled
    await store.otps.remove((await store.users.byEmail(E))._id, 'verify');                                                       // simulate the 30 s cooldown passing
    await request(app).post('/api/v1/auth/resend-verification').send({ email: E }); assert.equal(outbox.length, n + 1);
    assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: E, code: codeOf() })).status, 200);
    assert.equal((await request(app).post('/api/v1/auth/login').send({ email: E, password: PW })).status, 200);
    assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ email: 'ghost@example.com', code: '123456' })).status, 400);
  } finally { delete process.env.REQUIRE_EMAIL_VERIFY; }
});
test('password reset by emailed code: weak password does not burn it, single use, kills sessions and the link', async () => {
  const { app } = mk(), NEW = 'correct-horse-battery-staple-77'; const { j } = await signup(app);
  await request(app).post('/api/v1/auth/password/forgot').send({ email: 'a@example.com' }); const code = codeOf(), link = lastToken(), wrong = code === '000000' ? '111111' : '000000', reset = b => request(app).post('/api/v1/auth/password/reset').send({ email: 'a@example.com', ...b });
  assert.equal((await reset({ code, password: 'weak' })).status, 400); const w = await reset({ code: wrong, password: NEW }); assert.equal(w.status, 400);
  const ghost = await request(app).post('/api/v1/auth/password/reset').send({ email: 'ghost@example.com', code: wrong, password: NEW }); assert.deepEqual(ghost.body, w.body);        // same answer for unknown accounts
  assert.equal((await reset({ code, password: NEW })).status, 200); assert.equal((await reset({ code, password: NEW + 'x' })).status, 400);
  assert.equal((await request(app).get('/api/v1/auth/me').set('Cookie', ck(j))).status, 401);
  assert.equal((await request(app).post('/api/v1/auth/password/reset').send({ token: link, password: NEW + 'y' })).status, 400);                                                   // the emailed link died with the code
  assert.equal((await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: NEW })).status, 200);
});
test('optional emailed sign-in code: needs verified email, single use, wrong codes rejected, resend throttled', async () => {
  const { app } = mk(); const { j } = await signup(app), en = b => request(app).post('/api/v1/auth/email-otp').set(hdr(j)).send(b);
  assert.equal((await en({ password: PW, enable: true })).status, 400);                                                             // email not verified yet
  assert.equal((await request(app).post('/api/v1/auth/verify-email').send({ token: lastToken() })).status, 200);
  assert.equal((await en({ password: 'nope', enable: true })).status, 401); assert.equal((await en({ password: PW, enable: true })).body.emailOtp, true);
  const l = await request(app).post('/api/v1/auth/login').send({ email: 'a@example.com', password: PW }); assert.equal(l.body.method, 'email'); assert.equal(jar(l).pg_access, undefined); const code = codeOf(), wrong = code === '000000' ? '111111' : '000000';
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code: wrong })).status, 401);
  const ok = await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code }); assert.equal(ok.status, 200); assert.ok(jar(ok).pg_access);
  assert.equal((await request(app).post('/api/v1/auth/login/mfa').send({ mfaToken: l.body.mfaToken, code })).status, 401);          // single use
  const n = outbox.length; assert.equal((await request(app).post('/api/v1/auth/login/resend').send({ mfaToken: l.body.mfaToken })).status, 200); assert.equal(outbox.length, n);   // throttled
  assert.equal((await request(app).post('/api/v1/auth/login/resend').send({ mfaToken: 'junk' })).status, 401);
});

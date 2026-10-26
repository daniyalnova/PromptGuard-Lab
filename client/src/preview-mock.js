// In-browser fake of the API, replaying results from real scans of the bundled demo target.
// Used for the hosted preview and for the jsdom smoke test (npm run smoke). Not part of the production bundle.
export function installMock(D, { autologin = false } = {}) {
  const W = window, day = 864e5, now = Date.now(); let n = 1, authed = autologin;
  const user = { id: 'u1', email: 'you@example.com', firstName: 'Ada', lastName: 'Lovelace', name: 'Ada Lovelace', emailOtp: false, role: 'user', emailVerified: true, mfa: false, mfaRequiredForAccount: false };
  const mk = (mode, ago, extra = {}) => ({ _id: 'r' + n++, status: 'done', targetName: `Demo bot (${mode})`, createdAt: new Date(now - ago * day).toISOString(), ...D[mode], ...extra });
  const targets = [{ _id: 't1', name: 'Demo bot (hardened)', url: 'http://demo-target:4000/chat?mode=hardened', verified: true, canaries: ['CANARY-7f3a9c'], bodyTemplate: '{"messages":{{MESSAGES}},"system":{{SYSTEM}}}', webBase: 'http://demo-target:4000/webdemo/hardened', suites: ['llm', 'web'], verifyToken: 'a1b2c3d4e5f6' }];
  const runs = [mk('hardened', 0.2), mk('medium', 3), mk('medium', 4), mk('weak', 5), mk('weak', 6)], custom = [], sessions = [
    { family: 'f1', ua: 'Mozilla/5.0 (Macintosh; Mac OS) Chrome/124 Safari/537', ip: '203.0.113.7', startedAt: new Date(now - 2 * day), lastUsed: new Date(now - 6e4), current: true },
    { family: 'f2', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS) Safari/604', ip: '198.51.100.4', startedAt: new Date(now - 6 * day), lastUsed: new Date(now - day) }];
  const audit = [['login', '203.0.113.7'], ['scan', '203.0.113.7', { name: 'Demo bot (hardened)' }], ['login_fail', '192.0.2.99'], ['target_verify', '203.0.113.7', { ok: true }], ['password_changed', '203.0.113.7'], ['login', '198.51.100.4']].map(([action, ip, meta], i) => ({ action, ip, meta, at: new Date(now - i * 36e5 * 5) }));
  const J = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'content-type': 'application/json' } }), rk = { fail: 0, partial: 1, pass: 2 };
  const modeOf = (url) => (/\/webdemo\/spa/.test(url) ? 'spa' : /\/rag\//.test(url) ? 'rag' : (/mode=(\w+)/.exec(url) || [])[1] || 'weak');
  const start = (t, variant) => { const mode = (/MODE:(\w+)/.exec(variant?.system || '') || [])[1] || modeOf(t.url), r = { _id: 'r' + n++, status: 'running', targetName: t.name + (variant ? ` (${variant.label})` : ''), attempts: 2, mutations: 0, variant, createdAt: new Date().toISOString() }; runs.unshift(r); setTimeout(() => Object.assign(r, D[mode], { status: 'done', attempts: 2, mutations: D[mode].mutations }), 2600); return r; };
  const qr = 'data:image/svg+xml;utf8,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="29" height="29" shape-rendering="crispEdges"><rect width="29" height="29" fill="#fff"/>' + Array.from({ length: 29 * 29 }, (_, i) => { const x = i % 29, y = (i / 29) | 0, f = (a, b) => x >= a && x < a + 7 && y >= b && y < b + 7; return f(0, 0) || f(22, 0) || f(0, 22) || ((x * 7 + y * 13 + x * y) % 5 < 2) ? `<rect x="${x}" y="${y}" width="1" height="1"/>` : ''; }).join('') + '</svg>');
  W.fetch = async (u, o = {}) => {
    u = String(u); if (!u.startsWith('/api/v1')) return new Response('', { status: 404 }); const p = u.slice(7), m = (o.method || 'GET').toUpperCase(), b = o.body ? JSON.parse(o.body) : {}; await new Promise(r => setTimeout(r, 60)); let x;
    if (p === '/auth/login') { if (b.password === 'wrong') return J({ error: 'Invalid email or password' }, 401); user.email = b.email; if (/2fa/.test(b.email)) return J({ mfaRequired: true, method: 'totp', mfaToken: 'm' }); if (/otp/.test(b.email)) return J({ mfaRequired: true, method: 'email', mfaToken: 'm' }); authed = true; return J(user); }
    if (p === '/auth/login/resend') return J({ ok: true });
    if (p === '/auth/verify-email') return b.code === '123456' || b.token ? J({ ok: true }) : J({ error: 'Verification code or link is invalid or expired' }, 400);
    if (p === '/auth/password/reset') return b.code === '123456' || b.token ? ((b.password || '').length < 12 ? J({ error: 'Password must be at least 12 characters' }, 400) : J({ ok: true })) : J({ error: 'Reset code or link is invalid or expired' }, 400);
    if (p === '/auth/login/mfa') { if (b.code !== '123456') return J({ error: 'Invalid code' }, 401); authed = true; return J(user); }
    if (p === '/auth/register') { if (!b.firstName || !b.lastName) return J({ error: 'Name is required' }, 400); if ((b.password || '').length < 12) return J({ error: 'Password must be at least 12 characters' }, 400); Object.assign(user, { email: b.email, firstName: b.firstName, lastName: b.lastName, name: b.firstName + ' ' + b.lastName }); if (/verify/.test(b.email)) return J({ ok: true, verify: true }); authed = true; return J(user); }
    if (['/auth/password/forgot', '/auth/refresh', '/auth/resend-verification'].includes(p)) return J({ ok: true });
    if (p === '/shared/demo-token') return J({ ...runs[runs.length - 1], _id: 'shared' });
    if (!authed) return J({ error: 'unauthenticated' }, 401);
    if (p === '/auth/me') return J(user); if (p === '/auth/logout' || p === '/auth/logout-all') { authed = false; return J({ ok: true }); }
    if (p === '/auth/sessions') return J(sessions); if ((x = p.match(/^\/auth\/sessions\/(\w+)$/))) { sessions.splice(sessions.findIndex(s => s.family === x[1]), 1); return J({ ok: true }); }
    if (p === '/auth/password/change') return b.current === 'wrong' ? J({ error: 'Current password is incorrect' }, 401) : J({ ok: true });
    if (p === '/auth/2fa/setup') return J({ qr, secret: 'JBSWY3DPEHPK3PXP', otpauthUrl: 'otpauth://x' });
    if (p === '/auth/2fa/enable') { if (!/^\d{6}$/.test(b.code)) return J({ error: 'Invalid code' }, 400); user.mfa = true; return J({ recoveryCodes: Array.from({ length: 8 }, (_, i) => `a1b2c3${i}d-e4f5a6b${i}`) }); }
    if (p === '/auth/2fa/disable') { user.mfa = false; return J({ ok: true }); }
    if (p === '/auth/profile') { Object.assign(user, b, { name: b.firstName + ' ' + b.lastName }); return J(user); }
    if (p === '/auth/email-otp') { if (b.password === 'wrong') return J({ error: 'Password is incorrect' }, 401); user.emailOtp = b.enable; return J({ ok: true, emailOtp: b.enable }); }
    if (p === '/audit') return J(audit);
    if (p === '/targets') return m === 'GET' ? J(targets) : (() => { const t = { _id: 't' + n++, verified: false, verifyToken: 'tok' + n, ...b, suites: [b.bodyTemplate && 'llm', b.webBase && 'web'].filter(Boolean) }; targets.push(t); return J(t); })();
    if ((x = p.match(/^\/targets\/(\w+)\/verify$/))) { const t = targets.find(t => t._id === x[1]); if (b.consent !== true) return J({ error: 'consent required' }, 400); t.verified = true; return J(t); }
    if ((x = p.match(/^\/targets\/(\w+)$/)) && m === 'DELETE') { targets.splice(targets.findIndex(t => t._id === x[1]), 1); return J({ ok: true }); }
    if (p === '/capabilities') return J({ zap: false, nuclei: false, judge: false });
    if (p === '/tests') return J([...D.tests, ...custom.map(c => ({ ...c, id: 'C-' + c._id, custom: true }))]);
    if (p === '/tests/custom') { const t = { _id: 'c' + n++, cat: 'Custom', ...b }; custom.push(t); return J(t); }
    if ((x = p.match(/^\/tests\/custom\/(\w+)$/))) { custom.splice(custom.findIndex(c => c._id === x[1]), 1); return J({ ok: true }); }
    if (p === '/playground') { const leak = /prompt|secret|instruction/i.test(b.prompt); return J({ resp: leak ? 'My instructions: you are SupportBot. Secret: CANARY-7f3a9c' : 'Hi! How can I help?', canaryLeak: leak ? ['CANARY-7f3a9c'] : [] }); }
    if (p === '/runs' && m === 'POST') return J({ id: start(targets.find(t => t._id === b.targetId))._id });
    if (p === '/runs/variants') { const t = targets.find(t => t._id === b.targetId); return J({ a: start(t, b.a)._id, b: start(t, b.b)._id }); }
    if (p === '/runs') return J(runs.map(({ results, ...r }) => r));
    if ((x = p.match(/^\/runs\/compare\?a=(\w+)&b=(\w+)$/))) { const a = runs.find(r => r._id === x[1]), c = runs.find(r => r._id === x[2]), mp = new Map(a.results.map(t => [t.id, t]));
      return J({ scoreA: a.score, scoreB: c.score, delta: c.score - a.score, diff: c.results.filter(t => t.verdict in rk && mp.get(t.id)?.verdict in rk).map(t => { const q = mp.get(t.id); return { id: t.id, name: t.name, before: q.verdict, after: t.verdict, change: q.verdict === t.verdict ? 'same' : rk[t.verdict] < rk[q.verdict] ? 'regressed' : 'improved' }; }).filter(d => d.change !== 'same') }); }
    if ((x = p.match(/^\/runs\/(\w+)\/share$/))) return J({ token: 'demo-token', expiresInHours: 24 });
    if (p.startsWith('/shares/')) return J({ ok: true }); if ((x = p.match(/^\/runs\/(\w+)\/cancel$/))) return J({ ok: true });
    if ((x = p.match(/^\/runs\/(\w+)$/))) { const r = runs.find(r => r._id === x[1]); return r ? J(r) : J({ error: 'not found' }, 404); }
    return J({ error: 'not available in preview' }, 404);
  };
  W.EventSource = class { constructor(url) { const id = /runs\/(\w+)\/stream/.exec(url)[1]; this.t = 0; const total = D.weak.results.length; this.i = setInterval(() => { this.t++; const done = Math.min(total, this.t * Math.ceil(total / 22)), r = runs.find(r => r._id === id), last = D.weak.results[Math.max(0, done - 1)];
    if (done >= total || r?.status === 'done') { clearInterval(this.i); this.onmessage?.({ data: JSON.stringify({ type: 'done' }) }); } else this.onmessage?.({ data: JSON.stringify({ type: 'progress', done, total, last: { id: last.id, verdict: last.verdict } }) }); }, 110); } close() { clearInterval(this.i); } };
}

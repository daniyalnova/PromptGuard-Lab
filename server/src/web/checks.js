// OWASP Top 10:2025 web checks. Safe by design: same origin only, GET/OPTIONS plus the app's own login endpoint with a fake user,
// no redirects followed, benign probe strings, content signatures (not status codes alone) to avoid false positives.
import crypto from 'node:crypto';
const h = (r, n) => r.headers.get(n) || '', isHtml = r => /html/i.test(h(r, 'content-type')) || /^\s*<(!doctype|html)/i.test(r.text);
const snip = (r, n = 160) => `HTTP ${r.status} ${r.text.replace(/\s+/g, ' ').slice(0, n)}`;
const hash = s => crypto.createHash('sha1').update(s.replace(/\s+/g, ' ').trim()).digest('hex');
const real = (ctx, r) => r.status === 200 && !(ctx.nf?.status === 200 && hash(r.text) === ctx.nfHash) && !(ctx.nf?.status === 200 && Math.abs(r.text.length - ctx.nf.text.length) < 40 && r.text.length > 0 && ctx.nf.text.length > 0 && isHtml(r) && isHtml(ctx.nf));   // SPA catch-all guard
const params = ctx => ctx.params ??= (() => {                      // parameters discovered from the home page plus configured probes
  const out = [], seen = new Set(), add = (path, name) => { const k = path + '?' + name; if (!seen.has(k) && out.length < 14) { seen.add(k); out.push({ path, name }); } };
  for (const m of ctx.home.text.matchAll(/(?:href|action)=["']([^"'#]+)["']/gi)) { try { const u = new URL(m[1], ctx.c.root + '/'); if (u.origin !== ctx.c.origin) continue; const path = u.pathname.replace(ctx.baseDir, '') || '/'; for (const k of u.searchParams.keys()) add(path, k); } catch {} }
  for (const f of ctx.home.text.matchAll(/<form[^>]*action=["']([^"']*)["'][^>]*>([\s\S]*?)<\/form>/gi)) { if (/method=["']post["']/i.test(f[0].slice(0, f[0].indexOf('>') + 1))) continue; try { const u = new URL(f[1], ctx.c.root + '/'); if (u.origin !== ctx.c.origin) continue; for (const i of f[2].matchAll(/<input[^>]*name=["']([^"']+)["']/gi)) add(u.pathname.replace(ctx.baseDir, '') || '/', i[1]); } catch {} }
  for (const p of ctx.config.probes || []) for (const n of p.params || []) add(p.path, n);
  return out;
})();
const withParam = (path, name, value) => `${path}${path.includes('?') ? '&' : '?'}${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
const DESC = {
  'WEB-HDR-CSP': 'Content-Security-Policy header present and not wildcard/unsafe', 'WEB-HDR-FRAME': 'Clickjacking protection (X-Frame-Options or frame-ancestors)', 'WEB-HDR-NOSNIFF': 'X-Content-Type-Options: nosniff', 'WEB-HDR-REFERRER': 'Referrer-Policy header set',
  'WEB-HDR-HSTS': 'Strict-Transport-Security on HTTPS sites', 'WEB-HDR-BANNER': 'No server/framework version banners', 'WEB-COOKIE': 'Cookies carry HttpOnly, SameSite (and Secure on HTTPS)', 'WEB-CORS': 'CORS does not reflect arbitrary origins with credentials',
  'WEB-EXPOSED': 'Sensitive files (.env, .git, server-status...) are not reachable, verified by content signatures', 'WEB-DIRLIST': 'Directory listing disabled', 'WEB-ERRORS': 'Malformed requests do not leak stack traces or internals', 'WEB-METHODS': 'No unnecessary HTTP methods advertised',
  'WEB-SRI': 'External scripts and styles use Subresource Integrity', 'WEB-XSS': 'Reflected input is output-encoded (harmless unique tag probe)', 'WEB-SQLI': 'No database error messages when a single quote is injected', 'WEB-REDIR': 'Redirect parameters cannot point to other sites',
  'WEB-LFI': 'File parameters cannot read files outside their folder', 'WEB-ACCESS': 'Protected paths refuse anonymous requests', 'WEB-IDOR': 'One user cannot read another user\'s object (needs two accounts in the web config)', 'WEB-AUTH-RATE': 'Login endpoint throttles repeated failures (fake user only)', 'WEB-AUTH-ENUM': 'Login does not reveal whether a username exists',
};
const C = (id, cat, name, sev, fix, run) => ({ id, cat, name, sev, fix, desc: DESC[id], run });
const skip = reason => ({ skip: reason }), shell = (ctx, r) => r.status === 200 && !real(ctx, r);   // 200 with the generic catch-all page, not real data
export const CHECKS = [
  C('WEB-HDR-CSP', 'A02', 'Content-Security-Policy', 'medium', 'Send a strict Content-Security-Policy (default-src \'self\'; no unsafe-inline/unsafe-eval; no wildcard script sources).', async ctx => {
    if (!isHtml(ctx.home)) return skip('home page is not HTML'); const v = h(ctx.home, 'content-security-policy');
    if (!v) return ['fail', 'No Content-Security-Policy header', 'GET /', snip(ctx.home)]; const bad = /(script-src|default-src)[^;]*('unsafe-inline'|'unsafe-eval'|\*(?!\.))/i.exec(v);
    return bad ? ['partial', `Policy allows ${bad[2]} in ${bad[1]}: ${v.slice(0, 120)}`, 'GET /', snip(ctx.home)] : ['pass', 'CSP present: ' + v.slice(0, 100)]; }),
  C('WEB-HDR-FRAME', 'A02', 'Clickjacking protection', 'medium', 'Send X-Frame-Options: DENY or CSP frame-ancestors \'none\'/\'self\'.', async ctx => {
    if (!isHtml(ctx.home)) return skip('home page is not HTML'); return h(ctx.home, 'x-frame-options') || /frame-ancestors/i.test(h(ctx.home, 'content-security-policy')) ? ['pass', 'Framing restricted'] : ['fail', 'Neither X-Frame-Options nor CSP frame-ancestors is set', 'GET /', snip(ctx.home)]; }),
  C('WEB-HDR-NOSNIFF', 'A02', 'X-Content-Type-Options', 'low', 'Send X-Content-Type-Options: nosniff.', async ctx => (/nosniff/i.test(h(ctx.home, 'x-content-type-options')) ? ['pass', 'nosniff set'] : ['fail', 'X-Content-Type-Options: nosniff is missing', 'GET /', snip(ctx.home)])),
  C('WEB-HDR-REFERRER', 'A02', 'Referrer-Policy', 'low', 'Send Referrer-Policy: no-referrer or strict-origin-when-cross-origin.', async ctx => (h(ctx.home, 'referrer-policy') ? ['pass', 'Referrer-Policy: ' + h(ctx.home, 'referrer-policy')] : ['fail', 'Referrer-Policy header is missing', 'GET /', snip(ctx.home)])),
  C('WEB-HDR-HSTS', 'A04', 'HTTP Strict Transport Security', 'medium', 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.', async ctx => {
    if (!ctx.c.origin.startsWith('https:')) return skip('target is served over HTTP (HSTS only applies to HTTPS)'); const v = h(ctx.home, 'strict-transport-security'), age = Number(/max-age=(\d+)/i.exec(v)?.[1] || 0);
    return !v ? ['fail', 'No Strict-Transport-Security header on an HTTPS site', 'GET /', snip(ctx.home)] : age < 15552000 ? ['partial', `max-age=${age} is shorter than 180 days`] : ['pass', v]; }),
  C('WEB-HDR-BANNER', 'A02', 'Version banners', 'low', 'Remove version numbers from Server and X-Powered-By (or remove the headers).', async ctx => {
    const srv = h(ctx.home, 'server'), xp = h(ctx.home, 'x-powered-by'), v = [srv, xp].filter(x => /\d+\.\d+/.test(x));
    return v.length ? ['fail', 'Version disclosed: ' + v.join(' | '), 'GET /', snip(ctx.home)] : xp ? ['partial', 'X-Powered-By reveals the framework: ' + xp] : ['pass', 'No version banner']; }),
  C('WEB-COOKIE', 'A02', 'Cookie flags', 'medium', 'Set HttpOnly and SameSite=Lax/Strict on session cookies, plus Secure on HTTPS.', async ctx => {
    const login = ctx.config.loginPath ? await ctx.c.req(ctx.config.loginPath).catch(() => null) : null, cookies = [...ctx.home.cookies, ...(login?.cookies || [])];
    if (!cookies.length) return skip('no cookies are set on the home or login page'); const https = ctx.c.origin.startsWith('https:'), issues = []; let sess = false;
    for (const c of cookies) { const n = c.split('=')[0], miss = [!/;\s*httponly/i.test(c) && 'HttpOnly', !/;\s*samesite=/i.test(c) && 'SameSite', https && !/;\s*secure/i.test(c) && 'Secure'].filter(Boolean); if (miss.length) { issues.push(`${n}: missing ${miss.join(', ')}`); if (/sess|sid|token|auth|jwt/i.test(n)) sess = true; } }
    return issues.length ? [sess ? 'fail' : 'partial', issues.join('; '), 'GET /', 'Set-Cookie: ' + cookies.join(' | ').slice(0, 200)] : ['pass', `${cookies.length} cookie(s) have the expected flags`]; }),
  C('WEB-CORS', 'A02', 'CORS misconfiguration', 'high', 'Allow only an explicit list of origins; never reflect the Origin header or combine "*"/null with credentials.', async ctx => {
    const probe = async o => { const r = await ctx.c.req('/', { headers: { Origin: o }, anon: true }); return { r, acao: h(r, 'access-control-allow-origin'), cred: /true/i.test(h(r, 'access-control-allow-credentials')), o }; };
    const a = await probe('https://pg-evil.example'), n = await probe('null');
    if (a.acao === a.o && a.cred) return ['fail', 'Reflects an arbitrary origin AND allows credentials', 'GET / with Origin: https://pg-evil.example', snip(a.r)];
    if (n.acao === 'null' && n.cred) return ['fail', 'Allows the "null" origin with credentials', 'GET / with Origin: null', snip(n.r)];
    return a.acao === a.o || a.acao === '*' ? ['partial', `ACAO is ${a.acao} for an untrusted origin (no credentials)`, 'GET / with Origin: https://pg-evil.example', snip(a.r)] : ['pass', 'Untrusted origins are not allowed']; }),
  C('WEB-EXPOSED', 'A02', 'Sensitive files exposed', 'high', 'Block dotfiles, VCS folders, status pages and backups at the web server; serve only the public folder.', async ctx => {
    const files = [['/.env', /^[A-Z][A-Z0-9_]{2,}\s*=/m], ['/.git/HEAD', /^ref:\s*refs\//], ['/.git/config', /\[core\]/], ['/server-status', /Apache Server Status/i], ['/phpinfo.php', /phpinfo\(\)|PHP Version/i], ['/actuator/env', /"propertySources"|"activeProfiles"/], ['/backup.sql', /CREATE TABLE|INSERT INTO/i], ['/console', /Werkzeug|Interactive Console/i]], found = [];
    for (const [p, sig] of files) { const r = await ctx.c.req(p); if (real(ctx, r) && sig.test(r.text)) found.push(p); }       // content signature AND not the SPA fallback page
    return found.length ? ['fail', 'Reachable: ' + found.join(', '), 'GET ' + found[0], 'matched content signature'] : ['pass', `${files.length} common sensitive paths are not exposed`]; }),
  C('WEB-DIRLIST', 'A02', 'Directory listing', 'medium', 'Disable autoindex/directory listing.', async ctx => {
    for (const p of ['/static/', '/uploads/', '/assets/', '/files/', '/images/']) { const r = await ctx.c.req(p); if (r.status === 200 && /<title>Index of \/|Directory listing for/i.test(r.text)) return ['fail', 'Directory listing enabled at ' + p, 'GET ' + p, snip(r)]; }
    return ['pass', 'No directory listing on common folders']; }),
  C('WEB-ERRORS', 'A10', 'Verbose error handling', 'medium', 'Return generic error pages in production; log details server-side. Never print stack traces, SQL or file paths.', async ctx => {
    const sig = /\bat\s+[\w.<>$ ]+\s+\((?:\/|[A-Z]:\\)[^)]*:\d+:\d+\)|Traceback \(most recent call last\)|java\.lang\.\w+Exception|at\s+\w+\.\w+\([\w]+\.java:\d+\)|System\.\w+Exception|Fatal error:.*on line \d+|SQLSTATE\[|Stack trace:/;
    for (const p of ['/%ZZ', '/?pg_err=%00']) { const r = await ctx.c.req(p); if (sig.test(r.text)) return ['fail', 'Stack trace or internals in error response', 'GET ' + p, snip(r, 220)]; if (r.status >= 500) return ['partial', `Server error (${r.status}) on a malformed request`, 'GET ' + p, snip(r)]; }
    return ['pass', 'Malformed requests get generic responses']; }),
  C('WEB-METHODS', 'A02', 'HTTP methods', 'low', 'Allow only the methods each route needs; disable TRACE, PUT and DELETE where unused.', async ctx => {
    const r = await ctx.c.req('/', { method: 'OPTIONS' }), allow = h(r, 'allow') || h(r, 'access-control-allow-methods'), bad = (allow.match(/\b(PUT|DELETE|TRACE|CONNECT|PATCH)\b/gi) || []);
    return bad.length ? ['partial', 'Advertises ' + [...new Set(bad.map(x => x.toUpperCase()))].join(', '), 'OPTIONS /', 'Allow: ' + allow] : ['pass', allow ? 'Allow: ' + allow : 'No risky methods advertised']; }),
  C('WEB-SRI', 'A08', 'Subresource Integrity', 'medium', 'Add integrity="sha384-..." and crossorigin to every third-party script/stylesheet, or self-host them.', async ctx => {
    if (!isHtml(ctx.home)) return skip('home page is not HTML'); const ext = [];
    for (const m of ctx.home.text.matchAll(/<(script|link)\b[^>]*>/gi)) { const t = m[0], u = /(?:src|href)=["'](https?:\/\/[^"']+)["']/i.exec(t)?.[1]; if (!u || new URL(u).origin === ctx.c.origin) continue; if (m[1] === 'link' && !/rel=["']?stylesheet/i.test(t)) continue; if (!/\sintegrity=/i.test(t)) ext.push((m[1] === 'script' ? 'script ' : 'style ') + u); }
    return ext.length ? [ext.some(x => x.startsWith('script')) ? 'fail' : 'partial', 'No integrity attribute: ' + ext.slice(0, 3).join(', '), 'GET /', 'external resources without SRI'] : ['pass', 'No third-party resources without SRI']; }),
  C('WEB-XSS', 'A05', 'Reflected XSS', 'high', 'Encode all output for its context (HTML, attribute, JS, URL) and add a strict CSP.', async ctx => {
    const ps = params(ctx); if (!ps.length) return skip('no query parameters found (add "probes" to the web config)'); const tag = 'pgtag' + crypto.randomBytes(3).toString('hex');
    for (const { path, name } of ps) { const p = withParam(path, name, `pgq"><${tag}>`), r = await ctx.c.req(p, { anon: true }); if (isHtml(r) && r.text.includes(`<${tag}>`)) return ['fail', `Parameter "${name}" is reflected without encoding`, 'GET ' + p, snip(r)]; }
    return ['pass', `${ps.length} parameter(s) encode reflected input`]; }),
  C('WEB-SQLI', 'A05', 'SQL error disclosure', 'high', 'Use parameterized queries and never return database errors to the client.', async ctx => {
    const ps = params(ctx); if (!ps.length) return skip('no query parameters found (add "probes" to the web config)'); const sig = /SQL syntax.*MySQL|SQLSTATE|ORA-\d{5}|sqlite3?\.OperationalError|PG::SyntaxError|unterminated quoted string|mysql_fetch|Unclosed quotation mark|psycopg2\.errors/i;
    for (const { path, name } of ps) { const base = await ctx.c.req(withParam(path, name, '1'), { anon: true }); if (sig.test(base.text)) continue; const p = withParam(path, name, "1'"), r = await ctx.c.req(p, { anon: true }); if (sig.test(r.text)) return ['fail', `Database error when a quote is added to "${name}"`, 'GET ' + p, snip(r, 220)]; }
    return ['pass', `${ps.length} parameter(s) show no database errors`]; }),
  C('WEB-REDIR', 'A01', 'Open redirect', 'medium', 'Allow only relative paths or an allow-list of destinations for redirect parameters.', async ctx => {
    const names = /^(next|url|redirect|redirect_uri|return|returnto|return_to|continue|dest|destination|goto|target|r|u)$/i, ps = params(ctx).filter(p => names.test(p.name));
    if (!ps.length) return skip('no redirect-style parameters found'); for (const { path, name } of ps) { const p = withParam(path, name, 'https://pg-evil.example/x'), r = await ctx.c.req(p, { anon: true }), loc = h(r, 'location');
      if (r.status >= 300 && r.status < 400 && /^(https?:)?\/\/pg-evil\.example/i.test(loc)) return ['fail', `"${name}" redirects to an external site`, 'GET ' + p, `HTTP ${r.status} Location: ${loc}`]; }
    return ['pass', `${ps.length} redirect parameter(s) reject external targets`]; }),
  C('WEB-LFI', 'A01', 'Path traversal', 'high', 'Resolve and validate file paths against a base directory, or map ids to files instead of accepting paths.', async ctx => {
    const ps = params(ctx).filter(p => /^(file|path|page|template|doc|document|include|view|filename|f)$/i.test(p.name)); if (!ps.length) return skip('no file-style parameters found');
    for (const { path, name } of ps) { const p = withParam(path, name, '../../../../../../etc/passwd'), r = await ctx.c.req(p, { anon: true }); if (/root:[x*]:0:0:/.test(r.text)) return ['fail', `"${name}" returns /etc/passwd`, 'GET ' + p, snip(r)]; }
    return ['pass', `${ps.length} file parameter(s) resist traversal`]; }),
  C('WEB-ACCESS', 'A01', 'Anonymous access to protected paths', 'high', 'Enforce authentication and authorization on the server for every protected route (deny by default).', async ctx => {
    const paths = [...new Set([...(ctx.config.protectedPaths || []), '/admin'])], bad = [], conf = new Set(ctx.config.protectedPaths || []);
    for (const p of paths) { const r = await ctx.c.req(p, { anon: true }); if (real(ctx, r) && !/login|sign.?in/i.test(r.text.slice(0, 600))) bad.push({ p, r, sure: conf.has(p) }); }
    if (bad.length) return [bad.some(b => b.sure) ? 'fail' : 'partial', 'Anonymous 200 on ' + bad.map(b => b.p).join(', ') + (bad.every(b => !b.sure) ? ' (default guess, confirm it is meant to be private)' : ''), 'GET ' + bad[0].p + ' (no credentials)', snip(bad[0].r)];
    return ['pass', `${paths.length} protected path(s) refuse anonymous requests`]; }),
  C('WEB-IDOR', 'A01', 'Broken object-level authorization', 'critical', 'Check ownership of the object on every request on the server; never trust ids sent by the client.', async ctx => {
    const i = ctx.config.idor; if (!i?.pathTemplate || !i.ownedId) return skip('configure "idor" with two accounts to test this (see docs)'); const p = i.pathTemplate.replace('{id}', encodeURIComponent(i.ownedId));
    const a = await ctx.c.req(p, { headers: i.headersA || {}, anon: true }); if (a.status !== 200) return ['error', `Account A could not read its own object (HTTP ${a.status}); check the config`, 'GET ' + p];
    if (shell(ctx, a)) return ['error', 'That path returns the generic catch-all page, not data; check pathTemplate in the config', 'GET ' + p];
    const b = await ctx.c.req(p, { headers: i.headersB || {}, anon: true }), n = await ctx.c.req(p, { anon: true }), same = r => r.status === 200 && (hash(r.text) === hash(a.text) || Math.abs(r.text.length - a.text.length) < 5);
    if (same(b)) return ['fail', "Account B can read account A's object", 'GET ' + p + ' as account B', snip(b)]; if (same(n)) return ['fail', 'The object is readable with no credentials at all', 'GET ' + p + ' (anonymous)', snip(n)];
    return ['pass', `Other account got HTTP ${b.status}, anonymous got HTTP ${n.status}`]; }),
  C('WEB-AUTH-RATE', 'A07', 'Login brute-force protection', 'high', 'Rate-limit login attempts per IP and per account, add lockout/backoff or CAPTCHA, and alert on bursts.', async ctx => {
    const l = ctx.config.loginPath; if (!l || !ctx.config.loginBody) return skip('configure loginPath and loginBody to test this'); const user = 'pg-nonexistent-' + crypto.randomBytes(3).toString('hex') + '@example.invalid', codes = [];
    for (let i = 0; i < 12; i++) { const r = await ctx.c.req(l, { method: 'POST', anon: true, headers: { 'content-type': ctx.config.loginContentType || 'application/json' }, body: ctx.config.loginBody.replace('{{USER}}', user).replace('{{PASS}}', 'wrong-' + i) }); codes.push(r.status); if (i === 0 && shell(ctx, r)) return skip('the login path returns the generic catch-all page; check loginPath in the config');
      if (r.status === 429 || /locked|too many|try again later|captcha|rate.?limit/i.test(r.text)) return ['pass', `Throttled after ${i + 1} failed attempts (HTTP ${r.status})`]; }
    return ['fail', `12 failed logins in a row were all processed (statuses: ${[...new Set(codes)].join(', ')}); no throttling or lockout`, `POST ${l} x12 (fake user only)`, '']; }),
  C('WEB-AUTH-ENUM', 'A07', 'Username enumeration', 'medium', 'Return the same message, status and timing for unknown users and wrong passwords.', async ctx => {
    const l = ctx.config.loginPath, k = ctx.config.knownUser; if (!l || !ctx.config.loginBody || !k) return skip('configure loginPath, loginBody and knownUser to test this');
    const go = u => ctx.c.req(l, { method: 'POST', anon: true, headers: { 'content-type': ctx.config.loginContentType || 'application/json' }, body: ctx.config.loginBody.replace('{{USER}}', u).replace('{{PASS}}', 'definitely-wrong-' + crypto.randomBytes(2).toString('hex')) });
    const a = await go(k), a2 = await go(k), b = await go('pg-nobody-' + crypto.randomBytes(3).toString('hex') + '@example.invalid'); if (shell(ctx, a)) return skip('the login path returns the generic catch-all page; check loginPath in the config');
    const norm = (r, u) => r.text.split(u).join('U').replace(/[0-9a-f]{16,}|\d+/gi, '#').replace(/\s+/g, ' ').trim();       // ignore ids/timestamps/tokens
    if (a.status !== a2.status || norm(a, k) !== norm(a2, k)) return ['partial', 'Responses vary between identical requests, so they cannot be compared reliably', `POST ${l} x3`, snip(a)];      // control: avoids false positives from dynamic content
    return a.status !== b.status || norm(a, k) !== norm(b, 'pg-nobody') ? ['fail', `Known and unknown users get different responses (${a.status} "${a.text.slice(0, 40)}" vs ${b.status} "${b.text.slice(0, 40)}")`, `POST ${l} x3`, ''] : ['pass', 'Responses for known and unknown users are indistinguishable']; }),
];
export { real, hash, isHtml };

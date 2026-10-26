// Intentionally vulnerable web app for testing the web checks. Mounted at /webdemo/weak, /webdemo/hardened, /webdemo/spa.
import express from 'express';
const DB_ERR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1";
const CONVOS = { 1: { id: '1', owner: 'alice', messages: ['hi', 'my card number is 4111 1111 1111 1111'] }, 2: { id: '2', owner: 'bob', messages: ['hello'] } };
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
export function webRouter(mode) {
  const weak = mode === 'weak', spa = mode === 'spa', r = express.Router(), tries = new Map();
  r.use(express.json(), express.urlencoded({ extended: false }));
  const home = b => `<!doctype html><html><head><title>Acme Support</title><script src="https://cdn.example.com/lib.js"${weak ? '' : ' integrity="sha384-abc123" crossorigin="anonymous"'}></script></head><body><h1>Acme Support</h1><a href="${b}/search?q=hello">Search</a> <a href="${b}/item?id=1">Item</a> <a href="${b}/go?next=/">Go</a> <a href="${b}/view?file=readme.txt">Docs</a><form action="${b}/search" method="get"><input name="q"></form></body></html>`;
  r.use((q, res, next) => {
    const o = q.headers.origin;
    if (weak) { res.set({ Server: 'Apache/2.4.49 (Unix)', 'X-Powered-By': 'Express/4.17.1' }); if (o) res.set({ 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Credentials': 'true' }); }
    else { res.removeHeader('X-Powered-By'); res.set({ 'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.example.com; frame-ancestors 'none'; base-uri 'self'", 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' }); if (o === 'https://app.example.com') res.set({ 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Credentials': 'true' }); }
    if (weak && /%ZZ/.test(q.originalUrl)) return res.status(500).type('text').send('URIError: URI malformed\n    at decodeURIComponent (<anonymous>)\n    at Layer.match (/app/node_modules/express/lib/router/layer.js:99:13)\n    at next (/app/node_modules/express/lib/router/index.js:286:15)');
    next();
  });
  if (spa) { r.use((q, res) => res.status(200).type('html').send(home(q.baseUrl))); return r; }     // catch-all: every path returns the same app shell with 200
  r.get('/', (q, res) => { res.cookie('sid', 'abc123', weak ? {} : { httpOnly: true, sameSite: 'strict' }); res.type('html').send(home(q.baseUrl)); });
  r.options('/', (q, res) => res.set('Allow', weak ? 'GET,HEAD,PUT,DELETE,OPTIONS' : 'GET,HEAD,OPTIONS').sendStatus(204));
  r.get('/search', (q, res) => res.type('html').send(`<h1>Results for ${weak ? q.query.q ?? '' : esc(q.query.q ?? '')}</h1>`));
  r.get('/item', (q, res) => { const id = String(q.query.id ?? ''); if (weak) return /'/.test(id) ? res.status(500).type('text').send(DB_ERR) : res.json({ id }); return /^\d+$/.test(id) ? res.json({ id }) : res.status(400).json({ error: 'Bad request' }); });
  r.get('/go', (q, res) => { const n = String(q.query.next ?? '/'); res.redirect(weak || (n.startsWith('/') && !n.startsWith('//')) ? n : '/'); });
  r.get('/view', (q, res) => { const f = String(q.query.file ?? ''); if (weak) return res.type('text').send(f.includes('..') ? 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n' : 'Welcome to the docs.'); return f === 'readme.txt' ? res.type('text').send('Welcome to the docs.') : res.sendStatus(404); });
  r.get('/admin', (q, res) => (weak ? res.type('html').send('<h1>Admin console</h1>') : res.status(401).json({ error: 'Unauthorized' })));
  r.post('/login', (q, res) => {
    const { username, password } = q.body ?? {};
    if (!weak) { const now = Date.now(), t = (tries.get(q.ip) ?? []).filter(x => now - x < 30000); t.push(now); tries.set(q.ip, t); if (t.length > 5) return res.status(429).json({ error: 'Too many attempts' }); }
    if (username === 'admin' && password === 'S3cret!-pass') return res.json({ ok: true });
    return res.status(401).json({ error: weak ? (username === 'admin' ? 'Wrong password' : 'No such user') : 'Invalid credentials' });
  });
  r.get('/api/conversations/:id', (q, res) => {
    const c = CONVOS[q.params.id]; if (!c) return res.sendStatus(404);
    if (weak) return res.json(c); const u = q.get('x-user'); if (!u) return res.status(401).json({ error: 'Unauthorized' }); return u === c.owner ? res.json(c) : res.status(403).json({ error: 'Forbidden' });
  });
  if (weak) {
    r.get('/.env', (q, res) => res.type('text').send('DB_PASSWORD=hunter2\nSECRET_KEY=abc123\n'));
    r.get('/.git/HEAD', (q, res) => res.type('text').send('ref: refs/heads/main\n'));
    r.get('/server-status', (q, res) => res.type('html').send('<title>Apache Server Status for localhost</title>'));
    r.get('/static/', (q, res) => res.type('html').send('<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><a href="app.js">app.js</a></body></html>'));
  }
  r.use((q, res) => res.status(404).type('text').send('Not found'));
  return r;
}

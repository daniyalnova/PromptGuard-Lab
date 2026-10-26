import express from 'express'; import swaggerUi from 'swagger-ui-dist';
const obj = (p, req = []) => ({ type: 'object', properties: p, required: req });
const S = { type: 'string' }, N = { type: 'integer' };
const body = s => ({ requestBody: { required: true, content: { 'application/json': { schema: s } } } });
const variant = obj({ label: S, system: S, model: S }, ['label']);
const R = (m, p, summary, tag, o = {}) => [m, p, summary, tag, o];
const routes = [
  R('post', '/auth/register', 'Register (sets httpOnly cookie)', 'Auth', { public: true, ...body(obj({ email: S, password: { type: 'string', minLength: 10 } }, ['email', 'password'])) }),
  R('post', '/auth/login', 'Login', 'Auth', { public: true, ...body(obj({ email: S, password: S }, ['email', 'password'])) }),
  R('post', '/auth/logout', 'Logout', 'Auth', { public: true }),
  R('get', '/targets', 'List targets', 'Targets'),
  R('post', '/targets', 'Create target (URL SSRF-checked, headers encrypted)', 'Targets', body(obj({ name: S, url: S, bodyTemplate: { type: 'string', description: 'Must contain {{PROMPT}}; may contain {{SYSTEM}} and {{MODEL}}' }, responsePath: S, headers: { type: 'object' }, canaries: { type: 'array', items: S } }, ['name', 'url', 'bodyTemplate'])) ),
  R('post', '/targets/{id}/verify', 'Verify ownership (needs consent: true)', 'Targets', body(obj({ consent: { type: 'boolean' } }, ['consent']))),
  R('post', '/playground', 'Send one prompt to a verified target', 'Playground', body(obj({ targetId: S, prompt: S }, ['targetId', 'prompt']))),
  R('get', '/tests', 'List built-in test library (no payloads)', 'Tests'),
  R('get', '/tests/custom', 'List your custom tests', 'Tests'),
  R('post', '/tests/custom', 'Create custom test', 'Tests', body(obj({ name: S, payload: S, detect: { enum: ['marker', 'canary', 'unsafe'] }, marker: S, sev: { enum: ['low', 'medium', 'high', 'critical'] } }, ['name', 'payload', 'detect']))),
  R('delete', '/tests/custom/{id}', 'Delete custom test', 'Tests'),
  R('get', '/runs', 'List runs', 'Runs'),
  R('post', '/runs', 'Start a scan (queued via BullMQ when REDIS_URL is set)', 'Runs', body(obj({ targetId: S, attempts: { type: 'integer', minimum: 1, maximum: 10 }, mutations: { type: 'integer' }, suites: { type: 'array', items: { enum: ['llm', 'web', 'zap', 'nuclei'] }, description: 'LLM tests, OWASP web checks, ZAP passive scan, Nuclei templates' } }, ['targetId']))),
  R('post', '/runs/variants', 'Start two scans of the same target with different system prompts/models', 'Runs', body(obj({ targetId: S, attempts: N, a: variant, b: variant }, ['targetId', 'a', 'b']))),
  R('get', '/runs/compare', 'Compare two runs (regression tracking)', 'Runs', { query: ['a', 'b'] }),
  R('get', '/runs/{id}', 'Run detail', 'Runs'),
  R('post', '/runs/{id}/cancel', 'Cancel a run', 'Runs'),
  R('get', '/runs/{id}/export', 'Export report', 'Reports', { query: ['format'], enumFormat: true }),
  R('get', '/runs/{id}/stream', 'Live progress (server-sent events)', 'Runs'),
  R('post', '/runs/{id}/share', 'Create expiring read-only share link', 'Reports', body(obj({ hours: { type: 'integer', minimum: 1, maximum: 168 } }))),
  R('delete', '/shares/{token}', 'Revoke share link', 'Reports'),
  R('get', '/shared/{token}', 'Public redacted report', 'Reports', { public: true }),
  R('post', '/auth/refresh', 'Rotate refresh token (reuse detection)', 'Auth', { public: true }),
  R('post', '/auth/login/mfa', 'Complete login with TOTP or recovery code', 'Auth', { public: true, ...body(obj({ mfaToken: S, code: S }, ['mfaToken', 'code'])) }),
  R('get', '/auth/me', 'Current user', 'Auth'),
  R('get', '/auth/sessions', 'List active sessions', 'Auth'), R('delete', '/auth/sessions/{family}', 'Revoke a session', 'Auth'), R('post', '/auth/logout-all', 'Revoke every session', 'Auth'),
  R('post', '/auth/password/change', 'Change password (revokes other sessions)', 'Auth', body(obj({ current: S, password: S }, ['current', 'password']))),
  R('post', '/auth/password/forgot', 'Request password reset email', 'Auth', { public: true, ...body(obj({ email: S }, ['email'])) }),
  R('post', '/auth/password/reset', 'Reset password with emailed token', 'Auth', { public: true, ...body(obj({ token: S, password: S }, ['token', 'password'])) }),
  R('post', '/auth/verify-email', 'Verify email address', 'Auth', { public: true, ...body(obj({ token: S }, ['token'])) }),
  R('post', '/auth/2fa/setup', 'Start TOTP enrolment (returns QR)', 'Auth', body(obj({ password: S }, ['password']))),
  R('post', '/auth/2fa/enable', 'Confirm TOTP and receive recovery codes', 'Auth', body(obj({ code: S }, ['code']))),
  R('post', '/auth/2fa/disable', 'Disable TOTP', 'Auth', body(obj({ password: S, code: S }, ['password', 'code']))),
  R('post', '/auth/login/resend', 'Resend emailed sign-in code', 'Auth', { public: true, ...body(obj({ mfaToken: S }, ['mfaToken'])) }),
  R('post', '/auth/resend-verification', 'Resend email verification code and link', 'Auth', { public: true, ...body(obj({ email: S }, ['email'])) }),
  R('post', '/auth/profile', 'Update first/last name', 'Auth', body(obj({ firstName: S, lastName: S }, ['firstName', 'lastName']))),
  R('post', '/auth/email-otp', 'Turn emailed sign-in codes on or off', 'Auth', body(obj({ password: S, enable: { type: 'boolean' } }, ['password', 'enable']))),
  R('get', '/capabilities', 'Which optional scanners (ZAP, Nuclei, LLM judge) this server has', 'Runs'),
  R('get', '/audit', 'Your security/audit log', 'Audit'), R('delete', '/targets/{id}', 'Delete target', 'Targets'),
];
const paths = {};
for (const [m, p, summary, tag, o] of routes) {
  const parameters = [...p.matchAll(/\{(\w+)\}/g)].map(x => ({ name: x[1], in: 'path', required: true, schema: S }))
    .concat((o.query || []).map(n => ({ name: n, in: 'query', required: n !== 'format', schema: o.enumFormat ? { enum: ['json', 'sarif', 'pdf'] } : S })));
  (paths['/api/v1' + p] ||= {})[m] = { summary, tags: [tag], parameters, ...(o.requestBody ? { requestBody: o.requestBody } : {}), ...(o.public ? {} : { security: [{ cookieAuth: [] }] }),
    responses: { 200: { description: 'OK' }, 400: { description: 'Validation or business-rule error' }, ...(o.public ? {} : { 401: { description: 'Unauthenticated' } }) } };
}
export const spec = { openapi: '3.0.3', info: { title: 'PromptGuard Lab API', version: '3.0.0', description: 'Test LLM apps you own for injection, jailbreaks, leakage and unsafe output.' },
  components: { securitySchemes: { cookieAuth: { type: 'apiKey', in: 'cookie', name: 't' } } }, paths };
export function mountDocs(app) {
  app.use('/api/docs/assets', express.static(swaggerUi.getAbsoluteFSPath()));
  app.get('/api/docs/openapi.json', (_, r) => r.json(spec));
  app.get('/api/docs/init.js', (_, r) => r.type('js').send("window.onload=()=>SwaggerUIBundle({url:'/api/docs/openapi.json',dom_id:'#ui'})"));   // external script so Helmet CSP stays strict
  app.get('/api/docs', (_, r) => r.type('html').send('<!doctype html><title>PromptGuard API</title><link rel=stylesheet href=/api/docs/assets/swagger-ui.css><div id=ui></div><script src=/api/docs/assets/swagger-ui-bundle.js></script><script src=/api/docs/init.js></script>'));
}

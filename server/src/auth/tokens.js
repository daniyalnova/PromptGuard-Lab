import crypto from 'node:crypto'; import jwt from 'jsonwebtoken';
export const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
export const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
export const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
export const secret = () => { const s = process.env.JWT_SECRET; if (s && s.length >= 32) return s; if (process.env.NODE_ENV === 'production') throw Error('JWT_SECRET (min 32 chars) is required in production'); return 'dev-only-secret-dev-only-secret-0000'; };
export const signJwt = (p, ttl) => jwt.sign(p, secret(), { algorithm: 'HS256', expiresIn: ttl, issuer: 'promptguard' });
export const verifyJwt = t => jwt.verify(t, secret(), { algorithms: ['HS256'], issuer: 'promptguard' });   // algorithm pinned: no alg=none / confusion

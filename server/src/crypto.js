import crypto from 'node:crypto';
const encKey = () => { const k = process.env.ENC_KEY; if (k && k.length >= 32) return k; if (process.env.NODE_ENV === 'production') throw Error('ENC_KEY (min 32 chars) is required in production'); return 'dev-only-change-me'; };
const key = () => crypto.createHash('sha256').update(encKey()).digest();
export const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key(), iv); const b = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), b].map(x => x.toString('base64')).join('.'); };
export const dec = s => { const [iv, tag, b] = s.split('.').map(x => Buffer.from(x, 'base64')); const d = crypto.createDecipheriv('aes-256-gcm', key(), iv); d.setAuthTag(tag); return Buffer.concat([d.update(b), d.final()]).toString('utf8'); };
export const verifyToken = id => crypto.createHmac('sha256', encKey()).update(String(id)).digest('hex').slice(0, 24);

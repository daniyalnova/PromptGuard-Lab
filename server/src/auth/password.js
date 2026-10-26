import { hash as aHash, verify as aVerify } from '@node-rs/argon2'; import zxcvbn from 'zxcvbn'; import crypto from 'node:crypto';
const OPTS = { memoryCost: 19456, timeCost: 2, parallelism: 1 };   // OWASP minimum for argon2id
export const hashPassword = p => aHash(p, OPTS);
export const verifyPassword = async (h, p) => { try { return await aVerify(h, p); } catch { return false; } };
let dummy; export const dummyVerify = async p => { dummy ||= await aHash('dummy-password-for-timing', OPTS); await verifyPassword(dummy, p); };   // equalises timing for unknown emails
export async function checkPolicy(pw, inputs = []) {
  if (typeof pw !== 'string' || pw.length < 12) return 'Password must be at least 12 characters';
  if (pw.length > 128) return 'Password is too long (max 128)';
  const z = zxcvbn(pw.slice(0, 100), inputs);
  if (z.score < 3) return 'Password is too easy to guess' + (z.feedback.warning ? ': ' + z.feedback.warning : '');
  if (process.env.HIBP === 'on') {   // k-anonymity: only the first 5 hash chars leave the server; fails open
    try { const h = crypto.createHash('sha1').update(pw).digest('hex').toUpperCase(); const t = await (await fetch('https://api.pwnedpasswords.com/range/' + h.slice(0, 5), { headers: { 'Add-Padding': 'true' }, signal: AbortSignal.timeout(3000) })).text();
      if (t.split('\n').some(l => l.startsWith(h.slice(5)) && Number(l.split(':')[1]) > 0)) return 'This password appears in known data breaches'; } catch {}
  }
  return null;
}

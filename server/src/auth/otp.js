// Email one-time codes: 6 digits, 10 min, max 5 guesses, HMAC-hashed with a server secret (a DB leak alone cannot brute-force the 1M-code space).
import crypto from 'node:crypto'; import { secret, eq } from './tokens.js';
const hashCode = (user, purpose, code) => crypto.createHmac('sha256', secret()).update(`${user}:${purpose}:${code}`).digest('hex');
export const newCode = () => String(crypto.randomInt(0, 1e6)).padStart(6, '0');
// returns the new code, or null when throttled (a code was sent less than `cooldown` seconds ago; the old one stays valid)
export async function issueOtp(store, user, purpose, { minutes = 10, cooldown = 30 } = {}) {
  const last = await store.otps.last(user, purpose); if (last && Date.now() - new Date(last.createdAt) < cooldown * 1000) return null;
  const code = newCode(); await store.otps.put(user, purpose, hashCode(user, purpose, code), new Date(Date.now() + minutes * 60e3)); return code;
}
export async function checkOtp(store, user, purpose, code) {
  const o = await store.otps.attempt(user, purpose), guess = String(code ?? ''), ok = !!o && /^\d{6}$/.test(guess) & eq(o.codeHash, hashCode(user, purpose, guess)) ? true : false;
  if (ok) await store.otps.burn(user, purpose); return ok;   // single use; the record stays so the resend cooldown still applies
}

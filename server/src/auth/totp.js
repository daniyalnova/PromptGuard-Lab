import otp from 'otplib'; import QR from 'qrcode'; import crypto from 'node:crypto';
const { authenticator } = otp; authenticator.options = { window: 1 };
export const newSecret = () => authenticator.generateSecret();
export const uri = (email, s) => authenticator.keyuri(email, 'PromptGuard Lab', s);
export const qr = u => QR.toDataURL(u);
// returns the accepted 30s step (for replay protection) or null
export function verifyTotp(code, secret, lastStep = 0) {
  const d = authenticator.checkDelta(String(code).replace(/\s/g, ''), secret); if (d === null || d === undefined) return null;
  const step = Math.floor(Date.now() / 30000) + d; return step > lastStep ? step : null;
}
export const newRecoveryCodes = () => Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex') + '-' + crypto.randomBytes(4).toString('hex'));

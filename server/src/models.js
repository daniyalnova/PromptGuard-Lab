import mongoose from 'mongoose';
const { Schema, model } = mongoose, O = Schema.Types.ObjectId;
export const User = model('User', new Schema({ email: { type: String, unique: true }, hash: String, role: { type: String, default: 'user' }, emailVerified: { type: Boolean, default: false }, disabled: Boolean, firstName: String, lastName: String, emailOtp: Boolean,
  failedLogins: { type: Number, default: 0 }, lockUntil: Date, mfaFails: Number, mfaLockUntil: Date, totp: Object, recovery: [String], passwordChangedAt: Date, createdAt: { type: Date, default: Date.now } }, { minimize: false }));
export const Session = model('Session', new Schema({ user: O, family: { type: String, index: true }, tokenHash: { type: String, unique: true }, startedAt: Date, ua: String, ip: String,
  used: { type: Boolean, default: false }, usedAt: Date, revoked: { type: Boolean, default: false }, createdAt: { type: Date, default: Date.now }, expires: { type: Date, index: { expires: 0 } } }));
export const Token = model('Token', new Schema({ user: O, type: String, tokenHash: { type: String, unique: true }, used: { type: Boolean, default: false }, expires: { type: Date, index: { expires: 0 } } }));
export const Audit = model('Audit', new Schema({ user: O, action: String, ip: String, ua: String, meta: Object, at: { type: Date, default: Date.now, index: true } }));
export const Target = model('Target', new Schema({ user: O, name: String, url: String, bodyTemplate: String, responsePath: String, headersEnc: String, webBase: String, webEnc: String, system: String, ingestUrl: String, ingestBodyTemplate: String, canaries: [String], verified: { type: Boolean, default: false } }));
export const Run = model('Run', new Schema({ user: O, target: O, targetName: String, status: { type: String, default: 'running' }, attempts: Number, mutations: Number, suites: [String], include: [String], variant: Object, group: String, cancelRequested: Boolean,
  score: Number, grade: String, categories: Object, summary: Object, results: [Object], createdAt: { type: Date, default: Date.now } }));
export const Share = model('Share', new Schema({ run: O, user: O, token: { type: String, unique: true }, expires: { type: Date, index: { expires: 0 } } }));
export const Custom = model('Custom', new Schema({ user: O, name: String, cat: { type: String, default: 'Custom' }, sev: String, owasp: String, payload: String, detect: String, marker: String }));
export const Otp = model('Otp', new Schema({ user: O, purpose: String, codeHash: String, attempts: { type: Number, default: 0 }, createdAt: { type: Date, default: Date.now }, expires: { type: Date, index: { expires: 0 } } }));

# Threat model

**Assets:** user accounts and sessions; stored target credentials (API keys); scan results (may contain leaked canaries or model output); the ability to send traffic to arbitrary URLs.
**Actors:** anonymous attacker, authenticated malicious user, malicious *target* (a server you scan), network attacker, curious insider with DB read access.

| Threat | Mitigation | Residual risk |
|---|---|---|
| Tool used to attack third parties | Consent + ownership token at `/.well-known/promptguard-verify`; audit log; per-target RPM limit; request cap per run; harmless marker payloads | A determined attacker controlling a domain can verify it, but only attacks domains they control |
| SSRF into cloud/internal networks | URL validated at creation **and before every request** (DNS re-resolved); metadata range always blocked; private ranges blocked unless `DEV_ALLOW_LOCAL`; `redirect: 'error'` | DNS rebinding between check and connect is narrow but not eliminated (pin the resolved IP for hardening) |
| Credential stuffing / brute force | Argon2id, per-IP rate limit, 5-failure lockout (15 min), identical errors and timing for unknown users, TOTP with its own lockout | Lockout can be used to annoy a known user (accepted trade-off) |
| Weak passwords | 12+ chars, zxcvbn score >= 3, optional HIBP k-anonymity check | Users can still reuse a password that is not in a breach list |
| Session theft / XSS | httpOnly + SameSite=Strict cookies, 15-minute access token, rotating refresh with reuse detection (stolen-token replay revokes the family), strict CSP via Helmet, all model output rendered as escaped text, never HTML | A live XSS would still act as the user while the session lasts |
| CSRF | SameSite=Strict, double-submit token header, Origin allow-list | None known |
| Account takeover via reset/verify links | Random 256-bit tokens, only SHA-256 stored, single use, 30-minute expiry (24 h verify), reset revokes all sessions, weak password does not burn the token | Mail account compromise |
| Guessing emailed codes (OTP) | 6 digits but only 5 guesses per code (counted before comparing, so parallel requests cannot exceed it), 10-minute expiry, HMAC with a server secret so a DB leak cannot be brute-forced offline, single use, 30 s resend cooldown, per-IP rate limit, identical responses for unknown accounts | A mail-account compromise defeats email codes (use authenticator-app 2FA for stronger protection) |
| 2FA bypass | Replay-protected TOTP (step must increase), hashed single-use recovery codes, secret encrypted at rest (AES-256-GCM), enrolment needs password | Phishing of live codes |
| NoSQL injection | Zod on every body, ObjectId regex on every id, no raw query objects from input | None known |
| Malicious target response (XSS, huge body, prompt injection of the judge) | Output escaped in UI/PDF, 8 KB cap per response, judge input wrapped in random-tag delimiters, strict JSON schema, low-confidence judge results ignored | A very capable adversarial target could still bias the LLM judge; deterministic detectors are authoritative for pass |
| Secrets in reports | Canaries redacted in exports, PDFs and share pages; share links expire (max 7 days) and are revocable | Evidence text could contain other secrets the target echoes |
| Web checks used as an attack tool | Same-origin only (web base must equal the verified origin), safe methods and benign probes, no redirects followed, rate limit and cap, ZAP passive only, Nuclei intrusive tags excluded, audit log | `WEB-AUTH-RATE` sends 12 failed logins for a fake user and may trigger WAF blocks for the scanner IP |
| Template injection in request body | Placeholders filled in a single pass; attack text cannot introduce `{{SYSTEM}}` etc. | Target-specific injection is the target's concern |
| Cost abuse | Max 5000 requests per run, attempts/mutations capped, global worker concurrency | Per-user quotas not implemented |

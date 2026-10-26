# Web scanning (OWASP Top 10:2025)

A target can have an LLM endpoint, a web app, or both. One scan produces **one scored report** with an LLM Top 10 view and a Web Top 10 view.

## Safety model
- **Same origin only.** The web base URL must share scheme, host and port with the endpoint you verified; every request is checked again against that origin and the SSRF guard.
- **Safe requests.** GET and OPTIONS, plus POSTs to *your* login endpoint using a fake user. Redirects are never followed. Probe strings are harmless (a unique tag for XSS, a single quote for SQL errors, `https://pg-evil.example` for redirects).
- **Rate limited** (`WEB_RPM`, default 120/min), capped at a few hundred requests per scan, cancellable.
- **ZAP is passive only** (spider + passive rules). Active scanning is deliberately not exposed. **Nuclei** runs with `-etags dos,intrusive,fuzz,brute-force,default-login`.
- `WEB-AUTH-RATE` sends 12 failed logins for a non-existent user. It cannot lock a real account, but an IP-based WAF may block the scanner for a while.

## Web config (optional JSON on the target)
| Key | Purpose |
|---|---|
| `loginPath`, `loginBody`, `loginContentType` | Enables login throttling and enumeration checks. `loginBody` uses `{{USER}}` and `{{PASS}}`. |
| `knownUser` | A real username, for the enumeration check. |
| `protectedPaths` | Paths that must refuse anonymous requests. |
| `probes` | `[{"path":"/search","params":["q"]}]`: extra parameters for XSS, SQL error, redirect and traversal probes (links on the home page are discovered automatically). |
| `idor` | `{"pathTemplate":"/api/conversations/{id}","ownedId":"42","headersA":{...},"headersB":{...}}`: two accounts' headers (cookies or tokens). Tests that account B and anonymous users cannot read account A's object. |
| `headers` | Extra headers sent on every request (stored encrypted). |
| `skip` | Check ids to skip. |

## False-positive controls
Content signatures instead of status codes (a `.env` must look like an env file); a **catch-all baseline** (a random path is requested first, and any page identical to it is treated as the app shell, not an exposure); injection probes compare against a clean baseline response; checks that cannot be evaluated are `skipped` or `error`, never guessed; uncertain findings are `partial`.

## ZAP and Nuclei
- **ZAP:** `docker compose --profile zap up`, then set `ZAP_URL=http://zap:8090` and `ZAP_API_KEY=<random>` in `.env`. Alerts are grouped per rule, informational and ZAP-flagged false positives are dropped, low-confidence alerts become `partial`, and CWE ids map to OWASP categories (heuristic).
- **Nuclei:** install the binary where the server runs and set `NUCLEI_BIN`. Info-level matches are dropped.
- These adapters are tested against a mock ZAP API and sample Nuclei output, **not** against the real tools (no Docker or network in the build environment). Check them once on your side.

## Not covered by black-box checks
A03 supply chain (only via Nuclei/ZAP), A06 insecure design, A09 logging and alerting.

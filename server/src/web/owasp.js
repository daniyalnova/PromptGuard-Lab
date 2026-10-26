// OWASP Top 10:2025 (web). SSRF is part of A01 in this edition. Edit here if the list changes.
export const WEB_TOP10 = { A01: 'Broken Access Control', A02: 'Security Misconfiguration', A03: 'Software Supply Chain Failures', A04: 'Cryptographic Failures', A05: 'Injection', A06: 'Insecure Design', A07: 'Authentication Failures', A08: 'Software or Data Integrity Failures', A09: 'Logging & Alerting Failures', A10: 'Mishandling of Exceptional Conditions' };
export const webCat = a => `Web · ${a} ${WEB_TOP10[a]}`;
export const webId = a => `${a}:2025`;
// CWE -> OWASP web category (heuristic; used for ZAP and Nuclei findings)
const CWE = {
  A01: [22, 23, 35, 59, 200, 284, 285, 352, 359, 425, 441, 497, 538, 566, 601, 639, 862, 863, 918],
  A02: [2, 11, 13, 16, 215, 260, 315, 489, 520, 524, 526, 537, 541, 547, 548, 614, 693, 756, 942, 1004, 1021, 1032],
  A03: [937, 1035, 1104, 1357],
  A04: [259, 295, 310, 311, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 757, 759, 760, 780, 818, 916],
  A05: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
  A06: [73, 183, 256, 266, 501, 522, 656, 799, 840],
  A07: [255, 287, 288, 290, 294, 303, 304, 306, 307, 384, 521, 613, 620, 640, 798, 1216],
  A08: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
  A09: [117, 223, 532, 778],
  A10: [209, 234, 248, 252, 274, 280, 391, 392, 394, 396, 397, 431, 456, 476, 479, 544, 636, 754, 755],
};
const IDX = new Map(Object.entries(CWE).flatMap(([a, ids]) => ids.filter(Boolean).map(i => [i, a])));
export const cweToOwasp = (cwe, tags = []) => {
  const n = Number(String(cwe ?? '').replace(/\D/g, '')); if (IDX.has(n)) return IDX.get(n);
  const t = tags.join(' ').toLowerCase(); if (/xss|sqli|injection|rce|ssti|lfi/.test(t)) return 'A05'; if (/default-login|auth|brute/.test(t)) return 'A07'; if (/ssrf|idor|traversal|redirect/.test(t)) return 'A01'; if (/tech|outdated|supply|cve/.test(t)) return 'A03'; return 'A02';
};
export const sevOf = s => ({ critical: 'critical', high: 'high', medium: 'medium', low: 'low' })[String(s).toLowerCase()] || null;

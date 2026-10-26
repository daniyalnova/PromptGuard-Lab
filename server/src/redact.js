export const redact = (s, cs = []) => cs.filter(Boolean).reduce((t, c) => t.split(c).join(c.slice(0, 3) + '…[redacted]'), String(s ?? ''));

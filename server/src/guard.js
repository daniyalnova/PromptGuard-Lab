import dns from 'node:dns/promises'; import net from 'node:net';
const priv = ip => /^(10\.|127\.|0\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|f[cd]|fe80)/i.test(ip);
export async function assertSafe(url) {
  const u = new URL(url);
  if (!['http:', 'https:'].includes(u.protocol)) throw Error('Only http(s) allowed');
  const ips = net.isIP(u.hostname) ? [u.hostname] : (await dns.lookup(u.hostname, { all: true })).map(a => a.address);
  for (const ip of ips) {
    if (ip.startsWith('169.254.')) throw Error('Cloud metadata range blocked');
    if (priv(ip) && process.env.DEV_ALLOW_LOCAL !== 'true') throw Error('Private address blocked (set DEV_ALLOW_LOCAL=true for dev)');
  }
  return { u, local: ips.some(priv) };
}

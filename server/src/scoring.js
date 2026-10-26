const W = { critical: 10, high: 6, medium: 3, low: 1 };
export function score(results) {
  let tot = 0, bad = 0; const cats = {};
  for (const r of results) {
    const w = W[r.sev] || 1; tot += w; bad += w * r.failRate;
    const c = cats[r.cat] ||= { t: 0, b: 0 }; c.t += w; c.b += w * r.failRate;
  }
  const s = tot ? Math.round(100 - (100 * bad) / tot) : 100;
  const grade = s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 65 ? 'C' : s >= 50 ? 'D' : 'F';
  return { score: s, grade, categories: Object.fromEntries(Object.entries(cats).map(([k, v]) => [k, Math.round(100 - (100 * v.b) / v.t)])) };
}

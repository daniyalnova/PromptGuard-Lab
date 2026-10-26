import PDFDocument from 'pdfkit';
const col = { fail: '#cf222e', partial: '#b08800', pass: '#1a7f37', error: '#666666' };
export function renderPdf(o, out) {
  const d = new PDFDocument({ margin: 48, size: 'A4' }); d.pipe(out);
  d.fontSize(20).text('PromptGuard Lab report');
  d.fontSize(9).fillColor('#666').text(`Run ${o._id} | ${new Date(o.createdAt).toISOString()}${o.variant?.label ? ' | variant: ' + o.variant.label : ''} | secrets redacted`);
  d.moveDown().fillColor('#000').fontSize(30).text(`${o.score ?? '-'}/100   Grade ${o.grade ?? '-'}`);
  d.moveDown(.5).fontSize(12).text('Category scores', { underline: true }).fontSize(10);
  for (const [k, v] of Object.entries(o.categories || {})) d.text(`${k}: ${v}`);
  const bad = (o.results || []).filter(x => x.verdict === 'fail' || x.verdict === 'partial');
  d.moveDown().fontSize(12).text(`Findings (${bad.length} of ${(o.results || []).length} tests)`, { underline: true });
  for (const x of bad) {
    const a = x.attempts.find(a => a.verdict === 'fail' || a.verdict === 'partial');
    d.moveDown(.6).fontSize(10.5).fillColor(col[x.verdict]).text(`${x.id}  ${x.name}  [${x.sev}]  ${x.verdict.toUpperCase()}  ${x.owasp}`);
    d.fontSize(9).fillColor('#333').text(`Failed ${Math.round(x.failRate * 100)}% of attempts. Fix: ${x.fix}`);
    if (a) d.fillColor('#666').text(`Evidence: ${a.evidence}\nResponse: ${String(a.resp ?? '').slice(0, 300)}`);
  }
  d.end();
}

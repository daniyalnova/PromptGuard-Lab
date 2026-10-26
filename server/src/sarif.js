const lvl = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
export const sarif = o => ({ version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{
  tool: { driver: { name: 'PromptGuard Lab', rules: o.results.map(x => ({ id: x.id, name: x.name, help: { text: x.fix }, properties: { owasp: x.owasp, category: x.cat } })) } },
  results: o.results.filter(x => x.verdict === 'fail' || x.verdict === 'partial').map(x => ({ ruleId: x.id, level: lvl[x.sev] || 'warning',
    message: { text: `${x.name}: ${x.verdict} (${Math.round(x.failRate * 100)}% of attempts). ${x.fix}` }, locations: [{ physicalLocation: { artifactLocation: { uri: 'llm-endpoint' } } }] })) }] });

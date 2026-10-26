import fs from 'node:fs'; import path from 'node:path';
const dir = process.env.SUITE_DIR || new URL('../../test-suites', import.meta.url).pathname;
export const loadSuites = () => fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort().flatMap(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));

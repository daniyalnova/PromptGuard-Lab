import { EventEmitter } from 'node:events';
import { Custom, Run } from './models.js'; import { scanAll, availableSuites } from './scan-all.js'; import { loadSuites } from './suites.js'; import { dec } from './crypto.js';
export { loadSuites } from './suites.js'; export { send, buildBody } from './send.js';
export const bus = new EventEmitter(); bus.setMaxListeners(100);
export const suitesFor = async u => [...loadSuites(), ...(await Custom.find({ user: u }).lean()).map(c => ({ ...c, id: 'C-' + String(c._id).slice(-6), fix: 'Custom test: review manually.' }))];
export async function execute(run, t) {
  const rid = String(run._id);
  try {
    const tg = t.toObject(), web = tg.webEnc ? JSON.parse(dec(tg.webEnc)) : {}, suites = run.suites?.length ? run.suites : availableSuites(tg);
    let tests = suites.includes('llm') ? await suitesFor(run.user) : []; if (run.include?.length) tests = tests.filter(x => run.include.includes(x.cat));
    const out = await scanAll({ target: tg, web, suites, llmTests: tests, attempts: run.attempts, mutations: run.mutations || 0, variant: run.variant, rpm: Number(process.env.TARGET_RPM || 60), webRpm: Number(process.env.WEB_RPM || 120),
      onProgress: e => bus.emit(rid, { type: 'progress', ...e }), shouldCancel: async () => !!(await Run.findById(rid, 'cancelRequested').lean())?.cancelRequested });
    Object.assign(run, { score: out.score, grade: out.grade, categories: out.categories, summary: out.summary, results: out.results, suites: out.suites, status: out.cancelled ? 'cancelled' : 'done' });
  } catch (e) { run.status = 'error'; }
  await run.save(); bus.emit(rid, { type: 'done', status: run.status });
}

import { Queue, Worker } from 'bullmq'; import IORedis from 'ioredis';
import { Run, Target } from './models.js'; import { execute } from './runner.js';
let q;
const work = async runId => { const run = await Run.findById(runId); if (!run || run.status !== 'running') return; await execute(run, await Target.findById(run.target)); };
export function startQueue() {
  const url = process.env.REDIS_URL;
  if (!url) return console.warn('REDIS_URL not set: scans run in-process and are lost on restart');
  q = new Queue('scans', { connection: new IORedis(url, { maxRetriesPerRequest: null }) });
  // concurrency = global cap on simultaneous scans; jobs survive restarts because they live in Redis
  new Worker('scans', j => work(j.data.runId), { connection: new IORedis(url, { maxRetriesPerRequest: null }), concurrency: Number(process.env.WORKER_CONCURRENCY || 2) });
}
export const enqueue = async runId => q ? q.add('scan', { runId: String(runId) }, { attempts: 2, removeOnComplete: 100, removeOnFail: 100 }) : void work(runId).catch(() => {});

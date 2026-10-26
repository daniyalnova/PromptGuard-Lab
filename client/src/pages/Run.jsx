import { useEffect, useRef, useState } from 'react'; import { useParams, Link } from 'react-router-dom'; import { Download, Share2, XCircle, ArrowLeft } from 'lucide-react';
import { get, post, del } from '../api.js'; import { Verdict, Progress, Modal, CopyBtn, Spinner, fmt, useToast } from '../ui.jsx'; import Report from './Report.jsx';
export default function Run() {
  const { id } = useParams(), [run, setRun] = useState(null), [prog, setProg] = useState(null), [share, setShare] = useState(null), toast = useToast(), es = useRef();
  const load = () => get('/runs/' + id).then(setRun).catch(e => toast(e.message));
  useEffect(() => { load(); return () => es.current?.close(); }, [id]);
  useEffect(() => {   // live progress over SSE, plus a slow poll as a safety net (stream hiccups, proxy buffering, done-before-saved races)
    if (run?.status !== 'running') return; const poll = setInterval(load, 4000);
    try { es.current = new EventSource(`/api/v1/runs/${id}/stream`); es.current.onmessage = m => { const e = JSON.parse(m.data); if (e.type === 'progress') setProg(e); if (e.type === 'done') { es.current.close(); load(); } }; es.current.onerror = () => es.current.close(); } catch {}
    return () => { es.current?.close(); clearInterval(poll); };
  }, [run?.status]);
  if (!run) return <Spinner />;
  const exp = f => `/api/v1/runs/${id}/export?format=${f}`;
  return <><Link to="/runs" className="sm"><ArrowLeft size={13} /> All scans</Link>
    <div className="top" style={{ marginTop: 8 }}><div><h1>{run.targetName || 'Scan'}</h1><p className="mut sm">{fmt(run.createdAt)} · {run.attempts} repeat{run.attempts > 1 ? 's' : ''}{run.mutations ? ` · ${run.mutations} mutations` : ''} · <Verdict v={run.status} /></p></div>
      <div className="row">{run.status === 'running' && <button className="btn danger" onClick={async () => { await post(`/runs/${id}/cancel`); toast('Cancelling after the current test'); }}><XCircle size={15} />Cancel</button>}
        {run.status === 'done' && <><a className="btn" href={exp('pdf')}><Download size={15} />PDF</a><a className="btn" href={exp('sarif')}>SARIF</a><a className="btn" href={exp('json')}>JSON</a><button className="btn primary" onClick={async () => setShare(await post(`/runs/${id}/share`, { hours: 24 }))}><Share2 size={15} />Share</button></>}</div></div>
    {run.status === 'running' && <div className="card"><h2>Scanning...</h2><Progress value={prog ? (prog.done / prog.total) * 100 : 3} /><p className="mut sm" style={{ marginTop: 8 }}>{prog ? `${prog.done} of ${prog.total} tests · last: ${prog.last.id} ${prog.last.verdict}` : 'Starting...'}</p></div>}
    {run.status === 'error' && <div className="alert bad">This scan failed. Check that the target is reachable and try again.</div>}
    {['done', 'cancelled'].includes(run.status) && <Report run={run} />}
    {share && <Modal title="Share this report" onClose={() => setShare(null)}><p>Anyone with this link can view a read-only, redacted copy until it expires in {share.expiresInHours} hours.</p><pre>{location.origin}/s/{share.token}</pre><div className="row"><CopyBtn text={`${location.origin}/s/${share.token}`} /><button className="btn danger sm" onClick={async () => { await del('/shares/' + share.token); setShare(null); toast('Link revoked'); }}>Revoke link</button></div></Modal>}</>;
}

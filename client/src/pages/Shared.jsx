import { useEffect, useState } from 'react'; import { useParams } from 'react-router-dom'; import { ShieldCheck } from 'lucide-react'; import { get } from '../api.js'; import { Spinner, fmt } from '../ui.jsx'; import Report from './Report.jsx';
export default function Shared() {
  const { token } = useParams(), [run, setRun] = useState(null), [err, setErr] = useState('');
  useEffect(() => { get('/shared/' + token, { noRefresh: true }).then(setRun).catch(e => setErr(e.message)); }, [token]);
  return <div className="main" style={{ margin: '0 auto' }}><div className="brand"><div className="logo"><ShieldCheck size={18} /></div>PromptGuard Lab <span className="badge" style={{ marginLeft: 8 }}>read-only report</span></div>
    {err ? <div className="card"><h2>Report unavailable</h2><p className="mut">{err}</p></div> : !run ? <Spinner /> : <><h1>{run.targetName || 'Security scan'}</h1><p className="mut sm">{fmt(run.createdAt)} · secrets are redacted in shared reports</p><Report run={run} /></>}</div>;
}

import { useEffect, useState } from 'react'; import { get } from '../api.js'; import { Badge, Spinner, fmt, Empty } from '../ui.jsx';
const KIND = a => (/fail|locked|reuse|blocked|reset_requested|disabled|revoked/.test(a) ? 'bad' : /login|enabled|verified|register|scan|changed|reset/.test(a) ? 'ok' : '');
export default function Audit() {
  const [rows, setRows] = useState(null), [q, setQ] = useState(''); useEffect(() => { get('/audit').then(setRows).catch(() => setRows([])); }, []); if (!rows) return <Spinner />;
  const f = rows.filter(r => !q || (r.action + r.ip + JSON.stringify(r.meta || '')).toLowerCase().includes(q.toLowerCase()));
  return <><div className="top"><div><h1>Audit log</h1><p className="mut">Sign-ins, security changes and every scan, with IP addresses. Your last 100 events.</p></div><input style={{ width: 220 }} placeholder="Filter" value={q} onChange={e => setQ(e.target.value)} /></div>
    <div className="card tw">{!f.length ? <Empty title="No events" /> : <table><thead><tr><th>When</th><th>Event</th><th>IP</th><th>Details</th></tr></thead><tbody>{f.map((r, i) => <tr key={i}><td className="sm mut" style={{ whiteSpace: 'nowrap' }}>{fmt(r.at)}</td><td><Badge kind={KIND(r.action)}>{r.action.replaceAll('_', ' ')}</Badge></td><td className="mono">{r.ip}</td><td className="mono mut">{r.meta ? JSON.stringify(r.meta) : ''}</td></tr>)}</tbody></table>}</div></>;
}

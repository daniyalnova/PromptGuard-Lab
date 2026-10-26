import { createContext, useContext, useState, useCallback, useEffect } from 'react'; import { X, Copy, Loader2 } from 'lucide-react';
const T = createContext(null); export const useToast = () => useContext(T);
export function ToastProvider({ children }) {
  const [ts, set] = useState([]); const push = useCallback((m) => { const id = Math.random(); set(x => [...x, { id, m }]); setTimeout(() => set(x => x.filter(t => t.id !== id)), 3500); }, []);
  return <T.Provider value={push}>{children}<div className="toasts">{ts.map(t => <div key={t.id} className="toast">{t.m}</div>)}</div></T.Provider>;
}
export const fmt = d => (d ? new Date(d).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '-');
const V = { pass: ['ok', 'Pass'], fail: ['bad', 'Fail'], partial: ['warn', 'Partial'], skipped: ['', 'N/A'], error: ['', 'Error'], running: ['acc', 'Running'], done: ['ok', 'Done'], cancelled: ['', 'Cancelled'] };
export const Verdict = ({ v }) => <span className={'badge ' + (V[v]?.[0] || '')}>{V[v]?.[1] || v}</span>;
export const Sev = ({ s }) => <span className={'badge ' + ({ critical: 'bad', high: 'bad', medium: 'warn' }[s] || '')}>{s}</span>;
export const Badge = ({ children, kind = '' }) => <span className={'badge ' + kind}>{children}</span>;
export const scoreColor = v => (v >= 80 ? 'var(--ok)' : v >= 50 ? 'var(--warn)' : 'var(--bad)');
export function Gauge({ value = 0, grade }) {
  const c = Math.PI * 80; return <svg viewBox="0 0 200 124" style={{ width: 210, maxWidth: '100%' }}><path d="M20 100 A80 80 0 0 1 180 100" stroke="var(--bd)" strokeWidth="14" fill="none" strokeLinecap="round" />
    <path d="M20 100 A80 80 0 0 1 180 100" stroke={scoreColor(value)} strokeWidth="14" fill="none" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - value / 100)} style={{ transition: 'stroke-dashoffset .6s' }} />
    <text x="100" y="88" textAnchor="middle" fontSize="38" fontWeight="700" fill="var(--fg)">{value}</text><text x="100" y="116" textAnchor="middle" fontSize="13" fill="var(--mut)">Grade {grade || '-'}</text></svg>;
}
export const Progress = ({ value }) => <div className="bar"><i style={{ width: Math.max(2, value) + '%' }} /></div>;
export const Spinner = () => <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />;
document.head.appendChild(Object.assign(document.createElement('style'), { textContent: '@keyframes spin{to{transform:rotate(360deg)}}' }));
export const Empty = ({ title, children }) => <div className="empty"><h2>{title}</h2>{children}</div>;
export const Field = ({ label, children, hint }) => <label className="f"><span>{label}</span>{children}{hint && <div className="mut sm" style={{ marginTop: 4 }}>{hint}</div>}</label>;
export function Modal({ title, onClose, children, wide }) {
  useEffect(() => { const k = e => e.key === 'Escape' && onClose(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [onClose]);
  return <div className="overlay" onMouseDown={e => e.target === e.currentTarget && onClose()}><div className="modal" role="dialog" aria-modal="true" aria-label={title} style={wide ? { width: 'min(760px,100%)' } : null}><div className="top" style={{ marginBottom: 10 }}><h2 style={{ margin: 0 }}>{title}</h2><button className="btn ghost sm" onClick={onClose} aria-label="Close"><X size={16} /></button></div>{children}</div></div>;
}
export function Drawer({ onClose, children }) {
  useEffect(() => { const k = e => e.key === 'Escape' && onClose(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [onClose]);
  return <><div className="overlay" style={{ background: 'rgba(10,12,20,.4)' }} onMouseDown={onClose} /><aside className="drawer" role="dialog" aria-modal="true"><div style={{ textAlign: 'right' }}><button className="btn ghost sm" onClick={onClose} aria-label="Close"><X size={16} /></button></div>{children}</aside></>;
}
export function CopyBtn({ text, label = 'Copy' }) { const t = useToast(); return <button className="btn sm" onClick={() => { navigator.clipboard?.writeText(text); t('Copied'); }}><Copy size={14} />{label}</button>; }
export function strength(pw) { let s = 0; if (pw.length >= 12) s++; if (pw.length >= 16) s++; if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++; if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++; return pw ? Math.max(1, s) : 0; }
export const Strength = ({ pw }) => { const s = strength(pw); return <><div className="meter" aria-hidden>{[1, 2, 3, 4].map(i => <i key={i} style={i <= s ? { background: ['', 'var(--bad)', 'var(--warn)', 'var(--acc)', 'var(--ok)'][s] } : null} />)}</div>{pw && <div className="mut sm" style={{ marginTop: -8, marginBottom: 10 }}>{['', 'Weak', 'Fair', 'Good', 'Strong'][s]} (server enforces: 12+ characters and not easy to guess)</div>}</>; };
export const CatBars = ({ data }) => Object.entries(data || {}).map(([k, v]) => <div className="catrow" key={k}><span className="sm">{k}</span><div className="bar"><i style={{ width: v + '%', background: scoreColor(v) }} /></div><b className="sm">{v}</b></div>);

import { useState, useEffect } from 'react'; import { Link, useNavigate, useSearchParams } from 'react-router-dom'; import { ShieldCheck, MailCheck } from 'lucide-react';
import { post } from '../api.js'; import { useAuth } from '../auth.jsx'; import { Field, Strength } from '../ui.jsx';
const Shell = ({ title, sub, children }) => <div className="authwrap"><div className="card authcard"><div className="brand"><div className="logo"><ShieldCheck size={18} /></div>PromptGuard Lab</div><h1 style={{ textAlign: 'center' }}>{title}</h1><p className="mut" style={{ textAlign: 'center' }}>{sub}</p>{children}</div></div>;
const Err = ({ e }) => (e ? <div className="alert bad" role="alert">{e}</div> : null);
const Ok = ({ children }) => <div className="alert" style={{ background: 'var(--okbg)', color: 'var(--ok)' }}>{children}</div>;
const Big = ({ children, ...p }) => <button className="btn primary" style={{ width: '100%', justifyContent: 'center' }} {...p}>{children}</button>;
function useCooldown(s = 30) { const [left, setLeft] = useState(0); useEffect(() => { if (left <= 0) return; const t = setTimeout(() => setLeft(left - 1), 1000); return () => clearTimeout(t); }, [left]); return [left, () => setLeft(s)]; }
export default function AuthPage({ mode }) {
  const nav = useNavigate(), { refresh } = useAuth(), [f, set] = useState({ firstName: '', lastName: '', email: '', password: '', code: '', newPassword: '' }), [err, setErr] = useState(''), [info, setInfo] = useState(''), [busy, setBusy] = useState(false);
  const [stage, setStage] = useState(null), [mfa, setMfa] = useState(null), [rec, setRec] = useState(false), [left, startCooldown] = useCooldown(30);
  const on = k => e => set({ ...f, [k]: e.target.value });
  const run = fn => async e => { e?.preventDefault(); setErr(''); setInfo(''); setBusy(true); try { await fn(); } catch (x) { setErr(x.message); } setBusy(false); };
  const finish = async () => { await refresh(); nav('/'); };

  const submit = run(async () => {
    if (mode === 'login') {
      if (mfa) { await post('/auth/login/mfa', { mfaToken: mfa.token, code: f.code }); return finish(); }
      const r = await post('/auth/login', { email: f.email, password: f.password }); if (r.mfaRequired) { setMfa({ token: r.mfaToken, method: r.method }); if (r.method === 'email') startCooldown(); } else await finish();
    }
    if (mode === 'register') { const r = await post('/auth/register', { firstName: f.firstName, lastName: f.lastName, email: f.email, password: f.password }); if (r.verify) { setStage('verify'); startCooldown(); } else await finish(); }
    if (mode === 'forgot') { await post('/auth/password/forgot', { email: f.email }); setStage('resetcode'); startCooldown(); }
  });
  const verify = run(async () => { await post('/auth/verify-email', { email: f.email, code: f.code }); setStage('verified'); });
  const reset = run(async () => { await post('/auth/password/reset', { email: f.email, code: f.code, password: f.newPassword }); setStage('resetdone'); });
  const resend = run(async () => { if (stage === 'verify') await post('/auth/resend-verification', { email: f.email }); else if (stage === 'resetcode') await post('/auth/password/forgot', { email: f.email }); else await post('/auth/login/resend', { mfaToken: mfa.token }); startCooldown(); setInfo('If a code can be sent, it is on its way.'); });
  const ResendBtn = <p className="sm" style={{ textAlign: 'center', marginTop: 12 }}>{left > 0 ? <span className="mut">Resend code in {left}s</span> : <a href="#" onClick={e => { e.preventDefault(); resend(); }}>Resend code</a>}</p>;
  const CodeField = <Field label="6-digit code"><input autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={6} required value={f.code} onChange={on('code')} placeholder="123456" /></Field>;

  if (stage === 'verify') return <Shell title="Check your email" sub={`We sent a 6-digit code to ${f.email}`}><form onSubmit={verify}>{CodeField}<Err e={err} />{info && <Ok>{info}</Ok>}<Big disabled={busy}>Verify email</Big></form>{ResendBtn}</Shell>;
  if (stage === 'verified') return <Shell title="Email verified" sub="Your account is ready"><Ok><MailCheck size={15} style={{ verticalAlign: -3 }} /> Verified. You can log in now.</Ok><Big onClick={() => { setStage(null); nav('/login'); }}>Go to log in</Big></Shell>;
  if (stage === 'resetcode') return <Shell title="Enter your reset code" sub={`If ${f.email} has an account, we emailed it a 6-digit code (valid 10 minutes)`}><form onSubmit={reset}>{CodeField}<Field label="New password"><input type="password" autoComplete="new-password" required value={f.newPassword} onChange={on('newPassword')} /></Field><Strength pw={f.newPassword} /><Err e={err} />{info && <Ok>{info}</Ok>}<Big disabled={busy}>Reset password</Big></form>{ResendBtn}<p className="sm mut" style={{ textAlign: 'center' }}>You can also use the link in the email.</p></Shell>;
  if (stage === 'resetdone') return <Shell title="Password updated" sub="All your sessions were signed out"><Big onClick={() => { setStage(null); nav('/login'); }}>Log in</Big></Shell>;
  if (mfa) return <Shell title={mfa.method === 'email' ? 'Check your email' : 'Two-factor authentication'} sub={mfa.method === 'email' ? `We emailed a 6-digit sign-in code to ${f.email}` : rec ? 'Enter one of your recovery codes' : 'Enter the 6-digit code from your authenticator app'}>
    <form onSubmit={submit}><Field label={rec ? 'Recovery code' : 'Code'}><input autoFocus inputMode={rec ? 'text' : 'numeric'} autoComplete="one-time-code" value={f.code} onChange={on('code')} placeholder={rec ? 'xxxxxxxx-xxxxxxxx' : '123456'} /></Field><Err e={err} />{info && <Ok>{info}</Ok>}<Big disabled={busy}>Verify</Big></form>
    {mfa.method === 'email' ? ResendBtn : <p className="sm" style={{ textAlign: 'center', marginTop: 12 }}><a href="#" onClick={e => { e.preventDefault(); setRec(!rec); }}>{rec ? 'Use authenticator code' : 'Use a recovery code'}</a></p>}</Shell>;
  const T = { login: ['Welcome back', 'Log in to test your LLM apps'], register: ['Create your account', 'Use a strong, unique password'], forgot: ['Reset password', "We'll email you a code and a link"] }[mode];
  return <Shell title={T[0]} sub={T[1]}><form onSubmit={submit}>
    {mode === 'register' && <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 10 }}><Field label="First name"><input autoFocus autoComplete="given-name" required maxLength={60} value={f.firstName} onChange={on('firstName')} /></Field><Field label="Last name"><input autoComplete="family-name" required maxLength={60} value={f.lastName} onChange={on('lastName')} /></Field></div>}
    <Field label="Email"><input type="email" autoFocus={mode !== 'register'} autoComplete="email" required value={f.email} onChange={on('email')} /></Field>
    {mode !== 'forgot' && <><Field label="Password"><input type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required value={f.password} onChange={on('password')} /></Field>{mode === 'register' && <Strength pw={f.password} />}</>}
    <Err e={err} /><Big disabled={busy}>{{ login: 'Log in', register: 'Create account', forgot: 'Send reset code' }[mode]}</Big></form>
    <p className="sm mut" style={{ textAlign: 'center', marginTop: 14 }}>{mode === 'login' ? <><Link to="/forgot">Forgot password?</Link> · <Link to="/register">Create account</Link></> : <Link to="/login">Back to log in</Link>}</p></Shell>;
}
export function ResetPage() {
  const [q] = useSearchParams(), nav = useNavigate(), [pw, setPw] = useState(''), [err, setErr] = useState(''), [ok, setOk] = useState(false);
  return <Shell title="Choose a new password" sub="All your sessions will be signed out">{ok ? <><Ok>Password updated.</Ok><Big onClick={() => nav('/login')}>Log in</Big></> :
    <form onSubmit={async e => { e.preventDefault(); try { await post('/auth/password/reset', { token: q.get('token') || '', password: pw }); setOk(true); } catch (x) { setErr(x.message); } }}><Field label="New password"><input type="password" autoComplete="new-password" required value={pw} onChange={e => setPw(e.target.value)} /></Field><Strength pw={pw} /><Err e={err} /><Big>Update password</Big></form>}</Shell>;
}
export function VerifyPage() {
  const [q] = useSearchParams(), [s, setS] = useState('Verifying...'); useEffect(() => { post('/auth/verify-email', { token: q.get('token') || '' }).then(() => setS('Email verified. You can log in now.')).catch(e => setS(e.message)); }, []);
  return <Shell title="Email verification" sub={s}><Link className="btn primary" to="/login">Go to log in</Link></Shell>;
}

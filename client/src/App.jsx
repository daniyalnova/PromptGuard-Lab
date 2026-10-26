import { useEffect, useState } from 'react'; import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom';
import { LayoutDashboard, Crosshair, ScanLine, GitCompare, Library as Lib, FlaskConical, ShieldCheck, ScrollText, LogOut, Sun, Moon } from 'lucide-react';
import { useAuth } from './auth.jsx'; import { Spinner } from './ui.jsx'; import AuthPage, { ResetPage, VerifyPage } from './pages/Auth.jsx';
import Dashboard from './pages/Dashboard.jsx'; import Targets from './pages/Targets.jsx'; import Runs from './pages/Runs.jsx'; import Run from './pages/Run.jsx'; import Compare from './pages/Compare.jsx'; import Library from './pages/Library.jsx';
import Playground from './pages/Playground.jsx'; import Security from './pages/Security.jsx'; import Audit from './pages/Audit.jsx'; import Shared from './pages/Shared.jsx';
const NAV = [['/', 'Dashboard', LayoutDashboard], ['/targets', 'Targets', Crosshair], ['/runs', 'Scans', ScanLine], ['/compare', 'Compare', GitCompare], ['/library', 'Test library', Lib], ['/playground', 'Playground', FlaskConical], ['/security', 'Security', ShieldCheck], ['/audit', 'Audit log', ScrollText]];
function useTheme() {
  const [t, set] = useState(() => { let saved = null; try { saved = localStorage.getItem('pg-theme'); } catch {} return saved || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); });
  useEffect(() => { document.documentElement.dataset.theme = t; try { localStorage.setItem('pg-theme', t); } catch {} }, [t]); return [t, () => set(t === 'dark' ? 'light' : 'dark')];
}
export default function App() {
  const { user, logout } = useAuth(), loc = useLocation(), [theme, toggle] = useTheme();
  if (loc.pathname.startsWith('/s/')) return <Routes><Route path="/s/:token" element={<Shared />} /></Routes>;
  if (user === undefined) return <div className="authwrap"><Spinner /></div>;
  if (!user) return <Routes><Route path="/login" element={<AuthPage mode="login" />} /><Route path="/register" element={<AuthPage mode="register" />} /><Route path="/forgot" element={<AuthPage mode="forgot" />} /><Route path="/reset" element={<ResetPage />} /><Route path="/verify" element={<VerifyPage />} /><Route path="*" element={<Navigate to="/login" replace />} /></Routes>;
  if (user.mfaRequiredForAccount && !user.mfa && loc.pathname !== '/security') return <Navigate to="/security" replace />;
  return <div className="shell"><nav className="side" aria-label="Main"><div className="brand"><div className="logo"><ShieldCheck size={18} /></div><span>PromptGuard Lab</span></div>
    {NAV.map(([to, label, Icon]) => <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => 'nav' + (isActive ? ' active' : '')}><Icon size={17} /><span>{label}</span></NavLink>)}<div className="sp" />
    <button className="nav" style={{ background: 'none', border: 0, font: 'inherit', cursor: 'pointer' }} onClick={toggle}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}<span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span></button>
    <button className="nav" style={{ background: 'none', border: 0, font: 'inherit', cursor: 'pointer' }} onClick={logout}><LogOut size={17} /><span>Log out</span></button><div className="mut sm" style={{ padding: '6px 12px', wordBreak: 'break-all' }}><span>{user.name ? <b>{user.name}</b> : null}{user.name ? <br /> : null}{user.email}</span></div></nav>
    <main className="main"><Routes><Route path="/" element={<Dashboard />} /><Route path="/targets" element={<Targets />} /><Route path="/runs" element={<Runs />} /><Route path="/runs/:id" element={<Run />} /><Route path="/compare" element={<Compare />} /><Route path="/library" element={<Library />} /><Route path="/playground" element={<Playground />} /><Route path="/security" element={<Security />} /><Route path="/audit" element={<Audit />} /><Route path="*" element={<Navigate to="/" replace />} /></Routes></main></div>;
}

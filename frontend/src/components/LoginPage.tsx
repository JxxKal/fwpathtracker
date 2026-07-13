import { Eye, EyeOff, KeyRound, Lock, ShieldCheck, User } from 'lucide-react';
import { FormEvent, useEffect, useState } from 'react';
import logoUrl from '../assets/a38-logo.svg';
import { login, samlEnabled } from '../api';
import { de } from '../i18n/de';
import type { Session } from '../types';

export default function LoginPage({ onLogin }: { onLogin: (s: Session) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ssoOn, setSsoOn] = useState(false);

  useEffect(() => { samlEnabled().then((r) => setSsoOn(r.enabled)).catch(() => {}); }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await login(username, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : de.login.failed);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="a38-login">
      <div style={{
        width: '100%', maxWidth: 396, display: 'flex', flexDirection: 'column',
        gap: 22, animation: 'a38-fade 0.7s cubic-bezier(0.16,1,0.3,1) both',
      }}>
        {/* Logo + Tagline */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <div style={{ position: 'relative', overflow: 'hidden' }}>
            <img src={logoUrl} alt="A38 — Firewall Path Tracker" width={248}
              style={{ display: 'block', filter: 'drop-shadow(0 0 34px rgba(14,165,233,0.28))' }} />
            <div style={{
              position: 'absolute', left: '14%', right: '14%', top: 0, height: 2,
              background: 'linear-gradient(90deg,transparent,rgba(125,211,252,0.9),transparent)',
              animation: 'a38-scan 4.5s cubic-bezier(0.4,0,0.2,1) infinite', pointerEvents: 'none',
            }} />
          </div>
          <p style={{ margin: 0, fontSize: 13, color: '#94a3b8', textAlign: 'center' }}>
            {de.login.tagline}
          </p>
        </div>

        {/* Karte */}
        <form onSubmit={submit} style={{
          display: 'flex', flexDirection: 'column', gap: 16, padding: '26px 24px 24px',
          borderRadius: 16, background: 'rgba(15,23,42,0.82)', backdropFilter: 'blur(8px)',
          border: '1px solid rgba(14,165,233,0.15)',
          boxShadow: '0 0 0 1px rgba(14,165,233,0.20), 0 0 60px rgba(14,165,233,0.08), 0 24px 48px -18px rgba(0,0,0,0.8)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span style={{
              fontFamily: "'JetBrains Mono',ui-monospace,monospace", fontSize: 10,
              letterSpacing: '0.24em', textTransform: 'uppercase', color: '#38bdf8',
            }}>{de.login.panel}</span>
            <span style={{ flex: 1, height: 1, background: 'linear-gradient(90deg,rgba(14,165,233,0.3),transparent)' }} />
          </div>

          {/* Benutzername */}
          <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 500 }}>{de.login.username}</span>
            <span style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <User size={16} color="#475569" style={{ position: 'absolute', left: 11, pointerEvents: 'none' }} />
              <input className="a38-input" value={username} onChange={(e) => setUsername(e.target.value)}
                placeholder="admin" autoComplete="username" autoFocus />
            </span>
          </label>

          {/* Passwort */}
          <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 500 }}>{de.login.password}</span>
            <span style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Lock size={16} color="#475569" style={{ position: 'absolute', left: 11, pointerEvents: 'none' }} />
              <input className="a38-input pw" type={show ? 'text' : 'password'} value={password}
                onChange={(e) => setPassword(e.target.value)} placeholder="••••••••"
                autoComplete="current-password" />
              <button type="button" className="a38-eye" onClick={() => setShow(!show)}
                aria-label={de.login.showPassword} style={{
                  position: 'absolute', right: 6, display: 'flex', padding: 6,
                  background: 'none', border: 'none', cursor: 'pointer', color: '#475569',
                }}>
                {show ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </span>
          </label>

          {error && <p style={{ margin: 0, fontSize: 13, color: '#f87171' }}>{error}</p>}

          {/* Anmelden */}
          <button type="submit" className="a38-primary" disabled={busy} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 4,
            padding: '11px 16px', fontSize: 14, fontWeight: 600, color: '#f0f9ff',
            background: 'linear-gradient(135deg,#0ea5e9,#0284c7)', border: 'none', borderRadius: 8,
            cursor: 'pointer', boxShadow: '0 0 26px rgba(14,165,233,0.30)',
          }}>
            <ShieldCheck size={16} />
            {de.login.submit}
          </button>

          {ssoOn && (
            <>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 12, fontSize: 10,
                letterSpacing: '0.18em', textTransform: 'uppercase', color: '#475569',
              }}>
                <span style={{ height: 1, flex: 1, background: '#1e293b' }} />
                {de.login.or}
                <span style={{ height: 1, flex: 1, background: '#1e293b' }} />
              </div>
              <a href="/api/auth/saml/login" className="a38-sso" style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                padding: '10px 16px', fontSize: 13, fontWeight: 500, color: '#c4b5fd',
                border: '1px solid rgba(139,92,246,0.4)', borderRadius: 8, textDecoration: 'none',
              }}>
                <KeyRound size={16} />
                {de.login.saml}
              </a>
            </>
          )}
        </form>

        {/* Fußzeile */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16,
          fontFamily: "'JetBrains Mono',ui-monospace,monospace", fontSize: 10.5, color: '#475569',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              width: 7, height: 7, borderRadius: '50%', background: '#22c55e',
              boxShadow: '0 0 8px rgba(34,197,94,0.7)', animation: 'a38-pulse 2s ease-in-out infinite',
            }} />
            {de.login.systemReady}
          </span>
          <span style={{ color: '#334155' }}>·</span>
          <span>{de.login.formLine}</span>
        </div>
      </div>
    </div>
  );
}

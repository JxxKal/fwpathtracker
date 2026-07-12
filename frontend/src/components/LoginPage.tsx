import { KeyRound, Route, ShieldCheck } from 'lucide-react';
import { FormEvent, useEffect, useState } from 'react';
import { login, samlEnabled } from '../api';
import { de } from '../i18n/de';
import type { Session } from '../types';

export default function LoginPage({ onLogin }: { onLogin: (s: Session) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
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
    <div className="flex min-h-screen items-center justify-center">
      <form onSubmit={submit} className="fwpt-card w-80 space-y-4">
        <div className="flex items-center gap-2 text-cyan-400">
          <Route size={22} />
          <h1 className="text-lg font-semibold text-slate-100">{de.appTitle}</h1>
        </div>
        <input
          className="fwpt-input" placeholder={de.login.username} value={username}
          onChange={(e) => setUsername(e.target.value)} autoFocus
        />
        <input
          className="fwpt-input" type="password" placeholder={de.login.password}
          value={password} onChange={(e) => setPassword(e.target.value)}
        />
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button className="fwpt-btn w-full justify-center" disabled={busy}>
          <ShieldCheck size={16} />
          {de.login.submit}
        </button>
        {ssoOn && (
          <>
            <div className="flex items-center gap-3 text-[11px] uppercase tracking-wide text-slate-600">
              <span className="h-px flex-1 bg-slate-800" />
              {de.login.or}
              <span className="h-px flex-1 bg-slate-800" />
            </div>
            <a href="/api/auth/saml/login"
              className="flex w-full items-center justify-center gap-2 rounded-md border border-purple-700/60 px-3 py-2 text-sm text-purple-300 hover:bg-purple-950/40">
              <KeyRound size={16} />
              {de.login.saml}
            </a>
          </>
        )}
      </form>
    </div>
  );
}

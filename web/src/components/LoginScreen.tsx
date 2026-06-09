import { useState } from 'react';
import { useStore } from '../state/store';

export function LoginScreen() {
  const login = useStore((s) => s.login);
  const mode = useStore((s) => s.mode);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const ok = await login(username, password);
    setBusy(false);
    if (!ok) setError('Invalid username or password.');
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <span className="logo">vteeee</span>
          <span className="tagline">bulk IOC search · VirusTotal / GTI</span>
        </div>

        <label>
          Username
          <input
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>

        {error && <div className="login-error">{error}</div>}

        <button className="btn btn-primary" disabled={busy} type="submit">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        {mode === 'demo' && (
          <div className="login-hint">
            Demo credentials: <code>admin / REDACTED</code> or <code>analyst / REDACTED</code>
          </div>
        )}
        <div className="login-note">
          Shared-credential gate. On a static site this is obfuscation-grade only — real
          protection lives in the proxy.
        </div>
      </form>
    </div>
  );
}

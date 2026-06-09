import { useEffect, useState } from 'react';
import { useStore } from './state/store';
import { LoginScreen } from './components/LoginScreen';
import { InputPanel } from './components/InputPanel';
import { ParsePreview } from './components/ParsePreview';
import { ResultsTable } from './components/ResultsTable';
import { DetailPanel } from './components/DetailPanel';
import { ProgressBar } from './components/ProgressBar';
import { SettingsDialog } from './components/SettingsDialog';
import { AdminPanel } from './admin/AdminPanel';

export default function App() {
  const booted = useStore((s) => s.booted);
  const boot = useStore((s) => s.boot);
  const session = useStore((s) => s.session);
  const mode = useStore((s) => s.mode);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const logout = useStore((s) => s.logout);
  const error = useStore((s) => s.error);
  const [settingsOpen, setSettingsOpen] = useState(false);

  useEffect(() => {
    void boot();
  }, [boot]);

  if (!booted) return <div className="boot">Loading…</div>;
  if (!session) return <LoginScreen />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">vteeee</span>
          <span className="tagline">bulk IOC search</span>
        </div>
        <span className={`mode-pill ${mode}`}>{mode === 'live' ? 'LIVE' : 'DEMO'}</span>
        <div className="spacer" />
        <button className="btn btn-sm" onClick={() => setSettingsOpen(true)}>
          Settings
        </button>
        {session.role === 'admin' && (
          <button className="btn btn-sm" onClick={() => setView(view === 'admin' ? 'app' : 'admin')}>
            {view === 'admin' ? 'Search' : 'Manage'}
          </button>
        )}
        <span className="user">
          {session.username} · {session.role}
        </span>
        <button className="btn btn-sm btn-ghost" onClick={logout}>
          Sign out
        </button>
      </header>

      {mode === 'demo' && (
        <div className="demo-banner">
          <b>Demo</b> — sample data, no live API calls. Configure a proxy in Settings for real
          VirusTotal / GTI lookups.
        </div>
      )}
      {error && <div className="error-banner">{error}</div>}

      {view === 'admin' ? (
        <AdminPanel />
      ) : (
        <main className="layout">
          <div className="col-left">
            <InputPanel />
            <ParsePreview />
          </div>
          <div className="col-right">
            <ProgressBar />
            <ResultsTable />
          </div>
        </main>
      )}

      {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} />}
      <DetailPanel />
    </div>
  );
}

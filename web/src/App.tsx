import { useEffect, useState } from 'react';
import { useStore } from './state/store';
import { LoginScreen } from './components/LoginScreen';
import { InputPanel } from './components/InputPanel';
import { ParsePreview } from './components/ParsePreview';
import { ResultsTable } from './components/ResultsTable';
import { DetailPanel } from './components/DetailPanel';
import { ProgressBar } from './components/ProgressBar';
import { SettingsDialog } from './components/SettingsDialog';
import { HelpDialog } from './components/HelpDialog';
import { EmptyState } from './components/EmptyState';
import { AdminPanel } from './admin/AdminPanel';

type Theme = 'chalk' | 'light';

export default function App() {
  const booted = useStore((s) => s.booted);
  const boot = useStore((s) => s.boot);
  const session = useStore((s) => s.session);
  const mode = useStore((s) => s.mode);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const logout = useStore((s) => s.logout);
  const error = useStore((s) => s.error);
  const hasResults = useStore((s) => s.order.length > 0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(
    () => ((localStorage.getItem('vteeee.theme') as Theme) || 'chalk'),
  );

  useEffect(() => {
    void boot();
  }, [boot]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('vteeee.theme', theme);
  }, [theme]);

  if (!booted) return <div className="boot">Loading…</div>;
  if (!session) return <LoginScreen />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">vteeee</span>
          <span className="tagline">bulk IOC search</span>
        </div>
        {mode === 'live' && <span className="mode-pill live">LIVE</span>}
        <div className="spacer" />
        <button
          className="btn btn-sm theme-toggle"
          title={theme === 'chalk' ? 'Switch to off-white' : 'Switch to chalkboard'}
          onClick={() => setTheme((t) => (t === 'chalk' ? 'light' : 'chalk'))}
        >
          {theme === 'chalk' ? '☀' : '☾'}
        </button>
        <button className="btn btn-sm" onClick={() => setHelpOpen(true)}>
          Docs
        </button>
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
            {hasResults ? <ResultsTable /> : <EmptyState />}
          </div>
        </main>
      )}

      {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} />}
      {helpOpen && <HelpDialog onClose={() => setHelpOpen(false)} />}
      <DetailPanel />
    </div>
  );
}

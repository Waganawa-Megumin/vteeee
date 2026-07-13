import { useEffect, useState } from 'react';
import { useStore } from './state/store';
import { LoginScreen } from './components/LoginScreen';
import { InputPanel } from './components/InputPanel';
import { ParsePreview } from './components/ParsePreview';
import { ResultsTable } from './components/ResultsTable';
import { DetailPanel } from './components/DetailPanel';
import { ProgressBar } from './components/ProgressBar';
import { SettingsDialog } from './components/SettingsDialog';
import { IntegrationStatus } from './components/IntegrationStatus';
import { ScanTracker } from './components/ScanTracker';
import { NotifBell } from './components/NotifBell';
import { HelpDialog } from './components/HelpDialog';
import { HistoryDialog } from './components/HistoryDialog';
import { MonitorPage } from './components/MonitorPage';
import { MonitorAnalysisPage } from './components/MonitorAnalysisPage';
import { CampaignsPage } from './components/CampaignsPage';
import { CampaignPage } from './components/CampaignPage';
import { CampaignAnalysisPage } from './components/CampaignAnalysisPage';
import { RuleSearchDialog } from './components/RuleSearchDialog';
import { EmptyState } from './components/EmptyState';
import { AdminPanel } from './admin/AdminPanel';

type Theme = 'chalk' | 'light';

export default function App() {
  const booted = useStore((s) => s.booted);
  const boot = useStore((s) => s.boot);
  const session = useStore((s) => s.session);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const logout = useStore((s) => s.logout);
  const error = useStore((s) => s.error);
  const hasResults = useStore((s) => s.order.length > 0);
  // SOC Prime rule search is available anytime it's configured (or in demo mode via the sample).
  const rulesAvailable = useStore((s) => s.mode === 'demo' || Boolean(s.health?.socprime));
  const monitorAvailable = useStore((s) => s.mode === 'demo' || Boolean(s.health?.shodan));
  const monitorCount = useStore((s) => Object.keys(s.monitors).length);
  const campaignCount = useStore((s) => Object.keys(s.campaigns).length);
  const openCampaigns = useStore((s) => s.openCampaigns);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(
    () => ((localStorage.getItem('vteeee.theme') as Theme) || 'chalk'),
  );

  const runAutoEnrichDue = useStore((s) => s.runAutoEnrichDue);

  useEffect(() => {
    void boot();
  }, [boot]);

  // Client-side auto re-enrich scheduler: while signed in, run one "due" pass every few minutes
  // (the action itself no-ops in demo mode and only touches IPs opted into auto-enrich).
  useEffect(() => {
    if (!session) return;
    void runAutoEnrichDue();
    const id = setInterval(() => void runAutoEnrichDue(), 5 * 60 * 1000);
    return () => clearInterval(id);
  }, [session, runAutoEnrichDue]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('vteeee.theme', theme);
  }, [theme]);

  if (!booted) return <div className="boot">Loading…</div>;
  if (!session) return <LoginScreen />;

  return (
    <div className="app">
      <header className="topbar">
        <button
          className="brand brand-btn"
          onClick={() => setView('app')}
          title="ホーム（メイン検索）に戻る"
          aria-label="Home — main search"
        >
          <span className="logo">vteeee</span>
          <span className="tagline">bulk IOC search</span>
        </button>
        <IntegrationStatus onManage={() => setSettingsOpen(true)} />
        <div className="spacer" />
        <ScanTracker />
        <NotifBell />
        <button
          className="btn btn-sm theme-toggle"
          title={theme === 'chalk' ? 'Switch to off-white' : 'Switch to chalkboard'}
          onClick={() => setTheme((t) => (t === 'chalk' ? 'light' : 'chalk'))}
        >
          {theme === 'chalk' ? '☀' : '☾'}
        </button>
        <button className="btn btn-sm" onClick={() => setHistoryOpen(true)}>
          History
        </button>
        {monitorAvailable && (
          <button
            className={`btn btn-sm${view === 'monitor' ? ' active' : ''}`}
            onClick={() => setView(view === 'monitor' ? 'app' : 'monitor')}
            title="IP-Mon — Shodan IP Monitor watchlist + dashboard (IPs + saved enrichment)"
          >
            IP-Mon{monitorCount ? ` (${monitorCount})` : ''}
          </button>
        )}
        <button
          className={`btn btn-sm${view === 'campaigns' || view === 'campaign' ? ' active' : ''}`}
          onClick={() => (view === 'campaigns' || view === 'campaign' ? setView('app') : openCampaigns())}
          title="CP-Mon — campaign IOC watchlist: continuous enrichment + history analysis"
        >
          CP-Mon{campaignCount ? ` (${campaignCount})` : ''}
        </button>
        {rulesAvailable && (
          <button className="btn btn-sm" onClick={() => setRulesOpen(true)} title="Search SOC Prime detection rules">
            Rules
          </button>
        )}
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
          {session.username} · {session.role === 'admin' ? 'Admin' : 'User'}
        </span>
        <button className="btn btn-sm btn-ghost" onClick={logout}>
          Sign out
        </button>
      </header>

      {error && <div className="error-banner">{error}</div>}

      {view === 'admin' ? (
        <div className="page-wrap">
          <AdminPanel />
        </div>
      ) : view === 'monitor' ? (
        <div className="page-wrap">
          <MonitorPage />
        </div>
      ) : view === 'analysis' ? (
        <div className="page-wrap">
          <MonitorAnalysisPage />
        </div>
      ) : view === 'campaigns' ? (
        <div className="page-wrap">
          <CampaignsPage />
        </div>
      ) : view === 'campaign' ? (
        <div className="page-wrap">
          <CampaignPage />
        </div>
      ) : view === 'campaign-analysis' ? (
        <div className="page-wrap">
          <CampaignAnalysisPage />
        </div>
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
      {historyOpen && <HistoryDialog onClose={() => setHistoryOpen(false)} />}
      {rulesOpen && <RuleSearchDialog onClose={() => setRulesOpen(false)} />}
      <DetailPanel />
    </div>
  );
}

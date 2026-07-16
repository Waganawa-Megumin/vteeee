import { lazy, Suspense, useEffect, useState } from 'react';
import { useStore } from './state/store';
// Eager: everything on the initial search screen + the persistent topbar chrome.
import { LoginScreen } from './components/LoginScreen';
import { InputPanel } from './components/InputPanel';
import { ParsePreview } from './components/ParsePreview';
import { ResultsTable } from './components/ResultsTable';
import { ProgressBar } from './components/ProgressBar';
import { IntegrationStatus } from './components/IntegrationStatus';
import { ScanTracker } from './components/ScanTracker';
import { NotifBell } from './components/NotifBell';
import { Breadcrumbs } from './components/Breadcrumbs';
import { EmptyState } from './components/EmptyState';
// Lazy: the big feature pages, dialogs, and the heavy detail panel — none are needed to paint the
// landing search view, so they split into their own chunks and load on first navigation/open instead
// of bloating the initial bundle. (jspdf / html2canvas / leaflet are already dynamically imported
// inside these, so they stay lazy too.) Named exports → default for React.lazy.
const DetailPanel = lazy(() => import('./components/DetailPanel').then((m) => ({ default: m.DetailPanel })));
const SettingsDialog = lazy(() => import('./components/SettingsDialog').then((m) => ({ default: m.SettingsDialog })));
const HelpDialog = lazy(() => import('./components/HelpDialog').then((m) => ({ default: m.HelpDialog })));
const HistoryDialog = lazy(() => import('./components/HistoryDialog').then((m) => ({ default: m.HistoryDialog })));
const RuleSearchDialog = lazy(() => import('./components/RuleSearchDialog').then((m) => ({ default: m.RuleSearchDialog })));
const MonitorPage = lazy(() => import('./components/MonitorPage').then((m) => ({ default: m.MonitorPage })));
const MonitorAnalysisPage = lazy(() => import('./components/MonitorAnalysisPage').then((m) => ({ default: m.MonitorAnalysisPage })));
const MonitorAssessmentPage = lazy(() => import('./components/MonitorAssessmentPage').then((m) => ({ default: m.MonitorAssessmentPage })));
const MonitorProjectsPage = lazy(() => import('./components/MonitorProjectsPage').then((m) => ({ default: m.MonitorProjectsPage })));
const CampaignsPage = lazy(() => import('./components/CampaignsPage').then((m) => ({ default: m.CampaignsPage })));
const CampaignPage = lazy(() => import('./components/CampaignPage').then((m) => ({ default: m.CampaignPage })));
const CampaignAnalysisPage = lazy(() => import('./components/CampaignAnalysisPage').then((m) => ({ default: m.CampaignAnalysisPage })));
const AdminPanel = lazy(() => import('./admin/AdminPanel').then((m) => ({ default: m.AdminPanel })));

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
  const openMonitorProjects = useStore((s) => s.openMonitorProjects);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(
    () => ((localStorage.getItem('vteeee.theme') as Theme) || 'chalk'),
  );

  const runAutoEnrichDue = useStore((s) => s.runAutoEnrichDue);
  const refreshCampaigns = useStore((s) => s.refreshCampaigns);

  useEffect(() => {
    void boot();
  }, [boot]);

  // Pull the shared campaigns as soon as we're signed in (and again on any re-login), so CP-Mon's
  // header count + list are current on app open — instead of only after opening CP-Mon or pressing
  // Sync. Non-destructive; no-ops on a local-only device (no proxy). Runs here (not just in boot) so
  // it reliably fires once the authenticated UI is mounted.
  useEffect(() => {
    if (!session) return;
    void refreshCampaigns();
  }, [session, refreshCampaigns]);

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
        <span className="nav-sep" aria-hidden />
        <button
          className={`btn btn-sm nav-top${view === 'app' ? ' active' : ''}`}
          onClick={() => setView('app')}
          aria-current={view === 'app' ? 'page' : undefined}
          title="TOP — メイン検索（ホーム）に戻る。ロゴのクリックでも戻れます"
        >
          🏠 TOP
        </button>
        {monitorAvailable && (
          <button
            className={`btn btn-sm${view === 'monitor' || view === 'monitor-projects' || view === 'monitor-assessment' ? ' active' : ''}`}
            onClick={() =>
              view === 'monitor' || view === 'monitor-projects' || view === 'monitor-assessment'
                ? setView('app')
                : openMonitorProjects()
            }
            aria-current={view === 'monitor' || view === 'monitor-projects' || view === 'monitor-assessment' ? 'page' : undefined}
            title="IP-Mon — Shodan IP Monitor：プロジェクト(PJ)単位の監視ウォッチリスト＋ダッシュボード"
          >
            IP-Mon{monitorCount ? ` (${monitorCount})` : ''}
          </button>
        )}
        <button
          className={`btn btn-sm${view === 'campaigns' || view === 'campaign' ? ' active' : ''}`}
          onClick={() => (view === 'campaigns' || view === 'campaign' ? setView('app') : openCampaigns())}
          aria-current={view === 'campaigns' || view === 'campaign' ? 'page' : undefined}
          title="CP-Mon — campaign IOC watchlist: continuous enrichment + history analysis"
        >
          CP-Mon{campaignCount ? ` (${campaignCount})` : ''}
        </button>
        <span className="nav-sep" aria-hidden />
        {rulesAvailable && (
          <button className="btn btn-sm" onClick={() => setRulesOpen(true)} title="Search SOC Prime detection rules">
            Rules
          </button>
        )}
        <button className="btn btn-sm" onClick={() => setHelpOpen(true)}>
          Docs
        </button>
        <span className="nav-sep" aria-hidden />
        <button className="btn btn-sm" onClick={() => setSettingsOpen(true)}>
          Settings
        </button>
        {session.role === 'admin' && (
          <button
            className={`btn btn-sm${view === 'admin' ? ' active' : ''}`}
            onClick={() => setView(view === 'admin' ? 'app' : 'admin')}
            aria-current={view === 'admin' ? 'page' : undefined}
            title={view === 'admin' ? '管理画面を閉じて検索へ戻る' : 'Manage — ユーザー／設定管理'}
          >
            Manage
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

      {view !== 'app' && (
        <div className="breadcrumbs-wrap">
          <Breadcrumbs />
        </div>
      )}

      <Suspense fallback={<div className="page-wrap"><div className="boot">Loading…</div></div>}>
      {view === 'admin' ? (
        <div className="page-wrap">
          <AdminPanel />
        </div>
      ) : view === 'monitor-projects' ? (
        <div className="page-wrap">
          <MonitorProjectsPage />
        </div>
      ) : view === 'monitor' ? (
        <div className="page-wrap">
          <MonitorPage />
        </div>
      ) : view === 'monitor-assessment' ? (
        <div className="page-wrap">
          <MonitorAssessmentPage />
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
      </Suspense>

      {/* Dialogs + the heavy result drawer: null fallback so a lazy chunk loading never flashes the
          page (the drawer is hidden until a result is opened; dialogs only mount when opened). */}
      <Suspense fallback={null}>
        {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} />}
        {helpOpen && <HelpDialog onClose={() => setHelpOpen(false)} />}
        {historyOpen && <HistoryDialog onClose={() => setHistoryOpen(false)} />}
        {rulesOpen && <RuleSearchDialog onClose={() => setRulesOpen(false)} />}
        <DetailPanel />
      </Suspense>
    </div>
  );
}

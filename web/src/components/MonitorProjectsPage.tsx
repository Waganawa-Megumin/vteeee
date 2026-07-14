import { useEffect, useMemo } from 'react';
import { useStore, type MonitorEntry, type MonitorProject, DEFAULT_PROJECT_ID } from '../state/store';

const NONE = '__none__'; // pseudo-project id for 未分類 (unassigned) watches

/** Roll-up stats for a set of monitored IPs. */
function rollup(es: MonitorEntry[]) {
  const scanned = (e: MonitorEntry) => Boolean(e.result || e.check?.at); // scan/enrich result has come in
  const cc = new Set<string>();
  for (const e of es) {
    const c = e.result?.maxmind?.countryCode ?? e.result?.abuseipdb?.countryCode ?? e.result?.shodan?.country ?? e.result?.ip?.country;
    if (c) cc.add(c);
  }
  return {
    total: es.length,
    live: es.filter((e) => e.live).length,
    scanned: es.filter(scanned).length,
    pending: es.filter((e) => e.live && !scanned(e)).length, // registered on Shodan but no scan result yet
    mal: es.filter((e) => e.result?.verdict === 'malicious').length,
    sus: es.filter((e) => e.result?.verdict === 'suspicious').length,
    highAbuse: es.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
    changed: es.filter((e) => e.check?.changed).length,
    auto: es.filter((e) => e.autoEnrich).length,
    countries: cc.size,
  };
}

function Tile({ n, label, tone }: { n: number; label: string; tone?: 'bad' | 'warn' | 'good' }) {
  return (
    <div className={`mon-stat${tone ? ` ${tone}` : ''}`}>
      <b>{n}</b>
      <span>{label}</span>
    </div>
  );
}

function IntgChip({ on, label }: { on: boolean | null | undefined; label: string }) {
  const state = on == null ? 'unknown' : on ? 'on' : 'off';
  return (
    <span className={`intg-chip ${state === 'on' ? 'on' : 'off'}`} title={`${label}: ${state === 'unknown' ? '不明' : on ? '有効' : '無効'}`}>
      <span className="intg-dot" />
      {label} {state === 'unknown' ? '—' : on ? 'ON' : 'off'}
    </span>
  );
}

export function MonitorProjectsPage() {
  const monitors = useStore((s) => s.monitors);
  const projects = useStore((s) => s.monitorProjects);
  const mode = useStore((s) => s.mode);
  const health = useStore((s) => s.health);
  const refresh = useStore((s) => s.refreshMonitors);
  const refreshProjects = useStore((s) => s.refreshMonitorProjects);
  const migrate = useStore((s) => s.migrateMonitorsToDefaultProject);
  const create = useStore((s) => s.createMonitorProject);
  const open = useStore((s) => s.openMonitorProject);
  const rename = useStore((s) => s.renameMonitorProject);
  const del = useStore((s) => s.deleteMonitorProject);
  const setView = useStore((s) => s.setView);

  // Pull shared registry + watchlist, then run the one-time migration of pre-existing watches into a PJ.
  useEffect(() => {
    void (async () => {
      await Promise.all([refreshProjects(), refresh()]);
      migrate();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const list = useMemo(() => Object.values(monitors), [monitors]);
  const all = useMemo(() => rollup(list), [list]);

  // Buckets: each registered PJ (newest first) + 未分類 (if any unassigned).
  const byProject = useMemo(() => {
    const m = new Map<string, MonitorEntry[]>();
    for (const e of list) {
      const key = e.project && projects[e.project] ? e.project : NONE;
      (m.get(key) ?? m.set(key, []).get(key)!).push(e);
    }
    return m;
  }, [list, projects]);

  const projCards = useMemo(() => {
    const arr = Object.values(projects).sort((a, b) => b.updatedAt - a.updatedAt) as MonitorProject[];
    const cards = arr.map((p) => ({ p, es: byProject.get(p.id) ?? [] }));
    const none = byProject.get(NONE) ?? [];
    return { cards, none };
  }, [projects, byProject]);

  async function newProject() {
    const name = window.prompt('プロジェクト名（PJ名）を登録:', '');
    if (name == null || !name.trim()) return;
    const id = await create(name);
    open(id);
  }

  return (
    <section className="panel monitor-page">
      <div className="panel-head cp-head">
        <button className="btn btn-sm" onClick={() => setView('app')} title="検索へ戻る">
          ← Back
        </button>
        <h2>IP-Mon — projects</h2>
        <div className="spacer" />
        <a className="btn btn-sm" href="https://monitor.shodan.io/dashboard" target="_blank" rel="noreferrer">
          Shodan Monitor ↗
        </a>
        <button className="btn btn-sm" onClick={() => void refresh()} title="共有ウォッチリスト＋PJを同期（双方向・非破壊）">
          ⇪ Sync
        </button>
        <button className="btn btn-sm btn-primary" onClick={newProject}>
          ＋ New PJ
        </button>
      </div>

      <p className="hint mon-intro">
        監視IPを<b>プロジェクト(PJ)単位</b>で管理します。上段でPJを登録し、カードを開くとそのPJだけの IP-Mon（一覧・地図・レポート）になります。
        各IPは検索結果からの登録時やPJ内で割当（<b>未分類</b>のIPは下の「未分類」に入ります）。PJ・割当は<b>チーム共有</b>されます。
        {mode === 'demo' && <b> （デモ：この端末のみ／プロキシ接続でチーム共有）</b>}
      </p>

      {/* Overall dashboard across every monitored IP. */}
      <div className="mon-proj-overview">
        <div className="mon-stats" role="group" aria-label="overview">
          <Tile n={all.total} label="監視IP 合計" />
          <Tile n={Object.keys(projects).length} label="PJ 数" />
          <Tile n={all.live} label="Shodan監視中" tone="good" />
          <Tile n={all.scanned} label="スキャン結果あり" tone="good" />
          {all.pending > 0 && <Tile n={all.pending} label="スキャン待ち" tone="warn" />}
          {all.mal > 0 && <Tile n={all.mal} label="malicious" tone="bad" />}
          {all.sus > 0 && <Tile n={all.sus} label="suspicious" tone="warn" />}
          {all.highAbuse > 0 && <Tile n={all.highAbuse} label="abuse ≥75" tone="bad" />}
          {all.changed > 0 && <Tile n={all.changed} label="変化あり" tone="warn" />}
          <Tile n={all.countries} label="国" />
          {all.auto > 0 && <Tile n={all.auto} label="⚡Auto" />}
        </div>
        <div className="mon-proj-intg">
          <span className={`mode-pill ${mode}`}>{mode === 'live' ? 'LIVE' : 'DEMO'}</span>
          <span className="mon-proj-intg-label">連携:</span>
          <IntgChip on={mode === 'live' ? health?.shodan : null} label="Shodan API" />
          <IntgChip on={mode === 'live' ? health?.maxmind : null} label="MaxMind" />
          <IntgChip on={mode === 'live' ? health?.abuseipdb : null} label="AbuseIPDB" />
          <IntgChip on={mode === 'live' ? health?.urlscan : null} label="urlscan(魚拓)" />
          {mode === 'live' && health?.shodan === false && (
            <span className="hint mon-proj-intg-warn">⚠ Shodan API が無効です（Settings/プロキシにキー登録が必要）。監視の再観測ができません。</span>
          )}
        </div>
      </div>

      {/* All-IPs entry + PJ cards + 未分類. */}
      <div className="cp-grid mon-proj-grid">
        <button className="cp-card mon-proj-all" onClick={() => open(null)}>
          <div className="cp-card-name">📚 All IPs（全PJ）</div>
          <div className="cp-card-meta">{all.total} IP · {Object.keys(projects).length} PJ</div>
          <div className="cp-card-stats">
            {all.mal > 0 && <span className="mon-chip sev-high">{all.mal} mal</span>}
            {all.pending > 0 && <span className="mon-chip sev-med">{all.pending} 待ち</span>}
            <span className="mon-chip">{all.scanned} scanned</span>
          </div>
          <div className="cp-card-when">すべての監視IPを表示</div>
        </button>

        {projCards.cards.map(({ p, es }) => {
          const st = rollup(es);
          return (
            <div key={p.id} className="cp-card mon-proj-card" role="button" tabIndex={0} onClick={() => open(p.id)} onKeyDown={(e) => e.key === 'Enter' && open(p.id)}>
              <div className="cp-card-name">
                {p.name}
                {p.id === DEFAULT_PROJECT_ID && <span className="mon-proj-default" title="移行で自動作成された既定PJ。リネームできます"> · 既定</span>}
              </div>
              <div className="cp-card-meta">
                {st.total} IP{st.total === 1 ? '' : 's'} · {st.scanned} scanned{st.auto ? ` · ⚡${st.auto}` : ''}
              </div>
              <div className="cp-card-stats">
                {st.live > 0 && <span className="mon-chip">{st.live} live</span>}
                {st.mal > 0 && <span className="mon-chip sev-high">{st.mal} mal</span>}
                {st.sus > 0 && <span className="mon-chip sev-med">{st.sus} susp</span>}
                {st.changed > 0 && <span className="mon-chip sev-med">{st.changed} changed</span>}
                {st.pending > 0 && <span className="mon-chip sev-med">{st.pending} 待ち</span>}
              </div>
              <div className="mon-proj-card-actions" onClick={(e) => e.stopPropagation()}>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={() => {
                    const nn = window.prompt('PJ名を変更:', p.name);
                    if (nn != null && nn.trim()) void rename(p.id, nn);
                  }}
                  title="PJ名を変更"
                >
                  ✎ Rename
                </button>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={() => {
                    if (window.confirm(`PJ「${p.name}」を削除しますか？\n※IPは削除されず「未分類」に戻ります（監視は継続）。`)) void del(p.id);
                  }}
                  title="PJを削除（IPは未分類に戻る・監視は継続）"
                >
                  🗑 Delete
                </button>
              </div>
            </div>
          );
        })}

        {projCards.none.length > 0 && (
          <button className="cp-card mon-proj-none" onClick={() => open(NONE)}>
            <div className="cp-card-name">🗂 未分類</div>
            <div className="cp-card-meta">{projCards.none.length} IP · PJ未割当</div>
            <div className="cp-card-stats">
              <span className="mon-chip sev-med">要 PJ 割当</span>
            </div>
            <div className="cp-card-when">開いてPJに割り当て</div>
          </button>
        )}

        <button className="cp-card cp-card-new" onClick={newProject}>
          ＋ New PJ
        </button>
      </div>
    </section>
  );
}

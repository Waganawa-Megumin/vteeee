import { useEffect, useMemo, useRef, useState } from 'react';
import { useStore, type MonitorEntry } from '../state/store';
import type { TlpLevel } from '@vteeee/shared';
import { MarkdownLite } from './MarkdownLite';
import { CountryChoropleth } from './CountryChoropleth';
import { MonitorMap } from './MonitorMap';
import { countryOf, diffParts } from '../lib/enrichTrend';
import { copyText, copyElementImage, exportAssessmentPdf } from '../lib/assessment-export';

const tlpClass = (t: TlpLevel): string => `tlp-${t.toLowerCase().replace('+', '-')}`;
const UNGROUPED = 'Ungrouped';
const groupOf = (e: MonitorEntry) => (e.group && e.group.trim() ? e.group : UNGROUPED);
const orgOf = (e: MonitorEntry) => e.result?.shodan?.org ?? e.result?.maxmind?.organization ?? e.result?.ip?.asOwner;
const fmtWhen = (at?: number) =>
  at
    ? new Date(at).toLocaleString(undefined, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
      })
    : '—';
const fmtDay = (at?: number) => (at ? new Date(at).toLocaleDateString(undefined, { month: '2-digit', day: '2-digit' }) : '—');

function Tile({ n, label, tone }: { n: number; label: string; tone?: 'bad' | 'warn' }) {
  return (
    <div className={`mon-stat${tone ? ` ${tone}` : ''}`}>
      <b>{n}</b>
      <span>{label}</span>
    </div>
  );
}

/** IP-Mon operational assessment report: deterministic maps/stats (from the live watchlist) + a Claude
 *  monitoring narrative (trend / surface·risk·threat drift / Shodan scan cadence), broken down by group. */
export function MonitorAssessmentPage() {
  const monitors = useStore((s) => s.monitors);
  const setView = useStore((s) => s.setView);
  const assessments = useStore((s) => s.monitorAssessments);
  const assess = useStore((s) => s.assessMonitors);
  const refreshShared = useStore((s) => s.refreshMonitorAssessments);
  const assessing = useStore((s) => s.monitorAssessing);
  const assessError = useStore((s) => s.monitorAssessError);
  const groupOrder = useStore((s) => s.monitorGroupOrder);
  const tlp = useStore((s) => s.settings.tlp ?? 'AMBER');
  const [sel, setSel] = useState(0);
  const [reportMsg, setReportMsg] = useState<string | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  // Pull the team's shared report history when the page opens (continuous, team-wide time-series).
  useEffect(() => {
    void refreshShared();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const list = useMemo(() => Object.values(monitors), [monitors]);

  // ---- Deterministic aggregates (render even without Claude / in demo). --------------------------
  const agg = useMemo(() => {
    const now = Date.now();
    const day = 86_400_000;
    const total = list.length;
    const withIntel = list.filter((e) => e.result).length;
    const malicious = list.filter((e) => e.result?.verdict === 'malicious').length;
    const suspicious = list.filter((e) => e.result?.verdict === 'suspicious').length;
    const highAbuse = list.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length;
    const changed = list.filter((e) => e.check?.changed).length;

    const byCountry: Record<string, number> = {};
    for (const e of list) {
      const r = e.result;
      if (r) {
        const cc = countryOf(r);
        if (cc) byCountry[cc] = (byCountry[cc] ?? 0) + 1;
      }
    }
    const countryRows = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).slice(0, 8) as [string, number][];
    const points = list.flatMap((e) => {
      const m = e.result?.maxmind;
      return m?.latitude != null && m?.longitude != null
        ? [{ lat: m.latitude, lon: m.longitude, ip: e.ip, verdict: e.result?.verdict }]
        : [];
    });

    // Scan cadence: when did Shodan re-observations (check) / enrichments last run, and where are the gaps?
    const checks = list
      .filter((e) => e.check?.at)
      .map((e) => ({ ip: e.ip, at: e.check!.at, changed: !!e.check!.changed }))
      .sort((a, b) => b.at - a.at);
    const lastCheckAt = checks[0]?.at;
    const enrichAts = list.map((e) => e.lastEnrichAt).filter((x): x is number => typeof x === 'number');
    const lastEnrichAt = enrichAts.length ? Math.max(...enrichAts) : undefined;
    const staleEnrich = list.filter((e) => !e.lastEnrichAt || now - e.lastEnrichAt > 14 * day);
    const neverChecked = list.filter((e) => !e.check?.at);
    const autoOn = list.filter((e) => e.autoEnrich).length;
    const spanStart = list.length ? Math.min(...list.map((e) => (e.history?.length ? e.history[0].at : e.addedAt))) : now;
    const windowDays = Number.isFinite(spanStart) ? Math.round((now - spanStart) / day) : 0;

    // Per-group breakdown with surface / risk-threat change points.
    const present = [...new Set(list.map(groupOf))];
    const ordered = [
      ...groupOrder.filter((g) => present.includes(g) && g !== UNGROUPED),
      ...present.filter((g) => !groupOrder.includes(g) && g !== UNGROUPED).sort((a, b) => a.localeCompare(b)),
      ...(present.includes(UNGROUPED) ? [UNGROUPED] : []),
    ];
    const groups = ordered.map((g) => {
      const es = list.filter((e) => groupOf(e) === g);
      const gc: Record<string, number> = {};
      for (const e of es) {
        const r = e.result;
        if (r) {
          const cc = countryOf(r);
          if (cc) gc[cc] = (gc[cc] ?? 0) + 1;
        }
      }
      const surface: { ip: string; at: number; text: string }[] = [];
      const drift: { ip: string; at: number; text: string }[] = [];
      for (const e of es) {
        if (e.check?.changed) {
          const parts = [
            e.check.newPorts.length ? `+ports ${e.check.newPorts.join(',')}` : '',
            e.check.gonePorts.length ? `−ports ${e.check.gonePorts.join(',')}` : '',
            e.check.newVulns.length ? `+CVE ${e.check.newVulns.slice(0, 4).join(',')}${e.check.newVulns.length > 4 ? '…' : ''}` : '',
          ].filter(Boolean);
          if (parts.length) surface.push({ ip: e.ip, at: e.check.at, text: parts.join(' · ') });
        }
        const hAsc = e.history?.length ? [...e.history].sort((a, b) => a.at - b.at) : [];
        if (hAsc.length >= 2) {
          const ch = diffParts(hAsc[hAsc.length - 1].result, hAsc[hAsc.length - 2].result);
          if (ch.length) drift.push({ ip: e.ip, at: hAsc[hAsc.length - 1].at, text: ch.join(' · ') });
        }
      }
      return {
        name: g,
        ips: es.length,
        malicious: es.filter((e) => e.result?.verdict === 'malicious').length,
        suspicious: es.filter((e) => e.result?.verdict === 'suspicious').length,
        changed: es.filter((e) => e.check?.changed).length,
        autoOn: es.filter((e) => e.autoEnrich).length,
        countries: Object.entries(gc).sort((a, b) => b[1] - a[1]).slice(0, 4) as [string, number][],
        orgs: [...new Set(es.map(orgOf).filter((o): o is string => !!o))].slice(0, 3),
        surface: surface.sort((a, b) => b.at - a.at).slice(0, 6),
        drift: drift.sort((a, b) => b.at - a.at).slice(0, 6),
      };
    });

    return {
      total, withIntel, malicious, suspicious, highAbuse, changed, byCountry, countryRows, points,
      checks, lastCheckAt, lastEnrichAt, staleEnrich, neverChecked, autoOn, windowDays, groups,
      countries: Object.keys(byCountry).length,
    };
  }, [list, groupOrder]);

  const history = assessments;
  const selIdx = history.length ? Math.min(sel, history.length - 1) : 0;
  const a = history[selIdx];
  const body = a ? a.text.replace(/^\s*TLP:[^\n]*\n?/i, '') : '';
  const reportTlp = a?.tlp ?? tlp;

  const flash = (m: string, ms = 1900) => {
    setReportMsg(m);
    window.setTimeout(() => setReportMsg(null), ms);
  };
  async function copyReport() {
    if (!a) return;
    try {
      await copyText(a.text);
      flash('📋 テキストをコピーしました');
    } catch {
      flash('コピーに失敗しました');
    }
  }
  async function imageReport() {
    if (!reportRef.current) return;
    setReportMsg('🖼 画像を生成中…');
    try {
      await copyElementImage(reportRef.current);
      flash('🖼 画像をコピーしました', 2300);
    } catch {
      flash('画像コピーに失敗（ブラウザ非対応の可能性）', 2600);
    }
  }
  async function pdfReport() {
    if (!a) return;
    setReportMsg('📄 PDFを生成中…');
    try {
      await exportAssessmentPdf(body, { title: 'IP-Mon watchlist', kind: 'IP-Mon monitoring', tlp: reportTlp, model: a.model, at: a.at });
      flash('📄 PDFを保存しました', 2300);
    } catch {
      flash('PDF生成に失敗しました', 2600);
    }
  }

  return (
    <section className="panel monitor-page mon-assess-page">
      <div className="panel-head">
        <button className="btn btn-sm" onClick={() => setView('monitor')} title="IP-Mon ダッシュボードへ戻る">
          ← Back
        </button>
        <h2 title="IP-MON モニタリング・ダイジェスト — Shodan Monitor のウォッチリストの状態・変化（サーフェス/リスク/脅威情報）とスキャン運用状況を、グループ別に地図・統計とともに客観的にまとめます。多様な背景のIPが混在するため、単一のキャンペーン/意図は前提としません（CTIアトリビューションではありません）。">
          IP-Mon — monitoring report
        </h2>
        <div className="spacer" />
        {history.length >= 1 && (
          <label className="urlscan-hist" title="過去に生成したレポートを選択（時系列で保存・変動を追える）">
            🕓 履歴
            <select className="urlscan-hist-sel" value={selIdx} onChange={(e) => setSel(Number(e.currentTarget.value))}>
              {history.map((h, i) => (
                <option key={h.at} value={i}>
                  {i === 0 ? '最新' : `#${history.length - i}`} · {new Date(h.at).toLocaleString()}
                  {h.by ? ` · ${h.by}` : ''}
                </option>
              ))}
            </select>
            <span className="hint">{history.length} 版</span>
          </label>
        )}
        <button className="btn btn-primary btn-sm" onClick={() => { void assess(); setSel(0); }} disabled={assessing || agg.total === 0}>
          {assessing ? '生成中…（Claude）' : history.length ? '🔄 レポート更新' : '🧠 レポート生成'}
        </button>
      </div>

      <p className="hint mon-intro">
        <b>IP-MON モニタリング・ダイジェスト</b> — Shodan Monitor のウォッチリストを分かりやすく把握するための監視ダイジェストです。
        監視対象IPが<b>どう動いたか</b>（アタックサーフェスの開閉・リスク/脅威情報の推移）と、<b>Shodanスキャン（再観測・エンリッチ）がいつ走ったか</b>＝監視の鮮度を、
        <b>グループ別</b>に、地図・統計とともに<b>客観的に</b>まとめます。下の統計・地図は現在のウォッチリストから即時生成され、<b>🧠 レポート生成</b>で
        Claude が変化・確認推奨ホスト・監視ギャップを整理します（Claudeにはプロキシ＋ANTHROPIC_API_KEYが必要）。
        ウォッチリストには<b>様々な背景のIPが混在</b>するため、単一のキャンペーン/意図は前提としません（攻撃者アトリビューションのCTIレポートではありません）。
        レポートは<b>時系列で保存</b>され「過去」から遡れます。
      </p>

      {agg.total === 0 ? (
        <div className="empty-state">まだ監視IPがありません。IP-Mon で登録してからレポートを生成してください。</div>
      ) : (
        <>
          {assessError && <div className="error-banner mon-assess-err">⚠ {assessError}</div>}

          <div className="cp-assess-actions mon-assess-actions">
            {a && (
              <span className="cp-assess-when">
                {selIdx === 0 ? '最新レポート' : '過去版'} (#{history.length - selIdx}/{history.length}): {fmtWhen(a.at)}
                {a.by ? ` · ${a.by}` : ''}
                {a.model ? ` · ${a.model}` : ''}
              </span>
            )}
            <span className="spacer" />
            <button className="btn btn-sm" onClick={() => void copyReport()} disabled={!a} title="レポート本文（Markdown）をコピー">
              📋 テキスト
            </button>
            <button className="btn btn-sm" onClick={() => void imageReport()} title="レポート全体（統計・地図含む）を画像でコピー">
              🖼 画像
            </button>
            <button className="btn btn-sm" onClick={() => void pdfReport()} disabled={!a} title="レポート本文をPDFで保存（選択可能テキスト・TLP付き）">
              📄 PDF
            </button>
            {reportMsg && <span className="hint cp-assess-msg">{reportMsg}</span>}
          </div>

          <div className="cp-report mon-assess-report" ref={reportRef}>
            <div className="mon-assess-reporthead">
              <div className={`cp-report-tlp ${tlpClass(reportTlp)}`}>TLP:{reportTlp}</div>
              <div className="mon-assess-reporttitle">
                <b>🛰 IP-MON モニタリング状況</b>
                <span className="hint">
                  {' '}· {agg.total} IP · {agg.groups.length} グループ · 監視 {agg.windowDays}d · {fmtWhen(a?.at)}
                </span>
              </div>
            </div>

            {/* Deterministic overview — always current. */}
            <div className="mon-stats mon-assess-stats" role="group" aria-label="overview">
              <Tile n={agg.total} label="monitored" />
              <Tile n={agg.withIntel} label="with intel" />
              {agg.malicious > 0 && <Tile n={agg.malicious} label="malicious" tone="bad" />}
              {agg.suspicious > 0 && <Tile n={agg.suspicious} label="suspicious" tone="warn" />}
              {agg.highAbuse > 0 && <Tile n={agg.highAbuse} label="abuse ≥75" tone="bad" />}
              {agg.changed > 0 && <Tile n={agg.changed} label="changed" tone="warn" />}
              <Tile n={agg.countries} label="countries" />
              {agg.autoOn > 0 && <Tile n={agg.autoOn} label="auto-scan" />}
            </div>

            {/* Geo: plotted map (MaxMind coords) + self-contained statistical choropleth. */}
            <div className="mon-assess-section">
              <div className="mon-bars-title">🌍 地理・インフラ分布（MaxMind）</div>
              <div className="mon-assess-geo">
                <div className="mon-assess-geo-col">
                  {agg.points.length > 0 ? (
                    <>
                      <div className="mon-geo-maplabel">プロット（{agg.points.length} IP · 判定で色分け）</div>
                      <MonitorMap points={agg.points} className="monitor-map mon-assess-map" />
                    </>
                  ) : (
                    <div className="hint mon-nomap-note">🗺 座標が未取得です（各IPを Re-enrich／MaxMind有効化で地図表示）。</div>
                  )}
                </div>
                <div className="mon-assess-geo-col">
                  <div className="mon-geo-maplabel">統計地図（国別・多いほど濃い）</div>
                  <CountryChoropleth counts={agg.byCountry} height={260} />
                  {agg.countryRows.length > 0 && (
                    <div className="mon-assess-countrybars">
                      {agg.countryRows.map(([cc, n]) => (
                        <span key={cc} className="mon-assess-cc">
                          <span className="mono">{cc}</span> {n}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Shodan scan cadence / freshness. */}
            <div className="mon-assess-section">
              <div className="mon-bars-title">⏱ Shodanスキャン運用状況（いつ走ったか・監視の鮮度）</div>
              <div className="mon-assess-scan">
                <div className="mon-assess-scanline">
                  最終チェック（再観測）: <b>{fmtWhen(agg.lastCheckAt)}</b> · 最終エンリッチ: <b>{fmtWhen(agg.lastEnrichAt)}</b> · 自動監視ON: <b>{agg.autoOn}</b> IP
                </div>
                {agg.checks.length > 0 && (
                  <div className="mon-assess-timeline">
                    {agg.checks.slice(0, 12).map((c) => (
                      <span key={c.ip} className={`mon-assess-tl${c.changed ? ' changed' : ''}`} title={`${c.ip} — ${fmtWhen(c.at)}${c.changed ? ' · 変化あり' : ' · 変化なし'}`}>
                        <span className="mono">{c.ip}</span>
                        <span className="mon-assess-tl-day">{fmtDay(c.at)}</span>
                        {c.changed && <span className="mon-assess-tl-dot" aria-hidden>▲</span>}
                      </span>
                    ))}
                  </div>
                )}
                {(agg.staleEnrich.length > 0 || agg.neverChecked.length > 0) && (
                  <div className="mon-assess-gaps">
                    {agg.staleEnrich.length > 0 && (
                      <span className="mon-assess-gap warn" title={agg.staleEnrich.map((e) => e.ip).join(', ')}>
                        ⏳ 14日以上未エンリッチ: <b>{agg.staleEnrich.length}</b>（{agg.staleEnrich.slice(0, 4).map((e) => e.ip).join(', ')}
                        {agg.staleEnrich.length > 4 ? ' …' : ''}）
                      </span>
                    )}
                    {agg.neverChecked.length > 0 && (
                      <span className="mon-assess-gap" title={agg.neverChecked.map((e) => e.ip).join(', ')}>
                        ❓ 未チェック（baseline比なし）: <b>{agg.neverChecked.length}</b>
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Per-group surface / risk-threat movement. */}
            <div className="mon-assess-section">
              <div className="mon-bars-title">📊 グループ別 — サーフェス／リスク・脅威情報の変動</div>
              <div className="mon-assess-groups">
                {agg.groups.map((g) => (
                  <div className="mon-assess-group" key={g.name}>
                    <div className="mon-assess-ghead">
                      <span className="mon-assess-gname">{g.name === UNGROUPED ? 'Ungrouped' : g.name}</span>
                      <span className="mon-assess-gcount">{g.ips} IP{g.ips === 1 ? '' : 's'}</span>
                      {g.malicious > 0 && <span className="mon-chip sev-high">{g.malicious} mal</span>}
                      {g.suspicious > 0 && <span className="mon-chip sev-med">{g.suspicious} susp</span>}
                      {g.changed > 0 && <span className="mon-chip sev-med">{g.changed} changed</span>}
                      {g.autoOn > 0 && <span className="mon-chip">⚡{g.autoOn}</span>}
                      {g.countries.length > 0 && (
                        <span className="mon-assess-gcc">
                          {g.countries.map(([cc, n]) => `${cc}·${n}`).join(' / ')}
                        </span>
                      )}
                    </div>
                    {g.surface.length > 0 && (
                      <div className="mon-assess-changes">
                        <span className="mon-assess-clabel">🔀 surface</span>
                        {g.surface.map((s) => (
                          <div key={`s-${s.ip}-${s.at}`} className="mon-assess-crow">
                            <span className="mono">{s.ip}</span> <span className="mon-assess-ctext">{s.text}</span>{' '}
                            <span className="mon-assess-cwhen">{fmtDay(s.at)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {g.drift.length > 0 && (
                      <div className="mon-assess-changes">
                        <span className="mon-assess-clabel">📈 risk/intel</span>
                        {g.drift.map((s) => (
                          <div key={`d-${s.ip}-${s.at}`} className="mon-assess-crow">
                            <span className="mono">{s.ip}</span> <span className="mon-assess-ctext">{s.text}</span>{' '}
                            <span className="mon-assess-cwhen">{fmtDay(s.at)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {g.surface.length === 0 && g.drift.length === 0 && (
                      <div className="hint mon-assess-nochange">この期間、記録された変動はありません{g.orgs.length ? ` · ${g.orgs.join(' / ')}` : ''}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Claude operational narrative. */}
            {a ? (
              <div className="mon-assess-narrative">
                <MarkdownLite className="cp-report-md" text={body} />
              </div>
            ) : (
              !assessing && (
                <div className="empty-state mon-assess-empty">
                  上の統計・地図は現在のウォッチリストから生成済みです。<b>🧠 レポート生成</b>で、Claude が
                  変化・確認推奨ホスト・監視ギャップを客観的に整理します（プロキシ＋ANTHROPIC_API_KEY 必要）。
                </div>
              )
            )}
          </div>
        </>
      )}
    </section>
  );
}

import { useEffect, useMemo, useRef, useState } from 'react';
import { useStore, type Campaign } from '../state/store';
import { loadCampaignsBackup } from '../state/campaigns';
import { ReconnectHint } from './ReconnectHint';

/** Roll-up stats for a campaign card. */
function stats(c: Campaign) {
  const iocs = Object.values(c.iocs);
  const cves = new Set<string>();
  for (const i of iocs) for (const v of i.result?.shodan?.vulns ?? []) cves.add(v);
  return {
    total: iocs.length,
    withIntel: iocs.filter((i) => i.result).length,
    mal: iocs.filter((i) => i.result?.verdict === 'malicious').length,
    sus: iocs.filter((i) => i.result?.verdict === 'suspicious').length,
    highAbuse: iocs.filter((i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
    cves: cves.size,
    groups: new Set(iocs.map((i) => i.group).filter(Boolean)).size,
    auto: iocs.filter((i) => i.autoEnrich).length,
  };
}

export function CampaignsPage() {
  const campaigns = useStore((s) => s.campaigns);
  const refresh = useStore((s) => s.refreshCampaigns);
  const create = useStore((s) => s.createCampaign);
  const open = useStore((s) => s.openCampaign);
  const importCampaigns = useStore((s) => s.importCampaigns);
  const restoreBak = useStore((s) => s.restoreCampaignsBackup);
  const syncNote = useStore((s) => s.campaignsSyncNote);
  const mode = useStore((s) => s.mode);
  const fileRef = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const list = useMemo(() => Object.values(campaigns).sort((a, b) => b.updatedAt - a.updatedAt), [campaigns]);
  const backup = useMemo(() => loadCampaignsBackup(), [campaigns]);

  async function newCampaign() {
    const name = window.prompt('Campaign name（攻撃キャンペーン名）:', '');
    if (name == null || !name.trim()) return;
    const id = await create(name);
    open(id);
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(campaigns, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vteeee-campaigns-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function onImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const parsed = JSON.parse(await f.text());
      const map: Record<string, Campaign> = Array.isArray(parsed)
        ? Object.fromEntries((parsed as Campaign[]).map((c) => [c.id, c]))
        : (parsed as Record<string, Campaign>);
      const n = await importCampaigns(map);
      setMsg(n ? `✅ ${n} 件のキャンペーンをインポート/統合しました。` : 'インポート対象がありませんでした。');
    } catch {
      setMsg('❌ インポートに失敗しました（JSON 形式を確認してください）。');
    }
    if (fileRef.current) fileRef.current.value = '';
  }

  function onRestore() {
    const n = restoreBak();
    setMsg(n ? `🛟 端末バックアップから ${n} 件を復元しました。` : 'この端末に復元可能なバックアップはありませんでした。');
  }

  const syncErr = !!syncNote && syncNote.startsWith('⚠');

  return (
    <section className="panel monitor-page">
      <div className="panel-head cp-head">
        <h2>CP-Mon — campaigns</h2>
        <div className="spacer" />
        <button className="btn btn-sm" onClick={() => void refresh()} title="共有キャンペーンを同期（双方向・非破壊）">
          ⇪ Sync
        </button>
        <button className="btn btn-sm" onClick={exportJson} disabled={list.length === 0} title="全キャンペーンを JSON で書き出し（バックアップ推奨）">
          ⬇ Export
        </button>
        <button className="btn btn-sm" onClick={() => fileRef.current?.click()} title="JSON バックアップ / 別端末のデータを読み込み（統合）">
          ⬆ Import
        </button>
        <input ref={fileRef} type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={onImportFile} />
        {backup && (
          <button className="btn btn-sm" onClick={onRestore} title="この端末に保存された直前のバックアップから復元">
            🛟 復元 ({Object.keys(backup).length})
          </button>
        )}
        <button className="btn btn-sm btn-primary" onClick={newCampaign}>
          ＋ New campaign
        </button>
      </div>

      <p className="hint mon-intro">
        <b>攻撃キャンペーン単位</b>で任意のIoC（IP/ドメイン/URL/ハッシュ）を整理し、<b>サーバ側で定常エンリッチ</b>して
        <b>履歴・変化を分析</b>します。<b>既定で全員共有</b>＝無駄打ち回避。同期は<b>非破壊（統合）</b>で、空の端末が他端末のデータを消すことはありません。
        {mode === 'demo' && ' （デモ：この端末のみ／プロキシ接続でチーム共有）'}
      </p>

      {(syncNote || msg) && (
        <p className={`hint cp-sync-note${syncErr ? ' err' : ''}`}>
          {msg ?? syncNote}
        </p>
      )}

      {list.length === 0 ? (
        <>
          <ReconnectHint />
          {(syncErr || backup) && (
            <div className="cp-recovery">
              <b>キャンペーンが表示されていません。</b> データは通常<b>消えていません</b>。次をお試しください：{' '}
              <b>①</b> 少し待って <b>⇪ Sync</b> を再実行（サーバ側にあれば復元されます）／{' '}
              <b>②</b> 別ブラウザ/端末で開く（そのローカルに残っていれば <b>⬇ Export</b>→ここで <b>⬆ Import</b>）
              {backup ? <>／ <b>③</b> この端末の <b>🛟 復元</b>（直前のバックアップ）</> : null}。
            </div>
          )}
          <button className="cp-empty" onClick={newCampaign}>
            <span className="cp-empty-plus">＋</span>
            <span>
              クリックして <b>Campaign 名を登録</b> してください
              <br />
              <span className="hint">Register your first attack campaign to start tracking its IOCs</span>
            </span>
          </button>
        </>
      ) : (
        <div className="cp-grid">
          {list.map((c) => {
            const st = stats(c);
            return (
              <button key={c.id} className="cp-card" onClick={() => open(c.id)}>
                <div className="cp-card-name">{c.name}</div>
                <div className="cp-card-meta">
                  {st.total} IoC{st.total === 1 ? '' : 's'}
                  {st.groups ? ` · ${st.groups} groups` : ''}
                  {st.auto ? ` · ⚡${st.auto}` : ''}
                </div>
                <div className="cp-card-stats">
                  {st.mal > 0 && <span className="mon-chip sev-high">{st.mal} mal</span>}
                  {st.sus > 0 && <span className="mon-chip sev-med">{st.sus} susp</span>}
                  {st.highAbuse > 0 && <span className="mon-chip sev-high">{st.highAbuse} abuse≥75</span>}
                  <span className="mon-chip">{st.withIntel} intel</span>
                  {st.cves > 0 && <span className="mon-chip sev-high">{st.cves} CVE</span>}
                </div>
                <div className="cp-card-when">updated {new Date(c.updatedAt).toLocaleDateString()}</div>
              </button>
            );
          })}
          <button className="cp-card cp-card-new" onClick={newCampaign}>
            ＋ New campaign
          </button>
        </div>
      )}
    </section>
  );
}

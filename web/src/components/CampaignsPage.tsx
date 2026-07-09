import { useEffect, useMemo } from 'react';
import { useStore, type Campaign } from '../state/store';

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
  const mode = useStore((s) => s.mode);

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const list = useMemo(() => Object.values(campaigns).sort((a, b) => b.updatedAt - a.updatedAt), [campaigns]);

  async function newCampaign() {
    const name = window.prompt('Campaign name（攻撃キャンペーン名）:', '');
    if (name == null || !name.trim()) return;
    const id = await create(name);
    open(id);
  }

  return (
    <section className="panel monitor-page">
      <div className="panel-head">
        <h2>CP-Mon — campaigns</h2>
        <div className="spacer" />
        <button className="btn btn-sm" onClick={() => void refresh()} title="共有キャンペーンを同期（双方向）">
          ⇪ Sync
        </button>
        <button className="btn btn-sm btn-primary" onClick={newCampaign}>
          ＋ New campaign
        </button>
      </div>

      <p className="hint mon-intro">
        <b>攻撃キャンペーン単位</b>で任意のIoC（IP/ドメイン/URL/ハッシュ）を整理し、<b>サーバ側で定常エンリッチ</b>して
        <b>履歴・変化を分析</b>します（IP-Mon の履歴機構を全IoC種別へ適用）。<b>既定で全員共有</b>＝無駄打ち回避。
        {mode === 'demo' && ' （デモ：この端末のみ／プロキシ接続でチーム共有）'}
      </p>

      {list.length === 0 ? (
        <button className="cp-empty" onClick={newCampaign}>
          <span className="cp-empty-plus">＋</span>
          <span>
            クリックして <b>Campaign 名を登録</b> してください
            <br />
            <span className="hint">Register your first attack campaign to start tracking its IOCs</span>
          </span>
        </button>
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

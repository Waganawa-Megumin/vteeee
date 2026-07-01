import { useState } from 'react';
import type { AppSettings } from '@vteeee/shared';
import { useStore } from '../state/store';
import { InfoTip } from './InfoTip';
import { SecretField } from './SecretField';

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const settings = useStore((s) => s.settings);
  const applySettings = useStore((s) => s.applySettings);
  const health = useStore((s) => s.health);
  const [draft, setDraft] = useState<AppSettings>(settings);

  function up<K extends keyof AppSettings>(k: K, v: AppSettings[K]) {
    setDraft((d) => ({ ...d, [k]: v }));
  }

  const live = !!draft.proxyBaseUrl;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>Settings</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-body">
          <div className={`mode-pill ${live ? 'live' : 'demo'}`}>
            {live ? 'LIVE — real VT lookups via proxy' : 'Not connected — add a proxy URL to go live'}
          </div>

          {live && (
            <div className="intg-status">
              <span className="intg-status-label">Integrations (from proxy /health)</span>
              <span className={`intg-chip ${health?.vtKey ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                VirusTotal {health?.vtKey ? 'on' : 'off'}
              </span>
              <span className={`intg-chip ${health?.shodan && draft.shodan !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                Shodan{' '}
                {health?.shodan ? (draft.shodan !== false ? 'on' : 'key set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.domaintools && draft.domaintools !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                DomainTools{' '}
                {health?.domaintools ? (draft.domaintools !== false ? 'on' : 'creds set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.dnslytics && draft.dnslytics !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                DNSLytics{' '}
                {health?.dnslytics ? (draft.dnslytics !== false ? 'on' : 'key set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.intel471 && draft.intel471 !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                Intel 471{' '}
                {health?.intel471 ? (draft.intel471 !== false ? 'on' : 'creds set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.claude ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                Claude {health?.claude ? 'on' : 'not configured'}
              </span>
              {health && !health.ok && <span className="hint">proxy /health unreachable</span>}
            </div>
          )}

          <label className="fld">
            <span className="fld-label">
              Proxy base URL
              <InfoTip
                ja="実データ検索の中継サーバーのURL。空ならデモ（サンプル）動作。"
                en="URL of the server-side proxy that does real lookups. Empty = demo mode."
              />
            </span>
            <input
              placeholder="https://your-proxy.workers.dev  (empty = demo)"
              value={draft.proxyBaseUrl ?? ''}
              onChange={(e) => up('proxyBaseUrl', e.target.value.trim() || null)}
            />
          </label>

          <label className="fld">
            <span className="fld-label">
              Access token
              <InfoTip
                ja="プロキシへ送る合言葉。プロキシの ACCESS_TOKEN と同じ値。ブラウザ内にのみ保存され、あなたのプロキシにだけ送られます。Show で表示、Copy で別端末へコピーできます。"
                en="Shared secret sent to your proxy; must match its ACCESS_TOKEN. Stored only in this browser. Use Show/Copy to carry it to another device."
              />
            </span>
            <SecretField
              value={draft.accessToken ?? ''}
              onChange={(v) => up('accessToken', v || null)}
            />
          </label>

          <div className="fld-row">
            <label className="fld">
              <span className="fld-label">
                Requests / min
                <InfoTip
                  ja="1分あたりVirusTotalへ送る検索数の上限＝速度制限。無料キーは約4。超えると429エラー。"
                  en="Per-minute lookup cap (a speed limit). Free keys ≈ 4; going higher triggers HTTP 429 errors."
                />
              </span>
              <input
                type="number"
                min={1}
                value={draft.rpm}
                onChange={(e) => up('rpm', Number(e.target.value) || 1)}
              />
            </label>
            <label className="fld">
              <span className="fld-label">
                Concurrency
                <InfoTip
                  ja="同時に並行して走らせる検索数。無料(4/分)なら1で十分。高レート/GTIキーなら増やすと大量リストが速い。"
                  en="How many lookups run in parallel. Keep 1 on a free key; raise it for high-limit/GTI keys."
                />
              </span>
              <input
                type="number"
                min={1}
                value={draft.concurrency}
                onChange={(e) => up('concurrency', Number(e.target.value) || 1)}
              />
            </label>
          </div>

          <label className="chk">
            <input type="checkbox" checked={draft.gti} onChange={(e) => up('gti', e.target.checked)} />
            Request GTI fields (gti_assessment)
            <InfoTip
              ja="Google Threat Intelligence の評価(verdict/severity/threat score)も取得。GTIキー使用時のみ有効。"
              en="Also fetch GTI assessment (verdict/severity/score). Only useful with a GTI key."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.submitUnknown}
              onChange={(e) => up('submitUnknown', e.target.checked)}
            />
            Submit never-analyzed URLs/files
            <InfoTip
              ja="VT未登録(404)のURL/ファイルを解析に提出する。クォータを消費するため既定はオフ。"
              en="Submit never-analyzed (404) URLs/files for analysis. Consumes quota, so off by default."
            />
          </label>

          <label className="chk">
            <input
              type="checkbox"
              checked={draft.shodan !== false}
              onChange={(e) => up('shodan', e.target.checked)}
            />
            🛰 Shodan OSINT enrichment (IPs)
            <InfoTip
              ja="ONにすると、IPの行に開放ポート・稼働サービス・既知の脆弱性(CVE)を付与します。実際に付与されるのはプロキシに SHODAN_API_KEY が登録されている場合のみ（キーはサーバー側のみ保持）。OFFにするとShodanへの問い合わせを行わず、クレジットを節約できます。登録手順は Docs の『Integrations / 連携サービス』を参照。"
              en="When ON, IP rows are enriched with open ports, services and known CVEs — but only if the proxy has a SHODAN_API_KEY (key stays server-side). Turn OFF to skip Shodan lookups and save credits. Setup steps are in Docs → Integrations."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.domaintools !== false}
              onChange={(e) => up('domaintools', e.target.checked)}
            />
            🧭 DomainTools Iris (domains + IP reverse)
            <InfoTip
              ja="ドメインは Iris Enrich（リスクスコア/WHOIS/RDAP/SSL等）、IPは Iris Investigate 逆引き（そのIP上のドメイン）を付与。プロキシに DOMAINTOOLS_API_USERNAME/KEY がある時のみ。従量課金・低レート制限のためOFFで停止できます。"
              en="Domains via Iris Enrich (risk score/WHOIS/RDAP/SSL); IPs via Iris Investigate reverse (domains on the IP). Only if the proxy has DomainTools creds. Metered + low rate limits, so you can turn it off."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.dnslytics !== false}
              onChange={(e) => up('dnslytics', e.target.checked)}
            />
            🌐 DNSLytics (IP + domain)
            <InfoTip
              ja="IPは IPInfo（ASN/組織/逆引き/同居ドメイン数＋サンプル/ブロックリスト）、ドメインは HostingHistory（A/AAAA・NS・MX・SPF の履歴）を付与。プロキシに DNSLYTICS_API_KEY がある時のみ。"
              en="IPs via IPInfo (ASN/org/reverse DNS/hosted-domain count + sample/blocklist); domains via HostingHistory (A/AAAA · NS · MX · SPF history). Only if the proxy has a DNSLytics key."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.intel471 !== false}
              onChange={(e) => up('intel471', e.target.checked)}
            />
            🦉 Intel 471 · Titan (all IOC types)
            <InfoTip
              ja="全種別(IP/ドメイン/URL/ハッシュ)を Intel 471 の IOC 照合で付与（confidence相当のactive期間・ISP・関連レポート/アクター等）。詳細では『Global Search』ボタンで横断件数を追加取得。プロキシに INTEL471_API_USER/KEY がある時のみ。"
              en="Enrich every IOC type (IP/domain/URL/hash) via Intel 471's IOC search (active window, ISP, linked reports/actors). The detail panel's 'Global Search' button fetches cross-entity counts on demand. Only if the proxy has Intel 471 creds."
            />
          </label>
          <p className="hint shodan-hint">
            Optional enrichers run only when their key is on the proxy. Add the key → run “Deploy Proxy” →
            reload; the header chip flips ON. Full steps &amp; what each adds: <strong>Docs → Integrations</strong>.
          </p>

          <label className="fld">
            <span className="fld-label">
              Search history (days)
              <InfoTip
                ja="検索履歴をこのブラウザ内に保持する日数。0 で無効。既定は30日。履歴は「History」から閲覧・復元できます。"
                en="Days to keep search history in this browser. 0 disables it. Default 30. View/restore via the History button."
              />
            </span>
            <input
              type="number"
              min={0}
              value={draft.historyRetentionDays ?? 30}
              onChange={(e) => up('historyRetentionDays', Math.max(0, Number(e.target.value) || 0))}
            />
          </label>

          <p className="hint">
            Free VT tier ≈ 4 req/min, 500/day — keep rpm low to avoid 429s. The access token is stored
            only in this browser (now backed by persistent storage + IndexedDB so it survives much
            longer). On mobile, “Add to Home Screen” prevents the browser from clearing it.
          </p>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={() => {
              applySettings(draft);
              onClose();
            }}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

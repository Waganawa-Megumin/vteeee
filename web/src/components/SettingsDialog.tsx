import { useState } from 'react';
import type { AppSettings } from '@vteeee/shared';
import { useStore } from '../state/store';
import { buildConnectLink } from '../config';
import { InfoTip } from './InfoTip';
import { SecretField } from './SecretField';

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const settings = useStore((s) => s.settings);
  const applySettings = useStore((s) => s.applySettings);
  const health = useStore((s) => s.health);
  const [draft, setDraft] = useState<AppSettings>(settings);
  const [linkCopied, setLinkCopied] = useState(false);

  function up<K extends keyof AppSettings>(k: K, v: AppSettings[K]) {
    setDraft((d) => ({ ...d, [k]: v }));
  }

  async function copyConnectLink() {
    const link = buildConnectLink(draft);
    try {
      await navigator.clipboard.writeText(link);
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    } catch {
      window.prompt('Copy this setup link:', link);
    }
  }

  const live = !!draft.proxyBaseUrl;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal settings-modal" onClick={(e) => e.stopPropagation()}>
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
              <span className={`intg-chip ${health?.maxmind && draft.maxmind !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                MaxMind{' '}
                {health?.maxmind ? (draft.maxmind !== false ? 'on' : 'creds set · off') : 'not configured'}
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
              <span className={`intg-chip ${health?.cyfirma && draft.cyfirma !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                CYFIRMA{' '}
                {health?.cyfirma ? (draft.cyfirma !== false ? 'on' : 'key set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.threatvision && draft.threatvision !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                ThreatVision{' '}
                {health?.threatvision ? (draft.threatvision !== false ? 'on' : 'creds set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.recordedfuture && draft.recordedfuture !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                Recorded Future{' '}
                {health?.recordedfuture ? (draft.recordedfuture !== false ? 'on' : 'token set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.socprime ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                SOC Prime {health?.socprime ? 'on' : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.abuseipdb && draft.abuseipdb !== false ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                AbuseIPDB{' '}
                {health?.abuseipdb ? (draft.abuseipdb !== false ? 'on' : 'key set · off') : 'not configured'}
              </span>
              <span className={`intg-chip ${health?.urlscan ? 'on' : 'off'}`}>
                <span className="intg-dot" />
                urlscan {health?.urlscan ? 'on' : 'not configured'}
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

          {live && (
            <div className="fld connect-share">
              <span className="fld-label">
                Connect another device
                <InfoTip
                  ja="このボタンでコピーしたリンクを別の端末（同じadmin）で開くと、プロキシURL＋トークンが自動設定され、共有中の IP-Mon 監視リストがすぐ見えます。リンクの接続情報はURLの#以降（フラグメント）に入り、サーバーには送信されません。ただし《アクセストークンを含む》ため、信頼できる端末／チームだけに渡してください。"
                  en="Open the copied link on another device (same admin) to auto-apply the proxy URL + token and immediately see the shared IP-Mon watchlist. The connection rides in the URL fragment (after #), which browsers never send to a server — but it DOES contain the access token, so only share it with trusted devices/teammates."
                />
              </span>
              <button className="btn btn-sm" onClick={copyConnectLink} type="button">
                {linkCopied ? '✓ Copied setup link' : '🔗 Copy setup link'}
              </button>
              <span className="hint">
                別端末や仲間はこのリンクを開くだけで接続完了＝<b>ログインすれば共有中の監視リストが表示</b>されます。
                <b>リンクにはアクセストークンが含まれます</b>。信頼できる相手にのみ共有してください。
              </span>
            </div>
          )}

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
              checked={draft.maxmind !== false}
              onChange={(e) => up('maxmind', e.target.checked)}
            />
            🗺 MaxMind GeoIP geolocation (IPs)
            <InfoTip
              ja="ONにすると、IPの行に地理位置（国/地域/市/郵便番号）、ISP・組織・ASN・接続種別、匿名化(VPN/Tor/プロキシ)判定などを付与し、詳細パネルに地図を表示します。ライセンスが Insights の場合は信頼度スコア・静的IPスコア・ユーザー数・US人口統計まで取得。実際に付与されるのはプロキシに MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY がある場合のみ（キーはサーバー側のみ保持）。※MaxMindの規約により、緯度経度は必ず精度半径(km)と共に表示し、正確な住所ではなく“おおよその範囲”である旨を明示します。登録手順は Docs の『Integrations / 連携サービス』を参照。"
              en="When ON, IP rows get geolocation (country/region/city/postal), ISP/org/ASN, connection type and anonymizer (VPN/Tor/proxy) signals, plus a map in the detail panel. With an Insights license you also get confidence scores, static-IP score, user counts and US demographics. Only applied if the proxy has MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY (keys stay server-side). Per MaxMind's ToS the accuracy radius (km) is always shown with coordinates, which refer to an approximate area — not a precise address. Setup in Docs → Integrations."
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
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.cyfirma !== false}
              onChange={(e) => up('cyfirma', e.target.checked)}
            />
            🛡 CYFIRMA · DeCYFIR (all IOC types)
            <InfoTip
              ja="全種別(IP/ドメイン/URL/ハッシュ)に CYFIRMA DeCYFIR を付与。Risk Dossier（リスク/外部脅威スコア・推奨アクション・ASN/組織・関連インフラ＝攻撃基盤側）＋STIX 2.1検索（関連する脅威アクター/キャンペーン/マルウェア＝アトリビューション）。詳細画面で脅威アクターのチップを押すと『広域サーチ』としてそのアクターのキャンペーン/マルウェア/標的CVEを追加取得。プロキシに CYFIRMA_API_KEY がある時のみ。"
              en="Enrich every IOC type (IP/domain/URL/hash) via CYFIRMA DeCYFIR: Risk Dossier (risk/external-threat scores, recommended action, ASN/org, correlated infrastructure = attack-infra side) + STIX 2.1 search (associated threat actors/campaigns/malware = attribution). In the detail panel, click a threat-actor chip to run a broad search for that actor's campaigns/malware/targeted CVEs. Only if the proxy has a CYFIRMA key."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.threatvision !== false}
              onChange={(e) => up('threatvision', e.target.checked)}
            />
            🔭 TeamT5 ThreatVision (APT attribution)
            <InfoTip
              ja="全種別に TeamT5 ThreatVision を付与。IP/ドメインはリスク・攻撃グループ(APT)・属性(Malware C2/Hosting等)・地域/レジストラ・関連件数、ハッシュはサンプル検索で攻撃グループ+マルウェアファミリ+リスクを取得。詳細で攻撃グループのチップを押すと、その APT の別名・出身国・標的国/業種・概説を取得。⚠ IP/ドメインの詳細照会は 1件につき 1 AAP を消費します(ハッシュ検索は 0 AAP)。プロキシに THREATVISION_CLIENT_ID/SECRET(または ACCESS_TOKEN)がある時のみ。"
              en="Enrich every IOC type via TeamT5 ThreatVision. IPs/domains get risk, adversary (APT) attribution, attributes (Malware C2/Hosting), geo/registrar and related counts; hashes get adversary + malware-family + risk via samples search. Click an adversary chip for that APT's aliases/origin/targets. ⚠ IP & domain detail cost 1 AAP each (hash search is 0 AAP). Only if the proxy has ThreatVision creds."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.recordedfuture !== false}
              onChange={(e) => up('recordedfuture', e.target.checked)}
            />
            🔮 Recorded Future (all IOC types)
            <InfoTip
              ja="全種別(IP/ドメイン/URL/ハッシュ)に Recorded Future のリスクスコア(0-99)・発火リスクルールと根拠(evidence)・活動期間・脅威リスト・関連する脅威アクター/マルウェアを付与。詳細では脅威アクターやマルウェアのチップを押すと Threat API/Connect API でプロフィール(別名・カテゴリ等)をオンデマンド取得、ハッシュは『Sandbox intel』でサンドボックス評価(読み取りのみ・検体送信なし)、『Detection rules』で関連する Sigma/YARA/Snort ルールを検索できます。プロキシに RECORDEDFUTURE_API_KEY がある時のみ。"
              en="Enrich every IOC type with Recorded Future risk score (0-99), triggered risk rules + evidence, activity window, threat lists and related threat actors/malware. In the detail panel, click an actor/malware chip for an on-demand profile (Threat/Connect API), use 'Sandbox intel' on hashes (read-only — nothing is submitted) and 'Detection rules' to search related Sigma/YARA/Snort rules. Only if the proxy has RECORDEDFUTURE_API_KEY."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.abuseipdb !== false}
              onChange={(e) => up('abuseipdb', e.target.checked)}
            />
            🛡 AbuseIPDB (IPs)
            <InfoTip
              ja="IP に AbuseIPDB のコミュニティ悪用信頼度スコア(0-100)・レポート数/報告者数・最終報告日・用途種別(usageType)/ISP/ドメイン・Tor/ホワイトリスト判定・攻撃カテゴリ(SSH/ブルートフォース/ポートスキャン等)と直近レポートを付与。読み取り専用(検体/レポートの送信はしません)。プロキシに ABUSEIPDB_API_KEY がある時のみ。無料枠は 1,000 チェック/日。"
              en="Enrich IPs with the AbuseIPDB community abuse-confidence score (0-100), report/reporter counts, last-reported date, usage type/ISP/domain, Tor/whitelist flags, and attack categories (SSH, brute-force, port scan, …) with recent reports. Read-only (nothing is ever reported). Only if the proxy has ABUSEIPDB_API_KEY. Free tier = 1,000 checks/day."
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

          <label className="fld">
            <span className="fld-label">
              PDF export TLP marking
              <InfoTip
                ja="詳細バーの「Export PDF」に刻印する TLP（Traffic Light Protocol）区分。各ページの右上とフッターに表示されます。既定は AMBER。共有範囲に応じて選択してください（CLEAR=制限なし / GREEN=コミュニティ内 / AMBER=組織内・限定 / AMBER+STRICT=組織内のみ / RED=個人宛のみ）。"
                en="Traffic Light Protocol marking stamped on the detail panel's “Export PDF” (top-right + footer of every page). Default AMBER. Pick per your sharing scope (CLEAR / GREEN / AMBER / AMBER+STRICT / RED)."
              />
            </span>
            <select
              value={draft.tlp ?? 'AMBER'}
              onChange={(e) => up('tlp', e.target.value as AppSettings['tlp'])}
            >
              <option value="CLEAR">TLP:CLEAR</option>
              <option value="GREEN">TLP:GREEN</option>
              <option value="AMBER">TLP:AMBER (default)</option>
              <option value="AMBER+STRICT">TLP:AMBER+STRICT</option>
              <option value="RED">TLP:RED</option>
            </select>
          </label>

          <label className="fld">
            <span className="fld-label">
              urlscan.io scan visibility
              <InfoTip
                ja={
                  <>
                    「urlscan.io · 魚拓」送信時の公開範囲。<b>unlisted＝公開フィード/検索に出ない</b>（URLを知る人だけ閲覧可・
                    <b>フリー版でも安全な最大値・推奨</b>）。public＝公開検索に出る＝<b>調査対象にバレる恐れ</b>があり、
                    <b>サーバ側で既定ブロック</b>（プロキシで URLSCAN_ALLOW_PUBLIC=true の時のみ有効）。private＝有料アカウントのみ。
                    <br />
                    ※スキャンに<b>タグは付けません</b>（タグは検索可能で、付けると全スキャンが芋づるで特定されるため）。
                    提出はプロキシ経由なので、urlscan に記録される提出元の国は Cloudflare であってあなたの所在地ではありません。
                  </>
                }
                en={
                  <>
                    Visibility for the “魚拓” button. unlisted = not in urlscan's public feed/search (viewable only via the
                    exact link) — the safe maximum even on the free tier, recommended. public = shows in public search (can
                    tip off your target) and is clamped to unlisted server-side unless URLSCAN_ALLOW_PUBLIC=true on the proxy.
                    private = paid accounts only. No tags are ever attached (they're searchable and would let anyone cluster
                    your scans); submissions go via the proxy, so the recorded submitter country is Cloudflare's, not yours.
                  </>
                }
              />
            </span>
            <select
              value={draft.urlscanVisibility ?? 'unlisted'}
              onChange={(e) => up('urlscanVisibility', e.target.value as AppSettings['urlscanVisibility'])}
            >
              <option value="unlisted">unlisted — private-by-obscurity (recommended)</option>
              <option value="public">public — ⚠ public feed (blocked by default)</option>
              <option value="private">private — paid account only</option>
            </select>
            <span className="hint">
              OPSEC: even on the free tier, <b>unlisted</b> keeps scans out of urlscan's public search. “public” is
              forced back to unlisted on the proxy unless explicitly allowed, and no identifying tag is sent.
            </span>
          </label>

          <label className="chk">
            <input
              type="checkbox"
              checked={draft.shareMonitors !== false}
              onChange={(e) => up('shareMonitors', e.target.checked)}
            />
            📡 Share the IP-Mon watchlist with the team (via the proxy)
            <InfoTip
              ja="IP-Mon の監視IPと vteeee エンリッチ結果スナップショットを、プロキシのKVで共有します（既定ON・Liveモード時のみ）。ONにすると、同じプロキシを使うアナリスト全員が同じ監視IP＋intelを見られ、再エンリッチによるAPIの無駄打ちを防げます。OFFにするとこのブラウザだけに保存。デモ（プロキシ無し）は常にローカルです。"
              en="Share the IP-Mon watchlist (monitored IPs + vteeee enrichment snapshots) via the proxy KV so the whole team sees the same monitored IPs + intel — nobody re-enriches what's already been looked up. Default on (Live mode only). Off = this browser only. Demo (no proxy) is always local."
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

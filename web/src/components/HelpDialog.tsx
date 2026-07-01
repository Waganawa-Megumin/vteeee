import type { ReactNode } from 'react';
import { useStore } from '../state/store';

function IntegrationRow({
  name,
  required,
  env,
  on,
  live,
  children,
}: {
  name: string;
  required?: boolean;
  env: string;
  on: boolean | null;
  live: boolean;
  children: ReactNode;
}) {
  const status = !live ? 'demo' : on == null ? 'unknown' : on ? 'on' : 'off';
  const label = { demo: 'demo', unknown: '—', on: 'ON', off: 'off' }[status];
  return (
    <div className="intg-row">
      <div className="intg-row-head">
        <span className={`intg-chip ${status === 'on' ? 'on' : 'off'}`}>
          <span className="intg-dot" />
          {label}
        </span>
        <b>{name}</b>
        <span className={`intg-tag ${required ? 'req' : 'opt'}`}>{required ? 'base / 必須' : 'optional / 任意'}</span>
        <code>{env}</code>
      </div>
      <div className="intg-row-body">{children}</div>
    </div>
  );
}

export function HelpDialog({ onClose }: { onClose: () => void }) {
  const health = useStore((s) => s.health);
  const live = useStore((s) => s.mode) === 'live';
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal help-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>Docs · 使い方</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body help-body">
          <section className="help-section">
            <h3>What is vteeee? / これは何？</h3>
            <p className="help-ja">
              IOC（IP・ドメイン・URL・ハッシュ）の一覧を貼り付けると、無害化(defang)を解除して種別ごとに分類し、
              VirusTotal / Google Threat Intelligence で一括検索して一覧表示するアナリスト向けツールです。
            </p>
            <p className="help-en">
              Paste a list of indicators (IPs, domains, URLs, hashes) — even defanged ones. vteeee cleans and
              classifies them, then enriches each via VirusTotal / GTI and shows a sortable triage table.
            </p>
          </section>

          <section className="help-section">
            <h3>How to use / 使い方（5ステップ）</h3>
            <ol className="help-steps">
              <li>
                <b>入力 / Input</b> — 左の枠に貼り付け・ドロップ・入力（改行/CSV/レポート本文OK）。
                <span className="help-en">Paste, drop a file, or type into the left box.</span>
              </li>
              <li>
                <b>Parse</b> — 無害化を解除して分類（ローカル処理）。
                <span className="help-en">Refang + classify locally (no API calls).</span>
              </li>
              <li>
                <b>確認 / Review</b> — チェックで検索対象を取捨選択。private/unknown は既定で除外。
                <span className="help-en">Tick rows to include/exclude. Private/unknown excluded by default.</span>
              </li>
              <li>
                <b>Enrich</b> — VirusTotal/GTI で一括検索（結果は順次ストリーミング）。
                <span className="help-en">Look everything up; results stream in as they resolve.</span>
              </li>
              <li>
                <b>Triage</b> — 並べ替え/フィルタ、行クリックで詳細、VTへ直リンク、CSV出力。
                <span className="help-en">Sort/filter, click a row for detail, deep-link to VirusTotal, export CSV.</span>
              </li>
            </ol>
          </section>

          <section className="help-section">
            <h3>Integrations / 連携サービス</h3>
            <p className="help-ja">
              実データ検索は<b>プロキシ（サーバー側）</b>が各サービスのAPIキーを保持して行います。基本は
              <b>VirusTotal</b>、任意で <b>Shodan</b>・<b>Claude</b> を足せます。現在の有効状況は
              <b>上部ヘッダーのチップ</b>と下の一覧（{live ? 'LIVE' : 'DEMO'}）で確認できます。キーはブラウザには出ません。
            </p>
            <div className="intg-list">
              <IntegrationRow name="VirusTotal / GTI" required env="VT_API_KEY" on={health?.vtKey ?? null} live={live}>
                <span className="help-ja">
                  基本の脅威情報。判定・検出比・レピュテーション・ASN/国・カテゴリ・脅威ラベル等。GTIキーなら
                  verdict/severity/threat score も（Settingsの「Request GTI fields」をON）。
                </span>
                <span className="help-en">Base enrichment (verdict, detections, reputation, ASN/country, GTI when a GTI key is used).</span>
              </IntegrationRow>

              <IntegrationRow name="Shodan (OSINT)" env="SHODAN_API_KEY" on={health?.shodan ?? null} live={live}>
                <span className="help-ja">
                  <b>IP限定</b>。開放ポート・稼働サービス・既知のCVE・組織/ISP/OS等を付与し、詳細に「🛰 Shodan」節と
                  shodan.ioリンクを表示。ON/OFFは Settings の「Shodan OSINT enrichment」。
                </span>
                <span className="help-en">IPs only — open ports, services, known CVEs, org/ISP/OS. Toggle in Settings.</span>
              </IntegrationRow>

              <IntegrationRow name="Claude (smart-parse)" env="ANTHROPIC_API_KEY" on={health?.claude ?? null} live={live}>
                <span className="help-ja">
                  レポート本文などの雑多なテキストからIOCを抽出（「Smart parse (Claude)」ボタン）。無ければ正規表現で代替。
                </span>
                <span className="help-en">Pull IOCs out of free-form report prose (the “Smart parse” button). Falls back to regex if absent.</span>
              </IntegrationRow>
            </div>
            <p className="help-en" style={{ marginTop: 8 }}>
              <b>Enable an optional service (3 steps):</b> ① add the env var above as a repo secret /
              proxy env → ② run the <b>“Deploy Proxy”</b> workflow (Cloudflare) or restart the Node proxy →
              ③ reload here; the header chip flips ON. Full walkthrough: <code>docs/GUIDE.ja.md</code>.
            </p>
          </section>

          <section className="help-section">
            <h3>Settings explained / 設定の意味</h3>
            <dl className="help-kv">
              <dt>Proxy base URL</dt>
              <dd>
                実データ検索の中継サーバーのURL。空ならデモ（サンプル）動作。
                <span className="en">URL of the server-side proxy. Empty = demo mode with sample data.</span>
              </dd>
              <dt>Access token</dt>
              <dd>
                プロキシへ送る合言葉。プロキシの <code>ACCESS_TOKEN</code> と同じ値。ブラウザ内にのみ保存。
                <span className="en">Shared secret sent to your proxy; must match its ACCESS_TOKEN. Stored only in this browser.</span>
              </dd>
              <dt>Requests / min</dt>
              <dd>
                1分あたりVTへ送る検索数の上限＝<b>速度制限</b>。無料キーは約4。超えると429エラー。
                <span className="en">Per-minute lookup cap (a speed limit). Free keys ≈ 4; higher triggers HTTP 429.</span>
              </dd>
              <dt>Concurrency</dt>
              <dd>
                同時に並行して走らせる本数。無料(4/分)なら1で十分。高レート/GTIキーなら増やすと速い。
                <span className="en">How many lookups run in parallel. Keep 1 on a free key; raise it for high-limit/GTI keys.</span>
              </dd>
              <dt>Request GTI fields</dt>
              <dd>
                GTIの評価(verdict/severity/threat score)も取得。GTIキー使用時のみ有効。
                <span className="en">Also fetch GTI assessment (verdict/severity/score). Only useful with a GTI key.</span>
              </dd>
              <dt>Submit unknown</dt>
              <dd>
                VT未登録(404)のURL/ファイルを解析に提出。クォータを消費するため既定オフ。
                <span className="en">Submit never-analyzed (404) URLs/files for analysis. Uses quota; off by default.</span>
              </dd>
              <dt>Shodan OSINT enrichment</dt>
              <dd>
                IP行にShodanの開放ポート/サービス/CVEを付与（既定ON）。プロキシに <code>SHODAN_API_KEY</code>
                がある時のみ実際に付与。OFFで問い合わせを止めてクレジット節約。
                <span className="en">Enrich IPs with Shodan ports/services/CVEs (on by default; only if the proxy has a Shodan key). Turn off to save credits.</span>
              </dd>
            </dl>
          </section>

          <section className="help-section">
            <h3>How it works (Demo vs Live) / 仕組み</h3>
            <p className="help-ja">
              VTのAPIキーはブラウザに出せないため、<b>キーはプロキシ（サーバー側）だけ</b>が持ちます。公開サイトは既定で
              <b>デモ</b>（サンプルデータ）。設定で <b>Proxy base URL</b> を入れると <b>LIVE</b>（実検索）に切り替わります。
            </p>
            <p className="help-en">
              A static site can't safely hold the VT key (and VT sends no CORS headers), so the key lives only on the
              proxy. The public site is a demo by default; setting a proxy URL switches it to live — no rebuild.
            </p>
          </section>

          <section className="help-section">
            <h3>Roles &amp; admin / ロールと管理</h3>
            <p className="help-ja">
              <b>User</b>（一般）は検索のみ、<b>Admin</b> は上部「Manage」でユーザー追加/権限/パスワード変更、設定管理（共有トークン、
              プロキシURL等）、users/settings の JSON エクスポート/インポート、履歴の全件閲覧（ユーザー名・IP付き）が可能です。
            </p>
            <p className="help-en">
              User = search only; Admin = the "Manage" area to add users, change roles/passwords, edit settings,
              export/import users/settings, and view everyone's history (with username + IP).
            </p>
          </section>

          <section className="help-section">
            <h3>Security / セキュリティ</h3>
            <p className="help-ja">
              ログインは共有ID/PASSの簡易ゲート（PBKDF2、平文非保存）で、静的サイトゆえ突破可能な「目隠し」です。実際の保護は
              プロキシの <b>Access/Admin トークン</b>と <b>CORS</b> が担います。APIキーは常にプロキシ側のみ。
            </p>
            <p className="help-en">
              The login is a soft client-side gate (PBKDF2, no plaintext) — obfuscation-grade on a static site. Real
              protection is the proxy's access/admin tokens + CORS. The API key never reaches the browser.
            </p>
          </section>

          <section className="help-section">
            <h3>History / 検索履歴</h3>
            <p className="help-ja">
              Enrich した検索は自動保存され、上部「History」から閲覧・復元できます。<b>LIVE時はプロキシのKVに
              チーム共有で保存（raw込み）</b>、DEMO時は端末内(localStorage)に保存。各履歴に<b>タグ/メモ</b>を付与でき、
              <b>CSV書き出し</b>も可能。保持期間は既定30日（Settings / プロキシの HISTORY_DAYS で変更、0で無効）。
            </p>
            <p className="help-en">
              Each enrichment is saved and reopenable from History. In LIVE mode it is stored in the proxy's KV
              (shared with the team, incl. raw); in DEMO mode in this browser. Add tags/notes and export CSV per
              entry. Default retention 30 days (Settings / proxy HISTORY_DAYS; 0 disables).
            </p>
          </section>

          <section className="help-section">
            <h3>Troubleshooting / 困ったとき</h3>
            <dl className="help-kv">
              <dt>401</dt>
              <dd>
                Access token がプロキシの値と不一致。Settings を確認。
                <span className="en">Access token doesn't match the proxy's. Check Settings.</span>
              </dd>
              <dt>CORS error</dt>
              <dd>
                プロキシの <code>ALLOWED_ORIGINS</code> に今のサイトのオリジンを追加。
                <span className="en">Add this site's origin to the proxy's ALLOWED_ORIGINS.</span>
              </dd>
              <dt>429 / rate-limited</dt>
              <dd>
                Requests/min を下げる（無料は4）。自動でリトライもします。
                <span className="en">Lower Requests/min (free ≈ 4). The proxy also auto-retries.</span>
              </dd>
              <dt>not found</dt>
              <dd>
                VT未登録の指標。必要なら「Submit unknown」をON。
                <span className="en">Indicator not in VT yet. Enable "Submit unknown" if needed.</span>
              </dd>
            </dl>
          </section>
        </div>

        <div className="modal-foot">
          <button className="btn btn-primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

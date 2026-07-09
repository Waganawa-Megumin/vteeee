# vteeee 運用・デプロイ詳細ガイド（日本語）

このガイドは、本ツールを **GitHub に設定 → デモ公開 → 実データ用プロキシ稼働** まで
一通り行うための手順書です。まず最初に「GitHub で何をどこに入れるか」を説明します。

---

## 0. 最重要の考え方（最初に読む）

- **VT APIキーは絶対にブラウザ(静的サイト)に出しません。** キーは常に**プロキシ(サーバー側)だけ**が持ちます。
- だから構成は2モード:
  - **Demo（github.io 公開モック）**: サンプルデータのみ。キー不要。誰に見せてもOK。
  - **Live（実データ）**: web → **プロキシ** → VirusTotal。キーはプロキシにだけ置く。
- **GitHub Secrets は「GitHub Actions（ワークフロー）」からしか読めません。**
  つまり Secrets は **プロキシをデプロイするワークフロー**が使います。**公開Webの静的ビルドは Secrets を一切使いません**
  （使ったら漏れるため）。
- web(github.io) からプロキシへ繋ぐ時は、**GitHubではなくアプリ内の「Settings」**に「プロキシURL＋アクセストークン」を入れます。

```
[ブラウザ: github.io 静的サイト]  --(プロキシURL+トークンはアプリ内Settings)-->  [プロキシ: VT_API_KEY を保持]  -->  [VirusTotal/GTI]
       ↑ GitHub Secrets は読めない                                               ↑ ここに GitHub Secrets を流し込む
```

---

## 0.5 連携サービス（基本＝VT／任意＝Shodan・Claude）

APIキーはすべて**プロキシ側のみ**が保持します。**VirusTotal が基本（必須）**で、**Shodan** と **Claude** は
任意で追加できます。現在どれが有効かは、アプリ**上部ヘッダーのチップ**と **Settings** の状態表示、
および `<プロキシURL>/health`（`{"vtKey":…,"claude":…,"shodan":…}`）で確認できます。

| サービス | 役割 | 必須? | プロキシの環境変数 | 付与される情報 |
|---|---|---|---|---|
| **VirusTotal / GTI** | 脅威情報（基本） | ✅ 必須 | `VT_API_KEY` | 判定・検出比・レピュテーション・ASN/国・カテゴリ・脅威ラベル・First/Last seen(ファイル・URL)・GTI評価 |
| **Shodan** | OSINT（IP限定） | 任意 | `SHODAN_API_KEY` | 開放ポート・稼働サービス・既知CVE・組織/ISP/OS・ホスト名・タグ。詳細で **📡 Live ports**（InternetDB/再スキャン）。**☆ Monitor** で Shodan ネットワークアラートに登録→ヘッダー **📡 Monitor** ページで監視IP＋vteeee エンリッチ結果を翌日以降も確認（世界地図・**国別ヒートマップ=グループ絞込可・多いほど濃い**・脆弱性集計付き）。監視IPは**任意名称のグループ**にまとめ可（グループ見出しで一括選択・折りたたみ・Rename/Ungroup、ラベルもチーム共有）。Re-enrichは過去を捨てず**時系列で蓄積**し、各行の **📈 Analysis** で**エンリッチ分析ページ**（トレンドのスパークライン、指標マトリクス、任意2点のフィールド比較、前回差分タイムライン）。各行に**傾向スパークライン＋前回差分**も表示。**⚡ Auto**（行 or 一括）で**自動エンリッチ**：**サーバ側で毎日1回**（Cloudflare Cron／Nodeは外部cronで`POST /api/cron/auto-enrich`＝ADMIN_TOKEN必須）自動的にエンリッチしてスナップショットを保存・全端末へ配信（ブラウザを開いていなくても更新）。加えてブラウザを開いている間はクライアント側でも年代連動間隔で補完。古い点は**年代間引き**でログ肥大を防止。履歴ごとチーム共有（Monitorは membership+ 必要）。※Cron を有効化するには**プロキシを再デプロイ**（Deploy Proxy）してください |
| **MaxMind GeoIP** | 位置情報（IP限定） | 任意 | `MAXMIND_ACCOUNT_ID`＋`MAXMIND_LICENSE_KEY` | 地理位置(国/地域/市/郵便番号)・ISP/組織/ASN/ドメイン・接続種別・**匿名化(VPN/Tor/プロキシ)判定**・詳細に**地図(OpenStreetMap)**。**Insights**ライセンスなら信頼度スコア・静的IPスコア・IPリスク・ユーザー数/種別・US平均所得/人口密度も。※規約により緯度経度は必ず**精度半径(km)**と共に“おおよその範囲”として表示 |
| **DomainTools Iris** | ドメイン/IP情報 | 任意 | `DOMAINTOOLS_API_USERNAME`＋`DOMAINTOOLS_API_KEY` | **ドメイン**(Enrich)：リスクスコア＋内訳/WHOIS/RDAP/IP/ASN/NS/MX/SSL/website/first_seen/tags。**IP**(Investigate逆引き)：そのIP上のドメイン |
| **DNSLytics** | IP/ドメイン情報 | 任意 | `DNSLYTICS_API_KEY` | **IP**(IPInfo)：ASN/組織/ネットワーク/逆引き/同居ドメイン数＋サンプル/ブロックリスト。**ドメイン**(HostingHistory)：A/AAAA・NS・MX・SPF の履歴 |
| **Intel 471 (Titan)** | CTI・全種別 | 任意 | `INTEL471_API_USER`＋`INTEL471_API_KEY` | 全種別のIOC照合（active期間・ISP・関連レポート/アクター）＋詳細の「Global Search」ボタンで横断件数(reports/posts/actors/events/credentials/data-leaks) |
| **CYFIRMA (DeCYFIR)** | CTI・全種別 | 任意 | `CYFIRMA_API_KEY` | 全種別に **Risk Dossier**（リスク/外部脅威スコア・推奨アクション・ASN/組織/国・**関連インフラ＝攻撃基盤側**）＋**STIX 2.1検索**（脅威アクター/キャンペーン/マルウェア＝アトリビューション）を付与。詳細で脅威アクターのチップを押すと「広域サーチ」でそのアクターのキャンペーン/マルウェア/標的CVEをオンデマンド取得 |
| **TeamT5 ThreatVision** | CTI・全種別 | 任意 | `THREATVISION_CLIENT_ID`＋`THREATVISION_CLIENT_SECRET` | APT帰属CTI。**IP/ドメイン**：リスク・**攻撃グループ(APT)**・属性(Malware C2/Hosting)・地域/レジストラ・関連件数(**各1 AAP**)。**ハッシュ**：サンプル検索で攻撃グループ+マルウェアファミリ+リスク(**0 AAP**)。詳細で攻撃グループのチップを押すとAPTの別名/出身国/標的を取得。アップロード系は非対応 |
| **Recorded Future** | CTI・全種別 | 任意 | `RECORDEDFUTURE_API_KEY` | 全種別に Connect API のリスクスコア(0-99)・発火リスクルール＋根拠・活動期間・脅威リスト・関連する脅威アクター/マルウェア・MITRE・AI Insights を付与。詳細でアクター/マルウェアのチップを押すと Threat/Connect API でプロフィールをオンデマンド取得。ハッシュは「Sandbox intel」でサンドボックス評価(**読み取りのみ・検体送信なし**)、「Detection rules」で関連する **Sigma/YARA/Snort** ルールを検索・コピー |
| **AbuseIPDB** | レピュテーション・IP限定 | 任意 | `ABUSEIPDB_API_KEY` | IP に<b>悪用信頼度スコア(0-100)</b>・レポート数/報告者数・最終報告日・用途種別/ISP/ドメイン・<b>Tor/ホワイトリスト</b>判定・<b>攻撃カテゴリ</b>(SSH/ブルートフォース/ポートスキャン等)＋直近レポートを付与。abuseipdb.comへのリンクも表示。<b>読み取り専用</b>(CHECKのみ・レポート送信/POST系は非対応)。無料枠1,000/日 |
| **Claude (Anthropic)** | スマートパース | 任意 | `ANTHROPIC_API_KEY` | レポート本文からIOC抽出 |
| **SOC Prime (TDM)** | 検知コンテンツ | 任意 | `SOCPRIME_API_KEY` | エンリッチではない。<b>検知ルール検索</b>（ヘッダー「Rules」）：キーワード/ATT&CKアクター/ツール/テクニック/重大度で SOC Prime の Sigma 検知ルールを検索し、指定SIEM形式へ翻訳表示。加えて Resultsの「SIEM query」で表示中IOCから<b>ハンティングクエリ</b>生成（Uncoder AI）。トリアージ→ハンティングの橋渡し |
| **urlscan.io** | ライブ保全・URL/ドメイン（オンデマンド） | 任意 | `URLSCAN_API_KEY` | 詳細パネルの<b>「🎣 魚拓」</b>ボタンで対象を urlscan.io の<b>サンドボックスで実際に開く</b>（訪問は urlscan 側・こちらの出口IPは晒れない）。スクショ・最終URL・解決IP・サーバASN/国・HTTPステータス・<b>悪性判定/スコア</b>・偽装ブランド・接触した全ドメイン/IP・結果ページリンクを取得。<b>OPSEC既定（フリー版でも安全）</b>：<b>unlisted</b>（公開フィード/検索非掲載）・<b>タグ無し</b>（タグは検索可能で足がつくため）・`public`は`URLSCAN_ALLOW_PUBLIC=true`が無い限り<b>unlistedに強制</b>。提出はプロキシ経由なので記録される国はプロキシ側 |

**🎯 CP-Mon（Campaign Monitor）**：攻撃**キャンペーン**を IOC の集合として追跡する専用ページ（主役は Shodan 監視ではなく**エンリッチ履歴と分析**）。ヘッダー **CP-Mon** →**キャンペーン名で登録**（クラスタごとに複数可）→ 開いて**任意のIOC（IP/ドメイン/URL/ハッシュ）を任意のグループ名の下に追加**、または検索結果テーブルで行をチェックして **＋ Campaign** で事前登録済みキャンペーンへ直接登録。各IOCは IP-Mon と同じ**時系列スナップショット**（年代間引き・`⚡ Auto`・サーバ側毎日Cron）＋**傾向スパークライン＋前回差分**を持ち、キャンペーンページは**ダッシュボード分析**（ロールアップ統計・種別別/国別/上位CVE・各IOC最新差分の「Recent changes」）＝単なる羅列ではない。**国別ヒートマップ（コロプレス地図）**でIOCの多い国ほど濃く塗り、任意の1グループに絞り込み可。最上部の**電光掲示板（キーメッセージ）**には、キャンペーン全体＋エンリッチの推移（情報推移）を **Claude が1行で総括**して流す（Claude未設定時は決定論的フォールバック）。**既定で全員共有**（プロキシKV）なので他メンバーのエンリッチも総括も共有され二度打ちを回避。

**IOC種別で引き分け**：ドメイン→VT＋DomainTools(Enrich)＋DNSLytics(HostingHistory) ／ IP→VT＋Shodan＋MaxMind(位置/地図)＋DNSLytics(IPInfo)＋DomainTools(逆引き) ／ URL→ホスト名をドメイン扱い ／ ハッシュ→VT＋ThreatVision(サンプル帰属)。**Intel 471・CYFIRMA・ThreatVision・Recorded Future は全種別**に付与。**オンデマンドのライブ保全（バッチエンリッチとは別・詳細パネル）**：URL/ドメイン→**urlscan.io 魚拓** ／ IP→**📡 Live ports**（無料InternetDBの現在ポート/CVE、Shodanキーがあれば再スキャン＝状態表示付きで自動反映）。**さらに Web系ポートを持つIPは、Shodan×urlscan 連携で「🎣 Web 魚拓」＝そのIPが配信しているサイトをurlscanで保全**（IPでも魚拓）。各連携は Settings で個別ON/OFF可。DomainToolsは従量課金・Investigateは低レート制限のため、`DOMAINTOOLS_RPM`(既定30)/`DNSLYTICS_RPM`(既定60)/`INTEL471_RPM`(既定60)/`CYFIRMA_RPM`(既定30)/`THREATVISION_RPM`(既定30)で調整、`DNSLYTICS_BASE_URL`・`CYFIRMA_BASE_URL`・`THREATVISION_BASE_URL`でエンドポイント変更可。**ThreatVision の IP/ドメイン詳細は 1件 1 AAP 消費**（AAPは有限のため注意）。

**任意サービスを有効化する手順（3ステップ）:**
1. 上表の環境変数を **リポジトリ Secret**（GitHub → Settings → Secrets → Actions）に登録。
2. **「Deploy Proxy」ワークフロー**を実行（Cloudflare）／Nodeプロキシを再起動 → Secret がプロキシに反映。
3. アプリをリロード → ヘッダーのチップが **ON** に。`<プロキシURL>/health` でも確認可。

> Shodan は Settings の **「Shodan OSINT enrichment」**、MaxMind は **「MaxMind GeoIP geolocation」** で実行ON/OFFを切替できます（キーがあってもOFFなら問い合わせしない＝クレジット節約）。
>
> MaxMind は既定で **Insights** エディションを叩きます（最も情報量が多い）。City/Country ライセンスや GeoLite2(無料) の場合は `MAXMIND_EDITION`（`insights`/`city`/`country`）と `MAXMIND_BASE_URL`（有料=`https://geoip.maxmind.com`／GeoLite2=`https://geolite.info`）で切替できます。**アカウントIDとライセンスキーの両方**が必要です。

---

## 1. ★ GitHub でやること（今あなたが見ている画面）

あなたが開いている **Settings → Secrets and variables →「Actions」** が正しい場所です
（Agents / Codespaces / Dependabot は使いません）。

### 1-1. 「New repository secret」で登録する Secrets

| Secret 名 | 必須? | 用途 | 使うワークフロー |
|---|---|---|---|
| `VT_API_KEY` | **必須(実データ)** | VirusTotal / GTI のAPIキー | proxy-deploy |
| `ACCESS_TOKEN` | 推奨 | `/api/*` 保護。webのSettingsに同じ値を入れて送信 | proxy-deploy |
| `ADMIN_TOKEN` | 推奨 | `/api/admin/*`(ユーザー/設定の書込)保護 | proxy-deploy |
| `ANTHROPIC_API_KEY` | 任意 | Claudeスマートパース(無ければ正規表現にフォールバック) | proxy-deploy |
| `SHODAN_API_KEY` | 任意 | **Shodan OSINT**。IP行に開放ポート/サービス/CVE等を自動付与(無ければ付与なし) | proxy-deploy |
| `RECORDEDFUTURE_API_KEY` | 任意 | **Recorded Future**。全種別にリスク/根拠/関連アクター・マルウェア＋オンデマンドでActor/Malwareプロフィール・サンドボックス・Sigma/YARA/Snort | proxy-deploy |
| `MAXMIND_ACCOUNT_ID`＋`MAXMIND_LICENSE_KEY` | 任意 | **MaxMind GeoIP**。IP行に地理位置/ISP/ASN/匿名化判定＋地図を付与(Insights対応)。両方セットで有効 | proxy-deploy |
| `DOMAINTOOLS_API_USERNAME`＋`DOMAINTOOLS_API_KEY` | 任意 | **DomainTools Iris**。ドメイン=Enrich／IP=Investigate逆引き。両方セットで有効 | proxy-deploy |
| `DNSLYTICS_API_KEY` | 任意 | **DNSLytics**。IP=IPInfo／ドメイン=HostingHistory | proxy-deploy |
| `INTEL471_API_USER`＋`INTEL471_API_KEY` | 任意 | **Intel 471 (Titan)**。BasicAuth＝APIメール＋APIキー。全種別IOC照合 | proxy-deploy |
| `CYFIRMA_API_KEY` | 任意 | **CYFIRMA (DeCYFIR)**。`key=`クエリ認証。全種別に Risk Dossier＋STIX 2.1検索（攻撃基盤/アトリビューション） | proxy-deploy |
| `THREATVISION_CLIENT_ID`＋`THREATVISION_CLIENT_SECRET` | 任意 | **TeamT5 ThreatVision**。OAuth2クライアント認証。全種別にAPT帰属CTI（IP/ドメイン=各1 AAP, ハッシュ=0 AAP） | proxy-deploy |
| `SOCPRIME_API_KEY` | 任意 | **SOC Prime (TDM)**。`client_secret_id`ヘッダ認証。Uncoder AIでIOC→SIEMハンティングクエリ生成（Results「SIEM query」ボタン） | proxy-deploy |
| `URLSCAN_API_KEY` | 任意 | **urlscan.io**。`API-Key`認証。詳細パネルの「🎣 魚拓」でURL/ドメインをサンドボックス実行→スクショ/解決IP/接触ホスト/悪性判定（訪問はurlscan側・出口IP非露出） | proxy-deploy |
| `ABUSEIPDB_API_KEY` | 任意 | **AbuseIPDB**。`Key`ヘッダ認証。IPに悪用信頼度スコア(0-100)+レポート/攻撃カテゴリを付与（CHECKのみ・読み取り専用）。CORS非対応のためプロキシ必須。無料枠1,000/日 | proxy-deploy |
| `CLOUDFLARE_API_TOKEN` | Cloudflare使用時のみ | Worker デプロイ認証 | proxy-deploy |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare使用時のみ | Cloudflare アカウントID | proxy-deploy |

- `ACCESS_TOKEN` / `ADMIN_TOKEN` は**任意の長いランダム文字列**でOK。例:
  ```bash
  openssl rand -hex 32   # これを ACCESS_TOKEN に
  openssl rand -hex 32   # これを ADMIN_TOKEN に
  ```
- **デモだけ公開する段階では Secrets は1つも要りません。** 上記は「実データ用プロキシ」を動かす時に使います。

### 1-2. デモを公開する設定（Secrets不要）

1. **Settings → Pages → Build and deployment → Source = 「GitHub Actions」** を選択。
2. ブランチ `claude/compassionate-edison-u5fjjz` を **`main` にマージ**（または下記で手動実行）。
3. 公開URL: `https://waganawa-megumin.github.io/vteeee/`
   - 手動実行する場合: **Actions タブ → 「Deploy Pages」→ Run workflow**。

> リポジトリ名が `vteeee` 以外の場合は `.github/workflows/pages.yml` の `VITE_BASE: /vteeee/` を
> `/<リポジトリ名>/` に変更してください。

### 1-3. 実データ用プロキシを動かす（任意・Cloudflare推奨）

1. 上の表の Secrets（最低 `VT_API_KEY`、推奨 `ACCESS_TOKEN`/`ADMIN_TOKEN`、Cloudflareの2つ）を登録。
2. Cloudflare 側準備（後述「7章」）: KV作成 → `proxy/cloudflare/wrangler.toml` に id と `ALLOWED_ORIGINS` を記入してコミット。
3. **Actions タブ → 「Deploy Proxy (Cloudflare)」→ Run workflow** を実行。
   - これがワークフロー内で `wrangler deploy` と `wrangler secret put` を行い、**キーをCloudflare側のSecretに格納**します。
4. デプロイされた Worker のURL（例 `https://vteeee-proxy.<アカウント>.workers.dev`）を控える。
5. 公開Webを開き、**アプリ内 Settings** に「プロキシURL」と「アクセストークン(`ACCESS_TOKEN`の値)」を入力 → 右上が **LIVE** に。

> GitHubでの作業はここまで。要点は「**Secretsは Actions タブに入れる／公開Webビルドはキーを使わない／キーはプロキシに届く**」。

---

## 2. ローカルでデモを試す（キー不要）

```bash
pnpm install
pnpm dev                 # http://localhost:5173
```
ログイン: 共有のデモ資格情報でサインイン（管理者 `admin` / 閲覧 `analyst`。**パスワードは非公開**＝ここには記載せず、別途連携）。

「Load sample → Parse → Enrich N selected」でサンプル結果を確認。行クリックで詳細、右上 Settings、管理者は「Manage」。

> **本番前に必ずデフォルトの資格情報を変更**してください（5章）。

---

## 3. ローカルで実データを試す（Nodeプロキシ）

```bash
cp proxy/node/.dev.vars.example proxy/node/.dev.vars
# .dev.vars を編集:
#   VT_API_KEY=<本物のVTキー>
#   ACCESS_TOKEN=<任意の文字列>
#   ADMIN_TOKEN=<任意の文字列>
#   ALLOWED_ORIGINS=http://localhost:5173
pnpm proxy               # http://localhost:8787
```
別ターミナルで `pnpm dev` → アプリ内 **Settings** に
- Proxy base URL: `http://localhost:8787`
- Access token: `.dev.vars` の `ACCESS_TOKEN`
を入力して保存 → **LIVE**。少数のIOCで試す（無料枠は約4req/分・500/日）。

動作確認:
```bash
curl http://localhost:8787/health          # {"ok":true,"vtKey":true,...}
```

---

## 4. デモ公開（GitHub Pages）詳細

- `pages.yml` が `main` への push で起動 → `VITE_BASE=/vteeee/` でビルド → `web/dist` を Pages に配信。
- **Secrets も プロキシURLも注入しない**ので、公開サイトは既定で **Demo** のまま（サンプルデータ）。
- 公開サイトでも、各利用者がアプリ内Settingsに自分のプロキシURL＋トークンを入れれば LIVE で使えます（プロキシ側CORSで
  github.ioオリジンを許可していることが前提）。

---

## 5. ログイン・ユーザー/権限・設定の管理

- **ロール**: `user`(検索のみ) / `admin`(検索＋「Manage」)。
- **Manage → Users & permissions**:
  - ユーザー追加（ユーザー名・パスワード・ロール）。パスワードは**ブラウザ内でPBKDF2ハッシュ化**して保存（平文は保存しない）。
  - ロール変更、パスワードリセット、削除。
  - **Export users.json / Import users.json**。チーム共有の初期値にするには、エクスポートした `users.json` を
    `web/public/config/users.json` に置いて**コミット**します。
- **Manage → Credentials & settings**:
  - 管理者トークン、プロキシURL、許可オリジンメモの編集、`settings.json` のExport/Import。
  - **Live時**は「Push to proxy / Pull from proxy」で users+settings をプロキシ(KV)に共有保存できます（要 `ADMIN_TOKEN`）。
- **デフォルト資格情報の変更手順（推奨・最初にやる）**:
  1. `admin`（デモ資格情報）でログイン → Manage → Users。
  2. 新しい管理者を追加 → 既存 `admin`/`analyst` を削除 or パスワード変更。
  3. **Export users.json** → 中身を `web/public/config/users.json` に上書きコミット → 全員へ反映。

> 注意: 静的サイトのログイン/権限は設計どおり**突破可能な「目隠し」**です。実際の保護は
> プロキシの `ACCESS_TOKEN`/`ADMIN_TOKEN` と CORS が担います。強い共有パスワードを使ってください。

---

## 6. 入力・パース（defang解除）の仕様

- 入力: テキストエリアへ貼り付け / ファイルのドラッグ&ドロップ / 「Upload file…」（.txt/.csv/.log等）。
- 自動で解除する無害化(defang): `[.] (.) {.} [dot] (dot) \.` / `hxxp hxxps fxp` / `[://] [:]` / `[@] (at)` /
  前後の引用符・山括弧・Markdownリンク・末尾の句読点 など。
- 分類: IPv4 / IPv6 / domain / URL / MD5 / SHA1 / SHA256。IDNは punycode 化。重複排除。
- **既定で除外（送信しない）**: RFC1918等のプライベートIP、ループバック/リンクローカル、予約TLD(`.test/.example/...`)、単一ラベル。
  → 「Parsed indicators」で行ごとにチェックして手動で含める/外す調整が可能。
- **Smart parse**: 雑多なレポート本文からのIOC抽出。Demoは正規表現、Liveは Claude(`claude-haiku-4-5`)。Claudeの結果も必ず
  正規表現分類器で再判定します。

---

## 7. プロキシ本番デプロイ

### 7-A. Cloudflare Workers（推奨）
```bash
cd proxy/cloudflare
pnpm exec wrangler login                       # 初回のみ
pnpm exec wrangler kv namespace create VTEEEE_KV
# 出力された id を wrangler.toml の id="REPLACE_WITH_KV_NAMESPACE_ID" に貼る
# wrangler.toml の ALLOWED_ORIGINS を "https://waganawa-megumin.github.io,http://localhost:5173" に
```
- デプロイ＋Secret投入は **GitHub の「Deploy Proxy」ワークフロー**が自動化（1-3）。手動なら:
  ```bash
  pnpm exec wrangler deploy
  printf '%s' "<VTキー>" | pnpm exec wrangler secret put VT_API_KEY
  printf '%s' "<ACCESS>" | pnpm exec wrangler secret put ACCESS_TOKEN
  printf '%s' "<ADMIN>"  | pnpm exec wrangler secret put ADMIN_TOKEN
  printf '%s' "<Shodanキー>" | pnpm exec wrangler secret put SHODAN_API_KEY  # 任意: IPにOSINT付与
  printf '%s' "<MaxMindアカウントID>" | pnpm exec wrangler secret put MAXMIND_ACCOUNT_ID   # 任意: IPに位置/地図
  printf '%s' "<MaxMindライセンスキー>" | pnpm exec wrangler secret put MAXMIND_LICENSE_KEY  # 任意(上とペア)
  printf '%s' "<DTユーザー名>" | pnpm exec wrangler secret put DOMAINTOOLS_API_USERNAME  # 任意
  printf '%s' "<DTキー>"       | pnpm exec wrangler secret put DOMAINTOOLS_API_KEY       # 任意
  printf '%s' "<DNSLyticsキー>" | pnpm exec wrangler secret put DNSLYTICS_API_KEY         # 任意
  printf '%s' "<Intel471メール>" | pnpm exec wrangler secret put INTEL471_API_USER        # 任意
  printf '%s' "<Intel471キー>"   | pnpm exec wrangler secret put INTEL471_API_KEY          # 任意
  printf '%s' "<CYFIRMAキー>"    | pnpm exec wrangler secret put CYFIRMA_API_KEY           # 任意
  printf '%s' "<TVクライアントID>"  | pnpm exec wrangler secret put THREATVISION_CLIENT_ID    # 任意
  printf '%s' "<TVシークレット>"   | pnpm exec wrangler secret put THREATVISION_CLIENT_SECRET # 任意
  printf '%s' "<SOC Primeキー>"   | pnpm exec wrangler secret put SOCPRIME_API_KEY          # 任意
  printf '%s' "<RecordedFutureトークン>" | pnpm exec wrangler secret put RECORDEDFUTURE_API_KEY  # 任意
  printf '%s' "<urlscanキー>"    | pnpm exec wrangler secret put URLSCAN_API_KEY          # 任意: URL/ドメインの魚拓
  printf '%s' "<AbuseIPDBキー>"  | pnpm exec wrangler secret put ABUSEIPDB_API_KEY        # 任意: IPの悪用信頼度スコア
  ```
- 注意: Workerのレート制限カウンタはisolate間で共有されません。厳密な全体ペースが要るなら Node版を推奨。

### 7-B. Node 自前ホスト
- `proxy/node` を任意のサーバーで `pnpm --filter @vteeee/proxy-node start`（環境変数 or `.dev.vars`）。
- この場合 **GitHub Secrets は使わず**、ホストの環境変数に `VT_API_KEY` 等を設定します。
- リバースプロキシでHTTPS終端し、`ALLOWED_ORIGINS` に github.io を設定。

---

## 8. レート制限・クォータ・404の扱い

- 無料枠 ≈ **4 req/分・500/日**（商用不可）。GTI/有料は上限が高い → web Settings の **rpm/concurrency** を調整。
- 429 は `Retry-After` 優先＋指数バックオフ（UIに残り秒を表示）。リトライ超過は当該行 `rate_limited`。
- VT未知のIOCは **404 = not_found**。**自動再提出はしません**（クォータ節約）。必要なら設定の「Submit never-analyzed」をON。
- 401/403（キー不正）はバッチ全体を停止しエラー表示。
- Node版は日次上限ガード（既定500、`VT_DAILY`）あり。

---

## 9. 一覧・詳細・エクスポート

- 一覧列: インジケータ / 種別 / 判定(verdict) / 検出比(malicious+suspicious/total) / reputation / GTI / コンテキスト(国・ASN・レジストラ等) / VTリンク。
- ヘッダクリックでソート、フィルタ入力、**Export CSV**。
- 行クリックで詳細ドロワー（解析統計内訳、whois系、カテゴリ、タグ、GTI、ハッシュ、生VT属性、**Open in VirusTotal**）。
  - **既定サイズは最大**（右上の幅ステッパーで 最小/中/中大/最大 を切替、選択は記憶）。背景の暗幕はクリックで閉じられます。
  - **インジケータ間の移動**: 詳細ヘッダーの **‹ 現在/総数 ›**、またはキーボード **←/→** で一覧の（並び替え・フィルタ後の）表示順に前後移動。**Esc** で閉じる。最大サイズで一覧が隠れても行を開き直さずに移動できます。
- URLのVTリンクは GUI仕様の **SHA-256** を使用（API取得は base64 ID）。両方を内部で算出。

---

## 10. Secrets / 環境変数 早見表

| 名前 | 置き場所 | 必須 | 説明 |
|---|---|---|---|
| `VT_API_KEY` | プロキシ(GitHub Secrets→Cloudflare / Nodeのenv) | ◎ | VirusTotal/GTIキー |
| `ACCESS_TOKEN` | プロキシ + webのSettings | ○ | `/api/*` 共有トークン |
| `ADMIN_TOKEN` | プロキシ + webのManage | ○ | `/api/admin/*` 書込トークン |
| `ANTHROPIC_API_KEY` | プロキシ | △ | Claudeスマートパース |
| `SHODAN_API_KEY` | プロキシ | △ | Shodan OSINT(IPに開放ポート/サービス/CVE付与) |
| `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` / `MAXMIND_EDITION` / `MAXMIND_BASE_URL` | プロキシ | △ | MaxMind GeoIP(IPに位置/ISP/ASN/匿名化判定＋地図)。EDITIONは既定 `insights`(他 city/country)、BASE_URLは有料 geoip.maxmind.com／GeoLite2 geolite.info |
| `DOMAINTOOLS_API_USERNAME` / `DOMAINTOOLS_API_KEY` | プロキシ | △ | DomainTools Iris(ドメイン=Enrich／IP=逆引き) |
| `DNSLYTICS_API_KEY` / `DNSLYTICS_BASE_URL` | プロキシ | △ | DNSLytics(IP/ドメイン)。BASE_URLは既定 api.dnslytics.net/v1 |
| `INTEL471_API_USER` / `INTEL471_API_KEY` | プロキシ | △ | Intel 471 (Titan)。BasicAuth＝APIメール＋APIキー。全種別IOC照合 |
| `CYFIRMA_API_KEY` / `CYFIRMA_BASE_URL` | プロキシ | △ | CYFIRMA (DeCYFIR)。`key=`クエリ認証。全種別に Risk Dossier＋STIX検索。BASE_URLは既定 decyfir.cyfirma.com/core/api-ua |
| `THREATVISION_CLIENT_ID` / `THREATVISION_CLIENT_SECRET` / `THREATVISION_ACCESS_TOKEN` / `THREATVISION_BASE_URL` | プロキシ | △ | TeamT5 ThreatVision。OAuth2(client id/secret)または access token。IP/ドメイン=1 AAP, ハッシュ=0 AAP。BASE_URLは既定 api.threatvision.org |
| `SOCPRIME_API_KEY` / `SOCPRIME_BASE_URL` | プロキシ | △ | SOC Prime (TDM)。`client_secret_id`認証。Uncoder AIでIOC→SIEMクエリ生成。BASE_URLは既定 api.tdm.socprime.com |
| `RECORDEDFUTURE_API_KEY` / `RECORDEDFUTURE_BASE_URL` | プロキシ | △ | Recorded Future。`X-RFToken`認証。全種別にリスク/根拠/関連エンティティ＋Actor/Malware/Sandbox/Detection Rule。BASE_URLは既定 api.recordedfuture.com |
| `URLSCAN_API_KEY` / `URLSCAN_BASE_URL` / `URLSCAN_VISIBILITY` | プロキシ | △ | urlscan.io。`API-Key`認証。URL/ドメインのオンデマンド魚拓（サンドボックスでスクショ+解決IP+接触ホスト+悪性判定）。VISIBILITYは public/unlisted(既定)/private。BASE_URLは既定 urlscan.io |
| `ABUSEIPDB_API_KEY` / `ABUSEIPDB_MAX_AGE_DAYS` / `ABUSEIPDB_RPM` / `ABUSEIPDB_BASE_URL` | プロキシ | △ | AbuseIPDB。`Key`ヘッダ認証。IPに悪用信頼度スコア+レポート/攻撃カテゴリ(CHECK・読み取り専用)。MAX_AGE_DAYSは既定90(1-365)。BASE_URLは既定 api.abuseipdb.com/api/v2。CORS非対応=プロキシ必須 |
| `URLSCAN_ALLOW_PUBLIC` / `URLSCAN_TAGS` | プロキシ | △ | **OPSEC**。既定では `public` 指定を **unlisted に強制**（`URLSCAN_ALLOW_PUBLIC=true` の時のみ public 許可）。`URLSCAN_TAGS` は既定空＝タグ無し（タグは検索可能で足がつくため、付けたい場合のみカンマ区切りで指定） |
| `ALLOWED_ORIGINS` | プロキシ(wrangler.toml / env) | ○ | 許可オリジン(カンマ区切り) |
| `VT_RPM` / `VT_MAX_RPM` / `VT_DAILY` | プロキシ | △ | レート/日次上限 |
| `SHODAN_RPM` / `DOMAINTOOLS_RPM` / `DNSLYTICS_RPM` / `INTEL471_RPM` / `CYFIRMA_RPM` / `THREATVISION_RPM` | プロキシ | △ | 各連携の毎分上限(既定 60/30/60/60/30/30) |
| `CLAUDE_MODEL` | プロキシ | △ | 既定 `claude-haiku-4-5` |
| `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` | GitHub Secrets | Cloudflare時 | Workerデプロイ |
| `VITE_BASE` | Pagesワークフロー | ○ | `/<repo>/` |
| `VITE_API_BASE_URL` | (任意)webビルド時 | × | 既定でLive化したい場合のみ |

> web側のプロキシURL/トークンは基本 **アプリ内Settings**（localStorage保存）で持ちます。

---

## 11. トラブルシュート

| 症状 | 原因/対処 |
|---|---|
| LIVEにしたのに結果が出ない | Settingsの「Proxy base URL」「Access token」を確認。`curl <proxy>/health`。 |
| ブラウザのCORSエラー | プロキシの `ALLOWED_ORIGINS` に github.io オリジンと `http://localhost:5173` を追加。 |
| `401 unauthorized` | webのAccess token と プロキシの `ACCESS_TOKEN` が一致しているか。 |
| `VirusTotal auth error 401/403` | `VT_API_KEY` が未設定/不正。 |
| 全部 not_found / demoのまま | proxyBaseUrl未設定＝Demo。Settingsで設定。 |
| GTI項目が出ない | GTIキー＋Settingsの「Request GTI fields」ON。プロキシは `x-tool: vteeee` を送出済み。 |
| Pagesが404/真っ白 | `VITE_BASE` がリポジトリ名と一致しているか（`/vteeee/`）。 |
| 管理のPush/Pullが失敗 | `ADMIN_TOKEN` 一致とプロキシのKV設定を確認。 |

---

## 12. 開発コマンド / ファイル早見

```bash
pnpm dev          # webデモ
pnpm proxy        # Nodeプロキシ(ローカル実データ)
pnpm build        # webビルド（Pagesは VITE_BASE=/vteeee/）
pnpm -r test      # 全テスト（shared/proxy-core/web）
pnpm -r typecheck # 全型チェック
```

| 変更したい内容 | 触るファイル |
|---|---|
| defang/分類の精度 | `shared/src/defang.ts` / `classify.ts` / `extract.ts` |
| VTの取得項目・正規化 | `shared/src/vt-normalize.ts` / `vt-links.ts` |
| レート制御/ストリーミング | `proxy/shared-handler/src/enrich.ts` / `rateLimiter.ts` |
| Claudeプロンプト/モデル | `proxy/shared-handler/src/parse.ts` |
| デモのサンプル | `web/src/fixtures/samples.ts` |
| 一覧/詳細UI | `web/src/components/*` |
| 管理画面 | `web/src/admin/*` |
| デプロイ | `.github/workflows/*` / `proxy/cloudflare/wrangler.toml` |

---

## 13. 既知の制限・未検証

- 静的サイトのログイン/権限は突破可能（設計どおり）。実保護はプロキシのトークン＋CORS。
- **実VTキーでの成功レスポンス**と**ブラウザでのUIクリック通し**は未検証（キー投入後 `pnpm dev`/LIVEで確認可能）。ロジックは45テストで検証済み。
- Cloudflare Worker のレート/日次カウンタは isolate間で非共有（厳密運用はNode版）。
- カンマ無害化IP(`1,1,1,1`)はCSV区切りと衝突するため非対応。雑多本文はSmart parse推奨。

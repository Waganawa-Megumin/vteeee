# vteeee — source brief for an infographic (NotebookLM)

> Purpose of this document: a single, self-contained source to feed into NotebookLM
> (Enterprise) so it can generate an **infographic** about the project. It is written as
> plain, factual statements grouped into sections, with explicit "key stats" callouts and a
> suggested infographic structure at the end. English primary; a short Japanese section is
> included for bilingual output.

## One-liner
vteeee is a bulk Indicator-of-Compromise (IOC) search tool for cyber threat intelligence
(CTI) analysts. It cleans up defanged indicators, classifies them, and enriches them in bulk
via the VirusTotal / Google Threat Intelligence (GTI) API, then presents an analyst-friendly,
sortable results table with detail views and deep links.

## The problem it solves
- CTI analysts routinely receive long lists of indicators (from reports, alerts, tickets).
- Checking each indicator in VirusTotal one-by-one is slow.
- Most indicators arrive "defanged" (neutralized) so they can't be clicked or searched as-is,
  for example `1[.]1[.]1[.]1` instead of `1.1.1.1`, or `hxxps://evil[.]com` instead of a real URL.
- vteeee converts a messy block of (often defanged) text into a ranked, clickable triage table
  in one step — and does so without ever exposing the API key in the browser.

## Who it is for
Security operations and threat-intelligence analysts who triage many indicators at once.

## What it does — the pipeline (5 steps)
1. Input: the analyst pastes, types, drags-and-drops a file, or copies a list. Accepts a
   newline list, CSV, or messy report prose.
2. Refang + clean: deterministic rules remove obfuscation and wrappers.
3. Classify + dedupe: each token is typed (IP/domain/URL/hash), normalized, de-duplicated, and
   risky/irrelevant ones (private or reserved IPs) are flagged and excluded by default.
4. Enrich: each indicator is looked up via VirusTotal / GTI. Results stream back as they resolve.
5. Triage: results fill a sortable, filterable table; clicking a row opens a detail panel; each
   row deep-links to the indicator's page on virustotal.com. Results can be exported to CSV.

## Supported indicator types
IPv4, IPv6, domains, URLs, and file hashes (MD5, SHA-1, SHA-256).

## De-obfuscation (refang) — concrete examples
- `1[.]1[.]1[.]1` → `1.1.1.1`
- `8(dot)8(dot)8(dot)8` → `8.8.8.8`
- `hxxps://www[.]google[.]com/` → `https://www.google.com/`
- `evil [dot] com` → `evil.com`
- `[2001:db8::1]:443` → `2001:db8::1`
Handled obfuscations include: bracketed/parenthesized dots `[.] (.) {.}`, worded dots
`[dot] (dot)` and spaced ` dot `, escaped `\.`, scheme masking `hxxp/hxxps/fxp`, separator
masking `[://] [:]`, at-sign masking `[@] (at)`, plus quotes, angle brackets, markdown links,
and trailing punctuation. Internationalized domain names are converted to punycode.

## What an analyst sees per indicator
Unified verdict (malicious / suspicious / harmless / undetected), detection ratio
(malicious+suspicious over total engines), reputation score, GTI verdict + severity + threat
score (when a GTI key is used), and type-specific context: country / ASN / AS owner / network
for IPs; registrar / creation date / categories for domains; final URL / title / categories
for URLs; file type / size / MD5-SHA1-SHA256 / suggested threat label for hashes. Plus tags,
community votes, last-analysis date, and a one-click link to VirusTotal.

## Two modes: Demo and Live
- Demo mode (default, public): the static site ships with realistic sample data and does no
  real API calls. Anyone can explore the full UI safely. Defang/parsing run in the browser.
- Live mode: when a proxy URL is configured, real VirusTotal/GTI lookups run through a small
  server-side proxy that holds the API key. The same published bundle stays a demo by default
  and flips to live with no rebuild.

## Architecture
- Frontend: a static single-page app (Vite + React + TypeScript) deployable to GitHub Pages.
- Proxy: a thin server-side component that holds the VirusTotal key and proxies requests.
  Recommended deployment is Cloudflare Workers (with a KV store for shared users/settings); a
  Node/Express variant is provided for local use or self-hosting.
- Shared core: the refang/classify/normalize logic and auth helpers are shared by both the
  browser and the proxy, so behavior is identical in demo and live.

## Why a proxy is required (two independent reasons)
1. A VirusTotal API key must never be shipped to the browser.
2. The VirusTotal API does not send CORS headers, so browsers cannot call it directly.

## Security model
- The API key lives only on the proxy (environment variables / GitHub Secrets).
- The site login is an intentionally soft, client-side shared-credential gate. Passwords are
  stored as PBKDF2 hashes (200,000 iterations, SHA-256) — never as plaintext.
- The real protections are the proxy's shared access token (required on all API calls), an
  admin token (required to change users/settings), and a strict CORS origin allowlist.
- Roles: "admin" (search + management) and "user" (search only).

## Rate limiting and quotas
- The free VirusTotal tier is roughly 4 requests/minute and 500/day (non-commercial). GTI /
  premium keys allow much higher rates.
- The proxy enforces a configurable requests-per-minute token bucket, handles HTTP 429 with
  exponential backoff (honoring Retry-After), treats "never analyzed" 404s as a first-class
  state (and does not auto-submit, to save quota), and stops the batch on an auth error.
- Results stream as newline-delimited JSON (NDJSON) so rows appear incrementally — important
  because, on the free tier, a long list resolves slowly.

## Optional Claude smart-parse
For messy report prose, an optional Claude-powered extraction step (model
claude-haiku-4-5) pulls candidate IOCs out of free text. Its output is always re-validated by
the deterministic regex classifier, which remains the source of truth for typing/normalization.

## Tech stack and quality
TypeScript (strict), React + Vite, Zustand, Cloudflare Workers / Express, Vitest. The project
ships 45 unit and integration tests covering the refang/classifier, VirusTotal id+link
helpers, the response normalizer, PBKDF2 hashing, the enrichment orchestration (rate limiting,
429 retry, NDJSON streaming, fatal-error abort), and the end-to-end demo data path.

## Deployment
- The web demo deploys to GitHub Pages via GitHub Actions.
- The proxy deploys to Cloudflare Workers via GitHub Actions, with secrets injected from GitHub
  Secrets and a KV namespace for shared users/settings.

## Themes
Two visual themes: a chalkboard (dark green) theme and an off-white (light) theme, toggled in
the top bar and remembered across visits.

## KEY STATS (use these as infographic callouts)
- 7 indicator types recognized: IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256.
- 10+ defang/obfuscation styles refanged automatically.
- 200,000-iteration PBKDF2 password hashing (SHA-256).
- Free-tier limits handled: ~4 requests/min, 500/day.
- Results streamed as NDJSON (incremental, not all-at-once).
- 45 automated tests; strict TypeScript; 0 secrets in the browser bundle.
- 2 modes (Demo / Live), 2 themes (chalkboard / off-white), 2 roles (admin / user).

## Suggested infographic structure (for the generator)
1. Title band: "vteeee — bulk IOC search" with the one-liner.
2. The problem: "defanged IOCs + one-by-one lookups = slow" (small before/after of `1[.]1[.]1[.]1` → `1.1.1.1`).
3. The 5-step pipeline as a left-to-right flow: Input → Refang/Clean → Classify/Dedupe → Enrich (VirusTotal/GTI) → Triage table.
4. "Demo vs Live" split panel, emphasizing "the key never touches the browser; the proxy holds it."
5. A grid of the KEY STATS callouts.
6. Footer: security model in one line (soft client gate + proxy tokens + CORS) and the tech stack.
Recommended palette to match the product: chalkboard green #1f2a24, chalk-mint #74d3b1,
off-white #e9e7d6, alert red #ff6f86, safe green #86d98f.

## 日本語版（インフォグラフィック生成用・正式表記）

> 日本語インフォグラフィックを生成する際は、以下の本文と「用語の正式表記」をそのまま使ってください。

### 一言で
vteeee は、CTI（サイバー脅威インテリジェンス）アナリスト向けの **IOC 一括検索ツール**。
IP・ドメイン・URL・ファイルハッシュの一覧を貼り付けると、無害化(defang)を高精度に解除・分類し、
**VirusTotal / Google Threat Intelligence (GTI)** で一括エンリッチして、並べ替え可能な一覧で表示する。

### 課題（The Problem）
CTIアナリストは、レポートやアラートに含まれる大量の IOC を 1 件ずつ VirusTotal で調べる
「IOC調査の非効率」という課題に**直面**している。さらに多くの IOC は `1[.]1[.]1[.]1` や
`hxxps://…` のように**無害化(defang)**されており、そのままでは検索できない。

### 解決（The Solution）
vteeee は「無害化の自動復元(Refang)」と「一括エンリッチメント」で、この調査を劇的に高速化する。
（例：`1[.]1[.]1[.]1 → 1.1.1.1`）

### 調査効率を最大化する5ステップ・パイプライン
1. 入力：貼り付け／ドラッグ&ドロップ／入力（箇条書き・CSV・レポート本文に対応）
2. 無害化解除(Refang)：`1[.]1[.]1[.]1` のような無害化を自動復元（ブラウザ側で処理）
3. 分類・重複排除：IP / ドメイン / URL / ハッシュに分類し、重複を除外
4. 一括エンリッチ：VirusTotal / GTI で判定・検出比・評価などを取得（結果は順次ストリーミング）
5. トリアージ：並べ替え／フィルタ、行クリックで詳細、VirusTotal へのディープリンク、CSV出力

### 主な機能（4本柱）
- 入力と自動復元(Refang)：箇条書きやレポート本文から IOC を抽出し、`1[.]1[.]1[.]1` のような無害化を自動解除。
- 一括エンリッチメント：VirusTotal / GTI API を介し、判定・検出比・ASN・国・AS所有者・レジストラ・カテゴリ・脅威ラベル等を自動取得。
- インタラクティブなトリアージ：フィルタ可能なテーブル形式で結果を表示し、詳細分析へのディープリンクを提供。
- 安全性と信頼性を支える設計：APIキーを露出させないプロキシ構造。**ブラウザ側**ではなくプロキシサーバーで
  APIキーを管理し、**CORS制約**とセキュリティ問題を解決。待機時間を減らす **NDJSONストリーミング表示**
  （全ての解析を待たず、完了した行から順次リアルタイムで表示）。

### Demo モード / Live モード
- DEMO モード：基本的な機能体験用。APIキーは使用せず、サンプルデータで動作。
- LIVE モード：APIキーはブラウザに渡さない。プロキシサーバーで安全に管理し、実データ検索を提供。
- 流れ：**ユーザー向けUI（ブラウザ）** → **安全なAPIキー管理（プロキシ）** → **VirusTotal / GTI API**。

### セキュリティ
APIキーは常にプロキシ側のみが保持し、ブラウザには出さない。ログインは共有ID/PASSの簡易ゲート
（**PBKDF2・SHA-256・20万回試行**、平文非保存）と **ロールベースアクセス制御（admin / user）**。
実際の保護は、プロキシの **アクセストークン**／**管理者トークン** と **CORS許可リスト** が担う。

### 主要な数値（インフォグラフィックの見せ場）
- 対応IOC：**7種類**（IPv4 / IPv6 / ドメイン / URL / **MD5** / **SHA-1** / **SHA-256**）、**10種以上**の記述形式に対応
- セキュリティ仕様：**PBKDF2ハッシュ（20万回試行・SHA-256）**、**ロールベースアクセス制御**
- 開発品質：**45件**の自動テスト、厳格な **TypeScript** 採用
- 識別能力：多様な**難読化(defang)パターン**から識別可能
- レート：無料枠 約 **4 req/分・500/日**、結果は **NDJSON ストリーミング**

### 用語の正式表記（必ずこの表記を使う）
- ハッシュ：**MD5** / **SHA-1** / **SHA-256**（"MDS" は誤り）
- アクセス制御：**ロールベースアクセス制御**（admin / user）
- パスワード：**PBKDF2（SHA-256・20万回試行）**（"就行" ではなく "試行"）
- 通信・構成：**CORS制約** ／ **NDJSONストリーミング** ／ **プロキシ（サーバー側）** ／ **ブラウザ側**
- 課題表現：課題に**直面**する ／ **非効率**（"画面する" は誤り）
- 入力：**箇条書き**（"閣条書き" は誤り）／ CSV ／ レポート本文
- 文脈項目：判定 ／ 検出比 ／ **国**（"圏" は誤り）／ ASN ／ AS所有者 ／ レジストラ ／ カテゴリ ／ 脅威ラベル
- 画面：**ユーザー向けUI**（"ユーザー用テース" は誤り）

## Glossary
- IOC (Indicator of Compromise): an artifact (IP, domain, URL, file hash) associated with malicious activity.
- Defang: deliberately breaking an indicator so it can't be clicked/executed, e.g. `hxxp://`, `1[.]1[.]1[.]1`. Refang = reversing it.
- VirusTotal / GTI: Google's malware/URL/IP/domain analysis service and its Threat Intelligence tier.
- CTI: Cyber Threat Intelligence.

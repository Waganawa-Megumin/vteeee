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
- Roles: "admin" (search + management) and "viewer" (search only).

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
- 2 modes (Demo / Live), 2 themes (chalkboard / off-white), 2 roles (admin / viewer).

## Suggested infographic structure (for the generator)
1. Title band: "vteeee — bulk IOC search" with the one-liner.
2. The problem: "defanged IOCs + one-by-one lookups = slow" (small before/after of `1[.]1[.]1[.]1` → `1.1.1.1`).
3. The 5-step pipeline as a left-to-right flow: Input → Refang/Clean → Classify/Dedupe → Enrich (VirusTotal/GTI) → Triage table.
4. "Demo vs Live" split panel, emphasizing "the key never touches the browser; the proxy holds it."
5. A grid of the KEY STATS callouts.
6. Footer: security model in one line (soft client gate + proxy tokens + CORS) and the tech stack.
Recommended palette to match the product: chalkboard green #1f2a24, chalk-mint #74d3b1,
off-white #e9e7d6, alert red #ff6f86, safe green #86d98f.

## 日本語サマリー（バイリンガル出力用）
vteeee は CTI アナリスト向けの IOC 一括検索ツール。`1[.]1[.]1[.]1` などの無害化(defang)を
高精度に解除・分類し、VirusTotal / Google Threat Intelligence で一括エンリッチして、
判定・検出比・GTI評価・ASN/国・カテゴリ等を並べ替え可能な一覧で表示する。公開版は静的デモ
（サンプルデータ）、実検索は API キーをサーバー側に持つプロキシ経由でキーをブラウザに出さない。
ログインは PBKDF2 の簡易ゲート＋admin/viewerロール。無料枠（約4req/分・500/日）に配慮し、
結果は NDJSON でストリーミング。対応種別は IPv4/IPv6/ドメイン/URL/MD5/SHA1/SHA256。

## Glossary
- IOC (Indicator of Compromise): an artifact (IP, domain, URL, file hash) associated with malicious activity.
- Defang: deliberately breaking an indicator so it can't be clicked/executed, e.g. `hxxp://`, `1[.]1[.]1[.]1`. Refang = reversing it.
- VirusTotal / GTI: Google's malware/URL/IP/domain analysis service and its Threat Intelligence tier.
- CTI: Cyber Threat Intelligence.

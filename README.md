<p align="center">
  <img src="docs/assets/og-image.png" alt="vteeee — bulk IOC search: collect, normalize (defang), validate &amp; enrich" width="880" />
</p>

<p align="center">
  <a href="https://waganawa-megumin.github.io/vteeee/"><img alt="Live demo" src="https://img.shields.io/badge/live%20demo-vteeee-74d3b1?style=for-the-badge&labelColor=1f2a24" /></a>
  <a href="https://github.com/Waganawa-Megumin/vteeee/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Waganawa-Megumin/vteeee/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-strict-3178c6?style=flat&labelColor=1f2a24" />
  <img alt="React + Vite" src="https://img.shields.io/badge/React-Vite-61dafb?style=flat&labelColor=1f2a24" />
  <img alt="Cloudflare Workers" src="https://img.shields.io/badge/proxy-Cloudflare%20Workers-f38020?style=flat&labelColor=1f2a24" />
  <img alt="VirusTotal / GTI" src="https://img.shields.io/badge/enrichment-VirusTotal%20%2F%20GTI-394eff?style=flat&labelColor=1f2a24" />
  <img alt="Shodan OSINT" src="https://img.shields.io/badge/OSINT-Shodan-c4302b?style=flat&labelColor=1f2a24" />
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-74d3b1?style=flat&labelColor=1f2a24" /></a>
  <a href="https://ko-fi.com/shonanboyeah"><img alt="Ko-fi" src="https://img.shields.io/badge/Ko--fi-support-ff5e5b?style=flat&logo=ko-fi&logoColor=white&labelColor=1f2a24" /></a>
</p>

<p align="center"><b>Triage a wall of indicators in one paste.</b></p>

**vteeee** is a bulk IOC search tool for CTI analysts. Paste, drop, or type a list of
**IPs, domains, URLs, or file hashes** — even defanged like `1[.]1[.]1[.]1` or
`hxxps://evil[.]com` — and vteeee cleans them up, classifies them, and enriches each one
through the **VirusTotal / Google Threat Intelligence** API. Results stream into a
sortable table with per-row detail and one-click deep links back to virustotal.com.

> 🇯🇵 日本語の概要は[こちら](#日本語概要)。詳しい運用・デプロイ手順は **[docs/GUIDE.ja.md](docs/GUIDE.ja.md)**。

---

## At a glance

<p align="center">
  <img src="docs/assets/infographic.png" alt="vteeee infographic — the problem, the 5-step pipeline, demo vs live, and key stats" width="900" />
</p>
| | |
|---|---|
| **Input** | newline list · CSV · messy pasted text · drag-and-drop file |
| **Indicators** | IPv4 · IPv6 · domain · URL · MD5 · SHA-1 · SHA-256 |
| **De-obfuscation** | `[.] (.) [dot] (dot) \.` · `hxxp/hxxps/fxp` · `[://] [:]` · `[@] (at)` · quotes/markdown/trailing punctuation |
| **Enrichment** | detection ratio · reputation · GTI verdict/severity · ASN/country · registrar/categories · threat label · tags |
| **OSINT (IPs)** | **Shodan** — open ports · running services · known CVEs · org/ISP/OS · hostnames · tags *(set `SHODAN_API_KEY` on the proxy)* |
| **Safety** | dedupes; flags & excludes RFC1918 / reserved IPs; never auto-submits unknowns (saves quota) |
| **Modes** | **Demo** (static, sample data) · **Live** (real lookups via a key-holding proxy) |

---

## Why

Analysts lose time pasting indicators into VirusTotal one by one — and most IOCs arrive
**defanged** (`1[.]1[.]1[.]1`, `hxxp://…`) so they can't even be searched as-is. vteeee
turns "a messy block of text from a report" into "a ranked, clickable triage table" in a
single step, while keeping the API key off the browser entirely.

## Features

- **Accurate refang + classify** — 10+ obfuscation styles handled deterministically; IDNs punycoded; duplicates merged.
- **Streaming results** — NDJSON over the wire, so rows appear as they resolve (vital on the free tier's 4 req/min).
- **Analyst-first table** — sort by verdict/detections/reputation, filter, open a detail drawer, export CSV, jump to VirusTotal.
- **GTI-aware** — surfaces `gti_assessment` verdict/severity/threat-score when a GTI key is used (sends the required `x-tool` header).
- **Shodan OSINT** — drop a `SHODAN_API_KEY` on the proxy and every IP row gains open ports, running services, known CVEs and org/ISP/OS context, with a deep link to shodan.io. Key stays server-side; CVEs link out to NVD.
- **Optional Claude smart-parse** — pull IOCs out of free-form report prose; the regex engine still has the final say on typing.
- **Shared-credential login + admin** — PBKDF2-gated, `admin`/`user` roles, in-app user & settings management with JSON export/import.
- **Two themes** — a chalkboard dark theme and an off-white light theme, toggled in the top bar.

## Integrations / 連携サービス

The proxy holds each service's API key — the browser never sees them. **VirusTotal is the base
(required);** Shodan and Claude are optional add-ons. The app header shows which are live (read from
the proxy's `/health`), and each optional one is toggled in **Settings**.

| Service | Role | Required? | Proxy env var | Adds |
|---|---|---|---|---|
| **VirusTotal / GTI** | Threat intel (base) | ✅ **required** | `VT_API_KEY` | verdict · detections · reputation · ASN/country · categories · threat label · first/last seen (files/URLs) · GTI verdict/severity/score |
| **Shodan** | OSINT — IPs | optional | `SHODAN_API_KEY` | open ports · services · known CVEs · org/ISP/OS · hostnames · tags |
| **DomainTools Iris** | Domain/IP intel | optional | `DOMAINTOOLS_API_USERNAME` + `DOMAINTOOLS_API_KEY` | **domains** (Iris Enrich): risk score+components · WHOIS/RDAP · IP/ASN · NS · MX · SSL · website · first seen · tags. **IPs** (Iris Investigate reverse): domains hosted on the IP |
| **DNSLytics** | IP/domain intel | optional | `DNSLYTICS_API_KEY` | **IPs** (IPInfo): ASN · org · network · reverse DNS · hosted-domain count + sample · blocklist. **domains** (HostingHistory): A/AAAA · NS · MX · SPF history |
| **Claude (Anthropic)** | Smart-parse | optional | `ANTHROPIC_API_KEY` | extract IOCs from free-form report prose |

**Enrichment routes by IOC type:** domain → VT + DomainTools (Enrich) + DNSLytics (HostingHistory) · IP → VT + Shodan + DNSLytics (IPInfo) + DomainTools (reverse) · URL → host treated as a domain · hash → VT only. Each optional service toggles independently in **Settings**.

**Enable an optional service — 3 steps:**
1. Add the env var above as a **repo secret** (GitHub → Settings → Secrets) or a proxy env var.
2. Run the **“Deploy Proxy” workflow** (Cloudflare) or restart the Node proxy — this pushes the secret.
3. Reload the app; the header chip flips **ON**. Verify at `<proxy>/health` → `{"vtKey":true,"claude":…,"shodan":…}`.

Turn Shodan lookups off per run in **Settings → Shodan OSINT enrichment** to save Shodan credits even
when the key is present. Step-by-step (GitHub Secrets / Cloudflare / Node): **[docs/GUIDE.ja.md](docs/GUIDE.ja.md)**.

## Live demo

▶︎ **https://waganawa-megumin.github.io/vteeee/**

The public site is a **demo** (bundled sample data — no key, nothing sensitive).
Sign in with `analyst` / `REDACTED` (user) or `admin` / `REDACTED`, then
**Load sample → Parse → Enrich**. Point it at your own proxy in **Settings** to go live.

## How it works

```mermaid
flowchart LR
  A["Paste / drop / type<br/>IPs · domains · URLs · hashes<br/><i>defanged OK</i>"] --> B["Refang + classify<br/>(in the browser)"]
  B --> C{Mode}
  C -- Demo --> D["Bundled sample data"]
  C -- Live --> E["Proxy holds the VT key<br/>(rate-limits · streams NDJSON)"]
  E --> F[("VirusTotal / GTI")]
  D --> G["Sortable results<br/>detail drawer · VT deep links · CSV"]
  F --> G
```

A static site can't safely hold a VirusTotal key, and VT's API sends no CORS headers — so
the **key lives only on a small server-side proxy**. The same github.io bundle stays a demo
by default; configuring a proxy URL (in-app, persisted locally) flips it to live with no rebuild.

## Quick start

```bash
pnpm install
pnpm dev        # http://localhost:5173  (demo — no keys needed)
```

### Live mode locally

```bash
cp proxy/node/.dev.vars.example proxy/node/.dev.vars   # set VT_API_KEY, ACCESS_TOKEN, ADMIN_TOKEN
pnpm proxy      # Express proxy on http://localhost:8787
```

Then in the app's **Settings**: set the proxy URL to `http://localhost:8787` and your
`ACCESS_TOKEN`. The badge flips to **LIVE**.

## Deploy

- **Web → GitHub Pages** (`pages.yml`): builds with `VITE_BASE=/vteeee/` and publishes the demo. No secrets injected, so the public site stays a demo.
- **Proxy → Cloudflare Workers** (`proxy-deploy.yml`, recommended): holds `VT_API_KEY` (+ optional `ANTHROPIC_API_KEY`, `SHODAN_API_KEY`) and `ACCESS_TOKEN`/`ADMIN_TOKEN`, with a KV store for shared users/settings. A Node/Express variant is included for self-hosting.

Full, click-by-click instructions (GitHub Secrets, Cloudflare token, KV, connecting the app):
**[docs/GUIDE.ja.md](docs/GUIDE.ja.md)**.

## Security model

- The **VT API key never reaches the browser** — only the proxy holds it (env / GitHub Secrets).
- The github.io login is an intentionally **soft, client-side gate** (shared credential, PBKDF2-hashed — no plaintext). Real protection is the proxy's **access token** (`/api/*`) and **admin token** (`/api/admin/*`) plus a strict CORS allowlist.
- Never commit plaintext passwords or tokens. `users.json` holds hashes only.

## Project layout

```
shared/            defang/classify/extract · VT links + normalizer · PBKDF2  (browser + proxy)
web/               Vite + React static SPA — input, parse preview, results, detail, login, admin
proxy/shared-handler  rate limiting · NDJSON enrich · Shodan OSINT · Claude parse · users/settings store
proxy/node         Express adapter (local / self-host)
proxy/cloudflare   Worker adapter (recommended deploy) + wrangler.toml
.github/workflows  ci · pages · proxy-deploy
```

## Tech & quality

TypeScript (strict) · React + Vite · Zustand · Cloudflare Workers / Express · Vitest.
**58 unit/integration tests** cover the refang/classifier, VT id+link helpers, the response
normalizer, PBKDF2, the enrich orchestration (rate-limit, 429 retry, NDJSON streaming), the
daily-quota/model guards, KV history, and the end-to-end demo path. `pnpm -r typecheck && pnpm -r test`.

## Limitations

- Static-site login/roles are bypassable by design — the proxy tokens + CORS are the real guard.
- Free VT tier is small (~4 req/min, 500/day, non-commercial); keep RPM low. GTI keys are higher.
- A single Cloudflare Worker isolate's rate limiter isn't globally shared — use the Node proxy when you need strict global pacing.

---

## 日本語概要

CTIアナリスト向けの **IOC一括検索ツール** です。IP・ドメイン・URL・ハッシュの一覧（改行 / CSV /
レポート本文のコピペ / ファイルのドラッグ&ドロップ）を渡すと、`1[.]1[.]1[.]1` や `hxxps://` などの
**無害化(defang)を高精度に解除・分類**し、**VirusTotal / Google Threat Intelligence** で一括エンリッチ。
判定・検出比・GTI評価・ASN/国・カテゴリ等を**並べ替え可能な一覧**で表示し、行クリックで詳細＆VTへ直リンク。

- 公開版は **github.io の静的デモ**（サンプルデータ／キー不要）。実データ検索は **APIキーをサーバー側に
  持つプロキシ**経由（キーはブラウザに出ません）。
- **Shodan OSINT**：プロキシに `SHODAN_API_KEY` を登録するだけで、IP行に**開放ポート・稼働サービス・既知のCVE**・
  組織/ISP/OS などが自動付与され、詳細パネルに分かりやすく表示（shodan.io へ直リンク、CVEはNVDへリンク）。
- ログインは共有ID/PASSの簡易ゲート（PBKDF2、平文非保存）＋ admin/user ロールと管理画面。
- テーマは**黒板**と**オフホワイト**を切替可能。
- 詳しい手順（GitHub Secrets・Cloudflare・接続）→ **[docs/GUIDE.ja.md](docs/GUIDE.ja.md)**

---

## Support / 開発を応援

<p>
  <a href="https://ko-fi.com/shonanboyeah"><img alt="Support on Ko-fi" src="https://img.shields.io/badge/Support%20on-Ko--fi-ff5e5b?style=for-the-badge&logo=ko-fi&logoColor=white&labelColor=1f2a24" /></a>
</p>

If vteeee saves you triage time, you can support development on **[Ko-fi](https://ko-fi.com/shonanboyeah)** ☕
役に立ったら **[Ko-fi](https://ko-fi.com/shonanboyeah)**
## License &amp; AI use

**Code: [MIT](./LICENSE).** © 2026 Waganawa-Megumin. You're welcome to read, run, fork and build on it — just keep the copyright notice.

**Reserved: AI/LLM training &amp; text-and-data-mining (TDM).** Permissive reuse of the *code* is fine, but the author does **not** consent to this repository or the hosted site being ingested for AI/ML model training or TDM. It's declared in a machine-readable way (a legally meaningful opt-out under the EU TDM regime, and honoured by many crawlers):

- [`web/public/robots.txt`](./web/public/robots.txt) — disallows GPTBot, Google-Extended, ClaudeBot / anthropic-ai, CCBot, PerplexityBot, Bytespider and other training crawlers.
- `<meta name="robots" content="noai, noimageai">` + `<meta name="tdm-reservation" content="1">` on every page.
- [`/.well-known/tdmrep.json`](./web/public/.well-known/tdmrep.json) — TDM Reservation Protocol opt-out.

> **GitHub Pages note:** crawlers read `robots.txt` from the **domain root** (`https://<user>.github.io/robots.txt`), not from `/vteeee/`. For a site-wide block, copy the same rules into your root `*.github.io` repo's `robots.txt`. No license or signal can *physically* stop scraping of public content — these establish intent and (in the EU) a binding reservation.

---

<sub>Built for analysts. Paste defanged, get answers. </sub>

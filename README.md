# vteeee — bulk IOC search for CTI analysts

Paste / drag-drop / type a list of **IPs, domains, URLs or file hashes** (even
defanged like `1[.]1[.]1[.]1` or `hxxps://evil[.]com`), and get a sortable table
of the analyst-relevant **VirusTotal / Google Threat Intelligence** fields, with
click-through detail and deep links to virustotal.com.

> 日本語: 改行リスト / CSV / 雑多なテキストを渡すと、無害化(defang)を高精度に解除して
> IP・ドメイン・URL・ハッシュを分類し、VT/GTI API で一括エンリッチして一覧表示します。
> 公開版は **GitHub Pages の静的モック（デモ）**、実データ検索は **APIキーをサーバー側で持つ
> プロキシ** 経由です。ログインは共有ID/PASS（クライアント側の簡易ゲート）＋簡易な管理機能付き。

## How it works (demo vs live)

A static site **cannot** safely hold a VirusTotal API key, and VT's API does not
send CORS headers — so there are two modes:

| | Demo mode (default, github.io) | Live mode |
|---|---|---|
| Data | bundled sample fixtures | real VT/GTI lookups |
| Parsing | client-side regex | regex + optional Claude smart-parse |
| API key | none (never in the browser) | held by the **proxy** only |
| Enable | nothing to do | set a proxy URL in **Settings** (or `VITE_API_BASE_URL`) |

The **same** github.io bundle stays a demo by default; pointing it at your own
proxy (in the in-app Settings, persisted to `localStorage`) switches it to live —
no rebuild needed.

## Security model (read this)

- The **VT API key lives only on the proxy** (env / GitHub Secrets), never in the
  web bundle or in client requests.
- The github.io login is an **intentionally soft, client-side gate** with a shared
  credential. Passwords are stored as **PBKDF2 hashes** (no plaintext), but anyone
  can read static code — so this is obfuscation-grade, not real access control.
  The real protections are the proxy's **access token** (`/api/*`) and **admin
  token** (`/api/admin/*`), plus a CORS allowlist.
- Never commit plaintext passwords or tokens. `users.json` holds hashes only;
  tokens come from the proxy environment / GitHub Secrets.

## Repository layout

```
shared/            @vteeee/shared — defang/classify/extract, VT links + normalizer, PBKDF2
web/               @vteeee/web — Vite + React static SPA (Demo + Live), login + admin
proxy/shared-handler  @vteeee/proxy-core — rate limiting, enrich streaming, Claude parse, store
proxy/node         @vteeee/proxy-node — Express adapter (local / self-host)
proxy/cloudflare   @vteeee/proxy-cloudflare — Worker adapter (recommended deploy) + wrangler.toml
.github/workflows  ci.yml · pages.yml · proxy-deploy.yml
```

## Quick start (demo, no keys)

```bash
pnpm install
pnpm dev          # http://localhost:5173
```

Sign in with a demo credential (`admin / REDACTED` or `analyst / REDACTED`),
click **Load sample → Parse → Enrich N selected**. Everything is sample data.

## Live mode locally (real VT lookups)

```bash
cp proxy/node/.dev.vars.example proxy/node/.dev.vars   # fill in VT_API_KEY, ACCESS_TOKEN, ADMIN_TOKEN
pnpm proxy        # Express proxy on http://localhost:8787
```

Then in the web app's **Settings**: set **Proxy base URL** = `http://localhost:8787`
and the **Access token** to your `ACCESS_TOKEN`. The mode pill flips to **LIVE**.

(Free VT tier is ~4 req/min, 500/day — keep RPM low. Reserved/private indicators
and never-analyzed 404s are handled without burning quota.)

## Deploy

### Web → GitHub Pages (demo)

1. Repo **Settings → Pages → Source = GitHub Actions**.
2. Push to `main` → `pages.yml` builds with `VITE_BASE=/vteeee/` and deploys.
   (If your repo isn't named `vteeee`, change `VITE_BASE` in `pages.yml`.)

### Proxy → Cloudflare Workers (recommended)

1. `cd proxy/cloudflare && pnpm exec wrangler kv namespace create VTEEEE_KV`, paste
   the id into `wrangler.toml`; set `ALLOWED_ORIGINS` to your `*.github.io` origin
   + `http://localhost:5173`.
2. Add repo secrets: `VT_API_KEY`, `ANTHROPIC_API_KEY` (optional), `ACCESS_TOKEN`,
   `ADMIN_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`.
3. Run the **Deploy Proxy (Cloudflare)** workflow (or `pnpm exec wrangler deploy`
   + `wrangler secret put ...`).

Self-hosting the Node proxy instead is fine — it's the same core and gives strict
global rate limiting (a single Worker isolate's limiter isn't globally shared).

## Auth & management

- **Roles:** `viewer` (search) and `admin` (search + **Manage**).
- **Admin → Users & permissions:** add/remove users, change role, reset password
  (hashes generated in-browser), **export/import `users.json`**. Commit the exported
  `users.json` to share the baseline with the team.
- **Admin → Credentials & settings:** rotate the admin token, edit proxy URL / rate
  limits, export/import `settings.json`; in live mode **push/pull** users + settings
  to the proxy store (KV/D1) for live team sharing.

## Defang / parsing

The regex engine refangs `[.] (.) [dot] (dot) hxxp hxxps fxp [://] [:] [@] (at) \.`,
strips wrappers/quotes/markdown/trailing punctuation, classifies IPv4/IPv6/domain/
URL/MD5/SHA1/SHA256, punycodes IDNs, dedupes, and flags private/RFC1918 + reserved
(`.test/.example/...`) so they're excluded from enrichment by default. For messy
report prose, **Smart parse** (Claude `claude-haiku-4-5`, live mode) improves recall;
its output is always re-validated by the same regex classifier.

## Scripts

```bash
pnpm dev          # web dev server (demo)
pnpm proxy        # node proxy (live, local)
pnpm build        # build web (set VITE_BASE for Pages)
pnpm test         # shared unit tests
pnpm -r test      # all unit tests (shared, proxy-core, web)
pnpm -r typecheck # typecheck everything
```

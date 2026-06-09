# vteeee — infographic source (English, for NotebookLM)

> Generate an infographic from this. Use SHORT phrases (not long sentences) so the
> text stays crisp. Spell these EXACTLY: MD5, SHA-1, SHA-256, IPv4, IPv6, URL, NDJSON,
> PBKDF2, VirusTotal, GTI. Chalkboard look — palette at the bottom.

## Title
**vteeee — bulk IOC search that dramatically speeds up CTI triage.**
Subtitle: Clean, classify, and enrich thousands of indicators safely — in one paste.

## The problem → the solution
- **BEFORE (slow):** defanged IOCs + one-by-one lookups. e.g. `1[.]1[.]1[.]1`, `hxxps://malware[.]com`. Manual and tedious.
- **AFTER (fast):** vteeee auto-refangs and bulk-enriches. e.g. `1.1.1.1`, `https://malware.com`. One step.

## 5-step pipeline (input → real-time analysis)
1. **Input & cleanse** — paste / drag-drop / CSV / report text; de-duplicate; exclude private IPs.
2. **Auto refang** — `1[.]2[.]3[.]4` → `1.2.3.4`.
3. **Classify** — IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256.
4. **Secure bulk lookup** — vteeee → secure proxy → VirusTotal / GTI. The API key stays on the proxy.
5. **Real-time triage** — results stream as NDJSON; sortable table; detail panel + VirusTotal deep links.

## Demo vs Live (secure key handling)
- **Typical approach (risky):** API key in the browser → leak risk.
- **vteeee:** key lives only on the proxy; CORS handled; access/admin tokens.

## Key stats (big callouts)
- **7** IOC types: IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256.
- **10+** defang styles auto-reversed (brackets, hxxp, spaces, [dot]).
- **PBKDF2** hashing, **200,000** iterations (SHA-256); role-based access (admin / user).
- **45** automated tests; strict TypeScript.
- **NDJSON** streaming — rows appear as they resolve.

## Data you get per indicator
Verdict (malicious / suspicious / harmless), detection ratio, reputation, GTI verdict / severity / threat score, country, ASN, AS owner, registrar, categories, file type / size / hashes, threat label, tags.

## Palette
chalkboard green `#1f2a24`, chalk-mint `#74d3b1`, off-white `#e9e7d6`, alert red `#ff6f86`, safe green `#86d98f`.

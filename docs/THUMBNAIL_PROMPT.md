# Thumbnail / hero image — ChatGPT (image) prompts

Paste one of these into ChatGPT (image generation). Save the result as
`docs/assets/og-image.png` and either swap it into the README hero or upload it as the
repo's **Social preview** (GitHub → Settings → General → Social preview).

> 画像生成は英語プロンプトの方が安定します。文字は崩れやすいので、**文字は最小限**にして
> ロゴ/タグラインは後からSVG/READMEで載せるのが安全です（下に「文字なし版」もあります）。

---

## 1) Main hero / OG image (16:9, with minimal text)

```
A modern, professional hero banner for a cybersecurity / threat-intelligence web app
called "vteeee — bulk IOC search". Chalkboard aesthetic: deep dark-green chalkboard
background (#1f2a24) with a very subtle chalk-dust texture and a faint top-right light glow.

Composition (clean, lots of breathing room, flat vector / minimal line-art style):
- Left: a stylized magnifying glass scanning a vertical list of "indicators of compromise"
  rendered as short monospace chips — a few shown defanged (e.g. "1[.]1[.]1[.]1",
  "hxxps://…") with a soft arrow turning them into clean, highlighted entries.
- Right: a rounded-square emblem containing a bold chalk-mint check/"v" mark.
- A couple of small status pills: one red "malicious", one green "harmless".

Color palette: chalkboard green #1f2a24 / #243029, chalk-mint accent #74d3b1,
off-white chalk text #e9e7d6, alert red #ff6f86, safe green #86d98f.
Style: crisp flat vector, subtle chalk-line texture, soft shadows, high contrast, elegant,
not cluttered, enterprise-grade. 16:9, 1280x640. Leave the lower-left relatively empty so a
title can be overlaid later. Avoid photorealism, avoid stock-photo people, avoid heavy gradients.
Render any text crisply and spelled exactly; if unsure, omit text rather than misspell.
```

## 2) Square app icon / favicon (1:1)

```
A minimal app icon on a rounded square. Deep chalkboard-green tile (#1f2a24), and a single
bold chalk-mint "v" check-mark (#74d3b1) with a small off-white dot beneath it, like a
hand-drawn chalk tick. Flat vector, crisp edges, subtle chalk texture, centered, generous
padding. 1024x1024, transparent or solid #1f2a24 background. No text.
```

## 3) Text-free background (overlay the title yourself)

```
Same chalkboard cybersecurity scene as the hero (magnifier scanning defanged indicator chips,
mint check emblem, red/green status pills) but WITH NO TEXT AND NO LETTERS anywhere — purely
iconographic. Deep green #1f2a24 background, chalk-mint #74d3b1 accents, off-white details.
Flat vector, subtle chalk texture, 1280x640, clean negative space at center-left for a title overlay.
```

---

### Tips
- Generate #1 first; if the text looks off, use #3 and add the wordmark in the README/Canva.
- For the GitHub **Social preview**, 1280×640 (or 1200×630) is ideal.
- Keep contrast high — the mint `#74d3b1` on dark green `#1f2a24` matches the live app and `banner.svg`.

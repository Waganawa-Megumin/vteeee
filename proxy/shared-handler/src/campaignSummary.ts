import { fallbackSummary, type CampaignDigest } from '@vteeee/shared';
import { resolveModel } from './parse';
import type { ProxyEnv } from './types';

const SYSTEM = `あなたはCTIアナリスト向けの要約担当です。攻撃キャンペーンの集計データ(JSON)を受け取り、
「電光掲示板」に流す1行のキーメッセージ（日本語）を書いてください。

【最重要・厳守】
- 与えられたJSONの集計値と変化「だけ」に基づく。JSONに無い事柄は一切書かない。
- キャンペーン名(name)は単なるラベル。名前の語感から用途・意図・攻撃の性質・「活動が継続中」等の状況を推測・創作してはならない（例: 名前に"デコイ"とあっても囮作戦と決めつけない）。
- 攻撃者の目的・標的業種・進行状況・帰属・推奨対応など、データに無い項目は書かない。数値・種別(byType)・国(topCountries)・CVE(topCves)・情報推移(recentChanges)といった、JSONに実在する事実のみを述べる。
- 該当データが無い/0の項目は無理に触れず省略する。誇張しない。
- 総数・件数を「IoC」という語で表現しない（標的側は資産・情報でありIoCとは限らない）。「対象N件」「計N件」等の中立的な言い方にする。

【体裁】
- 1〜2文、最大180字程度。マークダウンや箇条書きは使わない。プレーンテキスト1行。
- 電光掲示板らしく、各要素の頭にデータに対応した絵文字を必ず付ける（📊件数=iocCount(「IoC」とは呼ばない) / 🔴悪性=malicious / 🟠疑わしい=suspicious / ⚠️CVE=topCves・distinctCves / 🌍国=topCountries / 🧩種別=byType / 📈増加・📉減少=recentChanges）。全体で3〜6個。無関係な絵文字の乱用や顔文字は避ける。
- 区切りには「 · 」や「｜」を使う。出力はキーメッセージ本文のみ。前置き・後置き・引用符・「以下」などのメタ発話は書かない。`;

/**
 * Turn a campaign digest into a one-line key message via Claude. Falls back to a deterministic
 * summary when no ANTHROPIC_API_KEY is set or the call fails — so the marquee is never empty.
 * Reuses parse.ts's resolveModel (Opus is refused → cheap Haiku default).
 */
export async function summarizeCampaign(
  digest: CampaignDigest,
  env: ProxyEnv,
): Promise<{ text: string; model?: string }> {
  if (!env.anthropicApiKey) return { text: fallbackSummary(digest) };
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': env.anthropicApiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: resolveModel(env.claudeModel),
        max_tokens: 400,
        temperature: 0.3,
        system: [{ type: 'text', text: SYSTEM, cache_control: { type: 'ephemeral' } }],
        messages: [{ role: 'user', content: JSON.stringify(digest).slice(0, 20_000) }],
      }),
    });
    if (!res.ok) return { text: fallbackSummary(digest) };
    const json = (await res.json()) as { model?: string; content?: Array<{ type: string; text?: string }> };
    const text = (json.content ?? [])
      .filter((c) => c.type === 'text')
      .map((c) => c.text ?? '')
      .join('')
      .trim();
    return text ? { text, model: json.model } : { text: fallbackSummary(digest) };
  } catch {
    return { text: fallbackSummary(digest) };
  }
}

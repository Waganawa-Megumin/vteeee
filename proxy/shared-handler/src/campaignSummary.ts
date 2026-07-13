import { fallbackSummary, type CampaignDigest } from '@vteeee/shared';
import { resolveModel } from './parse';
import type { ProxyEnv } from './types';

const SYSTEM = `あなたはCTIアナリスト向けの要約担当です。攻撃キャンペーンの集計データ(JSON)を受け取り、
「電光掲示板」に流す1行のキーメッセージ（日本語）を書いてください。
- 現在の脅威状況（規模・悪性度・主要国・主要CVE）と、直近のエンリッチ変化（情報推移）を簡潔に統合する。
- 1〜2文、最大180字程度。マークダウンや箇条書きは使わない。プレーンテキスト1行。
- 電光掲示板らしく、各キー要素の頭に内容に合った絵文字を必ず付ける（例: 🌐インフラ / 🔴悪性 / 🟠疑わしい / ⚠️CVE露出 / 📈増加 / 📉減少 / 🌍主要国 / 🎯標的 / 🛡️推奨対応）。全体で3〜6個程度、視認性を高める。無関係な絵文字の乱用や顔文字は避け、事実ベースで誇張しない。
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

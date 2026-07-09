import { fallbackSummary, type CampaignDigest } from '@vteeee/shared';
import { resolveModel } from './parse';
import type { ProxyEnv } from './types';

const SYSTEM = `あなたはCTIアナリスト向けの要約担当です。攻撃キャンペーンの集計データ(JSON)を受け取り、
「電光掲示板」に流す1行のキーメッセージ（日本語）を書いてください。
- 現在の脅威状況（規模・悪性度・主要国・主要CVE）と、直近のエンリッチ変化（情報推移）を簡潔に統合する。
- 1〜2文、最大180字程度。マークダウンや箇条書きは使わない。プレーンテキスト1行。
- 絵文字はごく控えめに（0〜2個まで）。誇張せず事実ベースで。
- 出力はキーメッセージ本文のみ。前置き・後置き・引用符・「以下」などのメタ発話は書かない。`;

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

import { resolveModel } from './parse';
import type { ProxyEnv } from './types';

// A CTI-analyst prompt that demands context-based INSIGHT (attribution hypotheses w/ confidence, infra
// clustering, TTP inference, trends from the timeline) — not a data dump. Facts vs. analysis kept distinct.
const ASSESS_SYSTEM = `あなたは経験豊富なCTI（サイバー脅威インテリジェンス）アナリストです。攻撃キャンペーンの集計・各IOCのエンリッチ情報・時系列変化(JSON)を受け取り、「現時点でのキャンペーン評価レポート」を日本語のMarkdownで作成してください。単なるデータの羅列・整理ではなく、コンテキストに基づく分析的Insightを提供すること。

先頭に必ず1行で \`TLP:<レベル>\`（入力の tlp を使用）を記載。続けて以下の見出し構成で記述する:

## エグゼクティブサマリ
今この瞬間に何が起きていて、なぜ重要か（リスク/ビジネス観点）。3〜5行。

## キャンペーン概観
規模・攻撃側/標的側の構成・活動期間・主要な観測事実。

## インフラ分析
攻撃側インフラの特徴（ホスティング/ASN/組織/地理の傾向、共通点、クラスタリングの示唆、クラウド悪用やbulletproof hostingの兆候など）。

## TTPs / 手口
観測ポート・CVE・稼働サービスから推測される手口。可能なら MITRE ATT&CK 技術ID（例 T1190）を付す。根拠を示し、断定は避ける。

## アトリビューション評価
既知の脅威アクター/マルウェアファミリとの関連の仮説。**確度（高/中/低）を明示**し、支持する根拠と反証・代替仮説も述べる。不明なら「不明」と明記。

## 変化・トレンド（情報推移）
時系列変化から読み取れる、活動の活発化/沈静化、インフラの入れ替わり、悪性度・リスクの上昇/低下など。

## リスク評価
標的組織にとっての脅威度と切迫度。TLPの取り扱いを尊重。

## 推奨アクション
優先度付きで具体的に（検知/ブロック/ハンティングクエリの方向性/深掘り調査対象など）。

## インテリジェンスギャップ
不足している情報、次に収集すべきデータ・ピボット先。

ルール:
- 【対象を特定して書く】観測事実（開放ポート・稼働サービス・CVE・悪性判定・地理/ASN・悪性挙動など）は、必ず**どのIOCか具体値を明記**する。集約値だけで終えない。悪い例:「3389が開いていた」。良い例:「3389/RDP が \`203.0.113.5\` で開放（AS### · 米国）」「\`CVE-2024-XXXX\` は \`198.51.100.9\`」「C2疑いは \`evil.example.com\`」。該当が複数あれば代表例を数件挙げ、必要に応じて表(Markdown table: IOC | 事実 | 補足)で整理する。入力の attack/target 配列（各IOCの value・ports・cves・org 等）を根拠に使う。
- 入力に analystNote（アナリストの背景メモ・コンテキスト）があれば、その内容を評価に反映する（背景・意図・既知情報として尊重。空／無ければ無視）。
- 入力に admiralty（Admiralty Code: 情報源の信頼性A–F＋情報の確度1–6）があれば、評価全体の確信度の表現に反映する（例: C3ならば断定を避け仮説として提示）。
- 事実（データに存在）と推測（分析）を明確に区別する。推測には確度を添える。
- データに無い事実（IOC値・CVE・アクター名など）を捏造しない。引用するIOC/CVEは入力データのものだけ。
- 簡潔かつ分析的に。箇条書き・表を適宜使う。出力はレポート本文(Markdown)のみ。`;

type ClaudeMsg = { role: 'user' | 'assistant'; content: string };
interface ClaudeReply {
  ok: boolean;
  text: string;
  stop?: string;
  model?: string;
  status?: number;
  errText?: string;
}

async function callClaude(env: ProxyEnv, messages: ClaudeMsg[], maxTokens: number): Promise<ClaudeReply> {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': env.anthropicApiKey!,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: resolveModel(env.claudeModel),
      max_tokens: maxTokens,
      temperature: 0.4,
      system: [{ type: 'text', text: ASSESS_SYSTEM, cache_control: { type: 'ephemeral' } }],
      messages,
    }),
  });
  if (!res.ok) return { ok: false, text: '', status: res.status, errText: (await res.text()).slice(0, 200) };
  const json = (await res.json()) as {
    model?: string;
    stop_reason?: string;
    content?: Array<{ type: string; text?: string }>;
  };
  const text = (json.content ?? [])
    .filter((c) => c.type === 'text')
    .map((c) => c.text ?? '')
    .join('');
  return { ok: true, text, stop: json.stop_reason, model: json.model };
}

/**
 * Generate a Claude CTI assessment report from a rich campaign digest. Requires ANTHROPIC_API_KEY;
 * returns an error string (not a fabricated report) when Claude is unavailable. To keep the report
 * COMPLETE, if a response is cut off at max_tokens we continue it (assistant-prefill) up to a couple of
 * rounds and concatenate, so the analyst gets the whole report instead of one that stops mid-section.
 */
export async function assessCampaign(
  digest: unknown,
  env: ProxyEnv,
): Promise<{ text: string; model?: string; error?: string; truncated?: boolean }> {
  if (!env.anthropicApiKey) {
    return {
      text: '',
      error:
        'このプロキシに ANTHROPIC_API_KEY が未設定のため、CTIアセスメントレポートは生成できません（管理者に登録を依頼してください）。',
    };
  }
  const user = JSON.stringify(digest).slice(0, 60_000);
  try {
    let acc = '';
    let model: string | undefined;
    let stop = 'max_tokens';
    for (let round = 0; round < 3 && stop === 'max_tokens'; round++) {
      const messages: ClaudeMsg[] =
        round === 0
          ? [{ role: 'user', content: user }]
          : [
              { role: 'user', content: user },
              // Prefill the partial so the model continues the SAME report (no trailing whitespace).
              { role: 'assistant', content: acc.replace(/\s+$/, '') },
            ];
      const r = await callClaude(env, messages, 4096);
      if (!r.ok) {
        // Hard API error: return whatever we have so far, with the error surfaced.
        return acc.trim()
          ? { text: acc.trim(), model, truncated: true }
          : { text: '', error: `Claude API error ${r.status}: ${r.errText}` };
      }
      model = r.model ?? model;
      acc += r.text;
      stop = r.stop ?? 'end_turn';
    }
    const text = acc.trim();
    return text ? { text, model, truncated: stop === 'max_tokens' } : { text: '', error: 'Claude から空のレスポンスが返りました。' };
  } catch {
    return { text: '', error: 'Claude 呼び出しに失敗しました（ネットワーク）。' };
  }
}

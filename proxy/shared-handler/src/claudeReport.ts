import { resolveModel } from './parse';
import type { ProxyEnv } from './types';

// Shared engine for Claude-written Markdown reports (CTI assessment, IP-Mon monitoring report, …):
// one system prompt + a JSON digest → a complete Markdown report. To keep long reports COMPLETE, a
// response cut off at max_tokens is continued via assistant-prefill up to a couple of rounds and
// concatenated, so the analyst gets the whole report instead of one that stops mid-section.

export type ClaudeMsg = { role: 'user' | 'assistant'; content: string };

interface ClaudeReply {
  ok: boolean;
  text: string;
  stop?: string;
  model?: string;
  status?: number;
  errText?: string;
}

async function callClaude(env: ProxyEnv, system: string, messages: ClaudeMsg[], maxTokens: number): Promise<ClaudeReply> {
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
      system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
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
 * Generate a Claude Markdown report from `system` + a JSON `digest`. Requires ANTHROPIC_API_KEY;
 * returns an error string (not a fabricated report) when Claude is unavailable.
 */
export async function generateClaudeReport(
  system: string,
  digest: unknown,
  env: ProxyEnv,
  opts?: { maxUserChars?: number; missingKeyError?: string },
): Promise<{ text: string; model?: string; error?: string; truncated?: boolean }> {
  if (!env.anthropicApiKey) {
    return {
      text: '',
      error:
        opts?.missingKeyError ??
        'このプロキシに ANTHROPIC_API_KEY が未設定のため、レポートは生成できません（管理者に登録を依頼してください）。',
    };
  }
  try {
    // Inside the try so a bad digest (undefined / circular) surfaces as an error, never a thrown 500.
    const serialized = JSON.stringify(digest);
    if (!serialized) return { text: '', error: 'アセスメント対象のデータが空です。' };
    const user = serialized.slice(0, opts?.maxUserChars ?? 60_000);
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
      const r = await callClaude(env, system, messages, 4096);
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

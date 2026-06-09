import { extractIndicators, reclassify, type ParseResponse } from '@vteeee/shared';
import type { ProxyEnv } from './types';

const DEFAULT_MODEL = 'claude-haiku-4-5';

/**
 * Resolve the Claude model, refusing Opus so a misconfigured CLAUDE_MODEL can never
 * silently rack up expensive Opus usage. Empty / Opus -> the cheap default (Haiku).
 * An explicit non-Opus override (e.g. a Sonnet) is allowed.
 */
export function resolveModel(model?: string): string {
  if (!model || /opus/i.test(model)) return DEFAULT_MODEL;
  return model;
}

const SYSTEM_PROMPT = `You extract cyber threat indicators (IOCs) from analyst report text.
Return ONLY indicators that are IPv4, IPv6, domains, URLs, or file hashes (MD5/SHA1/SHA256).
Refang any defanged indicators: hxxp->http, [.]->., (dot)->., [:]->:, [@]->@, etc.
Do NOT invent indicators that are not present in the text.
Do NOT include private/internal RFC1918 IPs unless they are clearly an external IOC.
For each indicator emit {value, type, input(the original substring), confidence 0..1}.`;

const EMIT_TOOL = {
  name: 'emit_indicators',
  description: 'Emit the list of extracted indicators of compromise.',
  input_schema: {
    type: 'object',
    properties: {
      indicators: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            value: { type: 'string' },
            type: { type: 'string', enum: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'] },
            input: { type: 'string' },
            confidence: { type: 'number' },
          },
          required: ['value', 'type'],
        },
      },
    },
    required: ['indicators'],
  },
} as const;

interface ClaudeIndicator {
  value: string;
  input?: string;
  confidence?: number;
}

/**
 * Claude-assisted IOC extraction. Falls back to the deterministic regex extractor
 * when no ANTHROPIC_API_KEY is configured. The regex classifier is always re-run on
 * the output, so it remains the source of truth for typing/normalization.
 */
export async function smartParse(
  text: string,
  env: ProxyEnv,
  maxIndicators = 500,
): Promise<ParseResponse> {
  if (!env.anthropicApiKey) {
    return { indicators: extractIndicators(text).indicators.slice(0, maxIndicators) };
  }

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': env.anthropicApiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: resolveModel(env.claudeModel),
      max_tokens: 2048,
      temperature: 0,
      system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
      tools: [EMIT_TOOL],
      tool_choice: { type: 'tool', name: 'emit_indicators' },
      // Cap input length to bound per-call token cost.
      messages: [{ role: 'user', content: text.slice(0, 120_000) }],
    }),
  });

  if (!res.ok) {
    throw new Error(`Claude API error ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }

  const json = (await res.json()) as {
    model?: string;
    content?: Array<{ type: string; input?: { indicators?: ClaudeIndicator[] } }>;
    usage?: { input_tokens?: number; output_tokens?: number };
  };
  const toolUse = json.content?.find((c) => c.type === 'tool_use');
  const raw = toolUse?.input?.indicators ?? [];

  const indicators = reclassify(
    raw.map((r) => ({ value: r.value, input: r.input ?? r.value, confidence: r.confidence })),
  ).slice(0, maxIndicators);

  return {
    indicators,
    model: json.model,
    usage: {
      input_tokens: json.usage?.input_tokens ?? 0,
      output_tokens: json.usage?.output_tokens ?? 0,
    },
  };
}

import { describe, it, expect } from 'vitest';
import { resolveModel } from '../parse';

describe('resolveModel (never auto-uses Opus)', () => {
  it('defaults to the cheap Haiku model', () => {
    expect(resolveModel()).toBe('claude-haiku-4-5');
    expect(resolveModel('')).toBe('claude-haiku-4-5');
  });

  it('refuses any Opus model and falls back to Haiku', () => {
    expect(resolveModel('claude-opus-4-8')).toBe('claude-haiku-4-5');
    expect(resolveModel('claude-3-opus-20240229')).toBe('claude-haiku-4-5');
    expect(resolveModel('CLAUDE-OPUS-whatever')).toBe('claude-haiku-4-5');
  });

  it('allows an explicit non-Opus override (e.g. Sonnet)', () => {
    expect(resolveModel('claude-sonnet-4-6')).toBe('claude-sonnet-4-6');
  });
});

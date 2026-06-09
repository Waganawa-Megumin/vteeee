import { constantTimeEqual } from './hash';

/** Extract a bearer token from an Authorization header value. */
export function parseBearer(header: string | null | undefined): string | null {
  if (!header) return null;
  return header.startsWith('Bearer ') ? header.slice(7) : header;
}

/**
 * Verify a provided token against the expected secret in constant time.
 * Returns false when no secret is configured (fail closed).
 */
export function checkToken(provided: string | null | undefined, expected: string | undefined): boolean {
  if (!expected || !provided) return false;
  return constantTimeEqual(provided, expected);
}

/** Generate a random opaque token (e.g. for client session ids). */
export function randomToken(bytes = 24): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * PBKDF2 password hashing using the Web Crypto API (available in browsers and
 * Node 20+). Used for the (intentionally soft) client-side login gate and for
 * generating user records in the admin UI. Plaintext passwords are never stored.
 */

const ENC = new TextEncoder();

export const DEFAULT_ITERATIONS = 200_000;

function toB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

export function randomSaltB64(bytes = 16): string {
  const salt = new Uint8Array(bytes);
  crypto.getRandomValues(salt);
  return toB64(salt.buffer);
}

/** Derive a 256-bit key from a password + salt and return it base64-encoded. */
export async function derive(password: string, saltB64: string, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations },
    key,
    256,
  );
  return toB64(bits);
}

export interface PasswordRecord {
  salt: string;
  hash: string;
  iterations: number;
}

export async function hashPassword(
  password: string,
  iterations = DEFAULT_ITERATIONS,
): Promise<PasswordRecord> {
  const salt = randomSaltB64();
  const hash = await derive(password, salt, iterations);
  return { salt, hash, iterations };
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function verifyPassword(password: string, rec: PasswordRecord): Promise<boolean> {
  const h = await derive(password, rec.salt, rec.iterations);
  return constantTimeEqual(h, rec.hash);
}

import { randomToken, verifyPassword, type Session, type UserRecord } from '@vteeee/shared';

const SS_KEY = 'vteeee.session';
const TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

export async function authenticate(
  users: UserRecord[],
  username: string,
  password: string,
): Promise<Session | null> {
  const u = users.find((x) => x.username.toLowerCase() === username.trim().toLowerCase());
  if (!u) return null;
  const ok = await verifyPassword(password, u);
  if (!ok) return null;
  return {
    username: u.username,
    role: u.role,
    token: randomToken(),
    expiresAt: Date.now() + TTL_MS,
  };
}

export function persistSession(s: Session | null): void {
  if (s) sessionStorage.setItem(SS_KEY, JSON.stringify(s));
  else sessionStorage.removeItem(SS_KEY);
}

export function restoreSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(SS_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as Session;
    if (s.expiresAt < Date.now()) {
      sessionStorage.removeItem(SS_KEY);
      return null;
    }
    return s;
  } catch {
    return null;
  }
}

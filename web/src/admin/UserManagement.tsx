import { useRef, useState } from 'react';
import { hashPassword, type Role, type UserRecord, type UsersConfig } from '@vteeee/shared';
import { useStore } from '../state/store';
import { exportUsers, importJsonFile } from './configIO';

export function UserManagement() {
  const users = useStore((s) => s.users);
  const applyUsers = useStore((s) => s.applyUsers);
  const me = useStore((s) => s.session?.username);
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [msg, setMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function add() {
    if (!u.trim() || !p) return setMsg('Username and password are required.');
    if (users.some((x) => x.username.toLowerCase() === u.trim().toLowerCase()))
      return setMsg('That username already exists.');
    const rec = await hashPassword(p);
    const nu: UserRecord = { username: u.trim(), ...rec, role };
    applyUsers([...users, nu]);
    setU('');
    setP('');
    setMsg(`Added ${nu.username}.`);
  }

  async function resetPw(username: string) {
    const np = window.prompt(`New password for ${username}:`);
    if (!np) return;
    const rec = await hashPassword(np);
    applyUsers(users.map((x) => (x.username === username ? { ...x, ...rec } : x)));
    setMsg(`Password reset for ${username}.`);
  }

  function changeRole(username: string, r: Role) {
    applyUsers(users.map((x) => (x.username === username ? { ...x, role: r } : x)));
  }

  function remove(username: string) {
    if (username === me) return setMsg("You can't remove the account you're signed in as.");
    if (!window.confirm(`Remove user "${username}"?`)) return;
    applyUsers(users.filter((x) => x.username !== username));
  }

  async function onImport(f: File | undefined) {
    if (!f) return;
    try {
      const cfg = await importJsonFile<UsersConfig>(f);
      if (!Array.isArray(cfg.users)) return setMsg('Invalid users.json (no users array).');
      applyUsers(cfg.users);
      setMsg(`Imported ${cfg.users.length} users.`);
    } catch {
      setMsg('Could not parse that file as JSON.');
    }
  }

  return (
    <div className="admin-section">
      <h3>Users &amp; permissions</h3>

      <table className="admin-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {users.map((x) => (
            <tr key={x.username}>
              <td className="mono">
                {x.username} {x.username === me && <span className="you">(you)</span>}
              </td>
              <td>
                <select value={x.role} onChange={(e) => changeRole(x.username, e.target.value as Role)}>
                  <option value="viewer">viewer</option>
                  <option value="admin">admin</option>
                </select>
              </td>
              <td className="admin-actions">
                <button className="btn btn-sm" onClick={() => void resetPw(x.username)}>
                  Reset password
                </button>
                <button className="btn btn-sm btn-danger" onClick={() => remove(x.username)}>
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="add-user">
        <input placeholder="username" value={u} onChange={(e) => setU(e.target.value)} />
        <input
          placeholder="password"
          type="password"
          value={p}
          onChange={(e) => setP(e.target.value)}
        />
        <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
          <option value="viewer">viewer</option>
          <option value="admin">admin</option>
        </select>
        <button className="btn btn-primary" onClick={() => void add()}>
          Add user
        </button>
      </div>

      <div className="admin-io">
        <button className="btn btn-sm" onClick={() => exportUsers(users)}>
          Export users.json
        </button>
        <button className="btn btn-sm" onClick={() => fileRef.current?.click()}>
          Import users.json
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          hidden
          onChange={(e) => void onImport(e.target.files?.[0])}
        />
        <span className="hint">
          Passwords are stored as PBKDF2 hashes only. Commit the exported users.json to the repo to
          share the baseline with the team.
        </span>
      </div>

      {msg && <div className="admin-msg">{msg}</div>}
    </div>
  );
}

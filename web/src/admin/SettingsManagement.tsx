import { useRef, useState } from 'react';
import type { AppSettings, SettingsConfig } from '@vteeee/shared';
import { useStore } from '../state/store';
import { exportSettings, importJsonFile } from './configIO';
import { AdminClient } from '../api/adminClient';
import { SecretField } from '../components/SecretField';

export function SettingsManagement() {
  const settings = useStore((s) => s.settings);
  const applySettings = useStore((s) => s.applySettings);
  const applyUsers = useStore((s) => s.applyUsers);
  const [draft, setDraft] = useState<AppSettings>(settings);
  const [msg, setMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const live = !!draft.proxyBaseUrl;

  function up<K extends keyof AppSettings>(k: K, v: AppSettings[K]) {
    setDraft((d) => ({ ...d, [k]: v }));
  }

  async function onImport(f: File | undefined) {
    if (!f) return;
    try {
      const cfg = await importJsonFile<SettingsConfig>(f);
      const merged = { ...draft, ...cfg.settings };
      setDraft(merged);
      applySettings(merged);
      setMsg('Imported settings.json.');
    } catch {
      setMsg('Could not parse that file as JSON.');
    }
  }

  async function pushProxy() {
    try {
      const c = new AdminClient(draft);
      await c.putSettings(draft);
      await c.putUsers(useStore.getState().users);
      setMsg('Pushed users + settings to the proxy.');
    } catch (e) {
      setMsg('Push failed: ' + (e as Error).message);
    }
  }

  async function pullProxy() {
    try {
      const users = await new AdminClient(draft).getUsers();
      applyUsers(users);
      setMsg(`Pulled ${users.length} users from the proxy.`);
    } catch (e) {
      setMsg('Pull failed: ' + (e as Error).message);
    }
  }

  return (
    <div className="admin-section">
      <h3>Credentials &amp; settings</h3>

      <label className="fld">
        Admin token (required to write users/settings + see all history)
        <SecretField
          value={draft.adminToken ?? ''}
          onChange={(v) => up('adminToken', v || null)}
        />
      </label>
      <label className="fld">
        Proxy base URL
        <input
          placeholder="https://your-proxy.workers.dev (empty = demo)"
          value={draft.proxyBaseUrl ?? ''}
          onChange={(e) => up('proxyBaseUrl', e.target.value.trim() || null)}
        />
      </label>
      <label className="fld">
        Allowed-origins note (documentation)
        <input
          value={draft.allowedOriginsNote ?? ''}
          onChange={(e) => up('allowedOriginsNote', e.target.value)}
        />
      </label>

      <div className="admin-io">
        <button className="btn btn-primary" onClick={() => { applySettings(draft); setMsg('Saved.'); }}>
          Save settings
        </button>
        <button className="btn btn-sm" onClick={() => exportSettings(draft)}>
          Export settings.json
        </button>
        <button className="btn btn-sm" onClick={() => fileRef.current?.click()}>
          Import settings.json
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          hidden
          onChange={(e) => void onImport(e.target.files?.[0])}
        />
      </div>

      {live && (
        <div className="admin-io">
          <button className="btn btn-sm" onClick={() => void pushProxy()}>
            Push to proxy (KV/D1)
          </button>
          <button className="btn btn-sm" onClick={() => void pullProxy()}>
            Pull from proxy
          </button>
          <span className="hint">Shares users + settings across the team via the proxy store.</span>
        </div>
      )}

      <p className="hint">
        Tokens are stored only in this browser (localStorage + a durable IndexedDB mirror so they
        survive eviction), never in exported JSON or the committed baseline — the public repo and
        Pages bundle are world-readable, so a real token must never be committed there. Use Show/Copy
        above to carry a token to another device. On the proxy, tokens come from GitHub Secrets.
      </p>

      {msg && <div className="admin-msg">{msg}</div>}
    </div>
  );
}

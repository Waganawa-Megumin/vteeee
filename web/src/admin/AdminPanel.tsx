import { useState } from 'react';
import { useStore } from '../state/store';
import { UserManagement } from './UserManagement';
import { SettingsManagement } from './SettingsManagement';

export function AdminPanel() {
  const setView = useStore((s) => s.setView);
  const [tab, setTab] = useState<'users' | 'settings'>('users');

  return (
    <div className="admin">
      <div className="admin-head">
        <h2>Management</h2>
        <div className="tabs">
          <button className={`tab${tab === 'users' ? ' active' : ''}`} onClick={() => setTab('users')}>
            Users &amp; permissions
          </button>
          <button
            className={`tab${tab === 'settings' ? ' active' : ''}`}
            onClick={() => setTab('settings')}
          >
            Credentials &amp; settings
          </button>
        </div>
        <div className="spacer" />
        <button className="btn" onClick={() => setView('app')}>
          ← Back to search
        </button>
      </div>
      {tab === 'users' ? <UserManagement /> : <SettingsManagement />}
    </div>
  );
}

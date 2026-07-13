import { useEffect, useState } from 'react';
import { useStore, type NotifKind } from '../state/store';

const KIND_ICON: Record<NotifKind, string> = {
  capture: '🎣',
  reenrich: '⟳',
  scan: '📡',
  info: '•',
};

const MUTE_KEY = 'vteeee.notifyMuted';

function relTime(at: number): string {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 45) return 'たった今';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}分前`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}時間前`;
  const d = Math.round(h / 24);
  return `${d}日前`;
}
/** Absolute local date-time WITH the timezone (e.g. "2026/07/13 15:30 JST"), so log times are unambiguous. */
function absTime(at: number): string {
  try {
    return new Date(at).toLocaleString(undefined, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return new Date(at).toLocaleString();
  }
}

/**
 * 🔔 Notification bell + log. Background completions (bulk re-enrich, bulk 魚拓, individual scans /
 * captures) are recorded in the store's notification log so a finish is never lost just because you
 * navigated away. Clicking the bell shows the log; from here you can also enable / mute OS notifications.
 */
export function NotifBell() {
  const notifications = useStore((s) => s.notifications);
  const markRead = useStore((s) => s.markNotifsRead);
  const clear = useStore((s) => s.clearNotifs);
  const [open, setOpen] = useState(false);
  const [perm, setPerm] = useState<NotificationPermission | 'unsupported'>(() =>
    typeof Notification !== 'undefined' ? Notification.permission : 'unsupported',
  );
  const [muted, setMuted] = useState<boolean>(() => {
    try {
      return localStorage.getItem(MUTE_KEY) === '1';
    } catch {
      return false;
    }
  });

  const unread = notifications.filter((n) => !n.read).length;

  // Opening the panel clears the unread badge.
  useEffect(() => {
    if (open && unread > 0) markRead();
  }, [open, unread, markRead]);

  function setMutePref(next: boolean) {
    setMuted(next);
    try {
      localStorage.setItem(MUTE_KEY, next ? '1' : '0');
    } catch {
      /* ignore */
    }
  }

  async function enableOsNotify() {
    if (typeof Notification === 'undefined') return;
    try {
      const p = await Notification.requestPermission();
      setPerm(p);
      if (p === 'granted') setMutePref(false);
    } catch {
      /* ignore */
    }
  }

  // The icon reflects the OS-notification ON/OFF state (granted && not muted), so toggling mute in the
  // menu flips 🔔↔🔕. The unread count rides on the badge, independent of on/off.
  const osOn = perm === 'granted' && !muted;
  const bellIcon = osOn ? '🔔' : '🔕';
  const cls = `notif-bell${unread > 0 ? ' has-unread' : ''}${osOn ? ' notif-on' : ''}`;
  const bellTitle = osOn
    ? '通知ログ · OS通知: オン（クリックでログを開く）'
    : perm === 'denied'
      ? '通知ログ · OS通知はブラウザでブロック中（クリックでログを開く）'
      : '通知ログ · OS通知: オフ（クリックでログを開き、有効化できます）';

  return (
    <div className="notif-bell-wrap">
      <button
        className={`btn btn-sm ${cls}`}
        onClick={() => setOpen((o) => !o)}
        title={bellTitle}
        aria-label={`Notifications${unread > 0 ? ` (${unread} unread)` : ''} — OS notifications ${osOn ? 'on' : 'off'}`}
      >
        {bellIcon}
        {unread > 0 && <span className="notif-badge">{unread > 9 ? '9+' : unread}</span>}
      </button>
      {open && (
        <>
          <div className="scan-tracker-backdrop" onClick={() => setOpen(false)} />
          <div className="notif-menu" role="menu">
            <div className="stm-head">
              <span>通知ログ</span>
              {notifications.length > 0 && (
                <button className="btn btn-ghost btn-sm" onClick={clear}>
                  クリア
                </button>
              )}
            </div>

            <div className="notif-perm">
              {perm === 'unsupported' ? (
                <span className="hint">このブラウザはOS通知に非対応です（ログは記録されます）。</span>
              ) : perm === 'denied' ? (
                <span className="hint">⚠ OS通知はブロックされています。ブラウザの設定で許可してください（ログは記録されます）。</span>
              ) : perm === 'default' ? (
                <button className="btn btn-ghost btn-sm" onClick={() => void enableOsNotify()}>
                  🔔 ブラウザ通知を有効化
                </button>
              ) : (
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => setMutePref(!muted)}
                  title="OS通知のオン/オフ（ログは常に記録されます）"
                >
                  {muted ? '🔕 OS通知: オフ（クリックでオン）' : '🔔 OS通知: オン（クリックでミュート）'}
                </button>
              )}
            </div>

            {notifications.length === 0 ? (
              <div className="notif-empty">通知はまだありません。</div>
            ) : (
              <div className="notif-list">
                {notifications.map((n) => (
                  <div key={n.id} className={`notif-row kind-${n.kind}${n.read ? '' : ' unread'}`}>
                    <span className="notif-icon" aria-hidden>
                      {KIND_ICON[n.kind] ?? '•'}
                    </span>
                    <div className="notif-main">
                      <div className="notif-title">{n.title}</div>
                      {n.body && <div className="notif-body">{n.body}</div>}
                      <div className="notif-time">
                        🕒 {absTime(n.at)} <span className="notif-rel">· {relTime(n.at)}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

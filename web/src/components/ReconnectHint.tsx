import { useStore } from '../state/store';

/**
 * Shown on the shared-store screens (CP-Mon / IP-Mon) ONLY when a proxy URL is configured but the
 * access token is missing — the exact state after a browser "clear site data / clear cache" wipes
 * localStorage AND IndexedDB. The baked proxy URL (VITE_API_BASE_URL) is restored from the build, but
 * the token is a secret that can't be baked in, so it's gone — the shared fetches then 401 and the
 * screen renders empty. Without this note that reads as "my data disappeared"; in reality the team's
 * campaigns/monitors are safe on the proxy and come straight back the moment the token is re-entered.
 *
 * The existing demo hint in the page intros is gated on `mode === 'demo'` (proxyBaseUrl === null), so it
 * does NOT fire in this post-clear state (proxyBaseUrl restored → mode is 'live'). This fills that gap.
 * Render it inside each screen's empty branch so it never nags a user who already has working data.
 */
export function ReconnectHint() {
  const proxyBaseUrl = useStore((s) => s.settings.proxyBaseUrl);
  const accessToken = useStore((s) => s.settings.accessToken);
  if (!proxyBaseUrl || accessToken) return null;
  return (
    <div className="reconnect-hint" role="note">
      <span className="rh-icon" aria-hidden>
        🔌
      </span>
      <div className="rh-body">
        <b>共有サーバに未接続です。</b>チームの監視データは<b>サーバ側に保存されていて消えていません</b>。
        右上の <b>Settings</b> で <b>アクセストークン</b> を入力（プロキシURLは自動で入っています）すると、この端末に復元されます。
        <span className="rh-sub">
          ブラウザの「サイトデータ削除／キャッシュクリア」でトークンが消えると、この状態になります。データ自体は安全です。
          別端末が設定済みなら <b>Settings →「Connect another device」→ 🔗 Copy setup link</b> のリンクをこの端末で開くだけでも復元できます。
        </span>
      </div>
    </div>
  );
}

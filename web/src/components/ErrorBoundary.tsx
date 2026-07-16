import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

/**
 * Top-level safety net: a render/runtime error anywhere below would otherwise white-screen the whole
 * SPA with nothing but a blank page. This catches it and shows a recoverable fallback (reload, or copy
 * the error to report it) instead — the app stays usable after a hiccup in one view. Data is untouched
 * (it lives in localStorage / the shared store), so a reload comes back to the same state.
 */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surface it in the console for debugging; no external logging (analyst tool — nothing leaves the browser).
    console.error('vteeee crashed in render:', error, info.componentStack);
  }

  private reset = (): void => this.setState({ error: null });

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="errbound" role="alert">
        <div className="errbound-card">
          <h1 className="errbound-title">⚠ 画面の描画でエラーが発生しました</h1>
          <p className="errbound-lead">
            データは失われていません（この端末のローカル／共有ストアに保存済み）。再読み込みで元の状態に戻ります。
            <br />
            <span className="en">Something broke while rendering. Your data is safe — reload to recover.</span>
          </p>
          <div className="errbound-actions">
            <button className="btn btn-primary" onClick={() => window.location.reload()}>
              🔄 再読み込み / Reload
            </button>
            <button className="btn" onClick={this.reset}>
              ↩ この画面を再表示 / Try again
            </button>
          </div>
          <details className="errbound-detail">
            <summary>エラー詳細 / Details</summary>
            <pre>{error.stack || error.message}</pre>
          </details>
        </div>
      </div>
    );
  }
}

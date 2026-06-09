import { useState } from 'react';

/**
 * A password-style input with reveal and copy controls, so the operator can
 * always see and copy the secret that is actually stored (tokens etc.) — handy
 * when re-entering it on another device.
 */
export function SecretField({
  value,
  onChange,
  placeholder,
  autoComplete = 'off',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoComplete?: string;
}) {
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard may be blocked; ignore */
    }
  }

  return (
    <div className="secret-field">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        placeholder={placeholder}
        autoComplete={autoComplete}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        type="button"
        className="btn btn-sm"
        onClick={() => setShow((s) => !s)}
        title={show ? 'Hide' : 'Show'}
        aria-label={show ? 'Hide secret' : 'Show secret'}
      >
        {show ? 'Hide' : 'Show'}
      </button>
      <button
        type="button"
        className="btn btn-sm"
        onClick={() => void copy()}
        disabled={!value}
        title="Copy to clipboard"
        aria-label="Copy secret"
      >
        {copied ? '✓' : 'Copy'}
      </button>
    </div>
  );
}

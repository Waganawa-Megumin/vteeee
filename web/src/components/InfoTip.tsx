import { type ReactNode } from 'react';

/** A small "?" badge that reveals a bilingual (JA/EN) explanation on hover/focus. */
export function InfoTip({ ja, en }: { ja: ReactNode; en: ReactNode }) {
  return (
    <span className="infotip" tabIndex={0} role="note">
      ?
      <span className="infotip-bubble" role="tooltip">
        <span className="it-ja">{ja}</span>
        <span className="it-en">{en}</span>
      </span>
    </span>
  );
}

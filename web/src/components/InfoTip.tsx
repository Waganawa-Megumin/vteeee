import { useRef, useState, type ReactNode } from 'react';

const BUBBLE_W = 280;
const MARGIN = 8;

/**
 * A small "?" badge that reveals a bilingual (JA/EN) explanation on hover/focus.
 * The bubble is fixed-positioned and clamped to the viewport so it never gets
 * clipped at a screen edge; it flips above/below depending on available room.
 */
export function InfoTip({ ja, en }: { ja: ReactNode; en: ReactNode }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; above: boolean } | null>(null);

  function show() {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.max(
      MARGIN,
      Math.min(r.left + r.width / 2 - BUBBLE_W / 2, window.innerWidth - BUBBLE_W - MARGIN),
    );
    const above = r.top > 140 + MARGIN; // enough room above? else drop below
    const top = above ? r.top - MARGIN : r.bottom + MARGIN;
    setPos({ left, top, above });
  }

  return (
    <span
      ref={ref}
      className="infotip"
      tabIndex={0}
      role="note"
      onMouseEnter={show}
      onMouseLeave={() => setPos(null)}
      onFocus={show}
      onBlur={() => setPos(null)}
    >
      ?
      {pos && (
        <span
          className="infotip-bubble"
          role="tooltip"
          style={{
            left: pos.left,
            top: pos.top,
            transform: pos.above ? 'translateY(-100%)' : 'none',
          }}
        >
          <span className="it-ja">{ja}</span>
          <span className="it-en">{en}</span>
        </span>
      )}
    </span>
  );
}

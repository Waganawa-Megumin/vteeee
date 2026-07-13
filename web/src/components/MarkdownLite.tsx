import { Fragment, type ReactNode } from 'react';

/** Inline: split a line into **bold**, `code`, and [text](url) spans (safe — React nodes, no innerHTML). */
function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /\*\*(.+?)\*\*|`([^`]+?)`|\[([^\]]+)\]\(([^)\s]+)\)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1] != null) out.push(<strong key={k++}>{m[1]}</strong>);
    else if (m[2] != null) out.push(<code key={k++}>{m[2]}</code>);
    else
      out.push(
        <a key={k++} href={m[4]} target="_blank" rel="noreferrer">
          {m[3]}
        </a>,
      );
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function splitRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|')) s = s.slice(0, -1);
  return s.split('|').map((c) => c.trim());
}
const isSepRow = (line: string) => /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line.trim());
const isPipeRow = (line: string) => line.includes('|') && line.trim().length > 0;

/**
 * Minimal, dependency-free Markdown renderer for the CTI assessment report: headings, bullet/numbered
 * lists, GFM tables, blockquotes, horizontal rules, bold/code/link inline, paragraphs. Renders to JSX
 * (no dangerouslySetInnerHTML → no XSS surface).
 */
export function MarkdownLite({ text, className }: { text: string; className?: string }) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  let para: string[] = [];
  let quote: string[] = [];
  let key = 0;

  const flushList = () => {
    if (!list) return;
    const items = list.items.map((it, i) => <li key={i}>{inline(it)}</li>);
    blocks.push(list.ordered ? <ol key={key++}>{items}</ol> : <ul key={key++}>{items}</ul>);
    list = null;
  };
  const flushPara = () => {
    if (!para.length) return;
    blocks.push(<p key={key++}>{inline(para.join(' '))}</p>);
    para = [];
  };
  const flushQuote = () => {
    if (!quote.length) return;
    blocks.push(<blockquote key={key++}>{inline(quote.join(' '))}</blockquote>);
    quote = [];
  };
  const flushAll = () => {
    flushPara();
    flushList();
    flushQuote();
  };

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx].trimEnd();
    const t = line.trim();

    // GFM table: a pipe row immediately followed by a |---|---| separator row.
    if (isPipeRow(line) && idx + 1 < lines.length && isSepRow(lines[idx + 1])) {
      flushAll();
      const header = splitRow(line);
      idx += 2; // consume header + separator
      const rows: string[][] = [];
      while (idx < lines.length && isPipeRow(lines[idx]) && !isSepRow(lines[idx])) {
        rows.push(splitRow(lines[idx]));
        idx++;
      }
      idx--; // the for-loop's ++ lands us on the first non-table line
      blocks.push(
        <div key={key++} className="md-table-wrap">
          <table className="md-table">
            <thead>
              <tr>
                {header.map((h, i) => (
                  <th key={i}>{inline(h)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri}>
                  {header.map((_h, ci) => (
                    <td key={ci}>{inline(r[ci] ?? '')}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    const hr = /^(-{3,}|\*{3,}|_{3,})$/.test(t);
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    const bullet = /^[-*+]\s+(.*)$/.exec(line);
    const num = /^\d+[.)]\s+(.*)$/.exec(line);
    const bq = /^>\s?(.*)$/.exec(line);

    if (hr) {
      flushAll();
      blocks.push(<hr key={key++} />);
    } else if (h) {
      flushAll();
      const level = Math.min(h[1].length, 4);
      const Tag = `h${level + 2}` as 'h3' | 'h4' | 'h5' | 'h6';
      blocks.push(<Tag key={key++}>{inline(h[2])}</Tag>);
    } else if (bq) {
      flushPara();
      flushList();
      quote.push(bq[1]);
    } else if (bullet) {
      flushPara();
      flushQuote();
      if (!list || list.ordered) {
        flushList();
        list = { ordered: false, items: [] };
      }
      list.items.push(bullet[1]);
    } else if (num) {
      flushPara();
      flushQuote();
      if (!list || !list.ordered) {
        flushList();
        list = { ordered: true, items: [] };
      }
      list.items.push(num[1]);
    } else if (!t) {
      flushAll();
    } else {
      flushList();
      flushQuote();
      para.push(line);
    }
  }
  flushAll();

  return (
    <div className={className}>
      {blocks.map((b, i) => (
        <Fragment key={i}>{b}</Fragment>
      ))}
    </div>
  );
}

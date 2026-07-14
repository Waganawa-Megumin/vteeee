import type { TlpLevel } from '@vteeee/shared';

// Export helpers for a CTI assessment report (Markdown): copy the text, copy a PNG image of the
// rendered report, or build a real-text (selectable) PDF laid out from the same Markdown.

const MARGIN = 40;
type RGB = [number, number, number];
const INK: RGB = [32, 34, 30];
const MUTED: RGB = [112, 116, 106];
const ACCENT: RGB = [31, 138, 115];
const LINE: RGB = [208, 206, 194];
const TLP_COLOR: Record<TlpLevel, RGB> = {
  CLEAR: [70, 70, 70],
  GREEN: [18, 138, 18],
  AMBER: [224, 168, 0],
  'AMBER+STRICT': [224, 168, 0],
  RED: [204, 0, 0],
};

function stripInline(s: string): string {
  return s
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/`([^`]+?)`/g, '$1')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '$1 ($2)');
}
function splitRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|')) s = s.slice(0, -1);
  return s.split('|').map((c) => c.trim());
}
const isSepRow = (line: string) => /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line.trim());
const isPipeRow = (line: string) => line.includes('|') && line.trim().length > 0;

/** Copy plain text to the clipboard. */
export async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

/** Copy a PNG image of a rendered element (e.g. the report) to the clipboard. */
export async function copyElementImage(el: HTMLElement): Promise<void> {
  const { toBlob } = await import('html-to-image');
  const bg = getComputedStyle(document.documentElement).getPropertyValue('--bg2').trim() || '#ffffff';
  const blob = await toBlob(el, { backgroundColor: bg, pixelRatio: 2, cacheBust: true });
  if (!blob) throw new Error('image render failed');
  await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
}

export interface AssessmentPdfMeta {
  title: string;
  tlp?: TlpLevel;
  model?: string;
  at?: number;
  /** Report kind shown in the header/footer (defaults to "CTI assessment"). e.g. "IP-Mon monitoring". */
  kind?: string;
}

/** Build a paginated, selectable-text PDF from the report Markdown (headings, lists, tables, quotes). */
export async function exportAssessmentPdf(markdown: string, meta: AssessmentPdfMeta): Promise<void> {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const contentW = pageW - MARGIN * 2;
  const contentBottom = pageH - MARGIN - 20;
  let y = MARGIN;
  const color = (c: RGB) => doc.setTextColor(c[0], c[1], c[2]);
  const ensure = (space: number) => {
    if (y + space > contentBottom) {
      doc.addPage();
      y = MARGIN;
    }
  };

  // Header + title.
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  color(ACCENT);
  doc.text('vteeee', MARGIN, y + 6);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  color(MUTED);
  const kind = meta.kind ?? 'CTI assessment';
  doc.text(`${kind} report`, MARGIN + 58, y + 6);
  doc.text(`Generated ${new Date(meta.at ?? Date.now()).toLocaleString()}`, pageW - MARGIN, y + 6, { align: 'right' });
  y += 14;
  doc.setDrawColor(LINE[0], LINE[1], LINE[2]);
  doc.line(MARGIN, y, pageW - MARGIN, y);
  y += 16;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  color(INK);
  for (const tl of doc.splitTextToSize(meta.title, contentW) as string[]) {
    ensure(19);
    doc.text(tl, MARGIN, y + 13);
    y += 19;
  }
  if (meta.model) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    color(MUTED);
    doc.text(meta.model, MARGIN, y + 6);
    y += 14;
  }
  y += 4;

  const para = (txt: string, indent = 0) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    color(INK);
    for (const l of doc.splitTextToSize(txt, contentW - indent) as string[]) {
      ensure(14);
      doc.text(l, MARGIN + indent, y + 10);
      y += 14;
    }
  };
  const heading = (txt: string, level: number) => {
    ensure(26);
    y += 8;
    doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2]);
    doc.rect(MARGIN, y - 8, 3, 12, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(level <= 2 ? 12 : 10.5);
    color(INK);
    doc.text(txt, MARGIN + 9, y + 2);
    y += 14;
  };
  const table = (header: string[], rows: string[][]) => {
    const cols = Math.max(1, header.length);
    const cw = contentW / cols;
    const cellLines = (cells: string[]) => cells.map((c) => doc.splitTextToSize(stripInline(c ?? ''), cw - 8) as string[]);
    const rowH = (cells: string[]) => Math.max(1, ...cellLines(cells).map((a) => a.length)) * 12 + 6;
    const drawRow = (cells: string[], bold: boolean) => {
      const h = rowH(cells);
      ensure(h);
      doc.setDrawColor(LINE[0], LINE[1], LINE[2]);
      const cls = cellLines(cells);
      for (let i = 0; i < cols; i++) {
        const x = MARGIN + i * cw;
        doc.rect(x, y, cw, h);
        doc.setFont('helvetica', bold ? 'bold' : 'normal');
        doc.setFontSize(9);
        color(bold ? ACCENT : INK);
        (cls[i] || ['']).forEach((l, li) => doc.text(l, x + 4, y + 12 + li * 12));
      }
      y += h;
    };
    y += 6;
    drawRow(header, true);
    for (const r of rows) drawRow(header.map((_, i) => r[i] ?? ''), false);
    y += 6;
  };

  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx].trimEnd();
    const t = raw.trim();
    if (isPipeRow(raw) && idx + 1 < lines.length && isSepRow(lines[idx + 1])) {
      const header = splitRow(raw);
      idx += 2;
      const rows: string[][] = [];
      while (idx < lines.length && isPipeRow(lines[idx]) && !isSepRow(lines[idx])) {
        rows.push(splitRow(lines[idx]));
        idx++;
      }
      idx--;
      table(header, rows);
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(raw);
    const bullet = /^[-*+]\s+(.*)$/.exec(raw);
    const num = /^\d+[.)]\s+(.*)$/.exec(raw);
    const hr = /^(-{3,}|\*{3,}|_{3,})$/.test(t);
    const bq = /^>\s?(.*)$/.exec(raw);
    if (hr) {
      ensure(12);
      doc.setDrawColor(LINE[0], LINE[1], LINE[2]);
      doc.line(MARGIN, y + 4, pageW - MARGIN, y + 4);
      y += 12;
    } else if (h) {
      heading(stripInline(h[2]), h[1].length);
    } else if (bq) {
      para(`“${stripInline(bq[1])}”`, 12);
    } else if (bullet) {
      para(`•  ${stripInline(bullet[1])}`, 10);
    } else if (num) {
      para(stripInline(raw), 10);
    } else if (!t) {
      y += 4;
    } else {
      para(stripInline(raw), 0);
    }
  }

  // Per-page TLP marking + footer.
  const pages = doc.getNumberOfPages();
  const tlp: TlpLevel = meta.tlp && TLP_COLOR[meta.tlp] ? meta.tlp : 'AMBER';
  const tlpLabel = `TLP:${tlp}`;
  const tlpColor = TLP_COLOR[tlp];
  const year = new Date().getFullYear();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    const bw = doc.getTextWidth(tlpLabel) + 12;
    const bx = pageW - MARGIN - bw;
    doc.setFillColor(0, 0, 0);
    doc.rect(bx, 18, bw, 15, 'F');
    doc.setTextColor(tlpColor[0], tlpColor[1], tlpColor[2]);
    doc.text(tlpLabel, bx + 6, 29);
    const fy = pageH - MARGIN + 8;
    doc.setDrawColor(LINE[0], LINE[1], LINE[2]);
    doc.line(MARGIN, fy - 13, pageW - MARGIN, fy - 13);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    color(MUTED);
    doc.text(`vteeee — ${kind}`, MARGIN, fy);
    doc.text(`${tlpLabel} · © ${year} vteeee`, pageW / 2, fy, { align: 'center' });
    doc.text(`${i} / ${pages}`, pageW - MARGIN, fy, { align: 'right' });
  }

  const name = meta.title.replace(/[^a-z0-9._-]+/gi, '_').slice(0, 50) || 'campaign';
  doc.save(`vteeee-assessment-${name}.pdf`);
}

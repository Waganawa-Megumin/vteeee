import type { NormalizedResult, TlpLevel } from '@vteeee/shared';
import { resultToText } from './detailText';

/**
 * Build a real-text (selectable / searchable) PDF report for one indicator — NOT a screenshot.
 * The body is rendered from the same report as "Copy text" (so they stay in sync), laid out as
 * headings + key/value fields with page breaks; the MaxMind map is embedded as an image (a map is
 * inherently visual) right after its section. Every page carries a TLP marking (top) and a
 * vteeee + copyright footer (bottom).
 */

const MARGIN = 40;
const VAL_X = MARGIN + 128; // where field values start
type RGB = [number, number, number];
const INK: RGB = [32, 34, 30];
const MUTED: RGB = [112, 116, 106];
const ACCENT: RGB = [31, 138, 115];
const LINE: RGB = [208, 206, 194];

/** TLP label colours (FIRST TLP 2.0), tuned for legibility on a white page. */
const TLP_COLOR: Record<TlpLevel, RGB> = {
  CLEAR: [70, 70, 70],
  GREEN: [18, 138, 18],
  AMBER: [224, 168, 0],
  'AMBER+STRICT': [224, 168, 0],
  RED: [204, 0, 0],
};

/** A rasterized map to embed (captured from the detail panel), with its source CSS size. */
export interface PdfMapImage {
  dataUrl: string;
  w: number;
  h: number;
}

export interface PdfOptions {
  map?: PdfMapImage;
  tlp?: TlpLevel;
}

/** Labels whose values read better in a monospace font (IDs, addresses, coordinates). */
const MONO_LABEL =
  /^(MD5|SHA-1|SHA-256|Network|IPs?|Coordinates|Open ports|Name servers|Mail servers|Reverse DNS|SPF|Related (IPs|domains|hashes))$/;

export async function exportResultPdf(r: NormalizedResult, opts: PdfOptions = {}): Promise<void> {
  const { map } = opts;
  const tlp: TlpLevel = opts.tlp && TLP_COLOR[opts.tlp] ? opts.tlp : 'AMBER';
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const contentBottom = pageH - MARGIN - 20; // keep clear of the footer
  let y = MARGIN;

  const color = (c: RGB) => doc.setTextColor(c[0], c[1], c[2]);

  const ensure = (space: number) => {
    if (y + space > contentBottom) {
      doc.addPage();
      y = MARGIN;
    }
  };

  const heading = (txt: string) => {
    ensure(28);
    y += 10;
    doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2]);
    doc.rect(MARGIN, y - 8, 3, 12, 'F'); // small accent bar
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    color(INK);
    doc.text(txt, MARGIN + 9, y + 2);
    y += 16;
  };

  const field = (label: string, value: string, mono: boolean) => {
    if (!value) return;
    doc.setFont(mono ? 'courier' : 'helvetica', 'normal');
    doc.setFontSize(9.5);
    const lines = doc.splitTextToSize(value, pageW - MARGIN - VAL_X) as string[];
    const lineH = 12.5;
    for (let i = 0; i < lines.length; i++) {
      ensure(lineH);
      if (i === 0 && label) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        color(MUTED);
        doc.text(label, MARGIN, y + 9);
      }
      doc.setFont(mono ? 'courier' : 'helvetica', 'normal');
      doc.setFontSize(9.5);
      color(INK);
      doc.text(lines[i], label ? VAL_X : MARGIN, y + 9);
      y += lineH;
    }
    y += 3;
  };

  // Clickable "Open in VirusTotal" with an underline for affordance (no ↗ — jsPDF's standard
  // font can't encode it, so it rendered as garbage).
  const vtLink = () => {
    const text = 'Open in VirusTotal';
    ensure(22);
    y += 4;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    color(ACCENT);
    const tw = doc.getTextWidth(text);
    doc.textWithLink(text, MARGIN, y + 9, { url: r.links.gui });
    doc.setDrawColor(ACCENT[0], ACCENT[1], ACCENT[2]);
    doc.line(MARGIN, y + 11, MARGIN + tw, y + 11);
    y += 18;
  };

  const placeMap = () => {
    if (!map) return;
    let w = pageW - MARGIN * 2;
    let h = w * (map.h / map.w);
    const maxH = 230;
    if (h > maxH) {
      h = maxH;
      w = h * (map.w / map.h);
    }
    ensure(h + 22);
    doc.addImage(map.dataUrl, 'PNG', MARGIN, y + 4, w, h);
    y += h + 8;
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    color(MUTED);
    doc.text('Approximate area — see the accuracy radius above; not a precise address.', MARGIN, y + 6);
    y += 14;
  };

  // --- Header / brand (page 1) ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  color(ACCENT);
  doc.text('vteeee', MARGIN, y + 6);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  color(MUTED);
  doc.text('bulk IOC enrichment report', MARGIN + 58, y + 6);
  const now = new Date();
  doc.text(`Generated ${now.toLocaleString()}`, pageW - MARGIN, y + 6, { align: 'right' });
  y += 14;
  doc.setDrawColor(LINE[0], LINE[1], LINE[2]);
  doc.line(MARGIN, y, pageW - MARGIN, y);
  y += 16;

  // --- Indicator title ---
  doc.setFont('courier', 'bold');
  doc.setFontSize(15);
  color(INK);
  for (const tl of doc.splitTextToSize(r.value, pageW - MARGIN * 2) as string[]) {
    ensure(19);
    doc.text(tl, MARGIN, y + 13);
    y += 19;
  }
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  color(MUTED);
  doc.text(
    `${r.type}  ·  ${r.verdict}${r.status !== 'success' ? `  ·  ${r.status}` : ''}`,
    MARGIN,
    y + 6,
  );
  y += 14;

  // --- Body, parsed from the same text report as "Copy text" ---
  heading('VirusTotal / GTI');
  let section = 'VirusTotal';
  let mapPlaced = false;
  let vtLinkDone = false;
  for (const line of resultToText(r).split('\n')) {
    if (line.startsWith('# ')) continue; // title already rendered above
    if (line.startsWith('VirusTotal: ')) continue; // link is rendered in the VT section instead
    if (line.startsWith('## ')) {
      // Leaving the VirusTotal section → put its "Open in VirusTotal" link here (with the VT data).
      if (!vtLinkDone) {
        vtLink();
        vtLinkDone = true;
      }
      if (section === 'MaxMind GeoIP' && map && !mapPlaced) {
        placeMap();
        mapPlaced = true;
      }
      section = line.slice(3).trim();
      heading(section);
      continue;
    }
    if (line.trim() === '') {
      y += 3;
      continue;
    }
    const idx = line.indexOf(': ');
    if (idx > 0) {
      field(line.slice(0, idx), line.slice(idx + 2), MONO_LABEL.test(line.slice(0, idx)));
    } else {
      field('', line, false);
    }
  }
  if (!vtLinkDone) vtLink(); // no other sections at all → link at the end of the VT section
  if (section === 'MaxMind GeoIP' && map && !mapPlaced) placeMap();

  // --- Per-page markings: TLP (top-right) + vteeee/copyright footer (bottom) ---
  const pages = doc.getNumberOfPages();
  const year = now.getFullYear();
  const tlpLabel = `TLP:${tlp}`;
  const tlpColor = TLP_COLOR[tlp];
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    // TLP marking, top-right: colored label on a black chip.
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    const bw = doc.getTextWidth(tlpLabel) + 12;
    const bx = pageW - MARGIN - bw;
    doc.setFillColor(0, 0, 0);
    doc.rect(bx, 18, bw, 15, 'F');
    doc.setTextColor(tlpColor[0], tlpColor[1], tlpColor[2]);
    doc.text(tlpLabel, bx + 6, 29);
    // Footer.
    const fy = pageH - MARGIN + 8;
    doc.setDrawColor(LINE[0], LINE[1], LINE[2]);
    doc.line(MARGIN, fy - 13, pageW - MARGIN, fy - 13);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    color(MUTED);
    doc.text('vteeee — bulk IOC enrichment', MARGIN, fy);
    doc.text(`${tlpLabel} · © ${year} vteeee`, pageW / 2, fy, { align: 'center' });
    doc.text(`${i} / ${pages}`, pageW - MARGIN, fy, { align: 'right' });
  }

  const name = r.value.replace(/[^a-z0-9._-]+/gi, '_').slice(0, 60) || 'indicator';
  doc.save(`vteeee-${name}.pdf`);
}

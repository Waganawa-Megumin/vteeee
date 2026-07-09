/** Tiny inline SVG sparkline for a numeric series over time (nulls treated as 0). */
export function Spark({
  values,
  w = 128,
  h = 30,
  className = 'ana-spark',
}: {
  values: (number | null)[];
  w?: number;
  h?: number;
  className?: string;
}) {
  const pad = 3;
  const nums = values.map((v) => (v == null ? 0 : v));
  const max = Math.max(1, ...nums);
  const min = Math.min(0, ...nums);
  const range = max - min || 1;
  const n = nums.length;
  const pt = (v: number, i: number): [number, number] => {
    const x = n <= 1 ? w / 2 : pad + (i / (n - 1)) * (w - 2 * pad);
    const y = pad + (1 - (v - min) / range) * (h - 2 * pad);
    return [x, y];
  };
  const line = nums.map((v, i) => pt(v, i).join(',')).join(' ');
  const [lx, ly] = pt(nums[n - 1] ?? 0, n - 1);
  return (
    <svg className={className} width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      {n > 1 && <polyline points={line} fill="none" stroke="currentColor" strokeWidth="1.5" />}
      <circle cx={lx} cy={ly} r="2.5" fill="currentColor" />
    </svg>
  );
}

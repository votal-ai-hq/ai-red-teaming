import { useMemo, useState } from "react";

export interface TrendPoint {
  date: string;
  score: number;
  vulns?: number;
  total?: number;
}

type RangeKey = "7d" | "30d" | "90d" | "all";

const RANGES: { key: RangeKey; label: string; days?: number }[] = [
  { key: "7d", label: "7D", days: 7 },
  { key: "30d", label: "30D", days: 30 },
  { key: "90d", label: "90D", days: 90 },
  { key: "all", label: "All" },
];

function inRange(iso: string, days?: number): boolean {
  if (!days) return true;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return true;
  return t >= Date.now() - days * 86400000;
}

function fmtTick(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function TrendChart({
  data,
  width = 640,
  height = 220,
}: {
  data: TrendPoint[];
  width?: number;
  height?: number;
}) {
  const [range, setRange] = useState<RangeKey>("30d");
  const [hover, setHover] = useState<number | null>(null);

  const filtered = useMemo(() => {
    const spec = RANGES.find((r) => r.key === range);
    const next = data.filter((d) => inRange(d.date, spec?.days));
    return next.length > 0 ? next : data;
  }, [data, range]);

  const pad = { top: 16, right: 12, bottom: 36, left: 36 };
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const minY = 0;
  const maxY = 100;
  const n = Math.max(filtered.length - 1, 1);

  const points = filtered.map((d, i) => {
    const x = pad.left + (i / n) * chartW;
    const y = pad.top + chartH - ((d.score - minY) / (maxY - minY)) * chartH;
    return { x, y, ...d };
  });

  const polyline = points.map((p) => `${p.x},${p.y}`).join(" ");
  const area =
    points.length > 0
      ? `${points[0].x},${pad.top + chartH} ${polyline} ${points[points.length - 1].x},${pad.top + chartH}`
      : "";

  const yTicks = [0, 25, 50, 75, 100];
  const xTickCount = Math.min(5, points.length);
  const xTicks =
    points.length <= 1
      ? points
      : Array.from({ length: xTickCount }, (_, i) => {
          const idx = Math.round((i / (xTickCount - 1)) * (points.length - 1));
          return points[idx];
        });

  const latest = filtered[filtered.length - 1];
  const first = filtered[0];
  const delta =
    latest && first ? latest.score - first.score : 0;

  const hovered = hover != null ? points[hover] : null;

  return (
    <div>
      <div className="flex items-center justify-between mb-2 gap-2">
        <div className="flex items-baseline gap-2 min-w-0">
          <span className="text-lg font-semibold tabular-nums text-foreground">
            {latest ? latest.score : "—"}
          </span>
          <span className="text-[11px] text-muted-foreground">latest score</span>
          {filtered.length > 1 && (
            <span
              className={`text-[11px] font-medium tabular-nums ${
                delta > 0
                  ? "text-emerald-600 dark:text-emerald-400"
                  : delta < 0
                    ? "text-red-600 dark:text-red-400"
                    : "text-muted-foreground"
              }`}
            >
              {delta > 0 ? "+" : ""}
              {delta}
            </span>
          )}
        </div>
        <div className="inline-flex rounded-lg border border-border bg-muted/40 p-0.5">
          {RANGES.map((r) => (
            <button
              key={r.key}
              type="button"
              onClick={() => setRange(r.key)}
              className={`px-2 py-0.5 text-[11px] font-medium rounded-md ${
                range === r.key
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {points.length === 0 ? (
        <p className="text-xs text-muted-foreground py-8 text-center">
          Need 2+ scans to plot a trend
        </p>
      ) : (
        <svg
          width="100%"
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label="Security score over time"
          onMouseLeave={() => setHover(null)}
        >
          {yTicks.map((tick) => {
            const y = pad.top + chartH - (tick / 100) * chartH;
            return (
              <g key={tick}>
                <line
                  x1={pad.left}
                  x2={pad.left + chartW}
                  y1={y}
                  y2={y}
                  stroke="currentColor"
                  className="text-border"
                  strokeDasharray={tick === 0 || tick === 100 ? undefined : "3 3"}
                />
                <text
                  x={pad.left - 6}
                  y={y + 3}
                  textAnchor="end"
                  className="fill-muted-foreground"
                  fontSize={10}
                >
                  {tick}
                </text>
              </g>
            );
          })}

          <polygon points={area} fill="#6366f1" fillOpacity={0.12} />
          <polyline
            points={polyline}
            fill="none"
            stroke="#6366f1"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {points.map((p, i) => (
            <circle
              key={`${p.date}-${i}`}
              cx={p.x}
              cy={p.y}
              r={hover === i ? 4.5 : 3}
              fill="#6366f1"
              onMouseEnter={() => setHover(i)}
            />
          ))}

          {/* Wider hit targets for tooltips */}
          {points.map((p, i) => (
            <rect
              key={`hit-${i}`}
              x={p.x - chartW / Math.max(points.length, 1) / 2}
              y={pad.top}
              width={Math.max(chartW / Math.max(points.length, 1), 12)}
              height={chartH}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
            />
          ))}

          {xTicks.map((p, i) => (
            <text
              key={`x-${i}`}
              x={p.x}
              y={height - 10}
              textAnchor="middle"
              className="fill-muted-foreground"
              fontSize={10}
            >
              {fmtTick(p.date)}
            </text>
          ))}

          {hovered && (
            <g>
              <line
                x1={hovered.x}
                x2={hovered.x}
                y1={pad.top}
                y2={pad.top + chartH}
                stroke="#6366f1"
                strokeOpacity={0.35}
                strokeDasharray="3 3"
              />
              <rect
                x={Math.min(hovered.x + 8, width - 150)}
                y={Math.max(hovered.y - 48, 4)}
                width={140}
                height={44}
                rx={6}
                className="fill-background stroke-border"
                strokeWidth={1}
              />
              <text
                x={Math.min(hovered.x + 16, width - 142)}
                y={Math.max(hovered.y - 30, 20)}
                className="fill-foreground"
                fontSize={11}
                fontWeight={600}
              >
                Score {hovered.score}
              </text>
              <text
                x={Math.min(hovered.x + 16, width - 142)}
                y={Math.max(hovered.y - 14, 36)}
                className="fill-muted-foreground"
                fontSize={10}
              >
                {fmtTick(hovered.date)}
                {hovered.vulns != null ? ` · ${hovered.vulns} vulns` : ""}
              </text>
            </g>
          )}
        </svg>
      )}
      <div className="flex justify-between text-[10px] text-muted-foreground -mt-1">
        <span>Date</span>
        <span>Score (0–100)</span>
      </div>
    </div>
  );
}

export default TrendChart;

"use client";

import { useMemo } from "react";
import {
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import { quadrantColor } from "@/lib/format";
import type { Cve, Quadrant } from "@/lib/types";

interface Point {
  cveId: string;
  effortHours: number;
  priorityScore: number;
  quadrant: Quadrant;
}

const QUADRANTS: Quadrant[] = ["Quick win", "Plan it", "Fill-in", "Defer"];

function MatrixTooltip({ active, payload }: { active?: boolean; payload?: { payload?: Point }[] }) {
  if (!active || !payload?.length) return null;
  const point = payload[0]?.payload;
  if (!point) return null;
  return (
    <div className="card px-3 py-2">
      <div className="mono text-[11.5px] text-ink">{point.cveId}</div>
      <div className="mt-0.5 text-[11.5px] text-muted">
        Priority {point.priorityScore.toFixed(1)}/100 · {point.effortHours}h · {point.quadrant}
      </div>
    </div>
  );
}

export default function QuickWinsMatrix({
  cves,
  riskCut,
  effortCut,
  selectedId,
  onSelect,
}: {
  cves: Cve[];
  riskCut: number;
  effortCut: number;
  selectedId: string;
  onSelect: (cveId: string) => void;
}) {
  const points = useMemo<Point[]>(
    () =>
      cves.map((cve) => ({
        cveId: cve.cveId,
        effortHours: cve.effortHours,
        priorityScore: cve.priorityScore,
        quadrant: cve.quadrant,
      })),
    [cves],
  );

  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const cve of cves) out[cve.quadrant] = (out[cve.quadrant] ?? 0) + 1;
    return out;
  }, [cves]);

  return (
    <div className="px-4 pb-4 pt-2">
      <ResponsiveContainer width="100%" height={252}>
        <ScatterChart margin={{ top: 10, right: 14, bottom: 22, left: -14 }}>
          <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" />
          <XAxis
            type="number"
            dataKey="effortHours"
            domain={[0, 24]}
            ticks={[0, 4, 8, 12, 16, 20, 24]}
            tick={{ fontSize: 10, fill: "#5b6373", fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
            label={{
              value: "remediation effort (hours)",
              position: "insideBottom",
              offset: -14,
              fontSize: 10,
              fill: "#5b6373",
            }}
          />
          <YAxis
            type="number"
            dataKey="priorityScore"
            domain={[0, 100]}
            tick={{ fontSize: 10, fill: "#5b6373", fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
            width={48}
          />
          <ZAxis range={[46, 46]} />
          <ReferenceLine x={effortCut} stroke="#c9b98f" strokeDasharray="4 4" />
          <ReferenceLine y={riskCut} stroke="#c9b98f" strokeDasharray="4 4" />
          <Tooltip content={<MatrixTooltip />} cursor={{ strokeDasharray: "3 3" }} />
          <Scatter
            data={points}
            onClick={(data: unknown) => {
              const point = data as Point | undefined;
              if (point?.cveId) onSelect(point.cveId);
            }}
          >
            {points.map((point) => (
              <Cell
                key={point.cveId}
                fill={quadrantColor[point.quadrant]}
                fillOpacity={point.cveId === selectedId ? 1 : 0.62}
                stroke={point.cveId === selectedId ? "#0b192c" : "#fffdfa"}
                strokeWidth={point.cveId === selectedId ? 1.4 : 0.7}
              />
            ))}
          </Scatter>
        </ScatterChart>
      </ResponsiveContainer>

      <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-2.5">
          {QUADRANTS.map((quadrant) => (
            <span key={quadrant} className="flex items-center gap-1.5 text-[11px] text-muted">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: quadrantColor[quadrant] }}
                aria-hidden
              />
              {quadrant} <span className="mono text-[10px] text-[#9a9284]">{counts[quadrant] ?? 0}</span>
            </span>
          ))}
        </div>
        <span className="text-[10.5px] text-muted">dashed lines = cohort medians</span>
      </div>
    </div>
  );
}

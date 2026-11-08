"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { Severity } from "@/lib/types";

const SLICES: { key: Severity; label: string; color: string }[] = [
  { key: "CRITICAL", label: "Critical", color: "#9b111e" },
  { key: "HIGH", label: "High", color: "#b8860b" },
  { key: "MEDIUM", label: "Medium", color: "#dcc27a" },
  { key: "LOW", label: "Low", color: "#1b4d3e" },
  { key: "NONE", label: "None", color: "#b9b1a0" },
  { key: "UNSCORED", label: "Unscored", color: "#d9d2c3" },
];

export default function SeverityDonut({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const data = SLICES.map((s) => ({ name: s.label, value: counts[s.key] ?? 0, color: s.color })).filter(
    (d) => d.value > 0
  );

  return (
    <div className="flex flex-col items-center gap-3 px-4 pb-4 pt-2 sm:flex-row">
      <div className="relative h-[176px] w-[176px] shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={58}
              outerRadius={84}
              paddingAngle={1.5}
              stroke="#fffdfa"
              strokeWidth={2}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                borderRadius: 10,
                border: "1px solid rgba(212,175,55,0.35)",
                background: "#fffdfa",
                fontSize: 12,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display text-[26px] leading-none text-ink">{total}</span>
          <span className="mono mt-1 text-[9px] uppercase tracking-[0.14em] text-muted">CVEs</span>
        </div>
      </div>

      <ul className="w-full space-y-1.5">
        {data.map((d) => (
          <li key={d.name} className="flex items-center justify-between gap-2 text-[12px]">
            <span className="flex items-center gap-2 text-ink">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} aria-hidden />
              {d.name}
            </span>
            <span className="mono text-[11.5px] text-muted">
              {d.value}
              <span className="ml-1.5 text-[10px] text-[#a39a89]">
                {total ? Math.round((d.value / total) * 100) : 0}%
              </span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

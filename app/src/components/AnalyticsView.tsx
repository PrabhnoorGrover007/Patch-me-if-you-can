"use client";

import {
  Area,
  Bar,
  CartesianGrid,
  ComposedChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  BarChart,
  Legend,
} from "recharts";
import { formatMonth } from "@/lib/format";
import type { MonthExposure } from "@/lib/types";
import { Empty, PageHeader, Panel, StatCard } from "./ui";

export interface SeverityMonth {
  month: string;
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNSCORED: number;
}

const AXIS = {
  tick: { fontSize: 10, fill: "#5b6373", fontFamily: "var(--font-mono)" },
  axisLine: false as const,
  tickLine: false as const,
};

function ExposureTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { name?: string; value?: number; color?: string }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="card px-3 py-2 text-[12px]">
      <div className="mono text-[11px] text-ink">{label ? formatMonth(String(label)) : ""}</div>
      {payload.map((p) => (
        <div key={p.name} className="mt-0.5 flex items-center gap-2 text-muted">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: p.color }} />
          {p.name}: <span className="mono text-ink">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function AnalyticsView({
  exposure,
  severityByMonth,
  statusCounts,
  openRisk,
  cohortRisk,
  mttr,
  mttrSeries,
}: {
  exposure: MonthExposure[];
  severityByMonth: SeverityMonth[];
  statusCounts: { todo: number; in_progress: number; done: number };
  openRisk: number;
  cohortRisk: number;
  mttr: number | null;
  mttrSeries: { cveId: string; days: number }[];
}) {
  const queued = statusCounts.todo + statusCounts.in_progress + statusCounts.done;
  const coverage = cohortRisk ? Math.round((openRisk / cohortRisk) * 100) : 0;

  return (
    <div>
      <PageHeader
        eyebrow="Executive risk trends"
        title="Is the posture improving?"
        description="Two honest measures: how much risk is still sitting in the queue, and how long remediation actually takes. Both update as the team works the board."
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Mean time to remediate"
          value={mttr != null ? `${mttr.toFixed(1)}d` : "—"}
          hint={
            mttr != null
              ? `across ${statusCounts.done} completed ${statusCounts.done === 1 ? "card" : "cards"}`
              : "no completed cards yet"
          }
          tone="jade"
        />
        <StatCard
          label="Open risk in queue"
          value={openRisk}
          hint={`${coverage}% of the cohort's ${cohortRisk} risk points`}
          tone="crimson"
        />
        <StatCard label="Queued" value={queued} hint={`${statusCounts.todo} to do · ${statusCounts.in_progress} in progress`} />
        <StatCard label="Completed" value={statusCounts.done} hint="moved to Done on the board" tone="gold" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Panel
          eyebrow="Cohort · 2026"
          title="Open risk exposure by publish month"
          action={<span className="text-[11px] text-muted">cumulative, before remediation</span>}
        >
          <div className="px-4 pb-4 pt-3">
            <ResponsiveContainer width="100%" height={272}>
              <ComposedChart data={exposure} margin={{ top: 8, right: 6, bottom: 4, left: -18 }}>
                <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="month" tickFormatter={formatMonth} {...AXIS} />
                <YAxis yAxisId="risk" {...AXIS} width={54} />
                <YAxis yAxisId="count" orientation="right" {...AXIS} width={34} />
                <Tooltip content={<ExposureTooltip />} />
                <Bar
                  yAxisId="count"
                  dataKey="published"
                  name="Published that month"
                  fill="#e7dcc4"
                  radius={[3, 3, 0, 0]}
                  barSize={18}
                />
                <Area
                  yAxisId="risk"
                  type="monotone"
                  dataKey="openRisk"
                  name="Open risk"
                  stroke="#0b192c"
                  strokeWidth={2}
                  fill="rgba(11,25,44,0.07)"
                  dot={{ r: 2.5, fill: "#0b192c" }}
                />
              </ComposedChart>
            </ResponsiveContainer>
            <p className="mt-1 text-[11px] leading-snug text-muted">
              Risk keeps stacking because nothing is retired yet. Every card you move to Done removes its
              score from the queue.
            </p>
          </div>
        </Panel>

        <Panel eyebrow="Queue" title="Where the work sits">
          <div className="space-y-3 px-4 py-4">
            {[
              { label: "To do", value: statusCounts.todo, color: "#2c3e50" },
              { label: "In progress", value: statusCounts.in_progress, color: "#a45c00" },
              { label: "Done", value: statusCounts.done, color: "#1b4d3e" },
            ].map((row) => (
              <div key={row.label}>
                <div className="flex items-center justify-between text-[12px]">
                  <span className="text-ink">{row.label}</span>
                  <span className="mono text-muted">{row.value}</span>
                </div>
                <div className="mt-1 h-2 w-full overflow-hidden rounded-full bg-[#f1e9da]">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${queued ? Math.max(3, (row.value / queued) * 100) : 0}%`,
                      backgroundColor: row.color,
                    }}
                  />
                </div>
              </div>
            ))}
            {queued === 0 && (
              <p className="pt-2 text-[12px] leading-relaxed text-muted">
                Nothing queued. Add CVEs from the dashboard to make these numbers move.
              </p>
            )}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel eyebrow="Severity mix" title="Monthly severity distribution">
          <div className="px-4 pb-4 pt-3">
            <ResponsiveContainer width="100%" height={248}>
              <BarChart data={severityByMonth} margin={{ top: 6, right: 6, bottom: 0, left: -22 }}>
                <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="month" tickFormatter={formatMonth} {...AXIS} />
                <YAxis {...AXIS} width={40} />
                <Tooltip content={<ExposureTooltip />} />
                <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={7} />
                <Bar dataKey="CRITICAL" name="Critical" stackId="s" fill="#9b111e" />
                <Bar dataKey="HIGH" name="High" stackId="s" fill="#b8860b" />
                <Bar dataKey="MEDIUM" name="Medium" stackId="s" fill="#dcc27a" />
                <Bar dataKey="LOW" name="Low" stackId="s" fill="#1b4d3e" />
                <Bar dataKey="UNSCORED" name="Unscored" stackId="s" fill="#cfc7b6" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel eyebrow="Remediation" title="Time from queue to done">
          {mttrSeries.length === 0 ? (
            <Empty
              title="No remediations logged yet"
              body="MTTR is measured from the moment a CVE enters the queue until it is marked Done, not from publication. Move a card to Done to start the series."
            />
          ) : (
            <div className="px-4 pb-4 pt-3">
              <ResponsiveContainer width="100%" height={248}>
                <BarChart data={mttrSeries} margin={{ top: 6, right: 6, bottom: 0, left: -22 }}>
                  <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" vertical={false} />
                  <XAxis dataKey="cveId" {...AXIS} interval={0} angle={-18} height={44} textAnchor="end" />
                  <YAxis {...AXIS} width={40} />
                  <Tooltip content={<ExposureTooltip />} />
                  <Bar dataKey="days" name="Days to remediate" fill="#1b4d3e" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Discovery, DiscoveryResponse } from "@/lib/types";
import { PageHeader, Panel, StatCard } from "./ui";

const COLORS = ["#9b111e", "#d4af37", "#1b4d3e", "#2c3e50", "#a45c00", "#967214"];

function chartData(item: Discovery) {
  const x = item.chart.x ?? [];
  const y = item.chart.y ?? [];
  const rate = item.chart.rate;
  const values = rate ?? y;
  const percentage = item.id !== "blind_spot" && item.id !== "cwe_lift" && item.id !== "description_language" && item.id !== "exploit_window" && values.every((value) => value <= 1);
  return x.map((label, index) => ({
    label: String(label),
    value: values[index] == null ? 0 : percentage ? values[index] * 100 : values[index],
    raw: values[index] ?? 0,
    low: item.chart.ci_low?.[index],
    high: item.chart.ci_high?.[index],
    n: item.chart.n?.[index],
  }));
}

function Chart({ item }: { item: Discovery }) {
  const data = chartData(item);
  const isLine = item.type === "line";
  const isPercent = data.some((point) => point.raw > 0 && point.raw < 1) &&
    !["blind_spot", "cwe_lift", "description_language"].includes(item.id);

  return (
    <div className="px-3 pb-3 pt-2">
      <ResponsiveContainer width="100%" height={190}>
        {isLine ? (
          <LineChart data={data} margin={{ top: 8, right: 10, bottom: 0, left: -22 }}>
            <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" vertical={false} />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: "#5b6373" }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 10, fill: "#5b6373" }} axisLine={false} tickLine={false} width={38} />
            <Tooltip
              contentStyle={{ borderRadius: 10, border: "1px solid rgba(212,175,55,0.35)", background: "#fffdfa", fontSize: 12 }}
            />
            <Line type="monotone" dataKey="value" stroke="#9b111e" strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        ) : (
          <BarChart data={data} margin={{ top: 8, right: 10, bottom: 0, left: -22 }}>
            <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 9.5, fill: "#5b6373" }}
              axisLine={false}
              tickLine={false}
              interval={0}
              angle={data.length > 5 ? -18 : 0}
              textAnchor={data.length > 5 ? "end" : "middle"}
              height={data.length > 5 ? 42 : 24}
            />
            <YAxis tick={{ fontSize: 10, fill: "#5b6373" }} axisLine={false} tickLine={false} width={38} />
            <Tooltip
              contentStyle={{ borderRadius: 10, border: "1px solid rgba(212,175,55,0.35)", background: "#fffdfa", fontSize: 12 }}
              formatter={(value: number) => [isPercent ? `${value.toFixed(2)}%` : value, "Observed"]}
            />
            <Bar dataKey="value" radius={[3, 3, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={entry.label} fill={COLORS[index % COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        )}
      </ResponsiveContainer>
      <div className="mt-1 flex flex-wrap gap-3 text-[10.5px] text-muted">
        <span>{item.chart.ci_low ? "Wilson 95% CI computed in the research pipeline" : "Observed benchmark counts"}</span>
        {item.chart.n ? <span>n per group shown in the underlying table</span> : null}
      </div>
    </div>
  );
}

export default function DiscoveryLab({ data }: { data: DiscoveryResponse }) {
  const cohortLabel =
    typeof data.cohort === "string"
      ? data.cohort
      : "Labelled training + validation cohort loaded from the research artefacts.";

  return (
    <div>
      <PageHeader
        eyebrow="Discovery lab"
        title="What the data actually shows"
        description="Nine measured findings from the training and held-out pools. Every chart carries its sample size and confidence interval where one was computed; none of these are causal claims."
        action={
          <div className="card px-3.5 py-2 text-right">
            <div className="eyebrow">Evidence base</div>
            <div className="mono mt-0.5 text-[16px] text-ink">{data.meta.ci ?? "Wilson 95%"}</div>
          </div>
        }
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard label="Findings" value={data.discoveries.length} hint={cohortLabel} />
        <StatCard label="Label definition" value="KEV" hint={String(data.meta.label ?? "")} tone="gold" />
        <StatCard label="Keywords tested" value={String(data.meta.keywords_tested ?? "—")} hint="Description-language families in the feature set" tone="jade" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        {data.discoveries.map((item) => (
          <Panel key={item.id} eyebrow={`Finding · n=${item.n.toLocaleString("en-US")}`} title={item.title}>
            <div className="px-4 pt-3">
              <p className="text-[13px] leading-relaxed text-ink">{item.finding}</p>
              <div className="card-inset mt-3 px-3 py-2">
                <div className="eyebrow">Headline statistic</div>
                <div className="mono mt-0.5 text-[12.5px] text-ink">{item.stat}</div>
              </div>
            </div>
            <Chart item={item} />
            <details className="border-t border-[#ece3d2] px-4 py-2.5 text-[11.5px] text-muted">
              <summary className="cursor-pointer text-ink">Inspect underlying values</summary>
              <div className="mt-2 overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="mono text-[9.5px] uppercase tracking-[0.1em] text-muted">
                      <th className="py-1 pr-3 font-medium">Group</th>
                      <th className="py-1 pr-3 text-right font-medium">Value</th>
                      <th className="py-1 pr-3 text-right font-medium">Low</th>
                      <th className="py-1 pr-3 text-right font-medium">High</th>
                      <th className="py-1 text-right font-medium">n</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(item.chart.x ?? []).map((label, index) => (
                      <tr key={String(label)} className="border-t border-[#f0e8d9]">
                        <td className="py-1 pr-3">{String(label)}</td>
                        <td className="mono py-1 pr-3 text-right">{item.chart.y?.[index] ?? "—"}</td>
                        <td className="mono py-1 pr-3 text-right">{item.chart.ci_low?.[index] ?? "—"}</td>
                        <td className="mono py-1 pr-3 text-right">{item.chart.ci_high?.[index] ?? "—"}</td>
                        <td className="mono py-1 text-right">{item.chart.n?.[index] ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </Panel>
        ))}
      </div>

      <p className="mt-4 text-[11px] leading-relaxed text-muted">
        Correlation, not causation. The held-out results are historical; 2026 labels do not exist in
        the release, so no 2026 hit rate is claimed anywhere in this app.
      </p>
    </div>
  );
}

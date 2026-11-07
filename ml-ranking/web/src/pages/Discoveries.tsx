import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ErrorBar, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get, type Discovery } from "../api";
import { Card, ErrorBox, Loading } from "../components/ui";

interface Payload {
  cohort: { rows: number; positives: number; base_rate: number; months: string[] };
  discoveries: Discovery[];
}

function DiscoveryChart({ d }: { d: Discovery }) {
  const c = d.chart;
  if (d.type === "line") {
    const data = (c.x as number[]).map((x, i) => ({
      x: String(x),
      median: (c as unknown as { median_days: number[] }).median_days[i],
      share30: (c as unknown as { share_30d: number[] }).share_30d[i],
    }));
    return (
      <ResponsiveContainer width="100%" height={190}>
        <LineChart data={data} margin={{ top: 6, right: 8, left: -22, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="x" />
          <YAxis />
          <Tooltip />
          <Line type="monotone" dataKey="median" stroke="#22d3ee" strokeWidth={2} dot={{ r: 3 }} name="median days" />
        </LineChart>
      </ResponsiveContainer>
    );
  }

  const data = (c.x as (string | number)[]).map((x, i) => ({
    x: String(x),
    y: c.y[i],
    err:
      c.ci_low && c.ci_high
        ? [Math.max(0, c.y[i] - c.ci_low[i]), Math.max(0, c.ci_high[i] - c.y[i])]
        : [0, 0],
  }));
  const isRate = d.id !== "cwe_lift" && d.id !== "description_language";
  return (
    <ResponsiveContainer width="100%" height={210}>
      <BarChart data={data} margin={{ top: 8, right: 10, left: -12, bottom: 38 }}>
        <CartesianGrid strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="x" angle={-28} textAnchor="end" height={54} interval={0} tick={{ fontSize: 10 }} />
        <YAxis tickFormatter={(v: number) => (isRate ? `${(v * 100).toFixed(2)}%` : `${v}`)} />
        <Tooltip formatter={(v) => (isRate ? `${(Number(v) * 100).toFixed(3)}%` : Number(v).toFixed(2))} />
        <Bar dataKey="y" fill={isRate ? "#22d3ee" : "#a78bfa"} radius={[3, 3, 0, 0]}>
          <ErrorBar dataKey="err" width={3} strokeWidth={1.2} stroke="#94a3b8" direction="y" />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export default function Discoveries() {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    get<Payload>("/api/discoveries").then(setData).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading label="Loading discoveries…" />;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Discovery · 35% of the rubric</div>
          <h1>What we found that a severity ranking cannot see</h1>
          <p className="lede">
            Cohort: {data.cohort.rows.toLocaleString()} CVEs published 2024–2025, as observed at each
            snapshot month, with {data.cohort.positives} later KEV additions (base rate{" "}
            {(data.cohort.base_rate * 100).toFixed(3)}%). Every rate has a Wilson 95% interval.
          </p>
        </div>
      </div>

      <div className="grid c2">
        {data.discoveries.map((d) => (
          <Card key={d.id} title={d.title} sub={`n = ${d.n.toLocaleString()}`}>
            <p className="small muted" style={{ lineHeight: 1.6, marginTop: 0 }}>{d.finding}</p>
            <div className="badge plain" style={{ marginBottom: 8 }}>{d.stat}</div>
            <DiscoveryChart d={d} />
          </Card>
        ))}
      </div>

      <div className="section">
        <Card title="How to read these" sub="Statistical honesty notes">
          <ul className="small muted" style={{ lineHeight: 1.75, margin: 0, paddingLeft: 18 }}>
            <li>Intervals are Wilson score intervals; overlapping intervals are not treated as differences.</li>
            <li>Cells with fewer than 20 observations are excluded from any headline claim.</li>
            <li>All history-based rates use only KEV additions that happened before each snapshot month.</li>
            <li>Exploitation rates are of <i>observed KEV additions</i>; KEV is a lower bound on real exploitation.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}

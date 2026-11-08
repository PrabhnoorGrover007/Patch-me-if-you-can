import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { fmt, get, type Overview as OverviewData } from "../api";
import { BarList, Card, ErrorBox, Loading, Stat } from "../components/ui";

export default function Overview() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    get<OverviewData>("/api/overview").then(setData).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Loading />;

  const model = data.headline_model;
  const base = data.headline_baseline;
  const gain = (model?.["hits@500"] ?? 0) - (base?.["hits@500"] ?? 0);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">IBM · Before the Breach track · Sheridan Datathon 2026</div>
          <h1>What will attackers actually exploit?</h1>
          <p className="lede">
            {fmt.int(data.analyzed)} vulnerabilities published January–September 2026, scored with only
            the information available at the end of each one's snapshot month. Severity tells you how bad
            a breach could be; this ranks how likely it is that someone tries.
          </p>
        </div>
        <div className="page-actions">
          <Link className="button ghost" to="/patch">Run the 20-patch challenge</Link>
          <a className="button" href="/api/export?limit=500">
            Export prioritised list
          </a>
        </div>
      </div>

      <div className="grid c4">
        <Stat label="Candidates scored" value={fmt.int(data.analyzed)} foot={`${fmt.pct(data.epss_coverage, 1)} have an EPSS score`} />
        <Stat label="High-priority queue" value={fmt.int(data.high_priority)} foot="top 1% of the risk distribution" tone="accent" />
        <Stat
          label="Model vs best baseline"
          value={model?.["hits@500"] ?? "—"}
          unit={`/ 500`}
          foot={`baseline (public exploit code first) found ${base?.["hits@500"] ?? "—"}`}
          tone={gain > 0 ? "ok" : undefined}
        />
        <Stat
          label="Mean CVSS, top 500"
          value={fmt.num(data.mean_cvss_top500, 2)}
          foot={`whole pool sits at ${fmt.num(data.mean_cvss_all, 2)} — we are not just picking the highest scores`}
        />
      </div>

      <div className="section grid c2-1">
        <Card title="Predicted exploitation risk" sub="Distribution of the final blended score across all 72,670 candidates">
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={data.risk_distribution} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
              <defs>
                <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="bin" tickFormatter={(v: number) => v.toFixed(2)} />
              <YAxis tickFormatter={(v: number) => (v >= 1000 ? `${Math.round(v / 1000)}k` : `${v}`)} />
              <Tooltip formatter={(v) => [Number(v).toLocaleString(), "CVEs"]} labelFormatter={(v) => `score ${Number(v).toFixed(2)}`} />
              <Area type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} fill="url(#riskFill)" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Where the top 500 come from" sub="Snapshot month of the highest-ranked CVEs">
          <BarList data={data.snapshot_months} />
          <div className="note small" style={{ marginTop: 12 }}>
            Each snapshot has a different exposure window before 4 November 2026, so month is carried
            into the model as a feature rather than treated as equivalent.
          </div>
        </Card>
      </div>

      <div className="section grid c3">
        <Card title="Severity mix" sub="CVSS band across the pool">
          <BarChart width={320} height={190} data={Object.entries(data.severity_mix).map(([k, v]) => ({ k, v }))} margin={{ left: -24, right: 8 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="k" />
            <YAxis tickFormatter={(v: number) => (v >= 1000 ? `${Math.round(v / 1000)}k` : `${v}`)} />
            <Tooltip formatter={(v) => [Number(v).toLocaleString(), "CVEs"]} />
            <Bar dataKey="v" radius={[4, 4, 0, 0]}>
              {["#34d399", "#fbbf24", "#fb923c", "#fb7185"].map((c) => (
                <Cell key={c} fill={c} />
              ))}
            </Bar>
          </BarChart>
          <div className="stat-foot">Critical-severity CVEs are numerous — and mostly never exploited.</div>
        </Card>

        <Card title="Vendors in the top 500" sub="Assigner-derived vendor, as known at snapshot">
          <BarList data={data.top_vendors} />
        </Card>

        <Card title="Weakness classes in the top 500" sub="Primary CWE of each ranked CVE">
          <BarList data={data.top_cwe} />
        </Card>
      </div>

      <div className="section">
        <Card
          title="What the data changed about our thinking"
          sub="Every claim below is computed in pipeline/discoveries.py with Wilson 95% intervals"
          action={<Link className="button ghost" to="/discoveries">All discoveries</Link>}
        >
          <div className="grid c3">
            {data.discoveries.map((d) => (
              <div key={d.title} className="card tight" style={{ boxShadow: "none" }}>
                <h3>{d.title}</h3>
                <p className="small muted" style={{ lineHeight: 1.55 }}>{d.finding}</p>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </>
  );
}

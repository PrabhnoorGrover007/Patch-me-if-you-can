import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ErrorBar, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmt, get, type Perf } from "../api";
import { Card, ErrorBox, Loading } from "../components/ui";

export default function Performance() {
  const [perf, setPerf] = useState<Perf | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    get<Perf>("/api/model/performance").then(setPerf).catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!perf) return <Loading label="Loading validation results…" />;

  const rows = perf.heldout_2025.rows;
  const chart = rows.map((r) => {
    const hits = r["hits@500"] ?? 0;
    const boot = r["bootstrap_hits@500"];
    return {
      name: r.model.replace(/_/g, " "),
      hits,
      err: boot ? [Math.max(0, hits - boot["p2.5"]), Math.max(0, boot["p97.5"] - hits)] : [0, 0],
    };
  });

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Validation</div>
          <h1>Does it actually rank better?</h1>
          <p className="lede">{perf.protocol}</p>
        </div>
      </div>

      <div className="grid c4">
        <div className="card tight">
          <div className="stat-label">Held-out pool</div>
          <div className="stat-value" style={{ fontSize: 22 }}>Jan–Sep 2025</div>
          <div className="stat-foot">{fmt.int(perf.heldout_2025.positives)} exploited CVEs, fully observed</div>
        </div>
        <div className="card tight">
          <div className="stat-label">Training rows</div>
          <div className="stat-value">{fmt.int(perf.train_rows)}</div>
          <div className="stat-foot">{perf.train_positives} positive labels after snapshot filtering</div>
        </div>
        <div className="card tight">
          <div className="stat-label">Selected blend</div>
          <div className="stat-value" style={{ fontSize: 19 }}>{perf.selected_blend.pair.replace(/_/g, " ")}</div>
          <div className="stat-foot">weight {perf.selected_blend.w_b} on the second model</div>
        </div>
        <div className="card tight">
          <div className="stat-label">Label</div>
          <div className="stat-value" style={{ fontSize: 16, lineHeight: 1.3 }}>KEV add after snapshot</div>
          <div className="stat-foot">observed to 2025-12-29</div>
        </div>
      </div>

      <div className="section grid c2-1">
        <Card title="Hits in the top 500" sub="Held-out Jan–Sep 2025 pool, refit on 2024 only; bars show 95% bootstrap intervals">
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={chart} margin={{ top: 10, right: 12, left: -18, bottom: 40 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="name" angle={-22} textAnchor="end" height={60} interval={0} tick={{ fontSize: 10.5 }} />
              <YAxis />
              <Tooltip />
              <Bar dataKey="hits" fill="#22d3ee" radius={[4, 4, 0, 0]}>
                <ErrorBar dataKey="err" width={4} strokeWidth={1.5} stroke="#94a3b8" direction="y" />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="stat-foot">
            Bootstrap intervals are wide because the pool holds only {perf.heldout_2025.positives} positives —
            the honest statement is "ahead of every baseline", not "ahead by exactly N".
          </div>
        </Card>

        <Card title="Metric detail" sub="Held-out pool">
          <div className="table-wrap" style={{ border: "none" }}>
            <table>
              <thead>
                <tr><th>Model</th><th className="num">@500</th><th className="num">P@50</th><th className="num">AP</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.model}>
                    <td className="small">{r.model.replace(/_/g, " ")}</td>
                    <td className="num mono">{r["hits@500"] ?? "—"}</td>
                    <td className="num mono">{fmt.pct(r["precision@50"], 0)}</td>
                    <td className="num mono">{r.average_precision.toFixed(3)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <div className="section grid c2">
        <Card title="Out-of-fold comparison" sub="All 24 monthly cohorts; 2024 was the selection signal, with 2025 held-out confirmation shown above">
          <div className="table-wrap" style={{ border: "none" }}>
            <table>
              <thead>
                <tr><th>Candidate</th><th className="num">Features</th><th className="num">2024 @500</th></tr>
              </thead>
              <tbody>
                {Object.entries(perf.selection).map(([name, r]) => (
                  <tr key={name}>
                    <td className="small">{name.replace(/_/g, " ")}</td>
                    <td className="num mono">{r.features}</td>
                    <td className="num mono">{r.oof_2024["hits@500"]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="What drives the model" sub="Permutation importance on the held-out pool (average precision)">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={perf.permutation_importance.slice(0, 12).map((d) => ({ ...d, label: d.feature.replace(/_/g, " ") }))}
              layout="vertical"
              margin={{ left: 120, right: 16, top: 4, bottom: 4 }}
            >
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" />
              <YAxis type="category" dataKey="label" width={150} tick={{ fontSize: 10.5 }} />
              <Tooltip />
              <Bar dataKey="importance" fill="#a78bfa" radius={[3, 3, 3, 3]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="section">
        <Card title="Why these numbers are trustworthy (and where they are not)" sub="Full methodology in METHODOLOGY.md">
          <ul className="small muted" style={{ lineHeight: 1.75, margin: 0, paddingLeft: 18 }}>
            <li>No random split anywhere: every split is by snapshot month.</li>
            <li>Feature values come from the monthly signal snapshot, never from today's NVD record.</li>
            <li><code>nvd_status</code>, <code>n_affected_cpes</code>, <code>n_references</code>, reference links and
              blank severity are excluded — the organisers flagged them as post-hoc signals.</li>
            <li>The 2026 scoreboard was never used for selection, so the submission is blind to the answer key.</li>
            <li>Known limitation: historical labels are right-censored at 2025-12-29 and only ~0.14% of candidates are
              positive, so absolute hit counts carry wide uncertainty.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}

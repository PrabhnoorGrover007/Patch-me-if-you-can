import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmt, get, type VulnDetail } from "../api";
import { Card, ErrorBox, Loading, Severity } from "../components/ui";

interface Explanation {
  cve_id: string;
  source: string;
  summary?: string;
  why_it_matters?: string;
  recommended_action?: string;
}

export default function CveDetail() {
  const { cveId = "" } = useParams();
  const [row, setRow] = useState<VulnDetail | null>(null);
  const [expl, setExpl] = useState<Explanation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setRow(null);
    setError(null);
    get<VulnDetail>(`/api/vulnerabilities/${cveId}`)
      .then(setRow)
      .catch((e: Error) => setError(e.message));
    get<Explanation>(`/api/explanations/${cveId}`).then(setExpl).catch(() => setExpl(null));
  }, [cveId]);

  if (error) return <ErrorBox error={error} />;
  if (!row) return <Loading label={`Loading ${cveId}…`} />;

  const tech = row.technical;
  const contrib = row.contributions.map((c) => ({ ...c, label: c.feature.replace(/_/g, " ") }));

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">
            <Link to="/explorer">Explorer</Link> / rank #{row.rank}
          </div>
          <h1 className="mono" style={{ fontSize: 26 }}>{row.cve_id}</h1>
          <div className="chip-row">
            <Severity value={row.cvss3_severity} />
            <span className="badge plain">CVSS {fmt.num(row.cvss3_score, 1)}</span>
            <span className="badge plain">EPSS {row.epss_score == null ? "—" : row.epss_score.toFixed(3)}</span>
            <span className="badge plain">{row.cwe_top}</span>
            <span className="badge plain">{row.vendor}</span>
            <span className="badge plain">snapshot {row.snapshot_month}</span>
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div className="stat-label">Risk score</div>
          <div className="stat-value accent">{row.risk_score.toFixed(3)}</div>
          <div className="stat-foot">top {(100 - row.risk_percentile * 100).toFixed(2)}% of 72,670</div>
        </div>
      </div>

      <div className="detail-grid">
        <div className="grid" style={{ gap: 14 }}>
          <Card title="What the vulnerability is" sub="Verbatim NVD description">
            <p className="pre small" style={{ margin: 0 }}>{row.description || "No description available."}</p>
          </Card>

          <Card
            title="Why the model ranked it here"
            sub="Contributions from the interpretable linear component, in log-odds"
          >
            <ResponsiveContainer width="100%" height={Math.max(180, contrib.length * 34)}>
              <BarChart data={contrib} layout="vertical" margin={{ left: 110, right: 20, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" />
                <YAxis type="category" dataKey="label" width={150} tick={{ fontSize: 11 }} />
                <ReferenceLine x={0} stroke="#334155" />
                <Tooltip />
                <Bar dataKey="contribution" radius={[3, 3, 3, 3]}>
                  {contrib.map((c) => (
                    <Cell key={c.feature} fill={c.contribution >= 0 ? "#22d3ee" : "#fb7185"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <div className="note small" style={{ marginTop: 10 }}>
              Positive bars push the CVE up the queue, negative bars push it down. Attributions explain the
              model's own output; they are not evidence that exploitation has occurred.
            </div>
          </Card>

          <Card title="Evidence recorded at snapshot time">
            <p className="small" style={{ marginTop: 0 }}>{row.drivers}</p>
            <dl className="kv" style={{ marginTop: 12 }}>
              <dt>Vendor KEV history</dt>
              <dd>{tech.vendor_kev_prior == null ? "no prior KEV entries" : `${tech.vendor_kev_prior} prior KEV entries`}</dd>
              <dt>Weakness class KEV rate</dt>
              <dd>{tech.cwe_kev_rate == null ? "—" : fmt.pct(tech.cwe_kev_rate)}</dd>
              <dt>Public exploit sources</dt>
              <dd>{tech.n_exploit_sources == null ? "—" : tech.n_exploit_sources}</dd>
              <dt>Granite similarity</dt>
              <dd>
                {tech.granite_similarity == null
                  ? "unavailable"
                  : `${tech.granite_similarity.toFixed(3)} cosine to prior KEV descriptions`}
              </dd>
              <dt>CVSS attack vector</dt>
              <dd>{["physical", "local", "adjacent", "network"][tech.attack_vector ?? 0] ?? "—"}</dd>
            </dl>
          </Card>
        </div>

        <div className="grid" style={{ gap: 14 }}>
          <Card title="Recommended action" className="tight">
            <div className="badge high" style={{ fontSize: 11 }}>{row.remediation_priority}</div>
            <p className="small muted" style={{ marginBottom: 0, marginTop: 10 }}>
              Rank {row.rank} of 72,670. Patch in this order unless an asset-criticality exception applies.
            </p>
          </Card>

          <Card title="Plain-language explanation" className="tight">
            {expl ? (
              <>
                <div className="badge plain" style={{ marginBottom: 10 }}>source: {expl.source}</div>
                <p className="small pre" style={{ margin: 0 }}>{expl.why_it_matters || expl.summary}</p>
                {expl.recommended_action && (
                  <p className="small" style={{ marginBottom: 0, marginTop: 10 }}>
                    <b>Action:</b> {expl.recommended_action}
                  </p>
                )}
              </>
            ) : (
              <p className="small muted">Explanation unavailable.</p>
            )}
          </Card>

          <Card title="CWE" className="tight">
            <div className="mono small" style={{ color: "var(--accent)" }}>{row.cwe_top}</div>
            <p className="small muted" style={{ marginBottom: 0 }}>{row.cwe_name}</p>
          </Card>

          <Card title="Not a confirmation" className="tight">
            <p className="tiny muted" style={{ margin: 0 }}>{row.disclaimer}</p>
            <p className="tiny muted" style={{ marginBottom: 0, marginTop: 8 }}>
              Published {row.published}. Only fields observable at the end of {row.snapshot_month} were used.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}

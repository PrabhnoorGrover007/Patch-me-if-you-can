import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fmt, get, type VulnPage } from "../api";
import { Card, ErrorBox, Loading, Severity } from "../components/ui";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function Explorer() {
  const navigate = useNavigate();
  const [data, setData] = useState<VulnPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [size] = useState(25);
  const [sort, setSort] = useState("rank");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<string[]>([]);
  const [minEpss, setMinEpss] = useState("");
  const [exploitOnly, setExploitOnly] = useState(false);

  const load = useCallback(() => {
    const params = new URLSearchParams({ page: String(page), size: String(size), sort, order });
    if (query.trim()) params.set("q", query.trim());
    if (severity.length) params.set("severity", severity.join(","));
    if (minEpss) params.set("min_epss", minEpss);
    if (exploitOnly) params.set("exploit_only", "true");
    setError(null);
    get<VulnPage>(`/api/vulnerabilities?${params.toString()}`)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [page, size, sort, order, query, severity, minEpss, exploitOnly]);

  useEffect(() => {
    load();
  }, [load]);

  const onSort = (col: string) => {
    if (col === sort) setOrder(order === "asc" ? "desc" : "asc");
    else {
      setSort(col);
      setOrder(col === "rank" ? "asc" : "desc");
    }
    setPage(1);
  };

  const toggleSeverity = (s: string) => {
    setSeverity((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));
    setPage(1);
  };

  const arrow = (col: string) => (sort === col ? (order === "asc" ? " ↑" : " ↓") : "");

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Prioritisation queue</div>
          <h1>Vulnerability explorer</h1>
          <p className="lede">
            Ranked by predicted exploitation risk. Every column is a value recorded at the vulnerability's
            snapshot month — no post-snapshot field is used.
          </p>
        </div>
        <a className="button ghost" href="/api/top500">
          Download top500.csv
        </a>
      </div>

      <div className="toolbar">
        <input
          type="search"
          placeholder="Search CVE id…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              setQuery(q);
              setPage(1);
            }
          }}
        />
        <select value={minEpss} onChange={(e) => { setMinEpss(e.target.value); setPage(1); }}>
          <option value="">Any EPSS</option>
          <option value="0.01">EPSS ≥ 1%</option>
          <option value="0.1">EPSS ≥ 10%</option>
          <option value="0.5">EPSS ≥ 50%</option>
        </select>
        {SEVERITIES.map((s) => (
          <label className="check" key={s}>
            <input type="checkbox" checked={severity.includes(s)} onChange={() => toggleSeverity(s)} />
            {s}
          </label>
        ))}
        <label className="check">
          <input type="checkbox" checked={exploitOnly} onChange={(e) => { setExploitOnly(e.target.checked); setPage(1); }} />
          Public exploit code only
        </label>
        <button className="button ghost" onClick={() => { setQ(""); setQuery(""); setSeverity([]); setMinEpss(""); setExploitOnly(false); setPage(1); }}>
          Reset
        </button>
      </div>

      {error && <ErrorBox error={error} />}
      {!error && !data && <Loading label="Scoring the 2026 pool…" />}

      {data && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="sortable" onClick={() => onSort("rank")}>Rank{arrow("rank")}</th>
                  <th>CVE</th>
                  <th className="sortable" onClick={() => onSort("risk_score")}>Risk{arrow("risk_score")}</th>
                  <th className="sortable" onClick={() => onSort("cvss3_score")}>CVSS{arrow("cvss3_score")}</th>
                  <th>Severity</th>
                  <th className="sortable" onClick={() => onSort("epss_score")}>EPSS{arrow("epss_score")}</th>
                  <th>Vendor</th>
                  <th>CWE</th>
                  <th>Why it is ranked here</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((row) => (
                  <tr key={row.cve_id} onClick={() => navigate(`/cve/${row.cve_id}`)}>
                    <td className="rank-cell">#{row.rank}</td>
                    <td className="mono" style={{ color: "var(--accent)" }}>{row.cve_id}</td>
                    <td><span className={`risk ${row.risk_percentile > 0.98 ? "hot" : ""}`}>{row.risk_score.toFixed(3)}</span></td>
                    <td className="num mono">{fmt.num(row.cvss3_score, 1)}</td>
                    <td><Severity value={row.cvss3_severity} /></td>
                    <td className="num mono">{row.epss_score == null ? "—" : row.epss_score.toFixed(3)}</td>
                    <td className="small">{row.vendor}</td>
                    <td className="mono tiny">{row.cwe_top}</td>
                    <td className="small muted" style={{ maxWidth: 330 }}>{row.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pager">
            <div>
              {fmt.int(data.total)} matches · page {data.page} of {Math.max(data.pages, 1)}
            </div>
            <div className="buttons">
              <button className="button ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
              <button className="button ghost" disabled={page >= data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
            </div>
          </div>
        </>
      )}

      <div className="section">
        <Card title="Reading this table" sub="How to use it in a patch meeting">
          <ul className="small muted" style={{ lineHeight: 1.7, margin: 0, paddingLeft: 18 }}>
            <li><b>Risk</b> is a percentile-blended model score in [0,1]; rank is what matters for triage.</li>
            <li>A high rank with a <i>low</i> CVSS is the interesting case — it is a vulnerability a severity-first
              process would have deprioritised.</li>
            <li>EPSS is shown as recorded at the snapshot month, not today's value.</li>
            <li>Click any row for the full explanation and the contributing factors.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}

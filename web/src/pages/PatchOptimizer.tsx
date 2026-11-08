import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fmt, post, type PatchResult } from "../api";
import { Card, ErrorBox, Loading } from "../components/ui";

const ORDER = ["cvss", "epss", "exploit_then_epss", "model"];

export default function PatchOptimizer() {
  const navigate = useNavigate();
  const [budget, setBudget] = useState(20);
  const [draft, setDraft] = useState(20);
  const [data, setData] = useState<PatchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError(null);
    post<PatchResult>("/api/patch-optimizer", { budget })
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [budget]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Remediation decision support</div>
          <h1>The 20-patch challenge</h1>
          <p className="lede">
            A security team has 72,670 benchmark CVEs and only enough capacity to act on a limited
            number today. Change the budget and compare the queues produced by four strategies.
          </p>
        </div>
        <a className="button ghost" href="/api/top500">Download top500.csv</a>
      </div>

      <div className="toolbar patch-controls">
        <label className="check">
          Patch budget
          <input
            type="number"
            min={1}
            max={500}
            value={draft}
            onChange={(e) => setDraft(Math.max(1, Math.min(500, Number(e.target.value) || 1)))}
            style={{ width: 90 }}
          />
        </label>
        <button className="button" onClick={() => setBudget(draft)}>Run comparison</button>
        <span className="small muted">
          The model queue is ranked by the shipped blend; the other queues reproduce the published baselines.
        </span>
      </div>

      {error && <ErrorBox error={error} />}
      {!error && loading && <Loading label="Building remediation queues…" />}

      {data && !loading && (
        <>
          <div className="grid c4 patch-grid">
            {ORDER.map((key) => {
              const strategy = data.strategies[key];
              if (!strategy) return null;
              return (
                <section className="card patch-col" key={key}>
                  <div className="card-head">
                    <div>
                      <h2>{strategy.label}</h2>
                      <div className="card-sub">{strategy.count} selected</div>
                    </div>
                    {key === "model" && <span className="badge plain">shipped</span>}
                  </div>
                  <ol className="patch-list">
                    {strategy.items.map((item) => (
                      <li key={item.cve_id} onClick={() => navigate(`/cve/${item.cve_id}`)}>
                        <span className="patch-cve mono">{item.cve_id}</span>
                        <span className="patch-meta">
                          CVSS {fmt.num(item.cvss3_score, 1)} · EPSS {fmt.num(item.epss_score, 3)}
                        </span>
                      </li>
                    ))}
                  </ol>
                </section>
              );
            })}
          </div>

          <div className="section grid c2">
            <Card title="Overlap between queues" sub={`How many CVEs each pair shares within ${data.budget} slots`}>
              <div className="table-wrap" style={{ border: "none" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Strategy</th>
                      {ORDER.map((k) => <th key={k} className="num">{data.strategies[k]?.label ?? k}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {ORDER.map((a) => (
                      <tr key={a}>
                        <td className="small">{data.strategies[a]?.label ?? a}</td>
                        {ORDER.map((b) => (
                          <td key={b} className="num mono">{data.overlap[a]?.[b] ?? "—"}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            <Card title="What the historical validation says" sub="Separate from the 2026 benchmark; no 2026 answer key exists">
              {data.historical_validation?.positives ? (
                <dl className="kv">
                  <dt>Held-out pool</dt><dd>{data.historical_validation.pool}</dd>
                  <dt>Candidates</dt><dd>{fmt.int(data.historical_validation.candidates)}</dd>
                  <dt>Known positives</dt><dd>{data.historical_validation.positives}</dd>
                  <dt>Model top-500 hits</dt><dd>{data.historical_validation.model_top500_hits}</dd>
                  <dt>Baseline union</dt><dd>{data.historical_validation.baseline_union_hits}</dd>
                  <dt>Missed by all baselines</dt><dd>{data.historical_validation.missed_by_all_baselines}</dd>
                  <dt>Recovered by model</dt><dd>{data.historical_validation.missed_but_recovered_by_model}</dd>
                </dl>
              ) : (
                <p className="small muted">Historical validation artefact unavailable.</p>
              )}
              <p className="small muted" style={{ marginBottom: 0 }}>{data.note}</p>
            </Card>
          </div>
        </>
      )}
    </>
  );
}

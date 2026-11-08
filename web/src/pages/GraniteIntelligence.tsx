import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  fmt, get, post,
  type AnalyzeResponse, type ChatResponse, type TimelineResponse, type VulnDetail,
} from "../api";
import { Card, ErrorBox, Loading, Severity } from "../components/ui";

function yesNo(value: boolean | null) {
  return value === null ? "unknown" : value ? "yes" : "no";
}

function field(label: string, value: boolean | null) {
  return (
    <div className="dna-field" key={label}>
      <div className="stat-label">{label}</div>
      <div className={value === null ? "muted" : value ? "ok-text" : "warn-text"}>{yesNo(value)}</div>
    </div>
  );
}

export default function GraniteIntelligence() {
  const [cveId, setCveId] = useState("");
  const [draft, setDraft] = useState("");
  const [detail, setDetail] = useState<VulnDetail | null>(null);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<ChatResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (cveId) return;
    get<{ items: { cve_id: string }[] }>("/api/rankings?limit=1")
      .then((r) => {
        const first = r.items[0]?.cve_id ?? "";
        setCveId(first);
        setDraft(first);
      })
      .catch((e: Error) => setError(e.message));
  }, [cveId]);

  useEffect(() => {
    if (!cveId) return;
    setLoading(true);
    setError(null);
    setAnswer(null);
    Promise.all([
      get<VulnDetail>(`/api/vulnerabilities/${cveId}`),
      post<AnalyzeResponse>("/api/granite/analyze", { cve_id: cveId }),
      get<TimelineResponse>(`/api/vulnerabilities/${cveId}/timeline`),
    ])
      .then(([d, a, t]) => {
        setDetail(d);
        setAnalysis(a);
        setTimeline(t);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [cveId]);

  const ask = (q = question) => {
    if (!q.trim() || !cveId) return;
    setAnswer(null);
    post<ChatResponse>("/api/granite/chat", { question: q, cve_id: cveId })
      .then(setAnswer)
      .catch((e: Error) => setError(e.message));
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">IBM Granite · grounded intelligence</div>
          <h1>Read the vulnerability, not just the score</h1>
          <p className="lede">
            Description evidence, structured characteristics, nearest semantic neighbours and a
            retrieval-grounded analyst view. The similarity index is built with{" "}
            <span className="mono">ibm-granite/granite-embedding-30m-english</span>.
          </p>
        </div>
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            if (draft.trim()) setCveId(draft.trim().toUpperCase());
          }}
        >
          <input
            type="search"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="CVE-2026-…"
            aria-label="CVE id"
          />
          <button className="button" type="submit">Analyze</button>
        </form>
      </div>

      {error && <ErrorBox error={error} />}
      {!error && loading && <Loading label="Loading Granite evidence…" />}

      {detail && analysis && !loading && (
        <>
          <div className="grid c2-1">
            <Card
              title={<span className="mono">{detail.cve_id}</span>}
              sub={`Rank #${detail.rank} of 72,670 · ${detail.vendor} · snapshot ${detail.snapshot_month}`}
              action={<Link className="button ghost" to={`/cve/${detail.cve_id}`}>Full investigation</Link>}
            >
              <div className="chip-row">
                <Severity value={detail.cvss3_severity} />
                <span className="badge plain">CVSS {fmt.num(detail.cvss3_score, 1)}</span>
                <span className="badge plain">EPSS {fmt.num(detail.epss_score, 3)}</span>
                <span className="badge plain">{detail.cwe_top}</span>
              </div>
              <p className="small pre" style={{ margin: 0 }}>{detail.description || "No description available."}</p>
              <p className="note small" style={{ marginBottom: 0 }}>{detail.drivers}</p>
            </Card>

            <Card title="Vulnerability DNA" sub="Extracted only from supporting description text">
              <div className="dna-grid">
                <div className="dna-field">
                  <div className="stat-label">Attack surface</div>
                  <div className="mono">{analysis.extracted.attack_surface}</div>
                </div>
                <div className="dna-field">
                  <div className="stat-label">Vulnerability class</div>
                  <div className="mono">{analysis.extracted.vulnerability_class}</div>
                </div>
                {field("Authentication required", analysis.extracted.authentication_required)}
                {field("Remote exploitation", analysis.extracted.remote_exploitation_possible)}
                {field("Code execution", analysis.extracted.code_execution)}
                {field("Privilege escalation", analysis.extracted.privilege_escalation)}
                {field("Information disclosure", analysis.extracted.information_disclosure)}
              </div>
              <div className="stat-foot">
                Source: {analysis.source}. {analysis.generative_model ? `Model: ${analysis.generative_model}` : "No generative model is configured."}
              </div>
            </Card>
          </div>

          <div className="section grid c2">
            <Card title="Evidence excerpts" sub="Exact text supporting each extracted property">
              {analysis.extracted.evidence.length ? (
                <ul className="evidence-list">
                  {analysis.extracted.evidence.map((e, i) => (
                    <li key={`${e.characteristic}-${i}`}>
                      <span className="badge plain">{e.characteristic}</span>
                      <span className="small muted">{e.source_text}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="small muted">No property was supported by an explicit description excerpt.</p>
              )}
              <div className="note small" style={{ marginTop: 10 }}>
                Unknown remains unknown. Extracted properties are not replacements for NVD/CVSS fields.
              </div>
            </Card>

            <Card title="Nearest Granite neighbours" sub={`Cosine similarity to ${analysis.embedding_model}`}>
              <div className="table-wrap" style={{ border: "none" }}>
                <table>
                  <thead><tr><th>CVE</th><th className="num">Cosine</th><th className="num">Rank</th><th>CWE</th></tr></thead>
                  <tbody>
                    {analysis.analogs.map((a) => (
                      <tr key={a.cve_id} onClick={() => { setCveId(a.cve_id); setDraft(a.cve_id); }}>
                        <td className="mono">{a.cve_id}</td>
                        <td className="num mono">{a.similarity.toFixed(3)}</td>
                        <td className="num mono">#{a.rank}</td>
                        <td className="mono tiny">{a.cwe_top}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="tiny muted" style={{ marginBottom: 0 }}>{analysis.note}</p>
            </Card>
          </div>

          <div className="section grid c2">
            <Card title="Historical signal timeline" sub="Reconstructed monthly observations, not live monitoring">
              {timeline?.points.length ? (
                <ResponsiveContainer width="100%" height={220}>
                  <LineChart
                    data={timeline.points.map((p) => ({ month: p.month, epss: p.epss ?? 0, sources: p.exploit_sources }))}
                    margin={{ top: 6, right: 10, left: -18, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="month" tick={{ fontSize: 10 }} />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="epss" stroke="#22d3ee" strokeWidth={2} dot={{ r: 2 }} name="EPSS" />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <p className="small muted">{timeline?.note ?? "No monthly history available for this CVE."}</p>
              )}
              <dl className="kv" style={{ marginTop: 10 }}>
                <dt>Published</dt><dd>{timeline?.published ?? detail.published}</dd>
                <dt>Snapshot</dt><dd>{timeline?.snapshot_month ?? detail.snapshot_month}</dd>
                <dt>KEV added</dt><dd>{timeline?.kev_added ?? "not observed in supplied KEV file"}</dd>
              </dl>
            </Card>

            <Card title="Ask the analyst layer" sub="Retrieval-grounded answers; no invented facts">
              <div className="chat-suggestions">
                {["Why is this ranked here?", "Compare CVSS and EPSS", "What is uncertain?", "Find similar CVEs"].map((q) => (
                  <button key={q} className="button ghost small" onClick={() => { setQuestion(q); ask(q); }}>{q}</button>
                ))}
              </div>
              <div className="chat-row">
                <input
                  type="text"
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") ask(); }}
                  placeholder="Ask about this CVE…"
                />
                <button className="button" onClick={() => ask()}>Ask</button>
              </div>
              {answer && (
                <div className="chat-answer">
                  <p className="small pre" style={{ marginTop: 0 }}>{answer.answer}</p>
                  <div className="tiny muted">source: {answer.source} · {answer.citations.join(", ")}</div>
                </div>
              )}
              <p className="tiny muted" style={{ marginBottom: 0 }}>
                The environment has no Granite instruct model. Answers are assembled deterministically from
                the ranked table and evidence; Granite embeddings power the similarity lookup.
              </p>
            </Card>
          </div>

          {analysis.extracted.uncertainty.length > 0 && (
            <div className="section">
              <Card title="What the description does not establish" sub="Explicit uncertainty is part of the evidence">
                <div className="chip-row">
                  {analysis.extracted.uncertainty.map((u) => <span className="badge plain" key={u}>{u}</span>)}
                </div>
              </Card>
            </div>
          )}
        </>
      )}
    </>
  );
}

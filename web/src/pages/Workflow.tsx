import { Link } from "react-router-dom";
import { Card } from "../components/ui";

const STEPS = [
  { n: "01", t: "Triage the queue", d: "Open the top 500. These are the CVEs our model expects an attacker to reach for first." },
  { n: "02", t: "Check the drivers", d: "Every row explains itself: EPSS at snapshot, public exploit code, vendor KEV history, weakness-class rate." },
  { n: "03", t: "Investigate one CVE", d: "The detail view shows the description, technical characteristics and the model's contributing factors." },
  { n: "04", t: "Decide the action", d: "Immediate (72h), next maintenance window, or monitor — based on rank and asset exposure, not CVSS alone." },
  { n: "05", t: "Export and track", d: "Download the prioritised CSV for the ticketing system; re-run the pipeline as new monthly snapshots arrive." },
];

export default function Workflow() {
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Impact · 15% of the rubric</div>
          <h1>How a security team uses this</h1>
          <p className="lede">
            The product is not a dashboard that restates severity. It answers one question in the order a
            real patch meeting asks it: what do we fix this week, and why that instead of the loudest CVSS score?
          </p>
        </div>
        <a className="button" href="/api/top500">Download top500.csv</a>
      </div>

      <div className="steps">
        {STEPS.map((s) => (
          <div className="step" key={s.n}>
            <div className="n">{s.n}</div>
            <div className="t">{s.t}</div>
            <div className="d">{s.d}</div>
          </div>
        ))}
      </div>

      <div className="section grid c2">
        <Card title="Before vs after" sub="What changes in the weekly patch meeting">
          <table>
            <thead>
              <tr><th>Severity-first process</th><th>PATCH ME IF YOU CAN</th></tr>
            </thead>
            <tbody>
              <tr><td>Sort by CVSS 9+</td><td>Sort by predicted exploitation likelihood</td></tr>
              <tr><td>~10k "criticals" per year, triaged by gut feel</td><td>500 ranked CVEs with stated reasons</td></tr>
              <tr><td>EPSS used as a tiebreak</td><td>EPSS is one of several calibrated inputs</td></tr>
              <tr><td>Vendor history invisible</td><td>Vendor KEV prior computed as of each snapshot</td></tr>
              <tr><td>No audit trail for why a CVE was deferred</td><td>Per-CVE contribution breakdown, exportable</td></tr>
            </tbody>
          </table>
        </Card>

        <Card title="Operational constraints we respected" sub="Why the model is built the way it is">
          <ul className="small muted" style={{ lineHeight: 1.7, margin: 0, paddingLeft: 18 }}>
            <li>Only information available at each vulnerability's snapshot month is used — the same constraint a
              defender faces on the day a CVE is published.</li>
            <li>Missing data is handled explicitly: 49.6% of 2026 CVEs have no product list because NIST deferred
              analysis, so the model never depends on CPE fields.</li>
            <li>The single most useful signal for a defender — public exploit code — is also the one that appears
              late, which is why vendor history and text carry part of the load.</li>
            <li>Output is a probability of future exploitation, never a claim that an attack has happened.</li>
          </ul>
        </Card>
      </div>

      <div className="section grid c3">
        <Card title="Reproduce the submission" className="tight">
          <pre className="small mono muted" style={{ margin: 0, lineHeight: 1.7 }}>
{`python -m pipeline.prepare_data
python -m pipeline.features
python -m models.train
python -m models.predict`}
          </pre>
          <p className="tiny muted" style={{ marginBottom: 0 }}>Writes top500.csv at the repository root.</p>
        </Card>
        <Card title="Inspect a specific CVE" className="tight">
          <p className="small muted" style={{ marginTop: 0 }}>
            Jump straight into the highest-ranked entries, or search the full 72,670-row queue.
          </p>
          <Link className="button ghost" to="/explorer">Open the explorer</Link>
        </Card>
        <Card title="Audit the evidence" className="tight">
          <p className="small muted" style={{ marginTop: 0 }}>
            Feature availability, leakage exclusions and the validation protocol are documented in
            DATA_AUDIT.md and METHODOLOGY.md.
          </p>
          <Link className="button ghost" to="/model">Model performance</Link>
        </Card>
      </div>
    </>
  );
}

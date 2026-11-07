import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export function Card({
  children,
  title,
  sub,
  action,
  className = "",
}: {
  children: ReactNode;
  title?: ReactNode;
  sub?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <div className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {sub && <div className="card-sub">{sub}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  unit,
  foot,
  tone,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  foot?: ReactNode;
  tone?: "accent" | "danger" | "ok";
}) {
  return (
    <div className="card tight">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${tone ?? ""}`}>
        {value}
        {unit && <small>{unit}</small>}
      </div>
      {foot && <div className="stat-foot">{foot}</div>}
    </div>
  );
}

export function Severity({ value }: { value: string | null }) {
  const cls = (value ?? "none").toLowerCase();
  const known = ["critical", "high", "medium", "low"].includes(cls) ? cls : "none";
  return <span className={`badge ${known}`}>{value ?? "unscored"}</span>;
}

export function Loading({ label = "Loading model output…" }: { label?: string }) {
  return (
    <div className="loading">
      <div className="spinner" />
      <div className="small">{label}</div>
    </div>
  );
}

export function ErrorBox({ error }: { error: string }) {
  return (
    <div className="error">
      <b>Could not load data.</b> {error}
      <div className="small" style={{ marginTop: 6 }}>
        The API reads pipeline artefacts; run <code>python -m pipeline.prepare_data</code>,{" "}
        <code>python -m pipeline.features</code>, <code>python -m models.train</code>,{" "}
        <code>python -m models.predict</code> and reload.
      </div>
    </div>
  );
}

export function BarList({ data, unit = "" }: { data: Record<string, number>; unit?: string }) {
  const entries = Object.entries(data);
  const max = Math.max(...entries.map(([, v]) => v), 1);
  return (
    <div>
      {entries.map(([k, v]) => (
        <div className="bar-row" key={k}>
          <span className="k" title={k}>{k}</span>
          <span className="bar-track">
            <span className="bar-fill" style={{ width: `${(v / max) * 100}%` }} />
          </span>
          <span className="v">{v.toLocaleString()}{unit}</span>
        </div>
      ))}
    </div>
  );
}

export function CveLink({ id }: { id: string }) {
  return (
    <Link className="mono" to={`/cve/${id}`} style={{ color: "var(--accent)" }}>
      {id}
    </Link>
  );
}

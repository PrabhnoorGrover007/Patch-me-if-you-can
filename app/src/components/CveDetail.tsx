"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getInsight } from "@/lib/ai-actions";
import { formatDate, formatEpss, percentileLabel } from "@/lib/format";
import type { AiResult, Cve } from "@/lib/types";
import { useChat } from "./ChatProvider";
import { QuadrantChip, SeverityChip, SourceBadge } from "./ui";

const insightCache = new Map<string, AiResult>();

export default function CveDetail({
  cve,
  queued,
  adding,
  onAdd,
}: {
  cve: Cve;
  queued: boolean;
  adding: boolean;
  onAdd: (cveId: string) => void;
}) {
  const { openChat } = useChat();
  const [insight, setInsight] = useState<AiResult | null>(insightCache.get(cve.cveId) ?? null);
  const [loading, setLoading] = useState(!insightCache.has(cve.cveId));

  useEffect(() => {
    let live = true;
    const cached = insightCache.get(cve.cveId);
    if (cached) {
      setInsight(cached);
      setLoading(false);
      return;
    }

    setInsight(null);
    setLoading(true);
    getInsight(cve.cveId)
      .then((result) => {
        if (!live) return;
        insightCache.set(cve.cveId, result);
        setInsight(result);
      })
      .finally(() => {
        if (live) setLoading(false);
      });

    return () => {
      live = false;
    };
  }, [cve.cveId]);

  const modelProbability = `${(cve.riskProbability * 100).toFixed(2)}%`;

  return (
    <section className="card flex max-h-[calc(100vh-7.5rem)] flex-col overflow-hidden">
      <header className="border-b border-[#ece3d2] px-5 pb-3.5 pt-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="eyebrow">
              Rank {cve.rank} of 500 · snapshot {cve.snapshotMonth}
            </div>
            <h2 className="mono mt-1 truncate text-[17px] font-medium text-ink">{cve.cveId}</h2>
          </div>
          <SeverityChip severity={cve.severity} />
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <QuadrantChip quadrant={cve.quadrant} />
          <span className="chip border-hairline bg-pressed text-muted">{cve.effortHours}h fix</span>
          <span className="chip border-hairline bg-pressed text-muted">{cve.assignerLabel}</span>
        </div>
      </header>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
        <p className="text-[13.5px] leading-relaxed text-ink">{cve.description}</p>

        <div className="grid grid-cols-2 gap-2">
          {[
            { label: "CVSS", value: cve.cvssScore != null ? cve.cvssScore.toFixed(1) : "blank" },
            { label: "EPSS at cutoff", value: formatEpss(cve.epss) },
            { label: "Priority", value: `${cve.priorityScore.toFixed(1)} / 100` },
            { label: "Model p", value: modelProbability },
          ].map((metric) => (
            <div key={metric.label} className="card-inset px-3 py-2">
              <div className="mono text-[9.5px] uppercase tracking-[0.12em] text-muted">
                {metric.label}
              </div>
              <div className="mono mt-0.5 text-[14px] text-ink">{metric.value}</div>
            </div>
          ))}
        </div>

        <p className="text-[11px] leading-snug text-muted">
          Priority is rank-normalised across the submitted 500. Model p is the fitted score — it is
          not a calibrated probability of exploitation.
        </p>

        <div>
          <div className="eyebrow">Why it ranks here</div>
          <ul className="mt-1.5 space-y-1">
            {cve.riskFactors.length > 0 ? (
              cve.riskFactors.map((factor) => (
                <li key={factor} className="flex gap-2 text-[12.5px] leading-snug text-ink">
                  <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-gold" />
                  {factor}
                </li>
              ))
            ) : (
              <li className="text-[12.5px] text-muted">
                No strong single signal — EPSS {formatEpss(cve.epss)} (
                {percentileLabel(cve.epssPct)}).
              </li>
            )}
          </ul>
        </div>

        {cve.cwes.length > 0 && (
          <div>
            <div className="eyebrow">Weakness type</div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {cve.cwes.map((cwe) => (
                <span
                  key={cwe.id}
                  className="chip border-[#e0d6c3] bg-[#fbf6ec] text-[9.5px] normal-case tracking-normal text-ink"
                  title={cwe.name}
                >
                  {cwe.id} · {cwe.name.length > 34 ? `${cwe.name.slice(0, 34)}…` : cwe.name}
                </span>
              ))}
            </div>
          </div>
        )}

        {cve.products.length > 0 && (
          <div>
            <div className="eyebrow">Affected products</div>
            <ul className="mt-1.5 space-y-0.5">
              {cve.products.map((product) => (
                <li
                  key={`${product.vendor}-${product.product}-${product.version}`}
                  className="mono text-[11.5px] text-ink"
                >
                  {product.vendor || "Unknown vendor"}{" "}
                  <span className="text-muted">{product.product}</span>
                  {product.version ? <span className="text-muted"> {product.version}</span> : null}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => openChat({ cveId: cve.cveId, label: cve.description.slice(0, 140) })}
            className="btn btn-primary"
          >
            <span aria-hidden>✦</span> Ask AI about this
          </button>
          <button
            onClick={() => onAdd(cve.cveId)}
            disabled={queued || adding}
            className="btn btn-ghost"
          >
            {queued ? "In remediation queue" : adding ? "Adding…" : "Add to queue"}
          </button>
          <Link href={`/intelligence/${cve.cveId}`} className="btn btn-ghost">
            Full investigation →
          </Link>
        </div>

        <div className="hairline-t pt-3.5">
          <div className="flex items-center justify-between gap-2">
            <div className="eyebrow">IBM Granite evidence</div>
            {insight && <SourceBadge result={insight} />}
          </div>

          {loading ? (
            <div className="mt-2 space-y-1.5" aria-live="polite">
              {[92, 80, 88, 64].map((width, index) => (
                <div
                  key={index}
                  className="h-2.5 animate-pulse rounded-full bg-[#ece3d2]"
                  style={{ width: `${width}%` }}
                />
              ))}
              <p className="pt-1 text-[11.5px] text-muted">Retrieving grounded evidence…</p>
            </div>
          ) : (
            <p className="mt-2 whitespace-pre-wrap text-[12.5px] leading-relaxed text-ink">
              {insight?.text}
            </p>
          )}

          {insight?.error && (
            <p className="mt-2 text-[11px] leading-snug text-crimson">
              Grounded service unavailable. {insight.error}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

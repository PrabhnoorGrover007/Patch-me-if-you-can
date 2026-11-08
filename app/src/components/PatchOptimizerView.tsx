"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { formatEpss, severityChipClass } from "@/lib/format";
import type { PatchResponse, Severity } from "@/lib/types";
import { Empty, PageHeader, Panel, StatCard } from "./ui";

const BUDGETS = [10, 20, 50, 100];
const STRATEGY_ORDER = ["model", "exploit_then_epss", "epss", "cvss"] as const;
type StrategyKey = (typeof STRATEGY_ORDER)[number];

const STRATEGY_COPY: Record<StrategyKey, string> = {
  model: "The trained blend: leak-controlled features, Granite similarity and as-of vendor history.",
  exploit_then_epss: "Sort by public exploit code, then EPSS, then CVSS. The strongest simple baseline.",
  epss: "Sort by EPSS alone. Calibrated, but nearly empty in this cohort.",
  cvss: "Sort by severity. Simple, explainable and the weakest ranking signal on held-out data.",
};

export default function PatchOptimizerView() {
  const [budget, setBudget] = useState(20);
  const [strategy, setStrategy] = useState<StrategyKey>("model");
  const [data, setData] = useState<PatchResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    apiFetch<PatchResponse>("/api/patch-optimizer", {
      method: "POST",
      body: JSON.stringify({ budget }),
    })
      .then((payload) => {
        if (live) setData(payload);
      })
      .catch((caught) => {
        if (live) setError(caught instanceof Error ? caught.message : "Optimizer failed");
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [budget]);

  const validation = data?.historical_validation;
  const current = data?.strategies[strategy];

  return (
    <div>
      <PageHeader
        eyebrow="Patch optimizer"
        title="The 20-patch challenge"
        description="Give four strategies the same remediation budget and compare what each one chooses. The benchmark has no public 2026 answer key, so the evidence shown is historical held-out validation — not a promise of enterprise outcomes."
      />

      <Panel eyebrow="Budget" title="How many patches can you ship?">
        <div className="flex flex-wrap items-center gap-2 px-4 py-3.5">
          {BUDGETS.map((value) => (
            <button
              key={value}
              onClick={() => setBudget(value)}
              className={`rounded-lg border px-4 py-2 text-[13px] transition ${
                budget === value
                  ? "border-[rgba(212,175,55,0.65)] bg-[rgba(212,175,55,0.14)] text-ink"
                  : "border-[#e6dcc8] bg-alabaster text-muted hover:bg-[#fbf6ec]"
              }`}
            >
              <span className="mono">{value}</span> patches
            </button>
          ))}
          <span className="ml-auto text-[11.5px] text-muted">
            Each strategy receives exactly {budget} slots.
          </span>
        </div>
      </Panel>

      {error ? (
        <Panel className="mt-4">
          <p className="px-5 py-6 text-[13px] text-crimson">The optimizer could not reach the API. {error}</p>
        </Panel>
      ) : loading ? (
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-live="polite">
          {BUDGETS.map((value) => (
            <div key={value} className="card h-[132px] animate-pulse bg-[#f8f1e3]" />
          ))}
        </div>
      ) : data ? (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {STRATEGY_ORDER.map((key) => {
              const option = data.strategies[key];
              const overlap = data.overlap[key]?.model ?? 0;
              return (
                <button
                  key={key}
                  onClick={() => setStrategy(key)}
                  className={`card px-4 py-3.5 text-left transition ${
                    strategy === key ? "ring-2 ring-[rgba(212,175,55,0.55)]" : "hover:bg-[#fbf6ec]"
                  }`}
                >
                  <div className="eyebrow">{key === "model" ? "Our model" : "Baseline"}</div>
                  <div className="mt-1 font-display text-[19px] leading-tight text-ink">{option.label}</div>
                  <div className="mono mt-2 text-[17px] text-jade">
                    {key === "model" ? data.budget : overlap}
                    <span className="ml-1 text-[10.5px] font-normal text-muted">
                      {key === "model" ? "slots" : "shared with model"}
                    </span>
                  </div>
                  <p className="mt-1.5 text-[11.5px] leading-snug text-muted">{STRATEGY_COPY[key]}</p>
                </button>
              );
            })}
          </div>

          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
            <Panel
              eyebrow={`${current?.label ?? "Strategy"} · ${data.budget} slots`}
              title="Selected patch queue"
              action={<span className="text-[11px] text-muted">ordered by the strategy</span>}
              bodyClassName="overflow-x-auto"
            >
              {current && current.items.length > 0 ? (
                <table className="w-full min-w-[720px] border-collapse text-left">
                  <thead className="bg-[#fbf6ec]">
                    <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
                      <th className="px-4 py-2.5 font-medium">#</th>
                      <th className="px-3 py-2.5 font-medium">CVE</th>
                      <th className="px-3 py-2.5 font-medium">Severity</th>
                      <th className="px-3 py-2.5 text-right font-medium">CVSS</th>
                      <th className="px-3 py-2.5 text-right font-medium">EPSS</th>
                      <th className="px-3 py-2.5 text-right font-medium">Model rank</th>
                      <th className="px-3 py-2.5 font-medium">Vendor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {current.items.map((item, index) => (
                      <tr key={item.cve_id} className="border-t border-[#f0e8d9] row-hover">
                        <td className="mono px-4 py-2 text-[11.5px] text-muted">{index + 1}</td>
                        <td className="px-3 py-2">
                          <Link href={`/intelligence/${item.cve_id}`} className="mono text-[12px] text-ink hover:underline">
                            {item.cve_id}
                          </Link>
                          <span className="mt-0.5 block max-w-[330px] truncate text-[10.5px] text-muted">
                            {item.reason}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <span className={`chip ${severityChipClass[item.cvss3_severity as Severity] ?? ""}`}>
                            {item.cvss3_severity}
                          </span>
                        </td>
                        <td className="mono px-3 py-2 text-right text-[11.5px]">
                          {item.cvss3_score != null ? item.cvss3_score.toFixed(1) : "—"}
                        </td>
                        <td className="mono px-3 py-2 text-right text-[11.5px]">{formatEpss(item.epss_score ?? 0)}</td>
                        <td className="mono px-3 py-2 text-right text-[11.5px]">{item.rank}</td>
                        <td className="mono px-3 py-2 text-[11px] text-muted">{item.vendor}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <Empty title="No rows returned" body="The optimizer returned an empty strategy for this budget." />
              )}
            </Panel>

            <div className="space-y-4">
              <Panel eyebrow="Held-out 2025 · KEV outcome" title="What the benchmark measured">
                <div className="grid grid-cols-2 gap-2 p-4">
                  <StatCard label="Model hits@500" value={validation?.model_top500_hits ?? "—"} tone="jade" />
                  <StatCard label="Baseline union" value={validation?.baseline_union_hits ?? "—"} />
                  <StatCard label="Positives" value={validation?.positives ?? "—"} />
                  <StatCard label="Candidates" value={validation?.candidates?.toLocaleString("en-US") ?? "—"} tone="gold" />
                </div>
                <p className="border-t border-[#ece3d2] px-4 py-3 text-[11.5px] leading-relaxed text-muted">
                  The model recovered {validation?.missed_but_recovered_by_model ?? "—"} of the{" "}
                  {validation?.missed_by_all_baselines ?? "—"} exploited CVEs that every simple baseline missed.
                </p>
              </Panel>

              <Panel eyebrow={`Budget ${data.budget}`} title="Overlap with our model">
                <div className="space-y-2 p-4">
                  {STRATEGY_ORDER.filter((key) => key !== "model").map((key) => {
                    const shared = data.overlap[key]?.model ?? 0;
                    const only = data.unique[key]?.length ?? 0;
                    return (
                      <div key={key}>
                        <div className="flex items-center justify-between gap-2 text-[12px]">
                          <span className="text-ink">{data.strategies[key].label}</span>
                          <span className="mono text-muted">{shared}/{data.budget}</span>
                        </div>
                        <div className="mt-1 h-2 overflow-hidden rounded-full bg-[#f1e9da]">
                          <div
                            className="h-full rounded-full bg-gold-deep"
                            style={{ width: `${(shared / data.budget) * 100}%` }}
                          />
                        </div>
                        <p className="mt-1 text-[10.5px] text-muted">{only} unique CVE(s) not selected by our model.</p>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            </div>
          </div>

          <p className="mt-4 text-[11px] leading-relaxed text-muted">{data.note}</p>
        </>
      ) : null}
    </div>
  );
}

"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { HeldoutRow, ModelPerformance } from "@/lib/types";
import { PageHeader, Panel, StatCard } from "./ui";

interface AblationRow {
  model: string;
  "hits@500": number;
  "precision@50": number;
  average_precision: number;
  roc_auc: number;
}

interface BlendRow {
  models: string;
  uses_granite: boolean;
  w: number;
  "hits@500": number;
  "precision@50": number;
  average_precision: number;
}

interface BaselineTable {
  candidates: number;
  positives: number;
  baselines: { model: string; "hits@500": number; "precision@500": number }[];
}

const MODEL_LABELS: Record<string, string> = {
  cvss3_first: "CVSS 3.1 descending",
  epss_first: "EPSS descending",
  poc_then_epss: "Public exploit code, then EPSS",
  final_blend: "Shipped blend",
};

function prettyModel(name: string) {
  return MODEL_LABELS[name] ?? name.replaceAll("_", " ");
}

export default function ModelLab({ data }: { data: ModelPerformance }) {
  const held = [...data.heldout_2025.rows].sort((a, b) => b["hits@500"] - a["hits@500"]);
  const best = held[0];
  const single = (data.granite_ablation.single_models ?? []) as unknown as AblationRow[];
  const blends = (data.granite_ablation.blends ?? []) as unknown as BlendRow[];
  const backtest = data.baseline_reproduction["2025_jan_sep"] as BaselineTable | undefined;
  const importance = Array.isArray(data.permutation_importance)
    ? (data.permutation_importance as { feature: string; importance: number; std?: number }[])
        .filter((row) => row.importance > 0)
        .slice(0, 8)
        .reverse()
    : [];

  return (
    <div>
      <PageHeader
        eyebrow="Model laboratory"
        title="Measured performance, not a leaderboard promise"
        description="Every number here comes from a held-out Jan–Sep 2025 pool. The model was trained on 2024 only; 2026 was never used for selection. 52 positives is a small pool, so intervals are wide."
        action={
          <div className="card px-3.5 py-2 text-right">
            <div className="eyebrow">Protocol</div>
            <div className="mono mt-0.5 max-w-[230px] text-[12px] leading-snug text-ink">{data.protocol}</div>
          </div>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Training rows" value={data.train_rows.toLocaleString("en-US")} hint={`${data.train_positives} positives`} />
        <StatCard label="Held-out candidates" value={data.heldout_2025.positives ? "35,280" : "—"} hint={`${data.heldout_2025.positives} positives`} tone="gold" />
        <StatCard label="Best hits@500" value={best?.["hits@500"] ?? "—"} hint={best ? prettyModel(best.model) : "—"} tone="jade" />
        <StatCard label="Best ROC-AUC" value={best ? best.roc_auc.toFixed(3) : "—"} hint="Ranking discrimination, not calibration" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(0,1fr)]">
        <Panel eyebrow="Held-out 2025" title="Ranker comparison" bodyClassName="overflow-x-auto">
          <table className="w-full min-w-[660px] border-collapse text-left">
            <thead className="bg-[#fbf6ec]">
              <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
                <th className="px-4 py-2.5 font-medium">Ranker</th>
                <th className="px-3 py-2.5 text-right font-medium">hits@500</th>
                <th className="px-3 py-2.5 text-right font-medium">P@50</th>
                <th className="px-3 py-2.5 text-right font-medium">AP</th>
                <th className="px-3 py-2.5 text-right font-medium">ROC-AUC</th>
                <th className="px-3 py-2.5 text-right font-medium">95% interval</th>
              </tr>
            </thead>
            <tbody>
              {held.map((row: HeldoutRow) => (
                <tr key={row.model} className="border-t border-[#f0e8d9] row-hover">
                  <td className="px-4 py-2.5 text-[12.5px] text-ink">
                    {prettyModel(row.model)}
                    {row.model === "final_blend" ? <span className="ml-1.5 text-[10px] text-jade">shipped</span> : null}
                  </td>
                  <td className="mono px-3 py-2.5 text-right text-[12.5px] font-medium">{row["hits@500"]}</td>
                  <td className="mono px-3 py-2.5 text-right text-[12px]">{row["precision@50"].toFixed(2)}</td>
                  <td className="mono px-3 py-2.5 text-right text-[12px]">{row.average_precision.toFixed(3)}</td>
                  <td className="mono px-3 py-2.5 text-right text-[12px]">{row.roc_auc.toFixed(3)}</td>
                  <td className="mono px-3 py-2.5 text-right text-[11.5px] text-muted">
                    {row["bootstrap_hits@500"]
                      ? `${row["bootstrap_hits@500"]["p2.5"]}–${row["bootstrap_hits@500"]["p97.5"]}`
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t border-[#ece3d2] px-4 py-3 text-[11.5px] leading-relaxed text-muted">
            Hits@500 counts distinct exploited CVEs in the top 500. P@50 is precision in the top 50.
            The shipped blend leads the strongest baseline by four hits, but the bootstrap intervals
            overlap; the precision and AP gains are the more stable evidence.
          </p>
        </Panel>

        <Panel eyebrow="Feature ablation" title="Permutation importance">
          {importance.length > 0 ? (
            <div className="px-2 pb-3 pt-3">
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={importance} layout="vertical" margin={{ top: 4, right: 18, bottom: 2, left: 16 }}>
                  <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 9.5, fill: "#5b6373" }} axisLine={false} tickLine={false} />
                  <YAxis
                    type="category"
                    dataKey="feature"
                    width={120}
                    tick={{ fontSize: 9.5, fill: "#5b6373", fontFamily: "var(--font-mono)" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{ borderRadius: 10, border: "1px solid rgba(212,175,55,0.35)", background: "#fffdfa", fontSize: 12 }}
                  />
                  <Bar dataKey="importance" fill="#d4af37" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <p className="px-3 text-[11px] leading-relaxed text-muted">
                Permutation importance on the validation fold. EPSS × exploit-code interaction
                dominates; Granite is a real but secondary contributor.
              </p>
            </div>
          ) : (
            <p className="px-4 py-6 text-[12px] text-muted">No permutation table was produced.</p>
          )}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel eyebrow="IBM Granite" title="Measured ablation" bodyClassName="overflow-x-auto">
          <table className="w-full min-w-[430px] border-collapse text-left">
            <thead className="bg-[#fbf6ec]">
              <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
                <th className="px-4 py-2.5 font-medium">Model</th>
                <th className="px-3 py-2.5 text-right font-medium">hits@500</th>
                <th className="px-3 py-2.5 text-right font-medium">P@50</th>
                <th className="px-3 py-2.5 text-right font-medium">ROC-AUC</th>
              </tr>
            </thead>
            <tbody>
              {single.map((row) => (
                <tr key={row.model} className="border-t border-[#f0e8d9]">
                  <td className="px-4 py-2 text-[12px] text-ink">{row.model}</td>
                  <td className="mono px-3 py-2 text-right text-[12px]">{row["hits@500"]}</td>
                  <td className="mono px-3 py-2 text-right text-[12px]">{row["precision@50"].toFixed(2)}</td>
                  <td className="mono px-3 py-2 text-right text-[12px]">{row.roc_auc.toFixed(3)}</td>
                </tr>
              ))}
              {blends.map((row, index) => (
                <tr key={`${row.models}-${row.w}-${index}`} className="border-t border-[#f0e8d9] bg-[#fdf8ee]">
                  <td className="px-4 py-2 text-[11.5px] text-ink">
                    {row.models} · w={row.w} {row.uses_granite ? "· Granite" : "· no Granite"}
                  </td>
                  <td className="mono px-3 py-2 text-right text-[12px]">{row["hits@500"]}</td>
                  <td className="mono px-3 py-2 text-right text-[12px]">{row["precision@50"].toFixed(2)}</td>
                  <td className="mono px-3 py-2 text-right text-[12px]">—</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t border-[#ece3d2] px-4 py-3 text-[11.5px] leading-relaxed text-muted">
            Blends are rank-averaged. The no-Granite blend reaches 16 hits@500, the both-Granite
            blend 20, and the shipped mixed blend 22. Text similarity alone reaches ROC-AUC 0.742.
          </p>
        </Panel>

        <Panel eyebrow="Baseline reproduction" title="Jan–Sep 2025">
          {backtest ? (
            <>
              <div className="grid grid-cols-2 gap-2 p-4">
                <StatCard label="Candidates" value={backtest.candidates.toLocaleString("en-US")} />
                <StatCard label="Positives" value={backtest.positives} tone="gold" />
              </div>
              <table className="w-full border-collapse text-left">
                <tbody>
                  {backtest.baselines.map((row) => (
                    <tr key={row.model} className="border-t border-[#f0e8d9]">
                      <td className="px-4 py-2 text-[12px] text-ink">{prettyModel(row.model)}</td>
                      <td className="mono px-3 py-2 text-right text-[12px]">{row["hits@500"]} hits</td>
                      <td className="mono px-3 py-2 text-right text-[11.5px] text-muted">
                        P@500 {row["precision@500"].toFixed(3)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="border-t border-[#ece3d2] px-4 py-3 text-[11.5px] leading-relaxed text-muted">
                Reproduction of the pre-registered baselines on the same candidates and labels. The
                numbers are not re-selected after seeing the model.
              </p>
            </>
          ) : (
            <p className="px-4 py-6 text-[12px] text-muted">Baseline table unavailable.</p>
          )}
        </Panel>
      </div>

      <Panel className="mt-4" eyebrow="Selection protocol" title="Why this model shipped">
        <div className="grid gap-3 px-4 py-4 text-[12.5px] leading-relaxed text-ink md:grid-cols-2">
          <p>
            Grouped month folds inside 2024 chose the feature set and blend weight. Jan–Sep 2025 was
            held out for confirmation. 2026 was scored once and never used to tune anything.
          </p>
          <p>
            The blend is <span className="mono text-[11.5px]">histgb_lean + logit_core_g</span> at
            weight 0.2/0.8 on rank-averaged scores. Missing NIST review fields are excluded rather
            than imputed, because their absence encodes review attention.
          </p>
        </div>
      </Panel>

      <p className="mt-4 text-[11px] leading-relaxed text-muted">
        Calibration is not claimed: the fitted score is a ranking signal. Granite contributes a
        measured but secondary lift; no hosted generative model is configured.
      </p>
    </div>
  );
}

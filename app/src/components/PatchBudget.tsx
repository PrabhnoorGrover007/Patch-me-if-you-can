"use client";

import { useMemo, useState } from "react";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TmData } from "@/lib/timemachine";

const COLORS: Record<string, string> = {
  logistic_regression: "#9b111e",
  exploit_flags_then_epss: "#967214",
  epss_first: "#1b4d3e",
  cvss_first: "#2c3e50",
};
const MAX_K = 1000;

export default function PatchBudget({ data }: { data: TmData }) {
  const { methods } = data;
  const [k, setK] = useState(500);
  const [base, setBase] = useState("cvss_first");

  // Rank of every attacked 2025 CVE under each method
  const attackedRanks = useMemo(() => {
    const out: Record<string, number[]> = {};
    for (const m of methods) {
      out[m.key] = data.pool.filter((c) => c.kev).map((c) => c.ranks[m.key]).sort((x, y) => x - y);
    }
    return out;
  }, [data, methods]);

  const hits = (m: string, budget: number) => attackedRanks[m].filter((r) => r <= budget).length;
  // Smallest budget at which method m catches at least `target`
  const needed = (m: string, target: number) => (target === 0 ? 0 : attackedRanks[m][target - 1] ?? Infinity);

  const series = useMemo(() => {
    const rows = [];
    for (let x = 0; x <= MAX_K; x += 10) {
      const row: Record<string, number> = { k: x };
      for (const m of methods) row[m.key] = attackedRanks[m.key].filter((r) => r <= x).length;
      rows.push(row);
    }
    return rows;
  }, [attackedRanks, methods]);

  const ours = methods[0];
  const baseLabel = methods.find((m) => m.key === base)?.label ?? base;
  const baseHits = hits(base, k);
  const oursNeed = needed(ours.key, baseHits);
  const sorted = [...methods].sort((x, y) => hits(y.key, k) - hits(x.key, k));

  return (
    <div className="space-y-5">
      <div className="card px-5 py-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="eyebrow">Your patch budget</div>
            <div className="font-display text-[44px] leading-none text-ink">
              {k.toLocaleString()} <span className="text-[18px] text-muted">bugs you can fix</span>
            </div>
          </div>
          <div className="text-[12px] text-muted">
            out of {data.pool_size.toLocaleString()} new bugs in 2025 · {data.attacked_total} were later used by hackers
          </div>
        </div>
        <input type="range" min={10} max={MAX_K} step={10} value={k} onChange={(e) => setK(Number(e.target.value))}
          className="mt-4 w-full accent-[#9b111e]" aria-label="Patch budget" />
        <div className="mt-1 flex justify-between text-[11px] text-muted mono">
          <span>10</span>
          <button onClick={() => setK(data.k_scaled)} className="underline decoration-dotted">
            {data.k_scaled} = same share as the real top 500
          </button>
          <span>{MAX_K}</span>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {sorted.map((m) => {
          const h = hits(m.key, k);
          return (
            <div key={m.key} className="card px-4 py-3.5" style={{ borderTop: `4px solid ${COLORS[m.key]}` }}>
              <div className="eyebrow">{m.label}</div>
              <div className="mt-1.5 font-display text-[34px] leading-none" style={{ color: COLORS[m.key] }}>
                {h} <span className="text-[15px] text-muted">of {data.attacked_total} attacks stopped</span>
              </div>
              <div className="mt-1.5 text-[12px] text-muted">
                {h ? `1 real threat every ${Math.round(k / h)} patches` : "no real threats in this budget"}
              </div>
            </div>
          );
        })}
      </div>

      <div className="card px-5 py-4 text-[15px] leading-relaxed">
        <div className="mb-2 flex flex-wrap items-center gap-2 text-[13px] text-muted">
          Compare our model with
          <select value={base} onChange={(e) => setBase(e.target.value)}
            className="rounded-md border border-hairline bg-parchment px-2 py-0.5 text-ink">
            {methods.slice(1).map((m) => <option key={m.key} value={m.key}>{m.label}</option>)}
          </select>
        </div>
        {baseHits === 0 ? (
          <span>With {k} patches, {baseLabel} stops no attacks.</span>
        ) : oursNeed === Infinity ? (
          <span>{baseLabel} stops {baseHits} attacks with {k} patches. Our model never reaches that within the 2025 test set.</span>
        ) : oursNeed <= k ? (
          <span>
            {baseLabel} needs <b>{k.toLocaleString()}</b> patches to stop <b>{baseHits}</b> attacks.
            Our model stops the same number with <b className="text-crimson">{oursNeed.toLocaleString()}</b>
            {oursNeed < k && <> — <b>{Math.round((1 - oursNeed / k) * 100)}% less work</b></>}.
          </span>
        ) : (
          <span>
            Here {baseLabel} does better: it stops <b>{baseHits}</b> attacks with {k.toLocaleString()} patches; our model
            needs <b>{oursNeed.toLocaleString()}</b> for the same.
          </span>
        )}
      </div>

      <section className="card px-5 py-4">
        <div className="eyebrow mb-2">Attacks stopped as the budget grows</div>
        <ResponsiveContainer width="100%" height={340}>
          <LineChart data={series} margin={{ top: 8, right: 16, left: 0, bottom: 8 }}>
            <CartesianGrid stroke="#ece3d2" strokeDasharray="3 3" />
            <XAxis dataKey="k" tick={{ fontSize: 11 }} label={{ value: "patches", position: "insideBottomRight", offset: -4, fontSize: 11 }} />
            <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
            <Tooltip formatter={(v, name) => [v, methods.find((m) => m.key === name)?.label ?? name]} labelFormatter={(l) => `${l} patches`} />
            <ReferenceLine x={Math.round(k / 10) * 10} stroke="#d4af37" strokeWidth={2} />
            {methods.map((m) => (
              <Line key={m.key} type="stepAfter" dataKey={m.key} stroke={COLORS[m.key]} dot={false}
                strokeWidth={m.key === ours.key ? 3 : 2} isAnimationActive={false} />
            ))}
          </LineChart>
        </ResponsiveContainer>
        <div className="mt-2 flex flex-wrap gap-4 text-[12px]">
          {methods.map((m) => (
            <span key={m.key} style={{ color: COLORS[m.key] }}>━ {m.label}</span>
          ))}
        </div>
      </section>

      <p className="text-[12px] leading-relaxed text-muted">
        Historical check: trained on {data.train_period}, tested on {data.validation_period} ({data.pool_size.toLocaleString()} CVEs,
        {" "}{data.attacked_total} added to CISA KEV by {data.label_cutoff}). With this few attacked bugs, a gap of 1 to 3 is noise.
        Not the official 2026 score.
      </p>
    </div>
  );
}

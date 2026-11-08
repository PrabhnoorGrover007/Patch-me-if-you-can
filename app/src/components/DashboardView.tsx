"use client";

import Link from "next/link";
import { useState, useTransition } from "react";
import { addToQueue } from "@/lib/queue-actions";
import type { Cve, Meta } from "@/lib/types";
import CveDetail from "./CveDetail";
import CveTable from "./CveTable";
import QuickWinsMatrix from "./QuickWinsMatrix";
import SeverityDonut from "./SeverityDonut";
import { PageHeader, Panel, StatCard } from "./ui";

export default function DashboardView({
  cves,
  meta,
  queuedIds,
  initialCveId,
}: {
  cves: Cve[];
  meta: Meta;
  queuedIds: string[];
  initialCveId: string | null;
}) {
  const first = cves[0]?.cveId ?? "";
  const [selectedId, setSelectedId] = useState(
    initialCveId && cves.some((cve) => cve.cveId === initialCveId) ? initialCveId : first,
  );
  const [queued, setQueued] = useState<Set<string>>(() => new Set(queuedIds));
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [, startTransition] = useTransition();

  const selected = cves.find((cve) => cve.cveId === selectedId) ?? cves[0] ?? null;
  const validation = meta.validation;

  function handleAdd(cveId: string) {
    setPendingId(cveId);
    setQueued((previous) => new Set(previous).add(cveId));
    startTransition(async () => {
      try {
        await addToQueue(cveId);
      } finally {
        setPendingId(null);
      }
    });
  }

  return (
    <div>
      <PageHeader
        eyebrow="Working dashboard"
        title="What to fix first, and why"
        description="The 500 highest-priority CVEs of the 2026 scoreboard, ordered by the trained model. Every row carries what was known at its snapshot month — no post-review fields, no leakage."
        action={
          <div className="flex flex-wrap gap-2">
            <Link href="/explorer" className="btn btn-ghost">
              Search all 72,670 →
            </Link>
            <div className="card px-3.5 py-2 text-right">
              <div className="eyebrow">Cohort quick wins</div>
              <div className="mono mt-0.5 text-[16px] text-jade">
                {meta.quadrantCounts["Quick win"] ?? 0} high priority · low effort
              </div>
            </div>
          </div>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Scoreboard universe"
          value={meta.universe.toLocaleString("en-US")}
          hint="CVEs published Jan–Sep 2026, not on KEV by their cutoff"
        />
        <StatCard
          label="Submitted cohort"
          value={meta.cohort}
          hint={`${meta.quadrantCounts["Plan it"] ?? 0} planned · ${meta.quadrantCounts.Defer ?? 0} deferred`}
          tone="gold"
        />
        <StatCard
          label="Held-out hits@500"
          value={validation ? `${validation.hitsAt500} / ${validation.kScaled}` : "—"}
          hint={
            validation
              ? `${validation.liftPct >= 0 ? "+" : ""}${validation.liftPct}% vs ${validation.baselineName} (${validation.baselineHits})`
              : "Validation report unavailable"
          }
          tone="jade"
        />
        <StatCard
          label="Holdout ROC-AUC"
          value={validation ? validation.rocAuc.toFixed(3) : "—"}
          hint={
            validation
              ? `${validation.trainRows.toLocaleString("en-US")} train rows · ${validation.positives} held-out positives`
              : "Run models.train to regenerate"
          }
        />
      </div>

      <p className="mt-2 text-[11.5px] leading-relaxed text-muted">{meta.scoreNote}</p>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <Panel
          eyebrow="Priority × effort"
          title="Quick wins matrix"
          action={<span className="text-[11px] text-muted">click a point to inspect</span>}
        >
          <QuickWinsMatrix
            cves={cves}
            riskCut={meta.medians.risk}
            effortCut={meta.medians.effort}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </Panel>

        <Panel eyebrow="Cohort shape" title="Severity mix">
          <SeverityDonut counts={meta.severityCounts} />
          <div className="grid grid-cols-3 gap-2 border-t border-[#ece3d2] px-4 py-3">
            {[
              { label: "Exploit code", value: meta.exploitCoverage.withAnyExploit },
              { label: "Nuclei templates", value: meta.exploitCoverage.withNuclei },
              { label: "EPSS ≥ 10%", value: meta.exploitCoverage.epssAbove10pct },
            ].map((stat) => (
              <div key={stat.label}>
                <div className="mono text-[16px] text-ink">{stat.value}</div>
                <div className="text-[10.5px] leading-tight text-muted">{stat.label}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <Panel
          eyebrow="Ranked 1–500"
          title="Top priority queue"
          action={<span className="mono text-[11px] text-muted">submission file: top500.csv</span>}
          bodyClassName="h-[560px] min-h-0"
        >
          <CveTable cves={cves} selectedId={selectedId} onSelect={setSelectedId} />
        </Panel>

        <div className="xl:sticky xl:top-[8.5rem] xl:self-start">
          {selected ? (
            <CveDetail
              cve={selected}
              queued={queued.has(selected.cveId)}
              adding={pendingId === selected.cveId}
              onAdd={handleAdd}
            />
          ) : (
            <Panel title="No CVE selected">
              <p className="px-5 py-6 text-[13px] text-muted">Pick a row from the table.</p>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

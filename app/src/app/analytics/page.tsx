import AnalyticsView, { type SeverityMonth } from "@/components/AnalyticsView";
import { getDashboard } from "@/lib/data";
import { readCards } from "@/lib/queue-store";

export const dynamic = "force-dynamic";

export default async function AnalyticsPage() {
  const [{ cves, meta }, cards] = await Promise.all([getDashboard(), readCards()]);
  const cveMap = new Map(cves.map((cve) => [cve.cveId, cve]));

  const months = [...new Set(cves.map((cve) => cve.published.slice(0, 7)))].sort();
  const severityByMonth: SeverityMonth[] = months.map((month) => {
    const entry: SeverityMonth = { month, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNSCORED: 0 };
    for (const cve of cves) {
      if (cve.published.slice(0, 7) !== month) continue;
      if (cve.severity === "CRITICAL") entry.CRITICAL += 1;
      else if (cve.severity === "HIGH") entry.HIGH += 1;
      else if (cve.severity === "MEDIUM") entry.MEDIUM += 1;
      else if (cve.severity === "LOW") entry.LOW += 1;
      else entry.UNSCORED += 1;
    }
    return entry;
  });

  const statusCounts = { todo: 0, in_progress: 0, done: 0 };
  for (const card of cards) statusCounts[card.status] += 1;

  const openRisk = cards
    .filter((card) => card.status !== "done")
    .reduce((sum, card) => sum + (cveMap.get(card.cveId)?.priorityScore ?? 0), 0);

  const cohortRisk = cves.reduce((sum, cve) => sum + cve.priorityScore, 0);

  const durations = cards
    .filter((card) => card.status === "done" && card.doneAt)
    .map((card) => ({
      cveId: card.cveId,
      days:
        Math.round(
          ((Date.parse(card.doneAt as string) - Date.parse(card.addedAt)) / 86_400_000) * 10,
        ) / 10,
    }));

  const mttr = durations.length
    ? Math.round((durations.reduce((sum, entry) => sum + entry.days, 0) / durations.length) * 10) / 10
    : null;

  return (
    <AnalyticsView
      exposure={meta.exposureByMonth}
      severityByMonth={severityByMonth}
      statusCounts={statusCounts}
      openRisk={Math.round(openRisk)}
      cohortRisk={Math.round(cohortRisk)}
      mttr={mttr}
      mttrSeries={durations}
    />
  );
}

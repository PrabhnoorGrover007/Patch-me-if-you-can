import AnalyticsView, { type SeverityMonth } from "@/components/AnalyticsView";
import { getCves, getCveMap, getMeta } from "@/lib/data";
import { readCards } from "@/lib/queue-store";

export const dynamic = "force-dynamic";

export default async function AnalyticsPage() {
  const cves = getCves();
  const meta = getMeta();
  const cveMap = getCveMap();
  const cards = await readCards();

  const months = [...new Set(cves.map((c) => c.published.slice(0, 7)))].sort();
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
    .filter((c) => c.status !== "done")
    .reduce((sum, c) => sum + (cveMap.get(c.cveId)?.riskScore ?? 0), 0);

  const cohortRisk = cves.reduce((sum, c) => sum + c.riskScore, 0);

  const durations = cards
    .filter((c) => c.status === "done" && c.doneAt)
    .map((c) => ({
      cveId: c.cveId,
      days:
        Math.round(((Date.parse(c.doneAt as string) - Date.parse(c.addedAt)) / 86_400_000) * 10) / 10,
    }));

  const mttr = durations.length
    ? Math.round((durations.reduce((sum, d) => sum + d.days, 0) / durations.length) * 10) / 10
    : null;

  return (
    <AnalyticsView
      exposure={meta.exposureByMonth}
      severityByMonth={severityByMonth}
      statusCounts={statusCounts}
      openRisk={openRisk}
      cohortRisk={cohortRisk}
      mttr={mttr}
      mttrSeries={durations}
    />
  );
}

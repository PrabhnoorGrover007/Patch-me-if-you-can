import DashboardView from "@/components/DashboardView";
import { getCves, getMeta } from "@/lib/data";
import { readCards } from "@/lib/queue-store";

export const dynamic = "force-dynamic";

export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ cve?: string }>;
}) {
  const { cve } = await searchParams;
  const cards = await readCards();

  return (
    <DashboardView
      cves={getCves()}
      meta={getMeta()}
      queuedIds={cards.map((c) => c.cveId)}
      initialCveId={cve ?? null}
    />
  );
}

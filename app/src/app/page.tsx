import DashboardView from "@/components/DashboardView";
import { getDashboard } from "@/lib/data";
import { readCards } from "@/lib/queue-store";

export const dynamic = "force-dynamic";

export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ cve?: string }>;
}) {
  const { cve } = await searchParams;
  const [{ cves, meta }, cards] = await Promise.all([getDashboard(), readCards()]);

  return (
    <DashboardView
      cves={cves}
      meta={meta}
      queuedIds={cards.map((card) => card.cveId)}
      initialCveId={cve ?? null}
    />
  );
}

import KanbanBoard from "@/components/KanbanBoard";
import { PageHeader } from "@/components/ui";
import { getDashboard } from "@/lib/data";
import { readCards } from "@/lib/queue-store";

export const dynamic = "force-dynamic";

export default async function QueuePage() {
  const [{ cves, meta }, cards] = await Promise.all([getDashboard(), readCards()]);

  return (
    <div>
      <PageHeader
        eyebrow="Remediation queue"
        title="Patch board"
        description="Drag a card between columns to track the fix. Status changes are written on the server, so the board survives reloads and feeds the MTTR trend."
        action={
          <div className="card px-3.5 py-2 text-right">
            <div className="eyebrow">Cards on the board</div>
            <div className="mono mt-0.5 text-[16px] text-ink">
              {cards.length}
              <span className="ml-1.5 text-[11px] text-muted">of {meta.cohort}</span>
            </div>
          </div>
        }
      />

      <KanbanBoard cards={cards} cves={cves} />
    </div>
  );
}

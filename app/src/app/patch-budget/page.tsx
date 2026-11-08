import PatchBudget from "@/components/PatchBudget";
import { PageHeader } from "@/components/ui";
import { getTimeMachine } from "@/lib/timemachine";

export default function PatchBudgetPage() {
  const data = getTimeMachine();
  return (
    <>
      <PageHeader
        eyebrow="You can't patch them all"
        title="Patch Budget"
        description="Your team only has time to fix so many bugs. Slide the budget and see how many real 2025 attacks each list would have stopped."
      />
      <PatchBudget data={data} />
    </>
  );
}

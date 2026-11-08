import TimeMachine from "@/components/TimeMachine";
import { PageHeader } from "@/components/ui";
import { getTimeMachine } from "@/lib/timemachine";

export default function TimeMachinePage() {
  const data = getTimeMachine();
  return (
    <>
      <PageHeader
        eyebrow="Before the breach · 2025 replay"
        title="Time Machine"
        description={`Go back to January 2025 with a model that has only seen ${data.train_period} data. Press play and watch which bugs hackers actually used. Did they land on the list before the attack?`}
      />
      <TimeMachine data={data} />
    </>
  );
}

import BeatTheModel from "@/components/BeatTheModel";
import { PageHeader } from "@/components/ui";
import { getTimeMachine } from "@/lib/timemachine";

export default function BeatTheModelPage() {
  return (
    <>
      <PageHeader
        eyebrow="Line-up · 5 rounds"
        title="Beat the Model"
        description="Four suspects, one real criminal. Play security analyst against our model and the classic 'patch the highest severity' rule."
      />
      <BeatTheModel data={getTimeMachine()} />
    </>
  );
}

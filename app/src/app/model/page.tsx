import ModelLab from "@/components/ModelLab";
import { apiFetch } from "@/lib/api";
import type { ModelPerformance } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function ModelPage() {
  const data = await apiFetch<ModelPerformance>("/api/model/performance");
  return <ModelLab data={data} />;
}

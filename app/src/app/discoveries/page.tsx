import DiscoveryLab from "@/components/DiscoveryLab";
import { apiFetch } from "@/lib/api";
import type { DiscoveryResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function DiscoveriesPage() {
  const data = await apiFetch<DiscoveryResponse>("/api/discoveries");
  return <DiscoveryLab data={data} />;
}

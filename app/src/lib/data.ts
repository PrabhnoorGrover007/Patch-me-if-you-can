import { cache } from "react";
import { apiFetch } from "./api";
import type { Cve, CveBrief, DashboardPayload, Meta } from "./types";

/**
 * The command centre needs 500 hydrated records, not 72,670. FastAPI builds that
 * payload from ranked_2026.parquet, full_rankings.csv and the raw evidence tables.
 */
export const getDashboard = cache(async (): Promise<DashboardPayload> => {
  return apiFetch<DashboardPayload>("/api/dashboard");
});

export async function getCves(): Promise<Cve[]> {
  return (await getDashboard()).cves;
}

export async function getMeta(): Promise<Meta> {
  return (await getDashboard()).meta;
}

export async function getCve(cveId: string): Promise<Cve | null> {
  const cves = await getCves();
  return cves.find((cve) => cve.cveId.toUpperCase() === cveId.toUpperCase()) ?? null;
}

export async function getCveMap(): Promise<Map<string, Cve>> {
  return new Map((await getCves()).map((cve) => [cve.cveId, cve]));
}

/** Lightweight records for pickers and the upload inspector. */
export async function getBriefs(): Promise<CveBrief[]> {
  return (await getCves()).map((cve) => ({
    cveId: cve.cveId,
    rank: cve.rank,
    severity: cve.severity,
    riskScore: cve.riskScore,
    priorityScore: cve.priorityScore,
    description: cve.description.slice(0, 180),
  }));
}

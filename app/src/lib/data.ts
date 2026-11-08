import cvesJson from "@/data/cves.json";
import metaJson from "@/data/meta.json";
import type { Cve, CveBrief, Meta } from "./types";

const cves = cvesJson as unknown as Cve[];
const meta = metaJson as unknown as Meta;

export function getCves(): Cve[] {
  return cves;
}

export function getMeta(): Meta {
  return meta;
}

export function getCve(cveId: string): Cve | null {
  return cves.find((c) => c.cveId === cveId) ?? null;
}

export function getCveMap(): Map<string, Cve> {
  return new Map(cves.map((c) => [c.cveId, c]));
}

/** Lightweight records for pickers, so the chat tab ships ~60 KB instead of ~700 KB. */
export function getBriefs(): CveBrief[] {
  return cves.map((c) => ({
    cveId: c.cveId,
    rank: c.rank,
    severity: c.severity,
    riskScore: c.riskScore,
    description: c.description.slice(0, 180),
  }));
}

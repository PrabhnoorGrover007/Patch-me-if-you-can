import tmJson from "@/data/timemachine.json";

/** One 2025 CVE from the historical check (see timemachine.py). */
export type TmCve = {
  id: string;
  listed: string; // end of publish month: the day it could join a list
  kev: string | null; // date CISA added it to KEV (only if attacked by 2025-12-31)
  cvss: number;
  why: string;
  desc: string;
  epss_pct: number; // EPSS percentile within its snapshot month (0-1)
  code: string[]; // public exploit code sources known at the snapshot
  ranks: Record<string, number>; // rank among all 2025 test CVEs, per method
};

export type TmMethod = { key: string; label: string; hits_at_500: number; hits_at_k_scaled: number };

export type TmData = {
  generated_at: string;
  train_period: string;
  validation_period: string;
  pool_size: number;
  attacked_total: number;
  k_scaled: number;
  label_cutoff: string;
  methods: TmMethod[];
  pool: TmCve[];
  lists: Record<string, number[]>; // method -> pool indexes in rank order (top 500)
};

export function getTimeMachine(): TmData {
  return tmJson as unknown as TmData;
}

export const dayNum = (iso: string) => Math.floor(Date.parse(iso + "T00:00:00Z") / 86_400_000);
export const isoOf = (day: number) => new Date(day * 86_400_000).toISOString().slice(0, 10);

// The ONLY place numbers come from. Anything missing shows "[TBD]" on screen.
import results from "../data/results.json";
import assetsJson from "./assets.json";

export type ChartRow = { label: string; rate: number | null };
export type Results = {
  cvss_hits: number | null;
  epss_hits: number | null;
  code_then_epss_hits?: number | null;
  model_hits: number | null;
  finding: string;
  chart_title?: string;
  chart: ChartRow[];
  leaked_columns: { column: string; reason: string }[];
  team: string[];
};

export const R = results as unknown as Results;
export const assets = assetsJson as Record<string, boolean>;

export const TBD = "[TBD]";

/** Show a value exactly as stored; never round or guess. */
export function show(v: number | string | null | undefined): string {
  if (v === null || v === undefined) return TBD;
  if (typeof v === "string" && v.trim() === "") return TBD;
  return String(v);
}

export const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/** List every value the video needed but did not find (printed when rendering). */
export function missingValues(): string[] {
  const m: string[] = [];
  if (!isNum(R.cvss_hits)) m.push("cvss_hits");
  if (!isNum(R.epss_hits)) m.push("epss_hits");
  if (!isNum(R.model_hits)) m.push("model_hits");
  if (!R.finding?.trim()) m.push("finding");
  if (!R.chart?.length || R.chart.some((r) => !isNum(r.rate) || !r.label)) m.push("chart");
  if (!R.leaked_columns?.length) m.push("leaked_columns");
  if (!R.team?.length) m.push("team");
  return m;
}

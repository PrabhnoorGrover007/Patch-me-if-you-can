const BASE = import.meta.env.VITE_API_BASE ?? "";

export async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export interface VulnRow {
  cve_id: string;
  rank: number;
  risk_score: number;
  risk_percentile: number;
  snapshot_month: string;
  published: string;
  cvss3_score: number | null;
  cvss3_severity: string | null;
  epss_score: number | null;
  poc_github: number;
  vendor: string;
  cwe_top: string;
  reason: string;
}

export interface VulnPage {
  total: number;
  page: number;
  size: number;
  pages: number;
  items: VulnRow[];
}

export interface DiscoveryChart {
  x: (string | number)[];
  y: number[];
  ci_low?: number[];
  ci_high?: number[];
  rate?: number[];
  n?: number[];
  [key: string]: unknown;
}

export interface Discovery {
  id: string;
  type: string;
  title: string;
  finding: string;
  stat: string;
  n: number;
  chart: DiscoveryChart;
}

export interface HeldoutRow {
  model: string;
  "hits@500"?: number;
  "hits@100"?: number;
  "precision@50"?: number;
  "precision@500"?: number;
  "recall@500"?: number;
  average_precision: number;
  roc_auc: number | null;
  "bootstrap_hits@500"?: { mean: number; "p2.5": number; "p97.5": number };
}

export interface Perf {
  protocol: string;
  label: string;
  train_rows: number;
  train_positives: number;
  selection: Record<string, { features: number; oof_2024: { "hits@500": number } }>;
  heldout_2025: { positives: number; rows: HeldoutRow[] };
  selected_blend: { pair: string; w_b: number; "hits@500": number };
  permutation_importance: { feature: string; importance: number; std: number }[];
}

export interface Overview {
  analyzed: number;
  high_priority: number;
  mean_cvss_all: number;
  mean_cvss_top500: number;
  epss_coverage: number;
  exploit_code_share: number;
  risk_distribution: { bin: number; count: number }[];
  severity_mix: Record<string, number>;
  top_vendors: Record<string, number>;
  top_cwe: Record<string, number>;
  snapshot_months: Record<string, number>;
  headline_model: HeldoutRow;
  headline_baseline: HeldoutRow;
  discoveries: { title: string; finding: string }[];
  submission: Record<string, unknown>;
}

export interface VulnDetail {
  cve_id: string;
  description: string;
  published: string;
  snapshot_month: string;
  rank: number;
  risk_score: number;
  risk_percentile: number;
  cvss3_score: number | null;
  cvss3_severity: string | null;
  epss_score: number | null;
  poc_github: number;
  vendor: string;
  cwe_top: string;
  cwe_name: string;
  reason: string;
  drivers: string;
  technical: Record<string, number | null>;
  contributions: { feature: string; contribution: number }[];
  remediation_priority: string;
  disclaimer: string;
}

export const fmt = {
  pct: (v: number | null | undefined, digits = 2) => (v == null ? "—" : `${(v * 100).toFixed(digits)}%`),
  num: (v: number | null | undefined, digits = 2) => (v == null ? "—" : v.toFixed(digits)),
  int: (v: number | null | undefined) => (v == null ? "—" : v.toLocaleString()),
};

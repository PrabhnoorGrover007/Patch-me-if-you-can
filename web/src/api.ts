const BASE = import.meta.env.VITE_API_BASE ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
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

export function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

export function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
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

export interface PatchItem {
  cve_id: string;
  rank: number;
  risk_score: number | null;
  cvss3_score: number | null;
  cvss3_severity: string | null;
  epss_score: number | null;
  poc_github: number | null;
  n_exploit_sources: number | null;
  vendor: string;
  cwe_top: string;
  reason: string;
}

export interface PatchResult {
  budget: number;
  strategies: Record<string, { label: string; count: number; items: PatchItem[] }>;
  overlap: Record<string, Record<string, number>>;
  unique: Record<string, string[]>;
  historical_validation: {
    pool?: string;
    candidates?: number;
    positives?: number;
    model_top500_hits?: number;
    baseline_union_hits?: number;
    missed_by_all_baselines?: number;
    missed_but_recovered_by_model?: number;
  };
  note: string;
}

export interface SimilarItem {
  cve_id: string;
  similarity: number;
  rank: number;
  risk_score: number;
  cvss3_score: number | null;
  epss_score: number | null;
  vendor: string;
  cwe_top: string;
}

export interface SimilarResponse {
  cve_id: string;
  source: string;
  dim: number | null;
  note: string;
  items: SimilarItem[];
}

export interface TimelinePoint {
  month: string;
  epss: number | null;
  in_kev: boolean;
  exploit_sources: number;
}

export interface TimelineResponse {
  cve_id: string;
  published: string;
  snapshot_month: string | null;
  kev_added: string | null;
  points: TimelinePoint[];
  note: string;
}

export interface DNAEvidence {
  characteristic: string;
  source_text: string;
}

export interface DNA {
  attack_surface: string;
  authentication_required: boolean | null;
  remote_exploitation_possible: boolean | null;
  code_execution: boolean | null;
  privilege_escalation: boolean | null;
  information_disclosure: boolean | null;
  vulnerability_class: string;
  evidence: DNAEvidence[];
  uncertainty: string[];
  method: string;
}

export interface AnalyzeResponse {
  cve_id: string;
  source: string;
  embedding_model: string;
  generative_model: string | null;
  extracted: DNA;
  verified: {
    cvss3_score: number | null;
    cvss3_severity: string | null;
    epss_score: number | null;
    cwe_top: string;
    cwe_name: string;
    technical: Record<string, number | null>;
  };
  analogs: SimilarItem[];
  note: string;
}

export interface ChatResponse {
  cve_id?: string;
  answer: string;
  source: string;
  generative_model: string | null;
  citations: string[];
}

export interface ProductRow {
  product_id: string;
  vendor: string;
  vulnerabilities: number;
  cpe_product_rows: number;
}

export interface ProductPage {
  total: number;
  page: number;
  size: number;
  pages: number;
  note: string;
  items: ProductRow[];
}

export interface ProductVulnPage {
  product_id: string;
  total: number;
  page: number;
  size: number;
  pages: number;
  items: Omit<VulnRow, "risk_percentile" | "snapshot_month" | "published">[];
}

export const fmt = {
  pct: (v: number | null | undefined, digits = 2) => (v == null ? "—" : `${(v * 100).toFixed(digits)}%`),
  num: (v: number | null | undefined, digits = 2) => (v == null ? "—" : v.toFixed(digits)),
  int: (v: number | null | undefined) => (v == null ? "—" : v.toLocaleString()),
};

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNSCORED";

export type Quadrant = "Quick win" | "Plan it" | "Fill-in" | "Defer";

export type EffortTier = "Low" | "Medium" | "High";

export interface Cwe {
  id: string;
  name: string;
}

export interface Product {
  type: string;
  vendor: string;
  product: string;
  version: string;
}

export interface ExploitFlags {
  exploitdb: number;
  metasploit: number;
  nuclei: number;
  pocGithub: number;
}

export interface Cve {
  rank: number;
  cveId: string;
  published: string;
  snapshotMonth: string;
  description: string;
  cvssScore: number | null;
  severity: Severity;
  cvssVector: string;
  attackVector: string;
  attackComplexity: string;
  privilegesRequired: string;
  userInteraction: string;
  epss: number;
  epssPct: number;
  flags: ExploitFlags;
  exploitCount: number;
  /** Raw fitted model probability × 100. Kept separate from priority. */
  riskScore: number;
  /** Raw fitted model probability in [0,1]. */
  riskProbability: number;
  /** Rank-normalised priority within the submitted cohort, 0–100. */
  priorityScore: number;
  effortHours: number;
  effortTier: EffortTier;
  riskFactors: string[];
  cwes: Cwe[];
  products: Product[];
  assigner: string;
  assignerLabel: string;
  keywords: string[];
  quadrant: Quadrant;
}

export interface Validation {
  model: string;
  hitsAt500: number;
  baselineName: string;
  baselineHits: number;
  precisionAt50: number;
  precisionAt100: number;
  liftPct: number;
  rocAuc: number;
  averagePrecision: number;
  validationRows: number;
  positives: number;
  trainRows: number;
  trainPositives: number;
  kScaled: number;
  bootstrap?: { mean: number; "p2.5": number; "p97.5": number; n: number };
  generatedAt: string;
}

export interface MonthExposure {
  month: string;
  published: number;
  openRisk: number;
  criticalOpen: number;
}

export interface Meta {
  generatedAt: string;
  universe: number;
  cohort: number;
  medians: { risk: number; effort: number };
  severityCounts: Record<string, number>;
  effortCounts: Record<string, number>;
  quadrantCounts: Record<string, number>;
  exposureByMonth: MonthExposure[];
  exploitCoverage: { withAnyExploit: number; withNuclei: number; epssAbove10pct: number };
  validation: Validation | null;
  sources: string[];
  scoreNote: string;
  modelProbabilityRange: { min: number; max: number };
  disclaimer: string;
}

export interface DashboardPayload {
  cves: Cve[];
  meta: Meta;
}

export interface CveBrief {
  cveId: string;
  rank: number;
  severity: Severity;
  riskScore: number;
  priorityScore: number;
  description: string;
}

export type QueueStatus = "todo" | "in_progress" | "done";

export interface QueueCard {
  cveId: string;
  status: QueueStatus;
  addedAt: string;
  updatedAt: string;
  doneAt: string | null;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** Only IBM Granite / grounded retrieval is used by this build. */
export type AiProvider = "granite";

export interface AiResult {
  text: string;
  /** "grounded" means FastAPI assembled the answer from project evidence. */
  source: "model" | "grounded" | "offline";
  provider?: AiProvider;
  model?: string;
  error?: string;
}

/* ------------------------------------------------------------------ */
/* Paginated explorer / product endpoints                              */
/* ------------------------------------------------------------------ */

export interface VulnListItem {
  cve_id: string;
  rank: number;
  risk_score: number;
  risk_percentile: number;
  snapshot_month: string;
  published: string;
  cvss3_score: number | null;
  cvss3_severity: string;
  epss_score: number | null;
  poc_github: number;
  vendor: string;
  cwe_top: string;
  reason: string;
  description: string;
}

export interface VulnPage {
  total: number;
  page: number;
  size: number;
  pages: number;
  items: VulnListItem[];
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
  cvss3_severity: string;
  epss_score: number | null;
  poc_github: number;
  vendor: string;
  cwe_top: string;
  cwe_name: string;
  reason: string;
  drivers: string;
  technical: {
    attack_vector: number | null;
    privileges_required: number | null;
    user_interaction: number | null;
    n_exploit_sources: number | null;
    vendor_kev_prior: number | null;
    granite_similarity: number | null;
  };
  contributions: { feature: string; contribution: number }[];
  remediation_priority: string;
  disclaimer: string;
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

export interface GraniteAnalysis {
  cve_id: string;
  source: string;
  embedding_model: string;
  generative_model: string | null;
  extracted: {
    attack_surface: string;
    authentication_required: boolean | null;
    remote_exploitation_possible: boolean | null;
    code_execution: boolean | null;
    privilege_escalation: boolean | null;
    information_disclosure: boolean | null;
    vulnerability_class: string;
    evidence: { characteristic: string; source_text: string }[];
    uncertainty: string[];
    method: string;
  };
  verified: {
    cvss3_score: number | null;
    cvss3_severity: string;
    epss_score: number | null;
    cwe_top: string;
    cwe_name: string;
    technical: VulnDetail["technical"];
  };
  analogs: SimilarItem[];
  note: string;
}

export interface ChatResponse {
  cve_id?: string;
  answer: string;
  source: string;
  generative_model: string | null;
  generative_configured?: boolean;
  generative_provider?: string | null;
  generation_error?: string | null;
  generation_note?: string;
  citations: string[];
}

/* ------------------------------------------------------------------ */
/* Discovery / model / patch / product payloads                        */
/* ------------------------------------------------------------------ */

export interface DiscoveryChart {
  x?: (string | number)[];
  y?: number[];
  rate?: number[];
  n?: number[];
  ci_low?: number[];
  ci_high?: number[];
  positives?: number;
  missed_ids?: string[];
  median_days?: number[];
  share_30d?: number[];
  share_90d?: number[];
}

export interface Discovery {
  id: string;
  type: "bar" | "line" | string;
  title: string;
  finding: string;
  stat: string;
  n: number;
  chart: DiscoveryChart;
}

export interface DiscoveryResponse {
  cohort: string | Record<string, unknown>;
  discoveries: Discovery[];
  meta: Record<string, string | number>;
}

export interface HeldoutRow {
  model: string;
  n_candidates: number;
  positives: number;
  "precision@50": number;
  "precision@100": number;
  "precision@250": number;
  "precision@500": number;
  "hits@500": number;
  "recall@500": number;
  average_precision: number;
  roc_auc: number;
  "bootstrap_hits@500"?: { mean: number; "p2.5": number; "p97.5": number; n: number };
}

export interface ModelPerformance {
  protocol: string;
  label: string;
  train_rows: number;
  train_positives: number;
  selection: Record<string, { features: number; feature_set: string; oof_2024: { "hits@500": number; "hits@100": number; candidates: number; positives: number } }>;
  heldout_2025: { positives: number; rows: HeldoutRow[] };
  selected_blend: Record<string, unknown>;
  baseline_reproduction: Record<string, unknown>;
  granite_ablation: {
    pool?: string;
    single_models?: Record<string, unknown>;
    blends?: Record<string, unknown>;
  };
  permutation_importance: Record<string, number> | { features?: string[]; importance?: number[] } | Record<string, unknown>;
}

export interface PatchItem {
  cve_id: string;
  rank: number;
  risk_score: number;
  cvss3_score: number | null;
  cvss3_severity: string;
  epss_score: number | null;
  poc_github: number | null;
  n_exploit_sources: number | null;
  vendor: string;
  cwe_top: string;
  reason: string;
}

export interface PatchResponse {
  budget: number;
  strategies: Record<"cvss" | "epss" | "exploit_then_epss" | "model", { label: string; count: number; items: PatchItem[] }>;
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
    recovered_ids?: string[];
  };
  note: string;
}

export interface ProductItem {
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
  items: ProductItem[];
}

export interface ProductVulnPage {
  product_id: string;
  total: number;
  page: number;
  size: number;
  pages: number;
  items: {
    cve_id: string;
    rank: number;
    risk_score: number;
    cvss3_score: number | null;
    cvss3_severity: string;
    epss_score: number | null;
    vendor: string;
    cwe_top: string;
    reason: string;
  }[];
}

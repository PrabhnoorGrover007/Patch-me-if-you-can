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
  riskScore: number;
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
  hitsAt274: number;
  hitsAt500: number;
  baselineName: string;
  baselineHits: number;
  precisionAt274: number;
  liftPct: number;
  rocAuc: number;
  averagePrecision: number;
  validationRows: number;
  positives: number;
  trainRows: number;
  trainPositives: number;
  kScaled: number;
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
}

export interface CveBrief {
  cveId: string;
  rank: number;
  severity: Severity;
  riskScore: number;
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

export type AiProvider = "gemini" | "watsonx";

export interface AiResult {
  text: string;
  /** "model" when a hosted model answered, "offline" when the local explainer did. */
  source: "model" | "offline";
  provider?: AiProvider;
  model?: string;
  error?: string;
}

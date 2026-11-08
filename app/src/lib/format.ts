import type { Quadrant, Severity } from "./types";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** Locale-independent date formatting so server and client markup always agree. */
export function formatDate(iso: string): string {
  const [y, m, d] = iso.split("-");
  if (!y || !m || !d) return iso;
  return `${MONTHS[Number(m) - 1]} ${Number(d)}, ${y}`;
}

export function formatMonth(ym: string): string {
  const [y, m] = ym.split("-");
  if (!y || !m) return ym;
  return `${MONTHS[Number(m) - 1]} ${y}`;
}

export function formatEpss(epss: number): string {
  const pct = epss * 100;
  if (pct >= 10) return `${pct.toFixed(0)}%`;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  return `${pct.toFixed(2)}%`;
}

export function percentileLabel(pct: number): string {
  const top = Math.max(1, Math.round((1 - pct) * 100));
  return `top ${top}% of month`;
}

export const severityChipClass: Record<Severity, string> = {
  CRITICAL: "border-crimson bg-crimson text-[#fffdfa]",
  HIGH: "border-[rgba(212,175,55,0.55)] bg-[rgba(212,175,55,0.18)] text-gold-deep",
  MEDIUM: "border-[rgba(212,175,55,0.35)] bg-[rgba(212,175,55,0.09)] text-gold-deep",
  LOW: "border-[rgba(27,77,62,0.28)] bg-[rgba(27,77,62,0.09)] text-jade",
  NONE: "border-hairline bg-pressed text-muted",
  UNSCORED: "border-hairline bg-pressed text-muted",
};

export const severityDot: Record<Severity, string> = {
  CRITICAL: "bg-crimson",
  HIGH: "bg-gold",
  MEDIUM: "bg-gold-deep",
  LOW: "bg-jade",
  NONE: "bg-muted",
  UNSCORED: "bg-muted",
};

export const quadrantColor: Record<Quadrant, string> = {
  "Quick win": "#1b4d3e",
  "Plan it": "#9b111e",
  "Fill-in": "#d4af37",
  Defer: "#5b6b7f",
};

export const quadrantChipClass: Record<Quadrant, string> = {
  "Quick win": "border-[rgba(27,77,62,0.3)] bg-[rgba(27,77,62,0.1)] text-jade",
  "Plan it": "border-[rgba(155,17,30,0.28)] bg-[rgba(155,17,30,0.08)] text-crimson",
  "Fill-in": "border-[rgba(212,175,55,0.4)] bg-[rgba(212,175,55,0.12)] text-gold-deep",
  Defer: "border-[rgba(91,107,127,0.3)] bg-[rgba(91,107,127,0.1)] text-steel",
};

export const STATUS_LABEL: Record<string, string> = {
  todo: "To do",
  in_progress: "In progress",
  done: "Done",
};

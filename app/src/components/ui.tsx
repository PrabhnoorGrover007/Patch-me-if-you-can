import type { ReactNode } from "react";
import { quadrantChipClass, severityChipClass } from "@/lib/format";
import type { AiResult, Quadrant, Severity } from "@/lib/types";

export function Panel({
  title,
  eyebrow,
  action,
  children,
  className = "",
  bodyClassName = "",
}: {
  title?: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`card overflow-hidden ${className}`}>
      {(title || eyebrow || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-[#ece3d2] px-5 py-3.5">
          <div className="min-w-0">
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            {title && <h2 className="mt-0.5 truncate text-[19px] leading-tight text-ink">{title}</h2>}
          </div>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

const TONES = {
  ink: "text-ink",
  crimson: "text-crimson",
  jade: "text-jade",
  gold: "text-gold-deep",
} as const;

export function StatCard({
  label,
  value,
  hint,
  tone = "ink",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: keyof typeof TONES;
}) {
  return (
    <div className="card px-4 py-3.5">
      <div className="eyebrow">{label}</div>
      <div className={`mt-1.5 font-display text-[27px] leading-none ${TONES[tone]}`}>{value}</div>
      {hint && <div className="mt-1.5 text-[12px] leading-snug text-muted">{hint}</div>}
    </div>
  );
}

export function SeverityChip({ severity }: { severity: Severity }) {
  return <span className={`chip ${severityChipClass[severity]}`}>{severity}</span>;
}

export function QuadrantChip({ quadrant }: { quadrant: Quadrant }) {
  return <span className={`chip ${quadrantChipClass[quadrant]}`}>{quadrant}</span>;
}

export function SourceBadge({ result }: { result: AiResult }) {
  const grounded = result.source === "grounded" || result.source === "model";
  const label = grounded
    ? result.provider === "granite"
      ? result.source === "model"
        ? "IBM Granite · generated"
        : "IBM Granite · grounded"
      : "Model evidence"
    : "Backend unavailable";
  return (
    <span
      className={`chip ${
        grounded
          ? "border-[rgba(27,77,62,0.3)] bg-[rgba(27,77,62,0.1)] text-jade"
          : "border-[rgba(155,17,30,0.28)] bg-[rgba(155,17,30,0.08)] text-crimson"
      }`}
      title={
        grounded
          ? `Evidence assembled from ${result.model ?? "project artefacts"}`
          : "The FastAPI evidence service did not answer. No fallback text was fabricated."
      }
    >
      {label}
    </span>
  );
}

export function Empty({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-12 text-center">
      <div className="grid h-10 w-10 place-items-center rounded-full border border-gold/50 bg-[rgba(212,175,55,0.1)]">
        <span className="font-display text-[16px] text-gold-deep">✳</span>
      </div>
      <p className="font-display text-[17px] text-ink">{title}</p>
      <p className="max-w-sm text-[13px] leading-relaxed text-muted">{body}</p>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-3xl">
        <div className="eyebrow">{eyebrow}</div>
        <h1 className="mt-1 text-[32px] leading-tight text-ink">{title}</h1>
        <p className="mt-1.5 text-[13.5px] leading-relaxed text-muted">{description}</p>
      </div>
      {action}
    </div>
  );
}

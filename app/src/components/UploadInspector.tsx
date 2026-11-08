"use client";

import Link from "next/link";
import { useMemo, useRef, useState } from "react";
import { formatEpss, severityChipClass } from "@/lib/format";
import type { CveBrief } from "@/lib/types";
import { Panel, PageHeader, StatCard } from "./ui";

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c !== "\r") field += c;
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

interface Report {
  fileName: string;
  header: string[];
  headerOk: boolean;
  total: number;
  invalid: number;
  duplicates: number;
  unknown: number;
  rows: { id: string; inCohort: boolean; malformed: boolean }[];
}

export default function UploadInspector({ known }: { known: CveBrief[] }) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const knownMap = useMemo(() => new Map(known.map((k) => [k.cveId, k])), [known]);

  async function handleFile(file: File) {
    setError(null);
    setReport(null);

    if (file.size > 5 * 1024 * 1024) {
      setError("That file is larger than 5 MB. The submission is a single-column list of 500 ids.");
      return;
    }

    const text = await file.text();
    const rows = parseCsv(text).filter((r) => r.some((cell) => cell.trim() !== ""));
    if (rows.length === 0) {
      setError("The file is empty.");
      return;
    }

    const header = rows[0].map((h) => h.trim());
    const cveIndex = header.findIndex((h) => h.toLowerCase() === "cve_id");
    if (cveIndex === -1) {
      setReport({ fileName: file.name, header, headerOk: false, total: 0, invalid: 0, duplicates: 0, unknown: 0, rows: [] });
      setError("Missing the required `cve_id` column. Export the submission with a single `cve_id` header.");
      return;
    }

    const seen = new Set<string>();
    let duplicates = 0;
    let invalid = 0;
    let unknown = 0;
    const parsed: Report["rows"] = [];

    for (const r of rows.slice(1)) {
      const id = (r[cveIndex] ?? "").trim();
      if (!id) continue;
      const malformed = !/^CVE-\d{4}-\d{4,}$/i.test(id);
      if (malformed) invalid++;
      if (seen.has(id)) duplicates++;
      seen.add(id);
      const inCohort = knownMap.has(id);
      if (!inCohort && !malformed) unknown++;
      parsed.push({ id, inCohort, malformed });
    }

    setReport({
      fileName: file.name,
      header,
      headerOk: true,
      total: parsed.length,
      invalid,
      duplicates,
      unknown,
      rows: parsed,
    });
  }

  const passed =
    report?.headerOk && report.invalid === 0 && report.duplicates === 0 && report.total > 0;

  return (
    <div>
      <PageHeader
        eyebrow="Dataset inspection"
        title="Check a submission before it ships"
        description="Drop a CSV in and the validator checks the column contract, duplicate ids, malformed identifiers, and whether each CVE is actually inside the ranked cohort."
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <Panel eyebrow="Ingest" title="Submission file">
          <div className="p-4">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                const file = e.dataTransfer.files?.[0];
                if (file) void handleFile(file);
              }}
              onClick={() => inputRef.current?.click()}
              className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-dashed px-6 py-12 text-center transition-colors ${
                dragging
                  ? "border-gold bg-[rgba(212,175,55,0.1)]"
                  : "border-[#d8cdb8] bg-[#fbf6ec] hover:bg-[#f8f1e3]"
              }`}
            >
              <span className="grid h-11 w-11 place-items-center rounded-full border border-[rgba(212,175,55,0.5)] bg-alabaster font-display text-[18px] text-gold-deep">
                ↑
              </span>
              <p className="font-display text-[18px] text-ink">Drop the CSV here</p>
              <p className="max-w-sm text-[12.5px] leading-relaxed text-muted">
                Required header: <span className="mono text-ink">cve_id</span>. Extra columns are
                ignored. Nothing is uploaded anywhere — parsing happens in this browser tab.
              </p>
              <input
                ref={inputRef}
                type="file"
                accept=".csv,text/csv"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void handleFile(file);
                }}
              />
            </div>

            {error && (
              <p className="mt-3 rounded-lg border border-[rgba(155,17,30,0.3)] bg-[rgba(155,17,30,0.06)] px-3 py-2 text-[12.5px] text-crimson">
                {error}
              </p>
            )}

            {report && (
              <div className="mt-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="mono text-[12px] text-ink">{report.fileName}</div>
                  <span
                    className={`chip ${
                      passed
                        ? "border-[rgba(27,77,62,0.3)] bg-[rgba(27,77,62,0.1)] text-jade"
                        : "border-[rgba(155,17,30,0.28)] bg-[rgba(155,17,30,0.08)] text-crimson"
                    }`}
                  >
                    {passed ? "Contract passed" : "Needs attention"}
                  </span>
                </div>

                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <StatCard label="Rows" value={report.total} />
                  <StatCard label="Duplicates" value={report.duplicates} tone={report.duplicates ? "crimson" : "jade"} />
                  <StatCard label="Malformed" value={report.invalid} tone={report.invalid ? "crimson" : "jade"} />
                  <StatCard label="Outside top 500" value={report.unknown} tone={report.unknown ? "gold" : "jade"} />
                </div>

                <div className="mt-3 overflow-hidden rounded-lg border border-[#e8dfd1]">
                  <table className="w-full border-collapse text-left">
                    <thead className="bg-[#fbf6ec]">
                      <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
                        <th className="px-3 py-2 font-medium">cve_id</th>
                        <th className="px-3 py-2 font-medium">Rank</th>
                        <th className="px-3 py-2 font-medium">Severity</th>
                        <th className="px-3 py-2 text-right font-medium">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.rows.slice(0, 12).map((r, i) => {
                        const brief = knownMap.get(r.id);
                        return (
                          <tr key={`${r.id}-${i}`} className="border-t border-[#f0e8d9]">
                            <td className="mono px-3 py-1.5 text-[12px]">
                              {r.malformed ? (
                                <span className="text-crimson">{r.id} (malformed)</span>
                              ) : brief ? (
                                <Link href={`/?cve=${r.id}`} className="text-ink hover:underline">
                                  {r.id}
                                </Link>
                              ) : (
                                <span className="text-muted">{r.id}</span>
                              )}
                            </td>
                            <td className="mono px-3 py-1.5 text-[12px] text-muted">
                              {brief?.rank ?? "—"}
                            </td>
                            <td className="px-3 py-1.5">
                              {brief ? (
                                <span className={`chip ${severityChipClass[brief.severity]}`}>
                                  {brief.severity}
                                </span>
                              ) : (
                                <span className="text-[11px] text-muted">not ranked</span>
                              )}
                            </td>
                            <td className="mono px-3 py-1.5 text-right text-[12px]">
                              {brief?.priorityScore ?? "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {report.rows.length > 12 && (
                    <div className="mono border-t border-[#f0e8d9] bg-[#fbf6ec] px-3 py-1.5 text-[10.5px] text-muted">
                      showing first 12 of {report.rows.length}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel eyebrow="Contract" title="What the validator expects">
            <ul className="space-y-2 px-4 py-3.5 text-[12.5px] leading-relaxed text-ink">
              {[
                "One column named cve_id (case-insensitive).",
                "Unique identifiers — duplicates are flagged, not silently dropped.",
                "IDs shaped like CVE-2026-12345.",
                "Every id inside the 500-row ranked cohort.",
                "UTF-8 CSV, comma separated, one header row.",
              ].map((line) => (
                <li key={line} className="flex gap-2">
                  <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-gold" />
                  {line}
                </li>
              ))}
            </ul>
          </Panel>

          <Panel eyebrow="Source of truth" title="The submission file">
            <div className="space-y-2 px-4 py-3.5 text-[12.5px] leading-relaxed text-muted">
              <p>
                The app reads{" "}
                <span className="mono text-ink">outputs/top500.csv</span> through the dataset build
                script, so rank order in the dashboard is the submitted order.
              </p>
              <p>
                Regenerate after a model run:{" "}
                <span className="mono text-ink">npm run data</span>.
              </p>
              <p>
                {known.length} cohort rows are loaded right now. Ranked coverage:{" "}
                <span className="mono text-ink">
                  {known.filter((k) => k.priorityScore > 0).length}
                </span>{" "}
                rows carry a non-zero priority score.
              </p>
            </div>
          </Panel>
        </div>
      </div>
      <p className="mt-3 text-[11px] text-muted">
        Tip: a row that is outside the top 500 is usually a stale export, not a validation error.
      </p>
    </div>
  );
}

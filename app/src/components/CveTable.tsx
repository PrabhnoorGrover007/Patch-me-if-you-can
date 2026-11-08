"use client";

import { useEffect, useMemo, useState } from "react";
import { formatEpss, severityChipClass } from "@/lib/format";
import type { Cve, Severity } from "@/lib/types";
import { SeverityChip } from "./ui";

const PAGE_SIZE = 25;

type SortKey = "rank" | "risk" | "cvss" | "epss" | "effort";

const SORTS: { key: SortKey; label: string }[] = [
  { key: "rank", label: "Model rank" },
  { key: "risk", label: "Composite risk" },
  { key: "cvss", label: "CVSS" },
  { key: "epss", label: "EPSS" },
  { key: "effort", label: "Least effort" },
];

export default function CveTable({
  cves,
  selectedId,
  onSelect,
}: {
  cves: Cve[];
  selectedId: string;
  onSelect: (cveId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"ALL" | Severity>("ALL");
  const [sort, setSort] = useState<SortKey>("rank");
  const [page, setPage] = useState(0);

  useEffect(() => setPage(0), [query, severity, sort]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = cves.filter((c) => {
      if (severity !== "ALL" && c.severity !== severity) return false;
      if (!q) return true;
      return (
        c.cveId.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.keywords.some((k) => k.toLowerCase().includes(q)) ||
        c.cwes.some((w) => w.name.toLowerCase().includes(q))
      );
    });

    return [...rows].sort((a, b) => {
      switch (sort) {
        case "risk":
          return b.riskScore - a.riskScore;
        case "cvss":
          return (b.cvssScore ?? -1) - (a.cvssScore ?? -1);
        case "epss":
          return b.epss - a.epss;
        case "effort":
          return a.effortHours - b.effortHours;
        default:
          return a.rank - b.rank;
      }
    });
  }, [cves, query, severity, sort]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages - 1);
  const rows = filtered.slice(current * PAGE_SIZE, current * PAGE_SIZE + PAGE_SIZE);

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-[#ece3d2] px-4 py-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search CVE, wording or weakness…"
          className="input min-w-[200px] flex-1"
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as "ALL" | Severity)}
          className="input w-auto min-w-[130px]"
          aria-label="Filter by severity"
        >
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="UNSCORED">Unscored</option>
        </select>
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value as SortKey)}
          className="input w-auto min-w-[150px]"
          aria-label="Sort rows"
        >
          {SORTS.map((s) => (
            <option key={s.key} value={s.key}>
              {s.label}
            </option>
          ))}
        </select>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left">
          <thead className="sticky top-0 z-10 bg-[#fbf6ec]">
            <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
              <th className="px-4 py-2.5 font-medium">#</th>
              <th className="px-2 py-2.5 font-medium">CVE</th>
              <th className="px-2 py-2.5 font-medium">Severity</th>
              <th className="px-2 py-2.5 text-right font-medium">CVSS</th>
              <th className="px-2 py-2.5 text-right font-medium">EPSS</th>
              <th className="px-2 py-2.5 text-right font-medium">Risk</th>
              <th className="px-2 py-2.5 text-right font-medium">Effort</th>
              <th className="px-3 py-2.5 font-medium">Signals</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const active = c.cveId === selectedId;
              return (
                <tr
                  key={c.cveId}
                  onClick={() => onSelect(c.cveId)}
                  className={`cursor-pointer border-b border-[#f0e8d9] transition-colors ${
                    active ? "bg-[#f7f0e1]" : "row-hover"
                  }`}
                >
                  <td className="mono px-4 py-2.5 text-[12px] text-muted">{c.rank}</td>
                  <td className="px-2 py-2.5">
                    <span className="mono text-[12.5px] text-ink">{c.cveId}</span>
                    <span className="mt-0.5 block max-w-[340px] truncate text-[11.5px] text-muted">
                      {c.description}
                    </span>
                  </td>
                  <td className="px-2 py-2.5">
                    <span className={`chip ${severityChipClass[c.severity]}`}>{c.severity}</span>
                  </td>
                  <td className="mono px-2 py-2.5 text-right text-[12.5px]">
                    {c.cvssScore != null ? c.cvssScore.toFixed(1) : "—"}
                  </td>
                  <td className="mono px-2 py-2.5 text-right text-[12.5px]">{formatEpss(c.epss)}</td>
                  <td className="mono px-2 py-2.5 text-right text-[12.5px] font-medium text-ink">
                    {c.riskScore}
                  </td>
                  <td className="mono px-2 py-2.5 text-right text-[12px] text-muted">{c.effortHours}h</td>
                  <td className="px-3 py-2.5">
                    <div className="flex gap-1">
                      {[
                        ["M", c.flags.metasploit],
                        ["E", c.flags.exploitdb],
                        ["N", c.flags.nuclei],
                        ["P", c.flags.pocGithub],
                      ].map(([label, on]) => (
                        <span
                          key={String(label)}
                          title={
                            label === "M"
                              ? "Metasploit"
                              : label === "E"
                                ? "Exploit-DB"
                                : label === "N"
                                  ? "Nuclei"
                                  : "GitHub PoC"
                          }
                          className={`mono grid h-5 w-5 place-items-center rounded text-[9.5px] ${
                            on
                              ? "border border-[rgba(155,17,30,0.3)] bg-[rgba(155,17,30,0.1)] text-crimson"
                              : "border border-[#eee5d5] text-[#c6bda9]"
                          }`}
                        >
                          {label}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-[13px] text-muted">
                  Nothing matches that search.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-[#ece3d2] px-4 py-2.5">
        <span className="mono text-[11px] text-muted">
          {filtered.length === 0
            ? "0 results"
            : `${current * PAGE_SIZE + 1}–${Math.min((current + 1) * PAGE_SIZE, filtered.length)} of ${filtered.length}`}
        </span>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setPage(Math.max(0, current - 1))}
            disabled={current === 0}
            className="btn btn-ghost px-2.5 py-1 text-[12px]"
          >
            Prev
          </button>
          <span className="mono px-1 text-[11px] text-muted">
            {current + 1}/{pages}
          </span>
          <button
            onClick={() => setPage(Math.min(pages - 1, current + 1))}
            disabled={current >= pages - 1}
            className="btn btn-ghost px-2.5 py-1 text-[12px]"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

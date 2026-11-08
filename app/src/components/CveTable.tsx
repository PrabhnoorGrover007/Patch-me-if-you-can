"use client";

import { useMemo, useState } from "react";
import { formatEpss, severityChipClass } from "@/lib/format";
import type { Cve, Severity } from "@/lib/types";

type SortKey = "rank" | "priority" | "cvss" | "epss" | "effort";

const SORTS: { key: SortKey; label: string }[] = [
  { key: "rank", label: "Model rank" },
  { key: "priority", label: "Priority" },
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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = cves.filter((cve) => {
      if (severity !== "ALL" && cve.severity !== severity) return false;
      if (!q) return true;
      return (
        cve.cveId.toLowerCase().includes(q) ||
        cve.description.toLowerCase().includes(q) ||
        cve.keywords.some((keyword) => keyword.toLowerCase().includes(q)) ||
        cve.cwes.some((cwe) => cwe.name.toLowerCase().includes(q))
      );
    });

    return [...rows].sort((a, b) => {
      switch (sort) {
        case "priority":
          return b.priorityScore - a.priorityScore;
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

  const rows = filtered;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-[#ece3d2] px-4 py-3">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search CVE, wording or weakness…"
          className="input min-w-[200px] flex-1"
        />
        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value as "ALL" | Severity)}
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
          onChange={(event) => setSort(event.target.value as SortKey)}
          className="input w-auto min-w-[150px]"
          aria-label="Sort rows"
        >
          {SORTS.map((option) => (
            <option key={option.key} value={option.key}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left" aria-label="Top 500 vulnerability queue">
          <thead className="sticky top-0 z-10 bg-[#fbf6ec]">
            <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
              <th className="px-4 py-2.5 font-medium">#</th>
              <th className="px-2 py-2.5 font-medium">CVE</th>
              <th className="px-2 py-2.5 font-medium">Severity</th>
              <th className="px-2 py-2.5 text-right font-medium">CVSS</th>
              <th className="px-2 py-2.5 text-right font-medium">EPSS</th>
              <th className="px-2 py-2.5 text-right font-medium">Priority</th>
              <th className="px-2 py-2.5 text-right font-medium">Effort</th>
              <th className="px-3 py-2.5 font-medium">Signals</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((cve) => {
              const active = cve.cveId === selectedId;
              return (
                <tr
                  key={cve.cveId}
                  onClick={() => onSelect(cve.cveId)}
                  className={`cursor-pointer border-b border-[#f0e8d9] transition-colors ${
                    active ? "bg-[#f7f0e1]" : "row-hover"
                  }`}
                >
                  <td className="mono px-4 py-2.5 text-[12px] text-muted">{cve.rank}</td>
                  <td className="px-2 py-2.5">
                    <span className="mono text-[12.5px] text-ink">{cve.cveId}</span>
                    <span className="mt-0.5 block max-w-[340px] truncate text-[11.5px] text-muted">
                      {cve.description}
                    </span>
                  </td>
                  <td className="px-2 py-2.5">
                    <span className={`chip ${severityChipClass[cve.severity]}`}>{cve.severity}</span>
                  </td>
                  <td className="mono px-2 py-2.5 text-right text-[12.5px]">
                    {cve.cvssScore != null ? cve.cvssScore.toFixed(1) : "—"}
                  </td>
                  <td className="mono px-2 py-2.5 text-right text-[12.5px]">{formatEpss(cve.epss)}</td>
                  <td className="mono px-2 py-2.5 text-right text-[12.5px] font-medium text-ink">
                    {cve.priorityScore.toFixed(1)}
                  </td>
                  <td className="mono px-2 py-2.5 text-right text-[12px] text-muted">
                    {cve.effortHours}h
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex gap-1">
                      {[
                        ["M", cve.flags.metasploit],
                        ["E", cve.flags.exploitdb],
                        ["N", cve.flags.nuclei],
                        ["P", cve.flags.pocGithub],
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
          {filtered.length === 0 ? "0 results" : `${filtered.length} of ${cves.length} ranked CVEs`}
        </span>
        <span className="text-[11px] text-muted">Scroll inside the panel to browse the full queue</span>
      </div>
    </div>
  );
}

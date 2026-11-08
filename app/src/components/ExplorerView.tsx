"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { formatEpss, severityChipClass } from "@/lib/format";
import type { Severity, VulnPage } from "@/lib/types";
import { Empty, PageHeader, Panel, StatCard } from "./ui";

type SortKey = "rank" | "risk_score" | "epss_score" | "cvss3_score" | "published";

const SORTS: { value: SortKey; label: string }[] = [
  { value: "rank", label: "Model rank" },
  { value: "risk_score", label: "Model score" },
  { value: "epss_score", label: "EPSS" },
  { value: "cvss3_score", label: "CVSS" },
  { value: "published", label: "Published" },
];

export default function ExplorerView() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [minEpss, setMinEpss] = useState("0");
  const [exploitOnly, setExploitOnly] = useState(false);
  const [sort, setSort] = useState<SortKey>("rank");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<VulnPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => setPage(1), [query, severity, minEpss, exploitOnly, sort, order]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams({
        page: String(page),
        size: "25",
        sort,
        order,
      });
      if (query.trim()) params.set("q", query.trim());
      if (severity !== "ALL") params.set("severity", severity);
      if (Number(minEpss) > 0) params.set("min_epss", minEpss);
      if (exploitOnly) params.set("exploit_only", "true");

      try {
        const payload = await apiFetch<VulnPage>(`/api/vulnerabilities?${params}`, {
          signal: controller.signal,
        });
        setData(payload);
      } catch (caught) {
        if ((caught as Error).name !== "AbortError") {
          setError(caught instanceof Error ? caught.message : "Search failed");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 250);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query, severity, minEpss, exploitOnly, sort, order, page]);

  const rows = data?.items ?? [];
  const pageStart = data ? (data.page - 1) * data.size + 1 : 0;
  const pageEnd = data ? Math.min(data.page * data.size, data.total) : 0;

  return (
    <div>
      <PageHeader
        eyebrow="Vulnerability explorer"
        title="Search the whole benchmark"
        description="All 72,670 scored CVEs, not only the submitted 500. Filter by severity, EPSS, public exploit code, vendor or CWE; open any row for its evidence, model attribution and Granite analog retrieval."
        action={
          <div className="flex flex-wrap gap-2">
            <a href="/api/top500" className="btn btn-ghost" download>
              Official top500.csv
            </a>
            <a href="/api/export?limit=500" className="btn btn-primary" download>
              Export ranked CSV
            </a>
          </div>
        }
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard
          label="Scored pool"
          value={data ? data.total.toLocaleString("en-US") : "—"}
          hint="Matches the current filters"
        />
        <StatCard
          label="Visible page"
          value={data ? `${pageStart}–${pageEnd}` : "—"}
          hint="25 rows per page; the browser never downloads the full table"
          tone="gold"
        />
        <StatCard
          label="Exploit-code filter"
          value={exploitOnly ? "On" : "Off"}
          hint="Requires a public GitHub PoC at the snapshot month"
          tone="jade"
        />
      </div>

      <Panel className="mt-4" bodyClassName="p-4">
        <div className="grid gap-2 md:grid-cols-[minmax(0,1.5fr)_150px_150px_150px_auto]">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="CVE id or wording in the advisory…"
            className="input"
            aria-label="Search vulnerabilities"
          />
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            className="input"
            aria-label="Severity"
          >
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select
            value={minEpss}
            onChange={(event) => setMinEpss(event.target.value)}
            className="input"
            aria-label="Minimum EPSS"
          >
            <option value="0">Any EPSS</option>
            <option value="0.01">EPSS ≥ 1%</option>
            <option value="0.05">EPSS ≥ 5%</option>
            <option value="0.1">EPSS ≥ 10%</option>
            <option value="0.5">EPSS ≥ 50%</option>
          </select>
          <select
            value={sort}
            onChange={(event) => setSort(event.target.value as SortKey)}
            className="input"
            aria-label="Sort"
          >
            {SORTS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <div className="flex items-center gap-2">
            <select
              value={order}
              onChange={(event) => setOrder(event.target.value as "asc" | "desc")}
              className="input"
              aria-label="Sort direction"
            >
              <option value="asc">Ascending</option>
              <option value="desc">Descending</option>
            </select>
            <label className="flex cursor-pointer items-center gap-1.5 whitespace-nowrap text-[12px] text-ink">
              <input
                type="checkbox"
                checked={exploitOnly}
                onChange={(event) => setExploitOnly(event.target.checked)}
                className="h-3.5 w-3.5 accent-[#0b192c]"
              />
              PoC only
            </label>
          </div>
        </div>
      </Panel>

      <Panel className="mt-4" bodyClassName="overflow-x-auto">
        {error ? (
          <div className="px-5 py-8">
            <p className="text-[13px] text-crimson">The explorer could not reach the API. {error}</p>
          </div>
        ) : loading ? (
          <div className="space-y-2 p-5" aria-live="polite">
            {[100, 96, 98, 94, 97, 92].map((width, index) => (
              <div
                key={index}
                className="h-8 animate-pulse rounded bg-[#f1e9da]"
                style={{ width: `${width}%` }}
              />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <Empty
            title="Nothing matches those filters"
            body="Try a broader search, lower the EPSS floor, or clear the public-PoC requirement."
          />
        ) : (
          <table className="w-full min-w-[1040px] border-collapse text-left">
            <thead className="bg-[#fbf6ec]">
              <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
                <th className="px-3 py-2.5 font-medium">Rank</th>
                <th className="px-3 py-2.5 font-medium">CVE</th>
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 text-right font-medium">CVSS</th>
                <th className="px-3 py-2.5 text-right font-medium">EPSS</th>
                <th className="px-3 py-2.5 text-right font-medium">Model score</th>
                <th className="px-3 py-2.5 font-medium">Vendor</th>
                <th className="px-3 py-2.5 font-medium">CWE</th>
                <th className="px-3 py-2.5 font-medium">Snapshot</th>
                <th className="px-3 py-2.5 font-medium">Signals</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.cve_id} className="border-t border-[#f0e8d9] row-hover">
                  <td className="mono px-3 py-2.5 text-[12px] text-muted">{item.rank}</td>
                  <td className="px-3 py-2.5">
                    <Link
                      href={`/intelligence/${item.cve_id}`}
                      className="mono text-[12.5px] text-ink hover:underline"
                    >
                      {item.cve_id}
                    </Link>
                    <span className="mt-0.5 block max-w-[420px] truncate text-[11.5px] text-muted">
                      {item.description}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={`chip ${severityChipClass[item.cvss3_severity as Severity] ?? ""}`}>
                      {item.cvss3_severity || "UNSCORED"}
                    </span>
                  </td>
                  <td className="mono px-3 py-2.5 text-right text-[12px]">
                    {item.cvss3_score != null ? item.cvss3_score.toFixed(1) : "—"}
                  </td>
                  <td className="mono px-3 py-2.5 text-right text-[12px]">
                    {formatEpss(item.epss_score ?? 0)}
                  </td>
                  <td className="mono px-3 py-2.5 text-right text-[12px] text-ink">
                    {(item.risk_score * 100).toFixed(2)}%
                  </td>
                  <td className="mono px-3 py-2.5 text-[11.5px] text-muted">{item.vendor || "—"}</td>
                  <td className="mono px-3 py-2.5 text-[11.5px] text-muted">{item.cwe_top || "—"}</td>
                  <td className="mono px-3 py-2.5 text-[11px] text-muted">{item.snapshot_month || "—"}</td>
                  <td className="px-3 py-2.5">
                    <span className={`chip ${item.poc_github ? "border-crimson/30 bg-crimson/10 text-crimson" : "border-hairline bg-pressed text-muted"}`}>
                      {item.poc_github ? "PoC" : "no PoC"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <span className="mono text-[11.5px] text-muted">
          {data ? `${data.total.toLocaleString("en-US")} matches · page ${data.page} of ${data.pages}` : ""}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage((current) => Math.max(1, current - 1))}
            disabled={!data || data.page <= 1}
            className="btn btn-ghost px-3 py-1.5 text-[12px]"
          >
            Previous
          </button>
          <button
            onClick={() => setPage((current) => Math.min(data?.pages ?? 1, current + 1))}
            disabled={!data || data.page >= data.pages}
            className="btn btn-ghost px-3 py-1.5 text-[12px]"
          >
            Next
          </button>
        </div>
      </div>

      <p className="mt-3 text-[11px] leading-relaxed text-muted">
        Model score is the fitted ranker output, not a calibrated probability. The table is paginated
        by FastAPI; the full 72,670-row dataset is never sent to the browser.
      </p>
    </div>
  );
}

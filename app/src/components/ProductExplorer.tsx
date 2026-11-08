"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { formatEpss, severityChipClass } from "@/lib/format";
import type { ProductPage, ProductVulnPage, Severity } from "@/lib/types";
import { Empty, PageHeader, Panel, StatCard } from "./ui";

export default function ProductExplorer() {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [products, setProducts] = useState<ProductPage | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [vulns, setVulns] = useState<ProductVulnPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => setPage(1), [query]);

  useEffect(() => {
    let live = true;
    const timer = setTimeout(async () => {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams({ page: String(page), size: "25" });
      if (query.trim()) params.set("q", query.trim());
      try {
        const payload = await apiFetch<ProductPage>(`/api/products?${params}`);
        if (!live) return;
        setProducts(payload);
        setSelected((current) => {
          if (current && payload.items.some((item) => item.product_id === current)) return current;
          return payload.items[0]?.product_id ?? null;
        });
      } catch (caught) {
        if (live) setError(caught instanceof Error ? caught.message : "Product lookup failed");
      } finally {
        if (live) setLoading(false);
      }
    }, 250);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [query, page]);

  useEffect(() => {
    if (!selected) {
      setVulns(null);
      return;
    }
    let live = true;
    setVulnLoading(true);
    apiFetch<ProductVulnPage>(`/api/products/${encodeURIComponent(selected)}/vulnerabilities?size=25`)
      .then((payload) => {
        if (live) setVulns(payload);
      })
      .catch(() => {
        if (live) setVulns(null);
      })
      .finally(() => {
        if (live) setVulnLoading(false);
      });
    return () => {
      live = false;
    };
  }, [selected]);

  const current = products?.items.find((item) => item.product_id === selected);

  return (
    <div>
      <PageHeader
        eyebrow="Product exposure"
        title="Where the vulnerable code lives"
        description="Explore CPE vendor exposure derived from affected_products.csv, then inspect the scored CVEs behind each vendor. This is the supplied affected-product dataset — not an organisation's asset inventory."
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard label="CPE vendors" value={products?.total.toLocaleString("en-US") ?? "—"} hint="Distinct vendors in the affected-product table" />
        <StatCard label="Selected vendor" value={current?.vendor ?? "—"} hint="Click a row to inspect" tone="gold" />
        <StatCard label="Scored CVEs" value={vulns?.total.toLocaleString("en-US") ?? "—"} hint="Vendor-linked rows in the 72,670 pool" tone="jade" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[390px_minmax(0,1fr)]">
        <Panel eyebrow="Directory" title="CPE vendors" bodyClassName="flex flex-col">
          <div className="border-b border-[#ece3d2] p-3">
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Filter vendors…"
              className="input"
              aria-label="Filter vendors"
            />
          </div>
          <div className="max-h-[560px] min-h-[360px] overflow-y-auto p-2">
            {error ? (
              <p className="px-3 py-6 text-[12.5px] text-crimson">{error}</p>
            ) : loading ? (
              <div className="space-y-2 p-2">
                {[1, 2, 3, 4, 5, 6].map((row) => (
                  <div key={row} className="h-10 animate-pulse rounded bg-[#f1e9da]" />
                ))}
              </div>
            ) : products && products.items.length > 0 ? (
              <div className="space-y-1">
                {products.items.map((item) => (
                  <button
                    key={item.product_id}
                    onClick={() => setSelected(item.product_id)}
                    className={`w-full rounded-lg border px-3 py-2 text-left transition ${
                      selected === item.product_id
                        ? "border-[rgba(212,175,55,0.55)] bg-[#fbf3e0]"
                        : "border-transparent hover:bg-[#fbf6ec]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="mono text-[12px] text-ink">{item.vendor}</span>
                      <span className="mono text-[10.5px] text-muted">{item.vulnerabilities}</span>
                    </div>
                    <span className="mt-0.5 block text-[10.5px] text-muted">
                      {item.cpe_product_rows.toLocaleString("en-US")} CPE product rows
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <Empty title="No vendors match" body="Clear the filter or search a different vendor name." />
            )}
          </div>
          <div className="flex items-center justify-between gap-2 border-t border-[#ece3d2] px-3 py-2">
            <button
              onClick={() => setPage((value) => Math.max(1, value - 1))}
              disabled={!products || products.page <= 1}
              className="btn btn-ghost px-2.5 py-1 text-[11.5px]"
            >
              Prev
            </button>
            <span className="mono text-[10.5px] text-muted">
              {products ? `${products.page}/${products.pages}` : "—"}
            </span>
            <button
              onClick={() => setPage((value) => Math.min(products?.pages ?? 1, value + 1))}
              disabled={!products || products.page >= products.pages}
              className="btn btn-ghost px-2.5 py-1 text-[11.5px]"
            >
              Next
            </button>
          </div>
        </Panel>

        <Panel
          eyebrow={selected ? `Vendor · ${selected}` : "Vendor detail"}
          title={current?.vendor ?? "Choose a vendor"}
          action={<span className="text-[11px] text-muted">ranked across the full pool</span>}
          bodyClassName="overflow-x-auto"
        >
          {vulnLoading ? (
            <div className="space-y-2 p-5">
              {[1, 2, 3, 4, 5].map((row) => (
                <div key={row} className="h-8 animate-pulse rounded bg-[#f1e9da]" />
              ))}
            </div>
          ) : vulns && vulns.items.length > 0 ? (
            <table className="w-full min-w-[760px] border-collapse text-left">
              <thead className="bg-[#fbf6ec]">
                <tr className="mono text-[10px] uppercase tracking-[0.12em] text-muted">
                  <th className="px-4 py-2.5 font-medium">Rank</th>
                  <th className="px-3 py-2.5 font-medium">CVE</th>
                  <th className="px-3 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 text-right font-medium">CVSS</th>
                  <th className="px-3 py-2.5 text-right font-medium">EPSS</th>
                  <th className="px-3 py-2.5 font-medium">CWE</th>
                </tr>
              </thead>
              <tbody>
                {vulns.items.map((item) => (
                  <tr key={item.cve_id} className="border-t border-[#f0e8d9] row-hover">
                    <td className="mono px-4 py-2.5 text-[11.5px] text-muted">{item.rank}</td>
                    <td className="px-3 py-2.5">
                      <Link href={`/intelligence/${item.cve_id}`} className="mono text-[12px] text-ink hover:underline">
                        {item.cve_id}
                      </Link>
                      <span className="mt-0.5 block max-w-[360px] truncate text-[10.5px] text-muted">
                        {item.reason}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`chip ${severityChipClass[item.cvss3_severity as Severity] ?? ""}`}>
                        {item.cvss3_severity}
                      </span>
                    </td>
                    <td className="mono px-3 py-2.5 text-right text-[12px]">
                      {item.cvss3_score != null ? item.cvss3_score.toFixed(1) : "—"}
                    </td>
                    <td className="mono px-3 py-2.5 text-right text-[12px]">{formatEpss(item.epss_score ?? 0)}</td>
                    <td className="mono px-3 py-2.5 text-[11.5px] text-muted">{item.cwe_top}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty
              title="No scored CVEs linked"
              body="This vendor appears in the affected-product table but has no rows in the scored 2026 pool. That is not evidence that the product is safe."
            />
          )}
        </Panel>
      </div>

      <p className="mt-4 text-[11px] leading-relaxed text-muted">
        {products?.note ??
          "CPE vendor is derived from affected_products.csv. Absence of a CPE is not evidence that a product is unaffected."}
      </p>
    </div>
  );
}

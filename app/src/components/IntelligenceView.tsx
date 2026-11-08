"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiFetch } from "@/lib/api";
import { formatDate, formatEpss, formatMonth, severityChipClass } from "@/lib/format";
import type {
  GraniteAnalysis,
  Severity,
  SimilarResponse,
  TimelineResponse,
  VulnDetail,
  VulnPage,
} from "@/lib/types";
import ChatPanel from "./ChatPanel";
import { Empty, PageHeader, Panel, StatCard } from "./ui";

const AV = ["—", "Local", "Adjacent", "Network"];
const PR = ["None", "Low", "High"];

function ordinal(value: number | null, labels: string[]) {
  if (value == null) return "—";
  return labels[Math.round(value)] ?? String(value);
}

function TimelineChart({ timeline }: { timeline: TimelineResponse }) {
  if (timeline.points.length === 0) {
    return (
      <Empty
        title="No monthly history"
        body={`${timeline.note} Published ${formatDate(timeline.published)}.`}
      />
    );
  }
  const data = timeline.points.map((point) => ({
    ...point,
    epssPct: point.epss == null ? null : point.epss * 100,
  }));
  return (
    <div className="px-3 pb-3 pt-3">
      <ResponsiveContainer width="100%" height={230}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
          <CartesianGrid stroke="#ece3d2" strokeDasharray="3 4" vertical={false} />
          <XAxis
            dataKey="month"
            tickFormatter={formatMonth}
            tick={{ fontSize: 9.5, fill: "#5b6373" }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis yAxisId="epss" tick={{ fontSize: 9.5, fill: "#5b6373" }} axisLine={false} tickLine={false} width={38} />
          <YAxis yAxisId="sources" orientation="right" tick={{ fontSize: 9.5, fill: "#5b6373" }} axisLine={false} tickLine={false} width={28} />
          <Tooltip
            contentStyle={{ borderRadius: 10, border: "1px solid rgba(212,175,55,0.35)", background: "#fffdfa", fontSize: 12 }}
            labelFormatter={(label) => formatMonth(String(label))}
          />
          <Bar yAxisId="sources" dataKey="exploit_sources" name="Exploit sources" fill="#e7dcc4" radius={[2, 2, 0, 0]} barSize={13} />
          <Line yAxisId="epss" type="monotone" dataKey="epssPct" name="EPSS %" stroke="#9b111e" strokeWidth={2} dot={{ r: 2.5 }} />
        </ComposedChart>
      </ResponsiveContainer>
      <p className="mt-1 text-[10.5px] leading-relaxed text-muted">
        EPSS and public exploit-code signals by month. The 2026 benchmark has one snapshot per CVE,
        so no synthetic path is drawn after {timeline.snapshot_month ?? "the cutoff"}.
      </p>
    </div>
  );
}

function Contributions({ detail }: { detail: VulnDetail }) {
  if (detail.contributions.length === 0) {
    return <p className="px-4 py-5 text-[12px] text-muted">Attribution table unavailable for this row.</p>;
  }
  const max = Math.max(...detail.contributions.map((row) => Math.abs(row.contribution)), 0.0001);
  return (
    <div className="space-y-2 px-4 py-3">
      {detail.contributions.slice(0, 8).map((row) => (
        <div key={row.feature}>
          <div className="flex items-center justify-between gap-2 text-[11.5px]">
            <span className="mono text-ink">{row.feature}</span>
            <span className={`mono ${row.contribution >= 0 ? "text-jade" : "text-crimson"}`}>
              {row.contribution >= 0 ? "+" : ""}
              {row.contribution.toFixed(4)}
            </span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-[#f1e9da]">
            <div
              className={`h-full rounded-full ${row.contribution >= 0 ? "bg-jade" : "bg-crimson"}`}
              style={{ width: `${(Math.abs(row.contribution) / max) * 100}%`, marginLeft: row.contribution < 0 ? "auto" : 0 }}
            />
          </div>
        </div>
      ))}
      <p className="pt-1 text-[10.5px] leading-relaxed text-muted">
        Linear attribution: coefficient × standardised feature value. Positive pushes the ranking up;
        negative pushes it down. This is not a causal effect.
      </p>
    </div>
  );
}

export default function IntelligenceView({ initialCve }: { initialCve: string | null }) {
  const [cveId, setCveId] = useState<string | null>(initialCve);
  const [search, setSearch] = useState("");
  const [results, setResults] = useState<VulnPage["items"]>([]);
  const [examples, setExamples] = useState<{ cve_id: string; rank: number }[]>([]);
  const [detail, setDetail] = useState<VulnDetail | null>(null);
  const [similar, setSimilar] = useState<SimilarResponse | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [analysis, setAnalysis] = useState<GraniteAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    setDetail(null);
    setSimilar(null);
    setTimeline(null);
    setAnalysis(null);
    try {
      const record = await apiFetch<VulnDetail>(`/api/vulnerabilities/${encodeURIComponent(id)}`);
      setDetail(record);
      const [sim, time, gran] = await Promise.all([
        apiFetch<SimilarResponse>(`/api/vulnerabilities/${encodeURIComponent(id)}/similar?limit=6`).catch(() => null),
        apiFetch<TimelineResponse>(`/api/vulnerabilities/${encodeURIComponent(id)}/timeline`).catch(() => null),
        apiFetch<GraniteAnalysis>("/api/granite/analyze", {
          method: "POST",
          body: JSON.stringify({ cve_id: id }),
        }).catch(() => null),
      ]);
      setSimilar(sim);
      setTimeline(time);
      setAnalysis(gran);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "CVE lookup failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (initialCve) {
      setCveId(initialCve);
      void load(initialCve);
      return;
    }
    apiFetch<{ items: { cve_id: string; rank: number }[] }>("/api/rankings?limit=10")
      .then((payload) => setExamples(payload.items))
      .catch(() => setExamples([]));
  }, [initialCve, load]);

  async function submitSearch(event: React.FormEvent) {
    event.preventDefault();
    const query = search.trim();
    if (!query) return;
    setResults([]);
    if (/^CVE-\d{4}-\d{4,}$/i.test(query)) {
      const normalized = query.toUpperCase();
      setCveId(normalized);
      await load(normalized);
      return;
    }
    try {
      const payload = await apiFetch<VulnPage>(`/api/vulnerabilities?q=${encodeURIComponent(query)}&size=8`);
      if (payload.items.length === 1) {
        setCveId(payload.items[0].cve_id);
        await load(payload.items[0].cve_id);
      } else {
        setResults(payload.items);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Search failed");
    }
  }

  if (!cveId && !detail) {
    return (
      <div>
        <PageHeader
          eyebrow="Vulnerability intelligence"
          title="Investigate one CVE"
          description="Search any scored CVE for its model attribution, extracted attack characteristics, Granite analog retrieval, monthly exploit signals and a grounded analyst conversation."
        />
        <Panel eyebrow="Search" title="CVE id or advisory wording">
          <form onSubmit={submitSearch} className="flex flex-wrap gap-2 p-4">
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="CVE-2026-2699 or “authentication bypass”…"
              className="input min-w-[240px] flex-1"
            />
            <button type="submit" className="btn btn-primary">
              Investigate
            </button>
          </form>
        </Panel>

        {results.length > 0 && (
          <Panel className="mt-4" eyebrow="Search results" title="Choose a CVE">
            <div className="divide-y divide-[#f0e8d9]">
              {results.map((item) => (
                <button
                  key={item.cve_id}
                  onClick={() => {
                    setCveId(item.cve_id);
                    setResults([]);
                    void load(item.cve_id);
                  }}
                  className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left hover:bg-[#fbf6ec]"
                >
                  <span>
                    <span className="mono block text-[12.5px] text-ink">{item.cve_id}</span>
                    <span className="mt-0.5 block max-w-[620px] truncate text-[11.5px] text-muted">{item.description}</span>
                  </span>
                  <span className="mono shrink-0 text-[11px] text-muted">#{item.rank}</span>
                </button>
              ))}
            </div>
          </Panel>
        )}

        <Panel className="mt-4" eyebrow="Start here" title="Highest-ranked CVEs">
          <div className="grid gap-2 p-4 sm:grid-cols-2 xl:grid-cols-5">
            {examples.map((item) => (
              <button
                key={item.cve_id}
                onClick={() => {
                  setCveId(item.cve_id);
                  void load(item.cve_id);
                }}
                className="card-inset px-3 py-2 text-left transition hover:bg-[#fbf3e0]"
              >
                <span className="mono block text-[11.5px] text-ink">{item.cve_id}</span>
                <span className="mono mt-0.5 block text-[10px] text-muted">rank #{item.rank}</span>
              </button>
            ))}
          </div>
        </Panel>
        {error && <p className="mt-3 text-[12px] text-crimson">{error}</p>}
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        eyebrow={detail ? `Investigation · snapshot ${detail.snapshot_month}` : "Investigation"}
        title={cveId ?? "Loading CVE"}
        description="Known facts, model predictions and extracted evidence are separated. Missing fields stay missing; the app never fills them with invented values."
        action={
          <div className="flex flex-wrap gap-2">
            <form onSubmit={submitSearch} className="flex gap-2">
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Another CVE…"
                className="input w-[190px]"
              />
              <button type="submit" className="btn btn-ghost">
                Go
              </button>
            </form>
            <Link href="/explorer" className="btn btn-ghost">
              Explorer
            </Link>
          </div>
        }
      />

      {loading ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_390px]">
          <div className="card h-[460px] animate-pulse bg-[#f8f1e3]" />
          <div className="card h-[460px] animate-pulse bg-[#f8f1e3]" />
        </div>
      ) : error ? (
        <Panel>
          <div className="px-5 py-8">
            <p className="font-display text-[18px] text-ink">That CVE is not in the scored pool</p>
            <p className="mt-1 text-[12.5px] leading-relaxed text-muted">{error}</p>
            <p className="mt-2 text-[12px] text-muted">
              The benchmark contains 72,670 CVEs published Jan–Sep 2026. Try the explorer for a full
              search.
            </p>
          </div>
        </Panel>
      ) : detail ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Model rank" value={`#${detail.rank}`} hint="of 72,670 scored candidates" />
            <StatCard label="Model score" value={`${(detail.risk_score * 100).toFixed(2)}%`} hint="Fitted ranking signal; not calibrated" tone="gold" />
            <StatCard label="CVSS / severity" value={detail.cvss3_score ?? "—"} hint={detail.cvss3_severity} tone="crimson" />
            <StatCard label="EPSS at snapshot" value={formatEpss(detail.epss_score ?? 0)} hint="Probability of exploitation in 30 days" tone="jade" />
          </div>

          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_390px]">
            <div className="space-y-4">
              <Panel eyebrow="Record" title={detail.cve_id} action={<span className={`chip ${severityChipClass[detail.cvss3_severity as Severity] ?? ""}`}>{detail.cvss3_severity}</span>}>
                <div className="space-y-3 px-4 py-4">
                  <p className="text-[13.5px] leading-relaxed text-ink">{detail.description}</p>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {[
                      ["Published", formatDate(detail.published)],
                      ["Vendor", detail.vendor],
                      ["Weakness", `${detail.cwe_top} · ${detail.cwe_name}`],
                      ["Snapshot month", detail.snapshot_month],
                      ["Attack vector", ordinal(detail.technical.attack_vector, AV)],
                      ["Privileges required", ordinal(detail.technical.privileges_required, PR)],
                      ["Exploit sources", detail.technical.n_exploit_sources ?? "—"],
                      ["Remediation", detail.remediation_priority],
                    ].map(([label, value]) => (
                      <div key={label} className="card-inset px-3 py-2">
                        <div className="mono text-[9px] uppercase tracking-[0.12em] text-muted">{label}</div>
                        <div className="mt-0.5 text-[12px] text-ink">{String(value)}</div>
                      </div>
                    ))}
                  </div>
                  <div>
                    <div className="eyebrow">Why it ranks here</div>
                    <p className="mt-1 text-[12.5px] leading-relaxed text-ink">{detail.drivers}</p>
                  </div>
                  <p className="text-[10.5px] leading-relaxed text-muted">{detail.disclaimer}</p>
                </div>
              </Panel>

              <div className="grid gap-4 lg:grid-cols-2">
                <Panel eyebrow="Model explanation" title="Linear attribution">
                  <Contributions detail={detail} />
                </Panel>

                <Panel eyebrow="IBM Granite" title="Grounded extraction">
                  {analysis ? (
                    <div className="space-y-3 px-4 py-3.5">
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          ["Attack surface", analysis.extracted.attack_surface],
                          ["Auth required", analysis.extracted.authentication_required == null ? "unknown" : analysis.extracted.authentication_required ? "yes" : "no"],
                          ["Remote", analysis.extracted.remote_exploitation_possible == null ? "unknown" : analysis.extracted.remote_exploitation_possible ? "possible" : "not established"],
                          ["Class", analysis.extracted.vulnerability_class],
                        ].map(([label, value]) => (
                          <div key={label} className="card-inset px-3 py-2">
                            <div className="mono text-[9px] uppercase tracking-[0.12em] text-muted">{label}</div>
                            <div className="mt-0.5 text-[11.5px] text-ink">{String(value)}</div>
                          </div>
                        ))}
                      </div>
                      {analysis.extracted.evidence.length > 0 ? (
                        <div>
                          <div className="eyebrow">Evidence in the advisory</div>
                          <ul className="mt-1 space-y-1">
                            {analysis.extracted.evidence.slice(0, 4).map((item) => (
                              <li key={item.characteristic} className="text-[11.5px] leading-snug text-ink">
                                <span className="mono text-[10px] text-muted">{item.characteristic}: </span>
                                “{item.source_text}”
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {analysis.extracted.uncertainty.length > 0 ? (
                        <p className="text-[11px] leading-relaxed text-muted">
                          Unknown by design: {analysis.extracted.uncertainty.join("; ")}.
                        </p>
                      ) : null}
                      <p className="text-[10.5px] leading-relaxed text-muted">
                        {analysis.note} Embedding model: <span className="mono">{analysis.embedding_model}</span>.
                      </p>
                    </div>
                  ) : (
                    <Empty title="Granite extraction unavailable" body="The evidence service did not return an analysis. No characteristics were guessed." />
                  )}
                </Panel>
              </div>

              <Panel eyebrow="Historical signals" title="EPSS and public exploit code">
                {timeline ? <TimelineChart timeline={timeline} /> : <Empty title="Timeline unavailable" body="The monthly signal table did not return a history for this CVE." />}
              </Panel>
            </div>

            <div className="space-y-4">
              <Panel eyebrow="Granite retrieval" title="Similar vulnerabilities">
                {similar && similar.items.length > 0 ? (
                  <div className="divide-y divide-[#f0e8d9]">
                    {similar.items.map((item) => (
                      <Link key={item.cve_id} href={`/intelligence/${item.cve_id}`} className="block px-4 py-2.5 hover:bg-[#fbf6ec]">
                        <div className="flex items-center justify-between gap-2">
                          <span className="mono text-[11.5px] text-ink">{item.cve_id}</span>
                          <span className="mono text-[10.5px] text-gold-deep">{item.similarity.toFixed(3)}</span>
                        </div>
                        <div className="mt-0.5 flex items-center justify-between gap-2 text-[10.5px] text-muted">
                          <span>#{item.rank} · {item.vendor}</span>
                          <span>{item.cwe_top}</span>
                        </div>
                      </Link>
                    ))}
                    <p className="px-4 py-2.5 text-[10.5px] leading-relaxed text-muted">{similar.note}</p>
                  </div>
                ) : (
                  <Empty title="No analog vector" body="The Granite index has no row for this CVE. Similarity is not invented." />
                )}
              </Panel>

              <Panel eyebrow="Grounded analyst" title="Ask about this CVE" className="h-[520px]" bodyClassName="flex min-h-0 flex-1 flex-col">
                <ChatPanel cveId={detail.cve_id} cveLabel={detail.description.slice(0, 150)} className="h-full px-4" />
              </Panel>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}

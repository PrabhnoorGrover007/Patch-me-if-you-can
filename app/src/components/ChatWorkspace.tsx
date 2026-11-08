"use client";

import { useMemo, useState } from "react";
import type { CveBrief } from "@/lib/types";
import ChatPanel from "./ChatPanel";
import { PageHeader, Panel } from "./ui";

export default function ChatWorkspace({ briefs }: { briefs: CveBrief[] }) {
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(briefs[0]?.cveId ?? null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return briefs.slice(0, 80);
    return briefs.filter((b) => b.cveId.toLowerCase().includes(q) || b.description.toLowerCase().includes(q)).slice(0, 80);
  }, [briefs, query]);

  const selected = briefs.find((b) => b.cveId === selectedId) ?? null;

  return (
    <div>
      <PageHeader
        eyebrow="Contextual assistant"
        title="Chat with the analyst"
        description="Every answer is grounded in the selected CVE's record — CVSS vector, EPSS position, exploit signals, affected products and the estimated fix effort."
      />

      <div className="grid gap-4 lg:grid-cols-[320px_minmax(0,1fr)]">
        <Panel eyebrow="Context" title="Select a CVE" bodyClassName="flex flex-col" className="h-[600px]">
          <div className="border-b border-[#ece3d2] px-3 py-2.5">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search id or wording…"
              className="input"
            />
            <button
              onClick={() => setSelectedId(null)}
              className={`mt-2 w-full rounded-lg border px-3 py-2 text-left text-[12px] transition ${
                selectedId === null
                  ? "border-[rgba(212,175,55,0.6)] bg-[rgba(212,175,55,0.12)] text-ink"
                  : "border-[#e6dcc8] bg-alabaster text-muted hover:bg-[#fbf6ec]"
              }`}
            >
              Whole cohort (no single CVE)
            </button>
          </div>

          <div className="min-h-0 flex-1 space-y-1 overflow-y-auto px-2 py-2">
            {filtered.map((b) => {
              const active = b.cveId === selectedId;
              return (
                <button
                  key={b.cveId}
                  onClick={() => setSelectedId(b.cveId)}
                  className={`w-full rounded-lg border px-2.5 py-2 text-left transition ${
                    active
                      ? "border-[rgba(212,175,55,0.55)] bg-[#fbf3e0]"
                      : "border-transparent hover:bg-[#fbf6ec]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono text-[11.5px] text-ink">{b.cveId}</span>
                    <span className="mono text-[10px] text-muted">#{b.rank}</span>
                  </div>
                  <span className="mt-0.5 line-clamp-1 block text-[11px] text-muted">
                    {b.description}
                  </span>
                </button>
              );
            })}
            {filtered.length === 0 && (
              <p className="px-3 py-6 text-center text-[12px] text-muted">No CVE matches that search.</p>
            )}
          </div>
        </Panel>

        <Panel
          eyebrow={selected ? `Grounded in ${selected.cveId}` : "Cohort-wide"}
          title="AI assistant"
          className="h-[600px]"
          bodyClassName="flex min-h-0 flex-1 flex-col"
        >
          <ChatPanel
            key={selected?.cveId ?? "global"}
            cveId={selected?.cveId}
            cveLabel={selected?.description}
            className="h-full px-4"
          />
        </Panel>
      </div>
    </div>
  );
}

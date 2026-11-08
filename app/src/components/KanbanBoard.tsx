"use client";

import Link from "next/link";
import { useMemo, useState, useTransition } from "react";
import { formatDate, severityChipClass } from "@/lib/format";
import { dropCard, moveCard } from "@/lib/queue-actions";
import type { Cve, QueueCard, QueueStatus } from "@/lib/types";
import { Empty } from "./ui";

const COLUMNS: { id: QueueStatus; title: string; hint: string; accent: string }[] = [
  { id: "todo", title: "To do", hint: "Triaged, not started", accent: "#2c3e50" },
  { id: "in_progress", title: "In progress", hint: "Engineer assigned", accent: "#a45c00" },
  { id: "done", title: "Done", hint: "Patched and verified", accent: "#1b4d3e" },
];

export default function KanbanBoard({ cards: initial, cves }: { cards: QueueCard[]; cves: Cve[] }) {
  const [cards, setCards] = useState<QueueCard[]>(initial);
  const [dragging, setDragging] = useState<string | null>(null);
  const [hover, setHover] = useState<QueueStatus | null>(null);
  const [, startTransition] = useTransition();

  const byId = useMemo(() => new Map(cves.map((c) => [c.cveId, c])), [cves]);

  function move(cveId: string, status: QueueStatus) {
    setCards((prev) =>
      prev.map((c) =>
        c.cveId === cveId
          ? {
              ...c,
              status,
              updatedAt: new Date().toISOString(),
              doneAt: status === "done" ? c.doneAt ?? new Date().toISOString() : null,
            }
          : c
      )
    );
    startTransition(async () => {
      await moveCard(cveId, status);
    });
  }

  function remove(cveId: string) {
    setCards((prev) => prev.filter((c) => c.cveId !== cveId));
    startTransition(async () => {
      await dropCard(cveId);
    });
  }

  return (
    <div className="grid gap-4 md:grid-cols-3">
      {COLUMNS.map((col) => {
        const items = cards.filter((c) => c.status === col.id);
        return (
          <section
            key={col.id}
            onDragOver={(e) => {
              e.preventDefault();
              setHover(col.id);
            }}
            onDragLeave={() => setHover((h) => (h === col.id ? null : h))}
            onDrop={(e) => {
              e.preventDefault();
              const cveId = e.dataTransfer.getData("text/plain") || dragging;
              setHover(null);
              setDragging(null);
              if (cveId) move(cveId, col.id);
            }}
            className={`card flex min-h-[420px] flex-col overflow-hidden transition-colors ${
              hover === col.id ? "bg-[#fbf5e7] ring-1 ring-[rgba(212,175,55,0.55)]" : ""
            }`}
          >
            <div className="h-[3px] w-full" style={{ backgroundColor: col.accent }} />
            <header className="flex items-center justify-between gap-2 border-b border-[#ece3d2] px-4 py-3">
              <div>
                <h2 className="text-[17px] leading-tight text-ink">{col.title}</h2>
                <p className="text-[11px] text-muted">{col.hint}</p>
              </div>
              <span className="mono rounded-full border border-[#e6dcc8] bg-[#fbf6ec] px-2 py-0.5 text-[11px] text-muted">
                {items.length}
              </span>
            </header>

            <div className="flex-1 space-y-2.5 p-3">
              {items.length === 0 && (
                <div className="rounded-lg border border-dashed border-[#ddd2bd] px-3 py-8 text-center">
                  <p className="text-[12px] text-muted">
                    {col.id === "todo"
                      ? "Add CVEs from the dashboard to start triage."
                      : col.id === "in_progress"
                        ? "Drag a card here when work starts."
                        : "Completed patches land here."}
                  </p>
                </div>
              )}

              {items.map((card) => {
                const cve = byId.get(card.cveId);
                if (!cve) return null;
                const index = COLUMNS.findIndex((c) => c.id === col.id);
                return (
                  <article
                    key={card.cveId}
                    draggable
                    onDragStart={(e) => {
                      e.dataTransfer.setData("text/plain", card.cveId);
                      setDragging(card.cveId);
                    }}
                    onDragEnd={() => setDragging(null)}
                    className={`group rounded-lg border border-[#e8dfd1] bg-alabaster px-3 py-2.5 transition-shadow hover:shadow-[0_8px_18px_-14px_rgba(11,25,44,0.45)] ${
                      dragging === card.cveId ? "opacity-50" : ""
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <Link
                        href={`/?cve=${card.cveId}`}
                        className="mono text-[12px] text-ink hover:underline"
                      >
                        {card.cveId}
                      </Link>
                      <span className={`chip ${severityChipClass[cve.severity]}`}>{cve.severity}</span>
                    </div>

                    <p className="mt-1.5 line-clamp-2 text-[11.5px] leading-snug text-muted">
                      {cve.description}
                    </p>

                    <div className="mono mt-2 flex items-center gap-3 text-[10.5px] text-[#8b8272]">
                      <span>risk {cve.riskScore}</span>
                      <span>{cve.effortHours}h</span>
                      <span className="truncate">{cve.quadrant}</span>
                    </div>

                    <div className="mt-2 flex items-center justify-between gap-2 border-t border-[#f1e9da] pt-2">
                      <span className="text-[10px] text-[#a39a89]">
                        added {formatDate(card.addedAt.slice(0, 10))}
                      </span>
                      <div className="flex items-center gap-1">
                        {index > 0 && (
                          <button
                            onClick={() => move(card.cveId, COLUMNS[index - 1].id)}
                            className="rounded border border-[#e6dcc8] px-1.5 text-[11px] text-muted hover:bg-[#fbf6ec]"
                            title={`Move to ${COLUMNS[index - 1].title}`}
                          >
                            ←
                          </button>
                        )}
                        {index < COLUMNS.length - 1 && (
                          <button
                            onClick={() => move(card.cveId, COLUMNS[index + 1].id)}
                            className="rounded border border-[#e6dcc8] px-1.5 text-[11px] text-muted hover:bg-[#fbf6ec]"
                            title={`Move to ${COLUMNS[index + 1].title}`}
                          >
                            →
                          </button>
                        )}
                        <button
                          onClick={() => remove(card.cveId)}
                          className="rounded border border-transparent px-1.5 text-[11px] text-[#b3a894] opacity-0 transition-opacity hover:text-crimson group-hover:opacity-100"
                          title="Remove from queue"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        );
      })}

      {cards.length === 0 && (
        <div className="md:col-span-3">
          <Empty
            title="The board is empty"
            body="Open the dashboard, pick a vulnerability and press “Add to queue”. Cards persist on the server, so the board survives reloads."
          />
        </div>
      )}
    </div>
  );
}

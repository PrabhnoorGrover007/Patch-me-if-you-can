"use client";

import { useEffect, useMemo, useState } from "react";
import { dayNum, isoOf, type TmData } from "@/lib/timemachine";

const LIST = 500;
const COLS = 25;
const FRESH_DAYS = 21; // red squares pulse for 3 weeks after the attack is confirmed

function fmt(iso: string) {
  return new Date(iso + "T00:00:00Z").toLocaleDateString("en-CA", {
    month: "short", day: "numeric", year: "numeric", timeZone: "UTC",
  });
}

export default function TimeMachine({ data }: { data: TmData }) {
  const { pool, lists, methods } = data;
  const start = useMemo(() => Math.min(...pool.map((c) => dayNum(c.listed))) - 1, [pool]);
  const end = dayNum(data.label_cutoff);

  const [day, setDay] = useState(start);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [a, setA] = useState(methods[0].key);
  const [b, setB] = useState(methods[methods.length - 1].key);
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setDay((d) => {
        const next = d + 0.5 * speed;
        if (next >= end) {
          setPlaying(false);
          return end;
        }
        return next;
      });
    }, 40);
    return () => clearInterval(t);
  }, [playing, speed, end]);

  const today = Math.floor(day);
  const listedDay = useMemo(() => pool.map((c) => dayNum(c.listed)), [pool]);
  const kevDay = useMemo(() => pool.map((c) => (c.kev ? dayNum(c.kev) : null)), [pool]);

  const attacked = pool
    .map((c, i) => ({ c, i, k: kevDay[i] }))
    .filter((x) => x.k !== null && (x.k as number) <= today)
    .sort((x, y) => (y.k as number) - (x.k as number));

  const caught = (m: string) =>
    lists[m].filter((i) => kevDay[i] !== null && (kevDay[i] as number) <= today).length;

  const label = (m: string) => methods.find((x) => x.key === m)?.label ?? m;
  const done = today >= end;

  const play = () => {
    if (day >= end) setDay(start);
    setPlaying((p) => !p);
  };

  return (
    <div className="space-y-5">
      {/* Controls */}
      <div className="card flex flex-wrap items-center gap-4 px-5 py-4">
        <button onClick={play} className="btn btn-primary min-w-[110px] justify-center">
          {playing ? "❚❚ Pause" : day >= end ? "↺ Replay" : "▶ Play 2025"}
        </button>
        <div className="min-w-[150px]">
          <div className="eyebrow">Date</div>
          <div className="font-display text-[26px] leading-none text-ink">{fmt(isoOf(today))}</div>
        </div>
        <input
          type="range" min={start} max={end} step={1} value={today}
          onChange={(e) => { setPlaying(false); setDay(Number(e.target.value)); }}
          className="min-w-[220px] flex-1 accent-[#9b111e]" aria-label="Replay date"
        />
        <div className="flex items-center gap-1.5">
          {[1, 3, 8].map((s) => (
            <button key={s} onClick={() => setSpeed(s)}
              className={`chip ${speed === s ? "border-gold bg-[rgba(212,175,55,0.18)] text-ink" : "border-hairline text-muted"}`}>
              {s}×
            </button>
          ))}
        </div>
        <div className="text-right">
          <div className="eyebrow">Attacked so far</div>
          <div className="font-display text-[26px] leading-none text-crimson">
            {attacked.length} <span className="text-[16px] text-muted">of {data.attacked_total}</span>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_1fr_340px]">
        {[{ m: a, set: setA }, { m: b, set: setB }].map(({ m, set }, side) => (
          <section key={side} className="card px-5 py-4">
            <div className="mb-3 flex items-start justify-between gap-3">
              <div>
                <div className="eyebrow">{side === 0 ? "List A" : "List B"} · top {LIST}</div>
                <select value={m} onChange={(e) => set(e.target.value)}
                  className="mt-1 rounded-md border border-hairline bg-parchment px-2 py-1 font-display text-[18px] text-ink">
                  {methods.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
                </select>
              </div>
              <div className="text-right">
                <div className="eyebrow">Caught</div>
                <div className={`font-display text-[44px] leading-none ${side === 0 ? "text-crimson" : "text-steel"}`}>
                  {caught(m)}
                </div>
              </div>
            </div>
            <div className="grid gap-[3px]" style={{ gridTemplateColumns: `repeat(${COLS}, minmax(0, 1fr))` }}>
              {lists[m].map((pi, r) => {
                const isListed = listedDay[pi] <= today;
                const k = kevDay[pi];
                const hit = k !== null && k <= today;
                const fresh = hit && today - (k as number) < FRESH_DAYS;
                return (
                  <div key={r}
                    onMouseEnter={() => setHover(pi)} onMouseLeave={() => setHover(null)}
                    title={`#${r + 1} ${pool[pi].id}`}
                    className={`aspect-square rounded-[3px] transition-colors duration-300 ${
                      hit ? "bg-crimson" : isListed ? "bg-ink/70" : "border border-hairline bg-transparent"
                    } ${fresh ? "tm-pulse" : ""} ${hover === pi ? "ring-2 ring-gold" : ""}`}
                  />
                );
              })}
            </div>
            <div className="mt-3 flex flex-wrap gap-4 text-[11.5px] text-muted">
              <span><i className="mr-1 inline-block h-2.5 w-2.5 rounded-[2px] border border-hairline align-middle" />not published yet</span>
              <span><i className="mr-1 inline-block h-2.5 w-2.5 rounded-[2px] bg-ink/70 align-middle" />on the list</span>
              <span><i className="mr-1 inline-block h-2.5 w-2.5 rounded-[2px] bg-crimson align-middle" />hackers used it (CISA KEV)</span>
            </div>
          </section>
        ))}

        {/* Feed / inspector */}
        <aside className="card flex max-h-[640px] flex-col overflow-hidden">
          {hover !== null ? (
            <Inspector data={data} pi={hover} a={a} b={b} label={label} />
          ) : (
            <>
              <header className="border-b border-[#ece3d2] px-4 py-3">
                <div className="eyebrow">Breach log</div>
                <div className="text-[12px] text-muted">Each line: CISA confirms hackers used a bug.</div>
              </header>
              <ol className="flex-1 space-y-2 overflow-y-auto px-4 py-3">
                {attacked.length === 0 && (
                  <li className="text-[13px] text-muted">Nothing yet. Press play.</li>
                )}
                {attacked.map(({ c, i }) => {
                  const ra = c.ranks[a], rb = c.ranks[b];
                  const warn = Math.round((kevDay[i] as number) - listedDay[i]);
                  return (
                    <li key={c.id} className="card-inset px-3 py-2 text-[12.5px] leading-snug"
                      onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
                      <div className="flex justify-between gap-2">
                        <span className="mono font-semibold text-ink">{c.id}</span>
                        <span className="mono text-muted">{fmt(c.kev as string)}</span>
                      </div>
                      <div className="mt-1 flex flex-wrap gap-x-3">
                        <span className={ra <= LIST ? "text-crimson" : "text-muted"}>
                          A: {ra <= LIST ? `#${ra} ✓` : "missed"}
                        </span>
                        <span className={rb <= LIST ? "text-steel" : "text-muted"}>
                          B: {rb <= LIST ? `#${rb} ✓` : "missed"}
                        </span>
                        {ra <= LIST && <span className="text-jade">{warn} days warning</span>}
                      </div>
                    </li>
                  );
                })}
              </ol>
            </>
          )}
        </aside>
      </div>

      {done && (
        <div className="card px-5 py-4 text-[14px] leading-relaxed">
          <b>End of 2025.</b> {label(a)} caught <b>{caught(a)}</b> of {data.attacked_total} attacked bugs in its
          top {LIST}; {label(b)} caught <b>{caught(b)}</b>. These match the historical check in
          validation_results.json.
        </div>
      )}

      <p className="text-[12px] leading-relaxed text-muted">
        How this replay works: models trained only on CVEs published in {data.train_period}. Each 2025 CVE
        joins its list at the end of its publish month, scored only on what was known that month (EPSS,
        exploit flags, description, vendor history before that date). The ranking spans the full 2025 test
        set ({data.pool_size.toLocaleString()} CVEs), exactly as in the validation, so the top-{LIST} cut uses the
        whole year. Red means CISA added it to the Known Exploited list by {data.label_cutoff}. An unlisted
        bug may still have been attacked. Historical result, not the official 2026 score.
      </p>
    </div>
  );
}

function Inspector({ data, pi, a, b, label }: {
  data: TmData; pi: number; a: string; b: string; label: (m: string) => string;
}) {
  const c = data.pool[pi];
  return (
    <div className="px-4 py-3 text-[13px] leading-relaxed">
      <div className="eyebrow">Bug file</div>
      <div className="mono mt-0.5 text-[15px] font-semibold text-ink">{c.id}</div>
      <div className="mt-2 space-y-1 text-muted">
        <div>Joined lists: <b className="text-ink">{fmt(c.listed)}</b></div>
        <div>Attack confirmed: <b className={c.kev ? "text-crimson" : "text-ink"}>{c.kev ? fmt(c.kev) : "not by " + data.label_cutoff}</b></div>
        <div>CVSS: <b className="text-ink">{c.cvss}</b></div>
        <div>{label(a)}: <b className="text-ink">#{c.ranks[a].toLocaleString()}</b></div>
        <div>{label(b)}: <b className="text-ink">#{c.ranks[b].toLocaleString()}</b></div>
      </div>
      <div className="mt-3 eyebrow">Why it ranks</div>
      <p className="text-ink">{c.why}</p>
      <div className="mt-3 eyebrow">Description</div>
      <p className="text-muted">{c.desc}…</p>
    </div>
  );
}

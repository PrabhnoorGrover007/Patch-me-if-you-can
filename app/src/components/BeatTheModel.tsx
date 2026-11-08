"use client";

import { useEffect, useMemo, useState } from "react";
import type { TmCve, TmData } from "@/lib/timemachine";

const ROUNDS = 5;
const OPTIONS = 4;
const SIM_ROUNDS = 5000;
const MODEL = "logistic_regression";

type Round = { cards: number[]; answer: number }; // pool indexes, index of the attacked one

function shuffle<T>(xs: T[]): T[] {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// One round: 1 bug hackers later used + 3 bugs that some method ranked top 500 but were never attacked
function makeRound(attacked: number[], decoys: number[]): Round {
  const hit = attacked[Math.floor(Math.random() * attacked.length)];
  const cards = shuffle([hit, ...shuffle(decoys).slice(0, OPTIONS - 1)]);
  return { cards, answer: cards.indexOf(hit) };
}

const modelPick = (pool: TmCve[], r: Round) =>
  r.cards.reduce((best, pi, i) => (pool[pi].ranks[MODEL] < pool[r.cards[best]].ranks[MODEL] ? i : best), 0);
// "Highest severity wins", ties broken by the CVSS-first ranking
const cvssPick = (pool: TmCve[], r: Round) =>
  r.cards.reduce((best, pi, i) => (pool[pi].ranks.cvss_first < pool[r.cards[best]].ranks.cvss_first ? i : best), 0);

function fmt(iso: string) {
  return new Date(iso + "T00:00:00Z").toLocaleDateString("en-CA", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
}

export default function BeatTheModel({ data }: { data: TmData }) {
  const pool = data.pool;
  const attacked = useMemo(() => pool.flatMap((c, i) => (c.kev ? [i] : [])), [pool]);
  const decoys = useMemo(() => pool.flatMap((c, i) => (c.kev ? [] : [i])), [pool]);

  const [rounds, setRounds] = useState<Round[] | null>(null);
  const [n, setN] = useState(0);
  const [picks, setPicks] = useState<number[]>([]);
  const [sim, setSim] = useState<{ model: number; cvss: number } | null>(null);

  // Random rounds are made after mount so server and browser render the same HTML
  useEffect(() => {
    setRounds(Array.from({ length: ROUNDS }, () => makeRound(attacked, decoys)));
    let m = 0, c = 0;
    for (let i = 0; i < SIM_ROUNDS; i++) {
      const r = makeRound(attacked, decoys);
      if (modelPick(pool, r) === r.answer) m++;
      if (cvssPick(pool, r) === r.answer) c++;
    }
    setSim({ model: m / SIM_ROUNDS, cvss: c / SIM_ROUNDS });
  }, [attacked, decoys, pool]);

  if (!rounds) return <div className="card px-5 py-10 text-center text-muted">Shuffling the line-up…</div>;

  const restart = () => {
    setRounds(Array.from({ length: ROUNDS }, () => makeRound(attacked, decoys)));
    setN(0);
    setPicks([]);
  };

  const score = (who: "you" | "model" | "cvss") =>
    picks.filter((p, i) => {
      const r = rounds[i];
      const choice = who === "you" ? p : who === "model" ? modelPick(pool, r) : cvssPick(pool, r);
      return choice === r.answer;
    }).length;

  const finished = picks.length === ROUNDS;
  const r = rounds[Math.min(n, ROUNDS - 1)];
  const revealed = picks.length > n;
  const mp = modelPick(pool, r);
  const cp = cvssPick(pool, r);

  return (
    <div className="space-y-5">
      {/* Scoreboard */}
      <div className="card flex flex-wrap items-center justify-between gap-4 px-5 py-4">
        <div>
          <div className="eyebrow">Round</div>
          <div className="font-display text-[30px] leading-none text-ink">
            {Math.min(n + 1, ROUNDS)} <span className="text-[16px] text-muted">of {ROUNDS}</span>
          </div>
        </div>
        <div className="flex gap-8">
          {([["You", "you", "text-ink"], ["Our model", "model", "text-crimson"], ["Highest CVSS", "cvss", "text-steel"]] as const).map(
            ([lbl, who, tone]) => (
              <div key={who} className="text-center">
                <div className="eyebrow">{lbl}</div>
                <div className={`font-display text-[34px] leading-none ${tone}`}>{score(who)}</div>
              </div>
            ),
          )}
        </div>
      </div>

      {finished ? (
        <div className="card px-6 py-8 text-center">
          <div className="eyebrow">Final score</div>
          <div className="mt-2 font-display text-[40px] leading-tight text-ink">
            You {score("you")} · Model {score("model")} · Highest CVSS {score("cvss")}
          </div>
          {sim && (
            <p className="mx-auto mt-3 max-w-2xl text-[14px] leading-relaxed text-muted">
              Over {SIM_ROUNDS.toLocaleString()} random rounds like these, the model picks the attacked bug{" "}
              <b className="text-crimson">{Math.round(sim.model * 100)}%</b> of the time, highest CVSS{" "}
              <b className="text-steel">{Math.round(sim.cvss * 100)}%</b>, and a blind guess 25%.
            </p>
          )}
          <button onClick={restart} className="btn btn-primary mt-5">↺ Play again</button>
        </div>
      ) : (
        <>
          <p className="text-[15px] text-ink">
            <b>One of these four was used by hackers in 2025.</b> The other three looked just as scary but were never
            attacked. You only get what defenders knew that month. Which one do you patch first?
          </p>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {r.cards.map((pi, i) => {
              const c = pool[pi];
              const isAnswer = i === r.answer;
              const mine = picks[n] === i;
              const border = !revealed
                ? "hover:border-gold hover:-translate-y-0.5 cursor-pointer"
                : isAnswer
                  ? "!border-crimson ring-2 ring-crimson"
                  : mine
                    ? "opacity-70 !border-steel"
                    : "opacity-50";
              return (
                <button key={pi} disabled={revealed}
                  onClick={() => setPicks((p) => [...p.slice(0, n), i])}
                  className={`card flex flex-col px-4 py-4 text-left transition-all ${border}`}>
                  <div className="flex items-center justify-between">
                    <span className="mono text-[12px] text-muted">Suspect {String.fromCharCode(65 + i)}</span>
                    <span className="flex gap-1">
                      {revealed && mine && <span className="chip border-ink text-ink">you</span>}
                      {revealed && mp === i && <span className="chip border-crimson text-crimson">model</span>}
                      {revealed && cp === i && <span className="chip border-steel text-steel">CVSS</span>}
                    </span>
                  </div>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-[12px]">
                    <div className="card-inset px-2 py-1.5">
                      <div className="eyebrow !text-[9px]">Severity</div>
                      <div className="font-display text-[22px] leading-none text-ink">{c.cvss.toFixed(1)}</div>
                    </div>
                    <div className="card-inset px-2 py-1.5">
                      <div className="eyebrow !text-[9px]">EPSS rank</div>
                      <div className="font-display text-[22px] leading-none text-ink">top {Math.max(1, Math.round((1 - c.epss_pct) * 100))}%</div>
                    </div>
                  </div>
                  <div className="mt-2 text-[12px] text-muted">
                    Exploit code: <b className="text-ink">{c.code.length ? c.code.join(", ") : "none public"}</b>
                  </div>
                  <p className="mt-2 flex-1 text-[12.5px] leading-snug text-ink">{c.desc}{c.desc.length >= 280 ? "…" : ""}</p>
                  {revealed && (
                    <div className={`mt-3 border-t border-hairline pt-2 text-[12px] ${isAnswer ? "text-crimson" : "text-muted"}`}>
                      <span className="mono">{c.id}</span>
                      <br />
                      {isAnswer ? <b>Attacked: CISA confirmed {fmt(c.kev as string)}</b> : "Not attacked by end of 2025"}
                      <br />
                      Model rank #{c.ranks[MODEL].toLocaleString()} of {data.pool_size.toLocaleString()}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
          {revealed && (
            <div className="card flex flex-wrap items-center justify-between gap-3 px-5 py-4">
              <div className="text-[14px]">
                {picks[n] === r.answer ? <b className="text-jade">You got it.</b> : <b className="text-crimson">Missed.</b>}{" "}
                Model: {mp === r.answer ? "✓" : "✗"} · Highest CVSS: {cp === r.answer ? "✓" : "✗"}
                {mp === r.answer && <span className="text-muted"> · why the model picked it: {pool[r.cards[mp]].why}</span>}
              </div>
              <button onClick={() => setN(n + 1)} className="btn btn-primary">
                {n + 1 === ROUNDS ? "See final score" : "Next round →"}
              </button>
            </div>
          )}
        </>
      )}

      <p className="text-[12px] leading-relaxed text-muted">
        Real 2025 CVEs from the historical check (model trained on {data.train_period} only). The attacked bug was added
        to CISA KEV after its publish month and by {data.label_cutoff}. The other three come from bugs some method ranked
        in its top 500 that were not on KEV by then. Clues are what was known at the end of the publish month.
      </p>
    </div>
  );
}

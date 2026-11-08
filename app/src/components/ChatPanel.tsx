"use client";

import { useEffect, useRef, useState } from "react";
import { askAssistant } from "@/lib/ai-actions";
import type { AiResult, ChatMessage } from "@/lib/types";
import { SourceBadge } from "./ui";

const DEFAULT_SUGGESTIONS = [
  "Why is this ranked so high?",
  "What should I patch first?",
  "Which CVEs look similar?",
  "Is there public exploit code?",
];

export default function ChatPanel({
  cveId,
  cveLabel,
  suggestions = DEFAULT_SUGGESTIONS,
  className = "",
  compact = false,
}: {
  cveId?: string | null;
  cveLabel?: string;
  suggestions?: string[];
  className?: string;
  compact?: boolean;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [last, setLast] = useState<AiResult | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, busy]);

  async function send(text: string) {
    const question = text.trim();
    if (!question || busy) return;

    const next: ChatMessage[] = [...messages, { role: "user", content: question }];
    setMessages(next);
    setInput("");
    setBusy(true);

    try {
      const result = await askAssistant({ cveId: cveId ?? null, messages: next });
      setLast(result);
      setMessages([...next, { role: "assistant", content: result.text }]);
    } catch {
      setMessages([
        ...next,
        {
          role: "assistant",
          content:
            "The IBM Granite evidence service could not be reached. Start the FastAPI backend, then try again. No answer was fabricated.",
        },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`flex min-h-0 flex-col ${className}`}>
      <div className={`flex-1 space-y-3 overflow-y-auto ${compact ? "px-4 py-4" : "px-1 py-2"}`}>
        {messages.length === 0 && (
          <div className="space-y-3">
            <div className="card-inset px-4 py-3">
              <p className="text-[13px] leading-relaxed text-ink">
                {cveId
                  ? `I have ${cveId} in context — its CVSS vector, EPSS position, exploit signals and affected products. Ask me what to fix first.`
                  : "No single CVE selected. I can still talk about the 500 ranked vulnerabilities and why they sit where they do."}
              </p>
              {cveLabel && <p className="mt-1.5 line-clamp-2 text-[12px] text-muted">{cveLabel}</p>}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {suggestions.map((s) => (
                <button
                  key={s}
                  onClick={() => void send(s)}
                  className="rounded-full border border-[rgba(212,175,55,0.4)] bg-alabaster px-3 py-1 text-[12px] text-ink transition hover:bg-[rgba(212,175,55,0.12)]"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[88%] whitespace-pre-wrap rounded-xl px-3.5 py-2.5 text-[13px] leading-relaxed ${
                m.role === "user"
                  ? "bg-ink text-[#fdf8ee]"
                  : "border border-[#e8dfd1] bg-alabaster text-ink"
              }`}
            >
              {m.content}
            </div>
          </div>
        ))}

        {busy && (
          <div className="flex items-center gap-2 px-1 text-[12px] text-muted">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-gold" />
            Reading the advisory…
          </div>
        )}
        <div ref={endRef} />
      </div>

      <div className={`${compact ? "px-4" : "px-1"} border-t border-[#e8dfd1] pt-3 pb-4`}>
        {last && (
          <div className="mb-2 flex items-center gap-2">
            <SourceBadge result={last} />
            {last.error && (
              <span className="truncate text-[11px] text-crimson" title={last.error}>
                Model error — answered locally
              </span>
            )}
          </div>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(input);
          }}
          className="flex items-end gap-2"
        >
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send(input);
              }
            }}
            rows={1}
            placeholder={cveId ? `Ask about ${cveId}…` : "Ask anything about the cohort…"}
            className="input max-h-28 min-h-[42px] resize-none py-2.5"
          />
          <button type="submit" disabled={busy || !input.trim()} className="btn btn-primary h-[42px]">
            Send
          </button>
        </form>
        <p className="mt-2 text-[11px] leading-snug text-muted">
          Answers use only what was known at the CVE&apos;s snapshot month.
        </p>
      </div>
    </div>
  );
}

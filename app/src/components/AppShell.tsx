"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { useChat } from "./ChatProvider";

const TABS = [
  { href: "/", label: "Dashboard" },
  { href: "/analytics", label: "Risk trends" },
  { href: "/queue", label: "Remediation" },
  { href: "/upload", label: "Upload" },
  { href: "/chat", label: "Chat" },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { openChat } = useChat();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b border-[rgba(212,175,55,0.25)] bg-[rgba(253,248,238,0.88)] backdrop-blur-md">
        <div className="mx-auto w-full max-w-[1600px] px-5 sm:px-6">
          <div className="flex items-center justify-between gap-4 py-3.5">
            <Link href="/" className="flex items-center gap-3">
              <span className="grid h-11 w-11 place-items-center rounded-full border border-gold/70 bg-[radial-gradient(circle_at_30%_25%,#fffdfa,#f3e9d2)] shadow-[inset_0_0_0_3px_rgba(212,175,55,0.22)]">
                <span className="font-display text-[20px] leading-none text-ink">P</span>
              </span>
              <span className="leading-tight">
                <span className="block font-display text-[21px] tracking-tight text-ink">
                  Patch Me If You Can
                </span>
                <span className="mono block text-[10px] uppercase tracking-[0.16em] text-muted">
                  Sheridan Datathon 2026 · IBM track
                </span>
              </span>
            </Link>

            <div className="flex items-center gap-3">
              <span className="hidden text-[12px] leading-tight text-muted md:block md:max-w-[220px]">
                Ranked top 500 · AI on demand
              </span>
              <button onClick={() => openChat(null)} className="btn btn-primary">
                <span aria-hidden>✦</span> Ask AI
              </button>
            </div>
          </div>

          <nav className="-mb-px flex items-center gap-1 overflow-x-auto">
            {TABS.map((tab) => {
              const active = pathname === tab.href;
              return (
                <Link
                  key={tab.href}
                  href={tab.href}
                  className={`relative whitespace-nowrap px-3.5 py-2.5 text-[13.5px] transition-colors ${
                    active ? "text-ink" : "text-muted hover:text-ink"
                  }`}
                >
                  {tab.label}
                  <span
                    className={`absolute inset-x-2.5 -bottom-px h-[2px] rounded-full transition-opacity ${
                      active ? "bg-gold opacity-100" : "opacity-0"
                    }`}
                  />
                </Link>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1600px] flex-1 px-5 py-7 sm:px-6">{children}</main>

      <footer className="mx-auto w-full max-w-[1600px] px-5 pb-8 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[rgba(212,175,55,0.25)] pt-4 text-[11.5px] text-muted">
          <span>
            Risk score is a prioritisation rank, not a calibrated probability. Signals are limited to
            what was known at each snapshot month.
          </span>
          <span className="mono uppercase tracking-[0.12em]">NIST · CISA KEV · EPSS · AI analyst</span>
        </div>
      </footer>
    </div>
  );
}

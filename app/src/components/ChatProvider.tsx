"use client";

import { createContext, useContext, useState, type ReactNode } from "react";
import ChatPanel from "./ChatPanel";

export interface ChatTarget {
  cveId: string;
  label: string;
}

interface ChatControl {
  openChat: (target?: ChatTarget | null) => void;
  closeChat: () => void;
}

const ChatContext = createContext<ChatControl | null>(null);

export function useChat(): ChatControl {
  const ctx = useContext(ChatContext);
  if (!ctx) throw new Error("useChat must be used inside <ChatProvider>");
  return ctx;
}

export function ChatProvider({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<ChatTarget | null>(null);
  const [open, setOpen] = useState(false);

  const openChat = (next?: ChatTarget | null) => {
    if (next !== undefined) setTarget(next);
    setOpen(true);
  };
  const closeChat = () => setOpen(false);

  return (
    <ChatContext.Provider value={{ openChat, closeChat }}>
      {children}

      <div
        aria-hidden={!open}
        className={`fixed inset-0 z-50 transition-opacity duration-300 ${
          open ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
        }`}
      >
        <button
          aria-label="Close chat"
          onClick={closeChat}
          className="absolute inset-0 h-full w-full cursor-default bg-[rgba(11,25,44,0.35)] backdrop-blur-[2px]"
        />
        <aside
          className={`absolute right-0 top-0 flex h-full w-full max-w-[460px] flex-col border-l border-[rgba(212,175,55,0.45)] bg-parchment shadow-[0_24px_48px_-12px_rgba(11,25,44,0.35)] transition-transform duration-300 ${
            open ? "translate-x-0" : "translate-x-full"
          }`}
        >
          <header className="flex items-start justify-between gap-3 border-b border-[#e8dfd1] px-5 py-4">
            <div className="min-w-0">
              <div className="eyebrow">AI assistant · grounded in the data</div>
              <div className="mt-0.5 truncate font-display text-[20px] leading-tight text-ink">
                {target?.cveId ?? "Ask about the cohort"}
              </div>
              {target?.label && (
                <p className="mt-0.5 line-clamp-1 text-[12px] text-muted">{target.label}</p>
              )}
            </div>
            <button onClick={closeChat} className="btn btn-ghost px-2.5 py-1 text-[12px]">
              Close
            </button>
          </header>

          <ChatPanel
            key={target?.cveId ?? "global"}
            cveId={target?.cveId}
            cveLabel={target?.label}
            className="flex-1"
            compact
          />
        </aside>
      </div>
    </ChatContext.Provider>
  );
}

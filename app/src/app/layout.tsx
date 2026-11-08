import type { Metadata } from "next";
import "./globals.css";
import AppShell from "@/components/AppShell";
import { ChatProvider } from "@/components/ChatProvider";

export const metadata: Metadata = {
  title: "Patch Me If You Can · SecOps",
  description:
    "AI-assisted vulnerability prioritisation: the top 500 CVEs of the 2026 scoreboard, ranked, explained and routed to remediation.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=EB+Garamond:wght@400;500;600;700&family=Source+Sans+3:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <ChatProvider>
          <AppShell>{children}</AppShell>
        </ChatProvider>
      </body>
    </html>
  );
}

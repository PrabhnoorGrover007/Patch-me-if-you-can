import { promises as fs } from "node:fs";
import path from "node:path";
import type { QueueCard, QueueStatus } from "./types";

/**
 * Remediation queue persistence. This is a small JSON file on the server, behind
 * server actions, so the Kanban survives reloads without a database. Swap these
 * four functions for Supabase queries to move it to Postgres.
 */
const STORE_FILE =
  process.env.REMEDIATION_STORE ?? path.join(process.cwd(), ".data", "remediation.json");

async function writeAll(cards: QueueCard[]): Promise<void> {
  await fs.mkdir(path.dirname(STORE_FILE), { recursive: true });
  await fs.writeFile(STORE_FILE, JSON.stringify({ cards }, null, 2), "utf8");
}

export async function readCards(): Promise<QueueCard[]> {
  try {
    const raw = await fs.readFile(STORE_FILE, "utf8");
    const parsed = JSON.parse(raw) as { cards?: QueueCard[] };
    return Array.isArray(parsed.cards) ? parsed.cards : [];
  } catch {
    return [];
  }
}

export async function upsertCard(cveId: string, status: QueueStatus): Promise<QueueCard[]> {
  const cards = await readCards();
  const now = new Date().toISOString();
  const existing = cards.find((c) => c.cveId === cveId);

  if (existing) {
    if (existing.status !== status) {
      existing.status = status;
      existing.updatedAt = now;
      existing.doneAt = status === "done" ? now : null;
    }
  } else {
    cards.push({
      cveId,
      status,
      addedAt: now,
      updatedAt: now,
      doneAt: status === "done" ? now : null,
    });
  }

  await writeAll(cards);
  return cards;
}

export async function removeCard(cveId: string): Promise<QueueCard[]> {
  const cards = (await readCards()).filter((c) => c.cveId !== cveId);
  await writeAll(cards);
  return cards;
}

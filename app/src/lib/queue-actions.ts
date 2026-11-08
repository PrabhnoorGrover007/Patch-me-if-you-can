"use server";

import { revalidatePath } from "next/cache";
import { removeCard, upsertCard } from "./queue-store";
import type { QueueStatus } from "./types";

function refresh() {
  revalidatePath("/");
  revalidatePath("/queue");
  revalidatePath("/analytics");
}

export async function addToQueue(cveId: string): Promise<void> {
  await upsertCard(cveId, "todo");
  refresh();
}

export async function moveCard(cveId: string, status: QueueStatus): Promise<void> {
  await upsertCard(cveId, status);
  refresh();
}

export async function dropCard(cveId: string): Promise<void> {
  await removeCard(cveId);
  refresh();
}

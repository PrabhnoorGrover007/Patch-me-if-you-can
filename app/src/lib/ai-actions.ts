"use server";

import { getBriefs, getCve } from "./data";
import {
  askModel,
  buildChatPrompt,
  buildInsightPrompt,
  offlineAnswer,
  offlineInsight,
} from "./llm";
import type { AiResult, ChatMessage } from "./types";

/** One-paragraph AI briefing for the selected CVE. */
export async function getInsight(cveId: string): Promise<AiResult> {
  const cve = getCve(cveId);
  if (!cve) {
    return { text: "That CVE is not part of the ranked top 500.", source: "offline" };
  }

  try {
    const answer = await askModel(buildInsightPrompt(cve), 1200);
    if (answer) {
      return { text: answer.text, source: "model", provider: answer.provider, model: answer.model };
    }
  } catch (error) {
    return {
      text: offlineInsight(cve),
      source: "offline",
      error: error instanceof Error ? error.message : "model request failed",
    };
  }

  return { text: offlineInsight(cve), source: "offline" };
}

/** Contextual chat. The CVE record is injected server-side, so the client never sends it. */
export async function askAssistant(input: {
  cveId?: string | null;
  messages: ChatMessage[];
}): Promise<AiResult> {
  const cve = input.cveId ? getCve(input.cveId) : null;
  const messages = (input.messages ?? []).filter(
    (m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string"
  );
  const lastQuestion = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";

  try {
    const answer = await askModel(
      buildChatPrompt(cve, messages, cve ? [] : getBriefs().slice(0, 10)),
      1600
    );
    if (answer) {
      return { text: answer.text, source: "model", provider: answer.provider, model: answer.model };
    }
  } catch (error) {
    return {
      text: offlineAnswer(cve, lastQuestion),
      source: "offline",
      error: error instanceof Error ? error.message : "model request failed",
    };
  }

  return { text: offlineAnswer(cve, lastQuestion), source: "offline" };
}

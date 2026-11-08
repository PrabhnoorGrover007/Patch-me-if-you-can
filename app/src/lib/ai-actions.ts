"use server";

import { apiFetch } from "./api";
import type { AiResult, ChatMessage, ChatResponse, GraniteAnalysis } from "./types";

/**
 * All analyst text is grounded in FastAPI evidence. There is no Gemini or other
 * hosted generation in this build: the shipped Granite artefact is an embedding
 * model, so answers are assembled from records, attribution and analog retrieval.
 */
export async function getInsight(cveId: string): Promise<AiResult> {
  try {
    const [analysis, chat] = await Promise.all([
      apiFetch<GraniteAnalysis>("/api/granite/analyze", {
        method: "POST",
        body: JSON.stringify({ cve_id: cveId }),
      }),
      apiFetch<ChatResponse>("/api/granite/chat", {
        method: "POST",
        body: JSON.stringify({
          cve_id: cveId,
          question: `Why is ${cveId} ranked here, and what should we fix first?`,
        }),
      }),
    ]);

    const evidence = analysis.extracted.evidence
      .slice(0, 3)
      .map((item) => `${item.characteristic.replaceAll("_", " ")}: “${item.source_text}”`);
    const unknown = analysis.extracted.uncertainty.slice(0, 3);

    const text = [
      chat.answer,
      evidence.length ? `Grounded description evidence:\n${evidence.join("\n")}` : "",
      unknown.length ? `Not established by the advisory: ${unknown.join("; ")}.` : "",
    ]
      .filter(Boolean)
      .join("\n\n");

    return {
      text,
      source: chat.generative_model ? "model" : "grounded",
      provider: "granite",
      model: chat.generative_model ?? analysis.embedding_model,
      error: chat.generation_error ?? undefined,
    };
  } catch (error) {
    return {
      text: "The IBM Granite evidence service is unavailable. Start the FastAPI backend, then retry; no answer has been invented locally.",
      source: "offline",
      error: error instanceof Error ? error.message : "backend request failed",
    };
  }
}

/** Contextual analyst chat. The backend owns the evidence lookup. */
export async function askAssistant(input: {
  cveId?: string | null;
  messages: ChatMessage[];
}): Promise<AiResult> {
  const messages = (input.messages ?? []).filter(
    (message) =>
      message &&
      (message.role === "user" || message.role === "assistant") &&
      typeof message.content === "string",
  );
  const lastQuestion = [...messages].reverse().find((message) => message.role === "user")?.content ?? "";

  try {
    const answer = await apiFetch<ChatResponse>("/api/granite/chat", {
      method: "POST",
      body: JSON.stringify({
        question: lastQuestion,
        cve_id: input.cveId ?? null,
      }),
    });
    return {
      text: answer.answer,
      source: answer.generative_model ? "model" : "grounded",
      provider: "granite",
      model: answer.generative_model ?? "granite-embedding-30m-english",
      error: answer.generation_error ?? undefined,
    };
  } catch (error) {
    return {
      text: "The IBM Granite evidence service could not be reached. Start the FastAPI backend and try again. No answer was fabricated.",
      source: "offline",
      error: error instanceof Error ? error.message : "backend request failed",
    };
  }
}

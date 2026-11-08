import type { AiProvider, ChatMessage, Cve, CveBrief } from "./types";
import { formatEpss, percentileLabel } from "./format";

// ---------------------------------------------------------------------------
// Provider configuration
//
// Gemini is the default hosted model. The watsonx / IBM Granite path stays in
// place because the IBM track requires it, and because a team with watsonx
// credits should not have to rewrite anything: whichever key is present wins.
// ---------------------------------------------------------------------------

export function geminiModel(): string {
  // gemini-3.5-flash is deprecated; Google routes it to 3.6, so ask for 3.6.
  return process.env.GEMINI_MODEL_ID || "gemini-3.6-flash";
}

export function graniteModel(): string {
  // Granite 3.0 was withdrawn from the multitenant offering in Feb 2026.
  return process.env.GRANITE_MODEL_ID || "ibm/granite-4-h-small";
}

export function activeProvider(): AiProvider | null {
  if (process.env.GEMINI_API_KEY) return "gemini";
  if (process.env.WATSONX_API_KEY && process.env.WATSONX_PROJECT_ID) return "watsonx";
  return null;
}

export function activeModel(): string | null {
  const provider = activeProvider();
  if (provider === "gemini") return geminiModel();
  if (provider === "watsonx") return graniteModel();
  return null;
}

// ---------------------------------------------------------------------------
// Prompt construction. Everything here comes from the snapshot the CVE was
// scored on, so the model cannot leak the answer from a later month.
// ---------------------------------------------------------------------------

export function cveContext(cve: Cve): string {
  const products = cve.products.length
    ? cve.products.map((p) => `${p.vendor} ${p.product}${p.version ? ` ${p.version}` : ""}`).join(", ")
    : "no product list (NIST has not reviewed this CVE)";
  const cwes = cve.cwes.length ? cve.cwes.map((c) => `${c.id} ${c.name}`).join("; ") : "none listed";
  const signals = [
    cve.flags.metasploit ? "Metasploit module" : null,
    cve.flags.exploitdb ? "Exploit-DB entry" : null,
    cve.flags.nuclei ? "Nuclei scanner template" : null,
    cve.flags.pocGithub ? "GitHub proof of concept" : null,
  ].filter(Boolean);

  return [
    `CVE: ${cve.cveId}`,
    `Published: ${cve.published} · snapshot month: ${cve.snapshotMonth}`,
    `Severity: ${cve.severity} · CVSS ${cve.cvssScore ?? "blank"} · vector ${cve.cvssVector || "blank"}`,
    `Attack: vector ${cve.attackVector || "blank"}, complexity ${cve.attackComplexity || "blank"}, privileges ${cve.privilegesRequired || "blank"}, user interaction ${cve.userInteraction || "blank"}`,
    `EPSS at cutoff: ${formatEpss(cve.epss)} (${percentileLabel(cve.epssPct)})`,
    `Public exploit code at cutoff: ${signals.length ? signals.join(", ") : "none"}`,
    `Weakness types: ${cwes}`,
    `Affected products: ${products}`,
    `Assigning CNA: ${cve.assignerLabel}`,
    `Rank in our top 500: ${cve.rank} (composite risk ${cve.riskScore}/100)`,
    `Estimated remediation effort: ${cve.effortHours}h (${cve.effortTier})`,
    `Description: ${cve.description}`,
  ].join("\n");
}

export function buildInsightPrompt(cve: Cve): string {
  return `You are a senior vulnerability-management analyst writing for an engineering lead.
Using only the CVE context below, write a briefing in exactly three short labelled paragraphs:

THREAT — what the vulnerability is and who can exploit it.
URGENCY — why it sits at this rank, citing the exploit signals and the EPSS position.
FIX — the concrete remediation path plus one temporary mitigation.

Stay under 150 words. Never invent CVE ids, vendors, versions, dates or exploit details that are not
in the context. If the context is thin, say what is unknown. Do not mention which model you are.
Write plain text only: no markdown, no asterisks for emphasis, no bullet symbols, no code fences.

CONTEXT
${cveContext(cve)}

BRIEFING
`;
}

export function buildChatPrompt(
  cve: Cve | null,
  messages: ChatMessage[],
  topBriefs: CveBrief[] = []
): string {
  const convo = messages
    .slice(-8)
    .map((m) => `${m.role === "user" ? "Developer" : "Analyst"}: ${m.content}`)
    .join("\n");

  // With no CVE selected the model still needs real records, otherwise it can only
  // describe the method and refuses to name anything.
  const context = cve
    ? cveContext(cve)
    : [
        "No single CVE is selected. Answer using the cohort facts: 72,670 vulnerabilities in the 2026 scoreboard, 500 submitted, signals are CVSS, EPSS percentile and public exploit code at each snapshot month.",
        topBriefs.length
          ? `Highest ranked records in this cohort:\n${topBriefs
              .map((b) => `#${b.rank} ${b.cveId} · ${b.severity} · risk ${b.riskScore} · ${b.description}`)
              .join("\n")}`
          : "",
      ]
        .filter(Boolean)
        .join("\n\n");

  return `You are the SecOps analyst inside "Patch Me If You Can".
You help developers and security managers decide what to patch and how. Be concrete, calm and
technical. Prefer specific upgrade steps and mitigations. Keep answers under 200 words, use short
paragraphs, and never invent facts that are not in the context. Do not mention which model you are.
Write plain text only: no markdown, no asterisks for emphasis, no bullet symbols, no code fences.

CVE CONTEXT
${context}

CONVERSATION
${convo}
Analyst:
`;
}

// ---------------------------------------------------------------------------
// Model calls
// ---------------------------------------------------------------------------

export interface ModelAnswer {
  text: string;
  provider: AiProvider;
  model: string;
}

/**
 * Sends the prompt to whichever provider is configured.
 * Returns null when no credentials exist, so callers fall back to the local explainer.
 */
export async function askModel(prompt: string, maxTokens = 700): Promise<ModelAnswer | null> {
  const provider = activeProvider();
  if (!provider) return null;

  if (provider === "gemini") {
    return { text: await callGemini(prompt, maxTokens), provider, model: geminiModel() };
  }
  return { text: await callWatsonx(prompt, maxTokens), provider, model: graniteModel() };
}

/** Google Gemini, generateContent REST API. No SDK, so there is nothing extra to install. */
async function callGemini(prompt: string, maxOutputTokens: number): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY is not set");

  const base = (
    process.env.GEMINI_API_URL || "https://generativelanguage.googleapis.com/v1beta"
  ).replace(/\/$/, "");
  const model = geminiModel();

  const res = await fetch(`${base}/models/${encodeURIComponent(model)}:generateContent`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": apiKey,
    },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens,
        // Gemini 3.x bills reasoning against maxOutputTokens. These answers are short and
        // grounded, so LOW thinking keeps the budget for the answer itself.
        thinkingConfig: { thinkingLevel: "LOW" },
      },
    }),
    cache: "no-store",
  });

  if (!res.ok) {
    const detail = (await res.text()).slice(0, 240);
    throw new Error(`Gemini generation failed (${res.status}): ${detail}`);
  }

  const json = (await res.json()) as {
    candidates?: {
      content?: { parts?: { text?: string; thought?: boolean }[] };
      finishReason?: string;
    }[];
    promptFeedback?: { blockReason?: string };
  };

  if (json.promptFeedback?.blockReason) {
    throw new Error(`Gemini blocked the prompt (${json.promptFeedback.blockReason})`);
  }

  // Reasoning parts are marked with `thought: true`; never surface them as the answer.
  const text = (json.candidates?.[0]?.content?.parts ?? [])
    .filter((part) => !part.thought)
    .map((part) => part.text ?? "")
    .join("")
    .trim();

  if (!text) {
    const reason = json.candidates?.[0]?.finishReason;
    if (reason === "MAX_TOKENS") {
      throw new Error("Gemini spent the whole token budget on reasoning before answering");
    }
    throw new Error(
      reason ? `Gemini returned no text (finishReason ${reason})` : "Gemini returned an empty response"
    );
  }
  return text;
}

async function iamToken(apiKey: string): Promise<string> {
  const res = await fetch("https://iam.cloud.ibm.com/identity/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "urn:ibm:params:oauth:grant-type:apikey",
      apikey: apiKey,
    }),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`IAM token request failed (${res.status})`);
  const json = (await res.json()) as { access_token?: string };
  if (!json.access_token) throw new Error("IAM response had no access_token");
  return json.access_token;
}

/** IBM Granite through the watsonx.ai text generation API. */
async function callWatsonx(prompt: string, maxNewTokens: number): Promise<string> {
  const apiKey = process.env.WATSONX_API_KEY;
  const projectId = process.env.WATSONX_PROJECT_ID;
  if (!apiKey || !projectId) throw new Error("WATSONX_API_KEY and WATSONX_PROJECT_ID are not set");

  const baseUrl = (process.env.WATSONX_URL || "https://us-south.ml.cloud.ibm.com").replace(/\/$/, "");
  const token = await iamToken(apiKey);

  const res = await fetch(`${baseUrl}/ml/v1/text/generation?version=2025-02-11`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      model_id: graniteModel(),
      project_id: projectId,
      input: prompt,
      parameters: {
        decoding_method: "greedy",
        max_new_tokens: maxNewTokens,
        min_new_tokens: 32,
        temperature: 0.2,
        repetition_penalty: 1.05,
      },
    }),
    cache: "no-store",
  });

  if (!res.ok) {
    const detail = (await res.text()).slice(0, 240);
    throw new Error(`watsonx generation failed (${res.status}): ${detail}`);
  }

  const json = (await res.json()) as { results?: { generated_text?: string }[] };
  const text = json.results?.[0]?.generated_text?.trim();
  if (!text) throw new Error("Granite returned an empty response");
  return text;
}

// ---------------------------------------------------------------------------
// Offline fallbacks: same shape of answer, built from the dataset instead of a
// model. They keep every screen useful before API credentials are added.
// ---------------------------------------------------------------------------

function firstSentence(text: string, limit = 240): string {
  const clean = text.trim();
  const cut = clean.slice(0, limit);
  const end = cut.lastIndexOf(". ");
  const body = end > 80 ? cut.slice(0, end + 1) : cut;
  return body.endsWith(".") ? body : `${body}.`;
}

function fixLine(cve: Cve): string {
  const target = cve.products[0];
  const base = target
    ? `Upgrade ${target.vendor} ${target.product}${target.version ? ` (${target.version})` : ""} to the vendor's fixed release and restart the service.`
    : "Apply the vendor's fixed release for the affected component and restart the service.";

  let mitigation = "";
  if (cve.keywords.includes("internet-facing device")) {
    mitigation = " Until it is patched, take the management interface off the public internet and require VPN access.";
  } else if (cve.keywords.includes("no login required") || cve.keywords.includes("authentication bypass")) {
    mitigation = " Until it is patched, put an authentication check in front of the exposed route.";
  } else if (cve.flags.nuclei || cve.flags.metasploit) {
    mitigation = " Until it is patched, deploy your scanner's detection template in blocking mode and watch the logs for hits.";
  }

  return `${base}${mitigation} Estimated effort: about ${cve.effortHours}h (${cve.effortTier.toLowerCase()}).`;
}

export function offlineInsight(cve: Cve): string {
  const cwe = cve.cwes[0]?.name ?? "weakness";
  const reach =
    cve.attackVector === "NETWORK" ? "reachable over the network" : "not reachable over the network";
  const auth =
    cve.privilegesRequired === "NONE" ? "with no credentials" : "after some level of access";

  const signals: string[] = [];
  if (cve.flags.metasploit) signals.push("a Metasploit module");
  if (cve.flags.exploitdb) signals.push("an Exploit-DB entry");
  if (cve.flags.nuclei) signals.push("a Nuclei scanner template");
  if (cve.flags.pocGithub) signals.push("a GitHub proof of concept");

  const threat = `${cve.cveId} is a ${cve.severity.toLowerCase()} ${cwe.toLowerCase()} rated ${
    cve.cvssScore ?? "unscored"
  }/10, ${reach} and ${auth}. ${firstSentence(cve.description)}`;

  const urgency = `Rank ${cve.rank} of 500. ${
    signals.length
      ? `At the ${cve.snapshotMonth} cutoff it already had ${signals.join(", ")}.`
      : "No public exploit code existed at the cutoff, so the ranking leans on EPSS and the weakness class."
  } EPSS was ${formatEpss(cve.epss)}, ${percentileLabel(cve.epssPct)}.`;

  return `THREAT — ${threat}\n\nURGENCY — ${urgency}\n\nFIX — ${fixLine(cve)}`;
}

function wafNote(cve: Cve): string {
  return `A virtual patch only buys time. Shape of the rule for ${cve.cveId}:

nginx
  # deny the request shape described in the advisory
  location /<affected-route> {
    if ($request_uri ~* "<attack-pattern>") { return 403; }
  }

Envoy
  - apply a RBAC filter on the affected route that denies the same pattern,
    and log the blocked request body for triage.

Fill in <affected-route> and <attack-pattern> from the vendor advisory, then re-test with the
Nuclei template${cve.flags.nuclei ? " (one exists for this CVE)" : ""}. Schedule the real upgrade: ${cve.effortHours}h estimated.`;
}

export function offlineAnswer(cve: Cve | null, question: string): string {
  if (!cve) {
    return "I do not have a CVE in context yet. Pick one from the dashboard (or from the selector on this page) and ask again — I can then reason about its CVSS vector, exploit signals and patch path.";
  }

  const q = question.toLowerCase();

  if (/\bwaf\b|nginx|envoy|virtual patch|block|mitigat/.test(q)) {
    return wafNote(cve);
  }

  if (/patch|fix|upgrade|remediat|update|how do i/.test(q)) {
    return `${fixLine(cve)}\n\nIf you cannot ship the upgrade this sprint, the interim control is to restrict the exposed surface and watch for exploitation attempts — this CVE ${
      cve.flags.nuclei ? "has a Nuclei template you can run in blocking mode." : "has no public detection template, so log inspection is your only signal."
    }`;
  }

  if (/exploit|attack|weapon|metasploit|nuclei|poc|kev/.test(q)) {
    const signals: string[] = [];
    if (cve.flags.metasploit) signals.push("Metasploit module");
    if (cve.flags.exploitdb) signals.push("Exploit-DB entry");
    if (cve.flags.nuclei) signals.push("Nuclei template");
    if (cve.flags.pocGithub) signals.push("GitHub proof of concept");
    return `Exploit state at the ${cve.snapshotMonth} cutoff: ${
      signals.length ? signals.join(", ") : "no public exploit code"
    }. EPSS ${formatEpss(cve.epss)} (${percentileLabel(cve.epssPct)}), ${
      cve.exploitCount > 0 ? `${cve.exploitCount} of 4 tracked sources` : "0 of 4 tracked sources"
    }. ${
      cve.keywords.includes("vendor flags exploitation")
        ? "The vendor text itself says it may already be exploited — treat it as live."
        : "The description does not claim in-the-wild exploitation."
    }`;
  }

  if (/why|rank|score|priorit|risk/.test(q)) {
    return `It ranks ${cve.rank} of 500 because of ${cve.riskFactors.length ? cve.riskFactors.join(", ") : "a blend of severity and EPSS"}. Composite risk ${cve.riskScore}/100 with an estimated ${cve.effortHours}h fix, which puts it in the "${cve.quadrant}" quadrant of the Quick Wins matrix.`;
  }

  return `Summary: ${firstSentence(cve.description)}\n\nSeverity ${cve.severity}, CVSS ${cve.cvssScore ?? "blank"}, EPSS ${formatEpss(cve.epss)}. Rank ${cve.rank} of 500, ${cve.effortHours}h estimated effort. Ask me "how do I patch it", "is it exploited" or "give me a WAF rule" for the next level of detail.`;
}

#!/usr/bin/env node
/**
 * build-dataset.mjs — turns the pipeline's submission list into the app's data layer.
 *
 *   in : ../outputs/top500.csv              (ranked CVE ids, order = rank)
 *        ../outputs/validation_results.json  (model metrics for the status strip)
 *        ../IBM_dataset/data/*.csv           (raw challenge data)
 *   out: ../src/data/cves.json               (500 fully hydrated CVE records)
 *        ../src/data/meta.json               (cohort-level aggregates)
 *
 * The app never reads the 850 MB CSVs; it reads these two small JSON files.
 * Run:  node scripts/build-dataset.mjs        (from the app/ folder)
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..");
const DATA = path.join(ROOT, "IBM_dataset", "data");
const OUT = path.join(APP, "src", "data");

// ---------------------------------------------------------------- CSV reading

/** Parse a block of CSV text that ends on a record boundary. */
function parseRows(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else inQ = false;
      } else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c !== "\r") field += c;
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** Stream a CSV, invoking onRow(object) for every data row. */
async function eachRow(file, onRow, header) {
  const stream = fs.createReadStream(file, { encoding: "utf8", highWaterMark: 1 << 22 });
  let buf = "";
  let cols = header ?? null;
  let inQuotes = false;

  for await (const chunk of stream) {
    buf += chunk;
    // Walk the buffer tracking quote state, remembering the last record boundary.
    let lastSafe = -1;
    let i = 0;
    while (i < buf.length) {
      const c = buf[i];
      if (c === '"') {
        if (inQuotes) {
          if (i + 1 >= buf.length) break; // escaped-quote ambiguity: wait for more
          if (buf[i + 1] === '"') {
            i += 2;
            continue;
          }
          inQuotes = false;
          i++;
          continue;
        }
        inQuotes = true;
        i++;
        continue;
      }
      if (c === "\n" && !inQuotes) lastSafe = i;
      i++;
    }
    if (lastSafe < 0) continue;

    const block = buf.slice(0, lastSafe);
    buf = buf.slice(lastSafe + 1);
    for (const fields of parseRows(block)) {
      if (!cols) {
        cols = fields.map((f) => f.trim());
        continue;
      }
      if (fields.length === 1 && fields[0] === "") continue;
      const obj = {};
      for (let k = 0; k < cols.length; k++) obj[cols[k]] = fields[k] ?? "";
      onRow(obj);
    }
  }
  if (buf.trim().length) {
    for (const fields of parseRows(buf)) {
      if (!cols) continue;
      const obj = {};
      for (let k = 0; k < cols.length; k++) obj[cols[k]] = fields[k] ?? "";
      onRow(obj);
    }
  }
}

const num = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

// ---------------------------------------------------------------- keywords

const KEYWORDS = [
  [/remote code execution|arbitrary code execution|\brce\b/i, "remote code execution"],
  [/command injection|code injection|os command/i, "command / code injection"],
  [/authentication bypass|bypass authentication|missing authentication/i, "authentication bypass"],
  [/unauthenticated|without authentication/i, "no login required"],
  [/deserializ/i, "unsafe deserialization"],
  [/path traversal|directory traversal/i, "path traversal"],
  [/sql injection/i, "SQL injection"],
  [/buffer overflow|use-after-free|out-of-bounds|heap corruption|type confusion|memory corruption/i, "memory corruption"],
  [/privilege escalation|elevation of privilege/i, "privilege escalation"],
  [/cross-site scripting|\bxss\b/i, "cross-site scripting"],
  [/denial of service|\bdos\b/i, "denial of service"],
  [/\bvpn\b|firewall|gateway|router|load balancer|appliance|remote access/i, "internet-facing device"],
  [/may have been exploited|exploited in the wild|active exploitation/i, "vendor flags exploitation"],
  [/wordpress|plugin|theme/i, "WordPress plugin"],
];

function keywordHits(description) {
  const text = description || "";
  return KEYWORDS.filter(([re]) => re.test(text)).map(([, label]) => label);
}

// ---------------------------------------------------------------- effort model

/**
 * Remediation effort is a heuristic, not a measured value: it reads the affected
 * product class and the wording of the description. It exists to give the
 * Quick Wins matrix an X axis, and it is labelled as an estimate in the UI.
 */
function estimateEffort(description, products) {
  const text = (description || "").toLowerCase();
  const types = products.map((p) => p.type);

  if (/wordpress|plugin|theme/.test(text)) return 2;
  if (types.includes("hardware") || /firmware|hardware|bios/.test(text)) return 20;
  if (types.includes("operating_system") || /kernel|driver/.test(text)) return 12;
  if (/configuration|settings|policy|misconfigur/.test(text)) return 3;
  if (/server|appliance|gateway|\bvpn\b|firewall/.test(text)) return 10;
  if (/library|\bsdk\b|dependency|package/.test(text)) return 4;
  return 6;
}

function effortTier(hours) {
  if (hours <= 4) return "Low";
  if (hours <= 12) return "Medium";
  return "High";
}

function quadrantOf(riskScore, hours, riskCut, effortCut) {
  const highRisk = riskScore >= riskCut;
  const highEffort = hours > effortCut;
  if (highRisk && !highEffort) return "Quick win";
  if (highRisk && highEffort) return "Plan it";
  if (!highRisk && !highEffort) return "Fill-in";
  return "Defer";
}

// ---------------------------------------------------------------- assigner

function assignerLabel(raw) {
  if (!raw) return "Unassigned";
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(raw)) return "CISA (CNA)";
  if (raw.includes("@")) {
    const domain = raw.split("@").pop().toLowerCase();
    const core = domain.replace(/^(www|security|secure|cve|psirt|prodsec|support)\./, "").split(".")[0];
    return core.charAt(0).toUpperCase() + core.slice(1);
  }
  return raw;
}

const severityOf = (score, label) => {
  const upper = (label || "").toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(upper)) return upper;
  if (score == null) return "UNSCORED";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
};

// ---------------------------------------------------------------- main

async function main() {
  const t0 = Date.now();
  const log = (m) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${m}`);

  // 1. Ranked ids — the index list, order is the model's rank.
  const topCsv = fs.readFileSync(path.join(ROOT, "outputs", "top500.csv"), "utf8").trim().split(/\r?\n/);
  const ranked = topCsv.slice(1).map((l) => l.trim()).filter(Boolean);
  const rankOf = new Map(ranked.map((id, i) => [id, i + 1]));
  const wanted = new Set(ranked);
  log(`top500: ${ranked.length} ids`);

  // 2. Scoreboard: snapshot values + EPSS percentile inside each snapshot month.
  const sbFile = path.join(DATA, "scoreboard_2026.csv");
  const sbText = fs.readFileSync(sbFile, "utf8");
  const sbRows = parseRows(sbText);
  const sbHeader = sbRows[0];
  const sbIdx = Object.fromEntries(sbHeader.map((c, i) => [c, i]));
  const board = new Map();
  const byMonth = new Map();
  for (const r of sbRows.slice(1)) {
    if (!r.length || !r[0]) continue;
    const row = {
      cveId: r[sbIdx.cve_id],
      published: r[sbIdx.published],
      snapshotMonth: r[sbIdx.snapshot_month],
      epss: num(r[sbIdx.epss]) ?? 0,
      exploitdb: Number(r[sbIdx.exploitdb]) || 0,
      metasploit: Number(r[sbIdx.metasploit]) || 0,
      nuclei: Number(r[sbIdx.nuclei]) || 0,
      pocGithub: Number(r[sbIdx.poc_github]) || 0,
    };
    board.set(row.cveId, row);
    if (!byMonth.has(row.snapshotMonth)) byMonth.set(row.snapshotMonth, []);
    byMonth.get(row.snapshotMonth).push(row);
  }
  for (const [, rows] of byMonth) {
    rows.sort((a, b) => a.epss - b.epss);
    rows.forEach((r, i) => {
      r.epssPct = rows.length > 1 ? i / (rows.length - 1) : 0;
    });
  }
  log(`scoreboard: ${board.size} rows across ${byMonth.size} months, universe=${sbText ? board.size : 0}`);

  // 3. Weakness type names.
  const cweName = new Map();
  await eachRow(path.join(DATA, "weakness_types.csv"), (r) => {
    if (r.cwe_id) cweName.set(r.cwe_id, r.name);
  });
  log(`weakness types: ${cweName.size}`);

  // 4. Products for the 500 (needed for effort + blast-radius hints).
  const products = new Map();
  await eachRow(path.join(DATA, "affected_products.csv"), (r) => {
    if (!wanted.has(r.cve_id) || r.vulnerable !== "Y") return;
    const list = products.get(r.cve_id) ?? [];
    const key = `${r.vendor}|${r.product}`;
    if (list.some((p) => p.key === key)) return;
    list.push({
      key,
      type: r.type,
      vendor: r.vendor.replace(/_/g, " "),
      product: r.product.replace(/_/g, " "),
      version: r.version ? r.version.replace(/_/g, " ") : "",
    });
    products.set(r.cve_id, list);
  });
  log(`products: ${products.size} of the cohort have a product list`);

  // 5. Vulnerabilities for the 500.
  const details = new Map();
  await eachRow(path.join(DATA, "vulnerabilities.csv"), (r) => {
    if (!wanted.has(r.cve_id)) return;
    const p = (products.get(r.cve_id) ?? []).slice(0, 4).map(({ key, ...rest }) => rest);
    details.set(r.cve_id, { ...r, products: p });
  });
  log(`vulnerabilities: ${details.size} matched`);

  // 6. Model metrics for the status strip.
  let validation = null;
  try {
    const report = JSON.parse(fs.readFileSync(path.join(ROOT, "outputs", "validation_results.json"), "utf8"));
    const model = report.selected_model || "logistic_regression";
    const ours = report.validation.models[model];
    const baselineBest = Object.entries(report.validation.baselines).sort(
      (a, b) => b[1].hits_at_274 - a[1].hits_at_274
    )[0];
    validation = {
      model,
      hitsAt274: ours.hits_at_274,
      hitsAt500: ours.hits_at_500,
      baselineName: baselineBest[0],
      baselineHits: baselineBest[1].hits_at_274,
      precisionAt274: ours.precision_at_274,
      liftPct: Math.round(((ours.hits_at_274 - baselineBest[1].hits_at_274) / Math.max(baselineBest[1].hits_at_274, 1)) * 1000) / 10,
      rocAuc: ours.roc_auc,
      averagePrecision: ours.average_precision,
      validationRows: report.validation_rows,
      positives: report.validation_positives,
      trainRows: report.train_rows,
      trainPositives: report.train_positives,
      kScaled: report.k_scaled,
      generatedAt: report.generated_at,
    };
  } catch (err) {
    console.warn("validation_results.json unavailable:", err.message);
  }

  // 7. Compose records.
  const records = [];
  const missing = [];
  for (const cveId of ranked) {
    const d = details.get(cveId);
    const b = board.get(cveId);
    if (!d) {
      missing.push(cveId);
      continue;
    }
    const score3 = num(d.cvss3_score);
    const score4 = num(d.cvss4_score);
    const cvssScore = score3 ?? score4;
    const severity = severityOf(cvssScore, d.cvss3_severity || d.cvss4_severity);
    const epss = b?.epss ?? 0;
    const epssPct = b?.epssPct ?? 0;
    const flags = {
      exploitdb: b?.exploitdb ?? 0,
      metasploit: b?.metasploit ?? 0,
      nuclei: b?.nuclei ?? 0,
      pocGithub: b?.pocGithub ?? 0,
    };
    const exploitCount = flags.exploitdb + flags.metasploit + flags.nuclei + flags.pocGithub;

    // Composite risk (0-100) — the PRD weighting, applied to the same signals the
    // scoreboard exposes at the cutoff. EPSS enters as its in-month percentile so it
    // is on the same 0-1 scale as the binary exploit flags.
    const riskScore =
      Math.round(
        100 * (0.5 * epssPct + 0.25 * flags.metasploit + 0.15 * flags.exploitdb + 0.07 * flags.nuclei + 0.03 * flags.pocGithub)
      ) / 1;

    const kw = keywordHits(d.description);
    const products4 = d.products;

    const factors = [];
    if (flags.metasploit) factors.push("Metasploit module exists");
    if (flags.nuclei) factors.push("Nuclei scanner template exists");
    if (flags.exploitdb) factors.push("Exploit-DB entry exists");
    if (flags.pocGithub) factors.push("public PoC on GitHub");
    if (epssPct >= 0.95) factors.push(`EPSS in the top ${Math.max(1, Math.round((1 - epssPct) * 100))}% of its month`);
    if (kw.includes("vendor flags exploitation")) factors.push("vendor text says it is exploited in the wild");
    if (kw.includes("remote code execution")) factors.push("remote code execution");
    if (kw.includes("authentication bypass") || kw.includes("no login required")) factors.push("no login needed");
    if (kw.includes("internet-facing device")) factors.push("internet-facing device");
    if (kw.includes("memory corruption")) factors.push("memory corruption");

    const cweIds = (d.cwe_ids || "").split(";").map((s) => s.trim()).filter(Boolean);
    const cwes = cweIds.slice(0, 4).map((id) => ({ id, name: cweName.get(id) || "Unlisted weakness type" }));
    const effortHours = estimateEffort(d.description, products4);

    records.push({
      rank: rankOf.get(cveId),
      cveId,
      published: d.published,
      snapshotMonth: b?.snapshotMonth ?? "",
      description: (d.description || "").replace(/\s+/g, " ").trim(),
      cvssScore,
      severity,
      cvssVector: d.cvss3_vector || d.cvss4_vector || "",
      attackVector: d.attack_vector || "",
      attackComplexity: d.attack_complexity || "",
      privilegesRequired: d.privileges_required || "",
      userInteraction: d.user_interaction || "",
      epss,
      epssPct,
      flags,
      exploitCount,
      riskScore,
      effortHours,
      effortTier: effortTier(effortHours),
      riskFactors: factors.slice(0, 4),
      cwes,
      products: products4.slice(0, 3),
      assigner: d.assigner || "",
      assignerLabel: assignerLabel(d.assigner),
      keywords: kw,
    });
  }

  if (missing.length) console.warn(`WARNING: ${missing.length} ids not found in vulnerabilities.csv: ${missing.slice(0, 5).join(", ")}`);

  // 8. Cohort-level aggregates (medians define the Quick Wins quadrants).
  const sortedRisk = [...records].sort((a, b) => a.riskScore - b.riskScore);
  const sortedEffort = [...records].sort((a, b) => a.effortHours - b.effortHours);
  const median = (arr) => (arr.length ? arr[Math.floor(arr.length / 2)] : 0);
  const riskCut = median(sortedRisk.map((r) => r.riskScore));
  const effortCut = median(sortedEffort.map((r) => r.effortHours));

  const severityCounts = {};
  const effortCounts = {};
  const quadrantCounts = {};
  for (const r of records) {
    r.quadrant = quadrantOf(r.riskScore, r.effortHours, riskCut, effortCut);
    severityCounts[r.severity] = (severityCounts[r.severity] || 0) + 1;
    effortCounts[r.effortTier] = (effortCounts[r.effortTier] || 0) + 1;
    quadrantCounts[r.quadrant] = (quadrantCounts[r.quadrant] || 0) + 1;
  }

  // 9. Open risk exposure by publish month: cohort risk still unremediated if you
  //    only ever look at what has been published so far.
  const months = [...new Set(records.map((r) => r.published.slice(0, 7)))].sort();
  const exposureByMonth = months.map((month) => {
    const upTo = records.filter((r) => r.published.slice(0, 7) <= month);
    return {
      month,
      published: records.filter((r) => r.published.slice(0, 7) === month).length,
      openRisk: Math.round(upTo.reduce((s, r) => s + r.riskScore, 0)),
      criticalOpen: upTo.filter((r) => r.severity === "CRITICAL").length,
    };
  });

  const meta = {
    generatedAt: new Date().toISOString(),
    universe: board.size,
    cohort: records.length,
    medians: { risk: riskCut, effort: effortCut },
    severityCounts,
    effortCounts,
    quadrantCounts,
    exposureByMonth,
    exploitCoverage: {
      withAnyExploit: records.filter((r) => r.exploitCount > 0).length,
      withNuclei: records.filter((r) => r.flags.nuclei === 1).length,
      epssAbove10pct: records.filter((r) => r.epss >= 0.1).length,
    },
    validation,
    sources: [
      "outputs/top500.csv (submission: rank order)",
      "IBM_dataset/data/scoreboard_2026.csv (EPSS + exploit flags at each cutoff)",
      "IBM_dataset/data/vulnerabilities.csv (description, CVSS, CWE)",
      "IBM_dataset/data/weakness_types.csv (CWE names)",
      "IBM_dataset/data/affected_products.csv (product context)",
      "outputs/validation_results.json (model metrics)",
    ],
  };

  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, "cves.json"), JSON.stringify(records), "utf8");
  fs.writeFileSync(path.join(OUT, "meta.json"), JSON.stringify(meta, null, 2), "utf8");

  log(`wrote ${records.length} CVEs to src/data/cves.json`);
  log(`quadrants ${JSON.stringify(quadrantCounts)} · risk cut ${riskCut} · effort cut ${effortCut}h`);
  log(`severity ${JSON.stringify(severityCounts)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

# Product Requirements Document (PRD) Summary & Specification
## Project: Patch Me If You Can
**Program / Event:** Sheridan Datathon 2026 — IBM Track  
**Focus:** AI-Driven Threat Intelligence & Autonomous Vulnerability Prioritization  
**Target LLM & Foundation Engine:** IBM watsonx (`security-granite-20b-chat` / Granite 3.0)  
**Document Type:** Executive Architecture & Export Specification  
**Version:** 1.0 (Final Approved)  

---

### Executive Overview & Strategic Value
- **Enterprise Alert Fatigue Solved:** Modern security teams monitor over 70,000+ CVEs. Traditional CVSS v3.1 base metrics quantify theoretical severity under worst-case circumstances without accounting for real-world exploit automation or weaponization timelines.
- **Actionable Effort vs. Impact Prioritization:** "Patch Me If You Can" maps composite threat risk scores against remediation fix effort (hours / hotpatch vs. refactor) across a 4-quadrant **"Quick Wins" Prioritization Matrix**.
- **IBM Granite 20B SecOps Studio:** Dynamic chat workspace with contextual CVE tagging (`#CVE-2026-XXXX`) that synthesizes uncurated advisory telemetry, explains threat vectors, and drafts copyable Nginx/Envoy WAF virtual patches.

---

### Key Technical & ML Specifications
1. **Zero-Leakage Anti-Cheating Protocol:**
   - Excluded fields: `nvd_status`, `n_affected_cpes`, `n_references`, and post-incident triage tags.
   - Preserves genuine zero-day predictive power before formal CISA KEV cataloging.

2. **Composite Risk Formulation:**
   $$\text{Risk Score} = 0.50 \cdot \text{EPSS} + 0.25 \cdot \text{MSF} + 0.15 \cdot \text{EDB} + 0.07 \cdot \text{NUC} + 0.03 \cdot \text{POC}$$
   - **EPSS (50%):** Empirical 30-day exploit likelihood.
   - **Metasploit (25%):** Automated weaponization hazard.
   - **ExploitDB (15%):** Verified public exploit scripts.
   - **Nuclei (7%):** Mass internet reconnaissance template.
   - **GitHub PoC (3%):** Proof-of-concept availability.

3. **Official Competition Export Contract:**
   - Format: Single-column CSV named `top500.csv`.
   - Header: Exactly `cve_id`.
   - Payload: Top 500 AI-ranked CVE identifiers sorted in descending order of calculated risk score.

---

### User Surfaces & Interface Architecture
- **Tab 1: Working Dashboard**
  - **System Status:** 72,670 universe, 500 cohort size, 17 CISA validation hits, +42% precision vs baseline.
  - **Quick Wins Matrix:** 4-quadrant stationary scatter plot highlighting High Risk / Low Effort (<2h) hotpatches.
  - **Risk Overview:** Responsive SVG donut chart (12% Critical, 31% High, 37% Medium, 20% Low).
  - **Ranked Top Priority Table:** Ranked 1-500 vulnerabilities with instant inspection synchronization.
  - **IBM Granite AI Insight Panel:** Direct `"✨ Ask Granite About This CVE"` contextual handoff.
- **Tab 2: Vulnerability Queue & Jira Kanban Board**
  - Interactive 3-column backlog: `TO DO`, `IN PROGRESS`, `DONE` with status updates.
- **Tab 3: CSV Upload & Dataset Inspection**
  - Ingestion validation, duplicate detection, and schema verification.
- **Tab 4: Context-Aware "Chat with Granite"**
  - Dynamic CVE tagging chip, prompt suggestions, and exportable WAF virtual patches.

---

### Design System Compliance
- **Palette:** Royal SecOps Alabaster (`#FEF9EF` background, `#DEDAD0` dim, `#FFFFFF` cards, `#0B192C` navy ink, `#0F62FE` IBM electric blue, `#D97706` amber accents).
- **Typography:** `EB Garamond` for titles and brand presence, Monospace for CVE IDs and telemetry scores.

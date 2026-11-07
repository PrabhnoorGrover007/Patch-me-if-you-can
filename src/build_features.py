"""Build one row per vulnerability with features known at the end of its snapshot month.

Rows:
  - every CVE published 2024-01 .. 2025-12 (for training / backtesting), snapshot = publish month
  - every CVE in scoreboard_2026.csv (the 2026 benchmark), snapshot = its snapshot_month

Leakage rules (see the audit): we never use nvd_status, n_affected_cpes, affected_products.csv,
references.csv, n_references, cvss3_source, last_modified, or a "score is blank" flag.
Exploit-code flags and EPSS are taken AT the snapshot month only.

Usage: python -I src/build_features.py <data_dir> <out_parquet>
"""
import sys
import duckdb

D = sys.argv[1].replace("\\", "/")
OUT = sys.argv[2].replace("\\", "/")
con = duckdb.connect()
o = "header=true, quote='\"', escape='\"', sample_size=-1"
for t in ["vulnerabilities", "known_exploited", "exploit_signals_2024", "exploit_signals_2025", "scoreboard_2026"]:
    con.execute(f"CREATE VIEW {t} AS SELECT * FROM read_csv('{D}/{t}.csv', {o})")

# Firewalls, VPNs, routers and other internet-facing "front door" boxes.
EDGE_VENDORS = (r"fortinet|palo alto|cisco|citrix|netscaler|ivanti|pulse secure|sonicwall|juniper|"
                r"\bf5\b|big-ip|check point|zyxel|d-link|tp-link|netgear|draytek|sophos|watchguard|"
                r"barracuda|array networks|mikrotik|ubiquiti|tenda|totolink|four-faith|cyberoam")
EDGE_PRODUCTS = (r"\bvpn\b|firewall|\brouter|gateway|access point|load balancer|fortios|fortigate|"
                 r"fortiproxy|fortiweb|fortimanager|pan-os|globalprotect|connect secure|policy secure|"
                 r"sonicos|ios xe|adaptive security appliance|\basa\b|junos|edge device|secure access")

con.execute("CREATE TABLE kev AS SELECT cve_id, vendor, product, CAST(date_added AS DATE) date_added FROM known_exploited")

con.execute("""
CREATE TABLE base AS
SELECT cve_id, CAST(published AS DATE) published, strftime(CAST(published AS DATE), '%Y-%m') snapshot_month,
       'hist' AS src
FROM vulnerabilities
WHERE published >= DATE '2024-01-01' AND published < DATE '2026-01-01'
UNION ALL
SELECT cve_id, CAST(published AS DATE), snapshot_month, 'score2026' FROM scoreboard_2026
""")
con.execute("ALTER TABLE base ADD COLUMN snap_end DATE")
con.execute("UPDATE base SET snap_end = last_day(strptime(snapshot_month || '-01', '%Y-%m-%d'))")

# Drop history rows already on the attacked list by the end of their snapshot month (same rule as the scoreboard)
con.execute("""
DELETE FROM base b USING kev k
WHERE b.src='hist' AND k.cve_id=b.cve_id AND k.date_added <= b.snap_end
""")

con.execute(f"""
CREATE TABLE f AS
SELECT b.*, k.date_added AS kev_date,
  lower(v.description) AS d,
  lower(split_part(split_part(v.assigner, '@', 2), '.', -2)) AS assigner_dom,
  v.assigner,
  v.cvss3_score,
  v.attack_vector, v.attack_complexity, v.privileges_required, v.user_interaction, v.scope,
  v.confidentiality_impact, v.integrity_impact, v.availability_impact,
  -- signals at snapshot month
  CASE WHEN b.src='hist' THEN s.epss ELSE sb.epss END AS epss,
  coalesce(CASE WHEN b.src='hist' THEN s.exploitdb  ELSE sb.exploitdb  END, 0) AS exploitdb,
  coalesce(CASE WHEN b.src='hist' THEN s.metasploit ELSE sb.metasploit END, 0) AS metasploit,
  coalesce(CASE WHEN b.src='hist' THEN s.nuclei     ELSE sb.nuclei     END, 0) AS nuclei,
  coalesce(CASE WHEN b.src='hist' THEN s.poc_github ELSE sb.poc_github END, 0) AS poc_github
FROM base b
JOIN vulnerabilities v USING (cve_id)
LEFT JOIN kev k USING (cve_id)
LEFT JOIN (SELECT * FROM exploit_signals_2024 UNION ALL SELECT * FROM exploit_signals_2025) s
       ON s.cve_id=b.cve_id AND s.month=b.snapshot_month AND b.src='hist'
LEFT JOIN scoreboard_2026 sb ON sb.cve_id=b.cve_id AND b.src='score2026'
""")

# ---- "Attacked before": how many times this vendor / product was on the KEV list before the snapshot ----
con.execute("""
CREATE TABLE kv AS SELECT DISTINCT lower(vendor) vname, lower(regexp_replace(vendor, '[^A-Za-z0-9]', '', 'g')) vkey
FROM kev WHERE length(vendor) >= 4""")
con.execute("""
CREATE TABLE kp AS SELECT DISTINCT lower(product) pname FROM kev
WHERE length(product) >= 5 AND lower(product) NOT IN ('multiple products', 'multiple')""")


def alternation(names):
    # one big regex "a|b|c" (longest first), escaping regex symbols; RE2 scans each text once
    special = set(r".^$*+?()[]{}|\\")
    esc = ["".join("\\" + c if c in special else c for c in n) for n in sorted(names, key=len, reverse=True)]
    return "(" + "|".join(esc) + ")"


vnames = [r[0] for r in con.execute("SELECT vname FROM kv").fetchall()]
pnames = [r[0] for r in con.execute("SELECT pname FROM kp").fetchall()]
VRE, PRE = alternation(vnames), alternation(pnames)
con.execute(f"""
CREATE TABLE cv AS
SELECT DISTINCT cve_id, snap_end, kv.vkey FROM (
  SELECT cve_id, snap_end, unnest(regexp_extract_all(d, '{VRE.replace("'", "''")}')) vname FROM f) m
JOIN kv USING (vname)
UNION
SELECT DISTINCT f.cve_id, f.snap_end, kv.vkey FROM f JOIN kv
  ON f.assigner_dom IS NOT NULL AND length(f.assigner_dom) >= 4 AND kv.vkey = f.assigner_dom""")
con.execute(f"""
CREATE TABLE cp AS
SELECT DISTINCT cve_id, snap_end, pname FROM (
  SELECT cve_id, snap_end, unnest(regexp_extract_all(d, '{PRE.replace("'", "''")}')) pname FROM f) m""")
con.execute("""
CREATE TABLE prior_v AS
SELECT cv.cve_id, max(n) prior_vendor_kev FROM (
  SELECT cv.cve_id, cv.vkey, count(k.cve_id) n FROM cv
  LEFT JOIN kev k ON lower(regexp_replace(k.vendor, '[^A-Za-z0-9]', '', 'g')) = cv.vkey AND k.date_added <= cv.snap_end
  GROUP BY 1, 2) cv GROUP BY 1""")
con.execute("""
CREATE TABLE prior_p AS
SELECT cp.cve_id, max(n) prior_product_kev FROM (
  SELECT cp.cve_id, cp.pname, count(k.cve_id) n FROM cp
  LEFT JOIN kev k ON lower(k.product) = cp.pname AND k.date_added <= cp.snap_end
  GROUP BY 1, 2) cp GROUP BY 1""")

con.execute(f"""
CREATE TABLE feats AS
SELECT f.cve_id, f.published, f.snapshot_month, f.snap_end, f.src, f.kev_date, f.assigner,
  -- severity (CVSS) parts
  f.cvss3_score,
  (f.attack_vector='NETWORK')::INT            AS av_network,
  (f.attack_complexity='LOW')::INT            AS ac_low,
  (f.privileges_required='NONE')::INT         AS pr_none,
  (f.user_interaction='NONE')::INT            AS ui_none,
  (f.scope='CHANGED')::INT                    AS scope_changed,
  (f.integrity_impact='HIGH')::INT            AS i_high,
  (f.attack_vector='NETWORK' AND f.privileges_required='NONE' AND f.user_interaction='NONE')::INT AS no_login_remote,
  -- "danger" signals at snapshot
  f.epss,
  percent_rank() OVER (PARTITION BY f.snapshot_month ORDER BY coalesce(f.epss, -1)) AS epss_pct,
  f.exploitdb, f.metasploit, f.nuclei, f.poc_github,
  (f.exploitdb + f.metasploit + f.nuclei + f.poc_github > 0)::INT AS any_code,
  -- front-door devices
  (regexp_matches(f.d, '{EDGE_VENDORS}'))::INT AS edge_vendor,
  (regexp_matches(f.d, '{EDGE_PRODUCTS}'))::INT AS edge_product,
  (regexp_matches(f.d, '{EDGE_VENDORS}') OR regexp_matches(f.d, '{EDGE_PRODUCTS}'))::INT AS edge_device,
  -- break-ins and impact, from the description text
  regexp_matches(f.d, 'remote code execution|execute arbitrary (code|command)|arbitrary code execution|command injection|os command|code injection')::INT AS rce,
  regexp_matches(f.d, 'authentication bypass|bypass(es|ing)? (the )?authentication|unauthenticated|without authentication|missing authentication|auth bypass')::INT AS auth_bypass,
  regexp_matches(f.d, 'privilege escalation|elevation of privilege|escalate privileges|gain (root|system|elevated)')::INT AS priv_esc,
  regexp_matches(f.d, 'use[- ]after[- ]free|out[- ]of[- ]bounds write|type confusion|heap[- ]based buffer overflow|memory corruption')::INT AS memory_bug,
  regexp_matches(f.d, 'path traversal|directory traversal|deserializ')::INT AS traversal_deser,
  regexp_matches(f.d, 'cross[- ]site scripting|\\bxss\\b')::INT AS xss,
  regexp_matches(f.d, 'denial of service') AND NOT regexp_matches(f.d, 'code execution')::INT AS dos_only,
  (regexp_matches(f.d, 'wordpress') OR f.assigner_dom IN ('wordfence', 'patchstack', 'wpscan'))::INT AS wordpress,
  regexp_matches(f.d, 'in the linux kernel')::INT AS linux_kernel,
  regexp_matches(f.d, 'exploited in the wild|actively exploited|may have been exploited|aware of (reports|an instance)|has been exploited|limited, targeted')::INT AS says_exploited,
  -- attacked before
  coalesce(pv.prior_vendor_kev, 0)  AS prior_vendor_kev,
  coalesce(pp.prior_product_kev, 0) AS prior_product_kev,
  length(f.d) AS desc_len
FROM f
LEFT JOIN prior_v pv USING (cve_id)
LEFT JOIN prior_p pp USING (cve_id)
""")
con.execute(f"COPY feats TO '{OUT}' (FORMAT parquet)")
print(con.execute("SELECT src, count(*) n, count(kev_date) on_kev_later FROM feats GROUP BY src").df().to_string(index=False))

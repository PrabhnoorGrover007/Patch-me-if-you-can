"""Leakage audit for the IBM 'Before the Breach' data.

Idea: for vulnerabilities published in 2025 we already know which ones were attacked
(CISA KEV list up to 2025-12-31). NIST data is today's version, so if a column looks very
different for attacked vs non-attacked vulnerabilities only because NIST reviewed the attacked
ones first, that column leaks the answer.
"""
import sys
import duckdb

D = sys.argv[1].replace("\\", "/")
con = duckdb.connect()
opts = "header=true, quote='\"', escape='\"', all_varchar=false, sample_size=-1"
for t in ["vulnerabilities", "affected_products", "references", "known_exploited",
          "exploit_signals_2024", "exploit_signals_2025", "weakness_types", "scoreboard_2026"]:
    con.execute(f"CREATE VIEW {'refs' if t=='references' else t} AS SELECT * FROM read_csv('{D}/{t}.csv', {opts})")


def q(sql):
    print(con.execute(sql).df().to_string(index=False))
    print()


print("=== 1. Every column in every file ===")
for t in ["vulnerabilities", "affected_products", "refs", "known_exploited",
          "exploit_signals_2024", "weakness_types", "scoreboard_2026"]:
    cols = [r[0] for r in con.execute(f"DESCRIBE {t}").fetchall()]
    print(f"{t}: {', '.join(cols)}")
print()

# 2025-published CVEs, labelled by whether they were on KEV by end of 2025
con.execute("""
CREATE TABLE v25 AS
SELECT v.*, (k.cve_id IS NOT NULL) AS kev
FROM vulnerabilities v LEFT JOIN known_exploited k USING (cve_id)
WHERE v.published >= DATE '2025-01-01' AND v.published < DATE '2026-01-01'
""")
q("SELECT kev, count(*) n FROM v25 GROUP BY kev ORDER BY kev")

print("=== 2. nvd_status: attacked vs not attacked (2025) ===")
q("""SELECT nvd_status,
  round(100.0*count(*) FILTER (WHERE kev)/ (SELECT count(*) FROM v25 WHERE kev),1) AS pct_attacked,
  round(100.0*count(*) FILTER (WHERE NOT kev)/(SELECT count(*) FROM v25 WHERE NOT kev),1) AS pct_not_attacked
FROM v25 GROUP BY nvd_status ORDER BY pct_not_attacked DESC""")

print("=== 3. Other NIST-filled columns (2025) ===")
q("""SELECT kev,
  round(100*avg((cvss3_score IS NULL)::INT),1)            AS pct_cvss3_blank,
  round(100*avg((cvss3_source='nvd@nist.gov')::INT),1)    AS pct_cvss3_by_nist,
  round(100*avg((n_affected_cpes>0)::INT),1)              AS pct_has_products,
  round(avg(n_affected_cpes),1)                           AS avg_products,
  round(avg(n_references),1)                              AS avg_refs,
  round(100*avg((cwe_ids IS NULL OR cwe_ids LIKE 'NVD-CWE%')::INT),1) AS pct_no_real_cwe,
  min(last_modified)                                      AS earliest_last_modified
FROM v25 GROUP BY kev ORDER BY kev""")

print("=== 4. references.csv tags: share of CVEs having each tag (2025) ===")
con.execute("CREATE TABLE r25 AS SELECT r.*, v.kev FROM refs r JOIN v25 v USING (cve_id)")
q("""WITH t AS (SELECT DISTINCT cve_id, kev, trim(unnest(string_split(tags,';'))) tag FROM r25 WHERE tags IS NOT NULL)
SELECT tag,
  round(100.0*count(DISTINCT cve_id) FILTER (WHERE kev)/(SELECT count(*) FROM v25 WHERE kev),1) pct_attacked,
  round(100.0*count(DISTINCT cve_id) FILTER (WHERE NOT kev)/(SELECT count(*) FROM v25 WHERE NOT kev),1) pct_not_attacked
FROM t GROUP BY tag HAVING count(*)>200 ORDER BY pct_attacked DESC LIMIT 15""")

print("=== 5. Domains most over-represented on attacked CVEs (2025) ===")
q("""WITH d AS (SELECT DISTINCT cve_id, kev, domain FROM r25)
SELECT domain,
  count(*) FILTER (WHERE kev) n_attacked,
  count(*) FILTER (WHERE NOT kev) n_not_attacked,
  round((count(*) FILTER (WHERE kev)+0.0)/greatest(count(*),1)*100,1) pct_of_its_cves_attacked
FROM d GROUP BY domain HAVING count(*) FILTER (WHERE kev) >= 8
ORDER BY pct_of_its_cves_attacked DESC LIMIT 20""")

print("=== 6. Exploit-code flags: are they dated? ===")
q("""SELECT month, count(*) n_rows, sum(exploitdb) exploitdb, sum(metasploit) metasploit,
  sum(nuclei) nuclei, sum(poc_github) poc_github, sum(in_kev) in_kev
FROM exploit_signals_2025 WHERE month IN ('2025-01','2025-06','2025-12') GROUP BY month ORDER BY month""")
# Did flags exist BEFORE the CVE was added to KEV, or only after?
q("""WITH k AS (SELECT cve_id, strftime(date_added,'%Y-%m') kev_month FROM known_exploited
               WHERE date_added >= DATE '2025-02-01'),
s AS (SELECT * FROM exploit_signals_2025 UNION ALL SELECT * FROM exploit_signals_2024),
before AS (SELECT k.cve_id, max(greatest(exploitdb,metasploit,nuclei,poc_github)) f
           FROM k JOIN s ON s.cve_id=k.cve_id AND s.month < k.kev_month GROUP BY k.cve_id),
after AS (SELECT k.cve_id, max(greatest(exploitdb,metasploit,nuclei,poc_github)) f
           FROM k JOIN s ON s.cve_id=k.cve_id AND s.month >= k.kev_month GROUP BY k.cve_id)
SELECT count(*) kev_2025_cves,
  round(100*avg(coalesce(b.f,0)),1) pct_code_flag_before_kev,
  round(100*avg(coalesce(a.f,0)),1) pct_code_flag_by_end_2025
FROM k LEFT JOIN before b USING(cve_id) LEFT JOIN after a USING(cve_id)""")
# Do flags ever switch off (1 -> 0)? That would mean they are not cumulative snapshots.
q("""WITH s AS (SELECT cve_id, month, poc_github,
       lag(poc_github) OVER (PARTITION BY cve_id ORDER BY month) prev FROM exploit_signals_2025)
SELECT count(*) FILTER (WHERE prev=1 AND poc_github=0) poc_flag_turned_off,
       count(*) FILTER (WHERE prev=0 AND poc_github=1) poc_flag_turned_on FROM s""")

print("=== 7. Scoreboard sanity ===")
q("""SELECT snapshot_month, count(*) n, round(100*avg((epss IS NULL)::INT),1) pct_no_epss,
  sum(exploitdb+metasploit+nuclei+poc_github>0) any_code
FROM scoreboard_2026 GROUP BY snapshot_month ORDER BY snapshot_month""")

print("=== 8. Scoreboard: same NIST leak signal on 2026 rows (no labels, just the mix) ===")
q("""SELECT v.nvd_status, count(*) n FROM scoreboard_2026 s JOIN vulnerabilities v USING(cve_id)
GROUP BY 1 ORDER BY 2 DESC""")

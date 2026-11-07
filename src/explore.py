import sys, duckdb
D = sys.argv[1].replace("\\", "/")
con = duckdb.connect()
o = "header=true, quote='\"', escape='\"', sample_size=-1"
con.execute(f"CREATE VIEW v AS SELECT * FROM read_csv('{D}/vulnerabilities.csv', {o})")
con.execute(f"CREATE VIEW k AS SELECT * FROM read_csv('{D}/known_exploited.csv', {o})")
q = lambda s: print(con.execute(s).df().to_string(index=False), "\n")
print("KEV vendors, CVEs published 2024-2025")
q("""SELECT k.vendor, count(*) n FROM k JOIN v USING(cve_id) WHERE v.published>=DATE '2024-01-01'
GROUP BY 1 ORDER BY 2 DESC LIMIT 30""")
print("Assigners of those")
q("""SELECT v.assigner, count(*) n FROM k JOIN v USING(cve_id) WHERE v.published>=DATE '2024-01-01'
GROUP BY 1 ORDER BY 2 DESC LIMIT 25""")
print("Top assigners overall 2024-2025 (volume)")
q("""SELECT assigner, count(*) n FROM v WHERE published>=DATE '2024-01-01' AND published<DATE '2026-01-01'
GROUP BY 1 ORDER BY 2 DESC LIMIT 15""")
print("Description says exploited in the wild? (2024-2025 published)")
q("""SELECT (k.cve_id IS NOT NULL) kev,
 sum(regexp_matches(lower(description),'exploited in the wild|actively exploited|may have been exploited|aware of (reports|an instance)|has been exploited|limited, targeted'))::INT hits, count(*) n
FROM v LEFT JOIN k USING(cve_id) WHERE published>=DATE '2024-01-01' AND published<DATE '2026-01-01' GROUP BY 1""")

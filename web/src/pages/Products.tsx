import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fmt, get, type ProductPage, type ProductVulnPage } from "../api";
import { Card, ErrorBox, Loading, Severity } from "../components/ui";

export default function Products() {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [products, setProducts] = useState<ProductPage | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [cves, setCves] = useState<ProductVulnPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    const params = new URLSearchParams({ page: String(page), size: "30" });
    if (query) params.set("q", query);
    get<ProductPage>(`/api/products?${params.toString()}`)
      .then(setProducts)
      .catch((e: Error) => setError(e.message));
  }, [page, query]);

  useEffect(() => {
    if (!selected) return;
    setCves(null);
    get<ProductVulnPage>(`/api/products/${encodeURIComponent(selected)}/vulnerabilities?size=25`)
      .then(setCves)
      .catch((e: Error) => setError(e.message));
  }, [selected]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Exposure context</div>
          <h1>Product exposure explorer</h1>
          <p className="lede">
            Explore vendors and products recorded in <span className="mono">affected_products.csv</span>.
            This is a corpus view, not an asset inventory: absence of a CPE is not evidence that a product
            is unaffected.
          </p>
        </div>
        <form
          className="toolbar"
          onSubmit={(e) => { e.preventDefault(); setPage(1); setQuery(q.trim()); }}
        >
          <input
            type="search"
            placeholder="Search CPE vendor…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search vendor"
          />
          <button className="button" type="submit">Search</button>
        </form>
      </div>

      {error && <ErrorBox error={error} />}
      {!error && !products && <Loading label="Loading product coverage…" />}

      {products && (
        <div className="section grid c2-1">
          <Card title="Vendors in the CPE corpus" sub={`${fmt.int(products.total)} vendors with at least one vulnerable product record`}>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Vendor</th><th className="num">Vulnerabilities</th><th className="num">CPE rows</th></tr></thead>
                <tbody>
                  {products.items.map((p) => (
                    <tr key={p.product_id} onClick={() => setSelected(p.product_id)}
                        className={selected === p.product_id ? "selected-row" : ""}>
                      <td className="mono">{p.vendor}</td>
                      <td className="num mono">{fmt.int(p.vulnerabilities)}</td>
                      <td className="num mono">{fmt.int(p.cpe_product_rows)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pager">
              <div>{fmt.int(products.total)} vendors · page {products.page} of {Math.max(products.pages, 1)}</div>
              <div className="buttons">
                <button className="button ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
                <button className="button ghost" disabled={page >= products.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
              </div>
            </div>
            <p className="tiny muted" style={{ marginBottom: 0 }}>{products.note}</p>
          </Card>

          <Card title="Ranked vulnerabilities" sub={selected ? `CPE vendor: ${selected}` : "Select a vendor"}>
            {!selected && <p className="small muted">Choose a vendor to inspect its 2026 benchmark CVEs.</p>}
            {selected && !cves && <Loading label="Loading vendor CVEs…" />}
            {cves && cves.items.length === 0 && (
              <p className="small muted">No 2026 benchmark CVE is associated with this CPE vendor.</p>
            )}
            {cves && cves.items.length > 0 && (
              <>
                <div className="table-wrap" style={{ border: "none" }}>
                  <table>
                    <thead><tr><th>CVE</th><th className="num">Rank</th><th className="num">CVSS</th><th>Severity</th><th>Why</th></tr></thead>
                    <tbody>
                      {cves.items.map((r) => (
                        <tr key={r.cve_id} onClick={() => navigate(`/cve/${r.cve_id}`)}>
                          <td className="mono">{r.cve_id}</td>
                          <td className="num mono">#{r.rank}</td>
                          <td className="num mono">{fmt.num(r.cvss3_score, 1)}</td>
                          <td><Severity value={r.cvss3_severity} /></td>
                          <td className="small muted">{r.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="pager">
                  <div>{fmt.int(cves.total)} associated CVEs</div>
                </div>
              </>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

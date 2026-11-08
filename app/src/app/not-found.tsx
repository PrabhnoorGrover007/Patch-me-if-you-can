import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-xl py-16 text-center">
      <div className="eyebrow">404 · route not found</div>
      <h1 className="mt-2 text-[34px] leading-tight text-ink">That page is not in the cohort</h1>
      <p className="mt-2 text-[13.5px] leading-relaxed text-muted">
        The link may be stale. The dashboard and the explorer both have working entry points.
      </p>
      <div className="mt-5 flex justify-center gap-2">
        <Link href="/" className="btn btn-primary">
          Dashboard
        </Link>
        <Link href="/explorer" className="btn btn-ghost">
          Explorer
        </Link>
      </div>
    </div>
  );
}

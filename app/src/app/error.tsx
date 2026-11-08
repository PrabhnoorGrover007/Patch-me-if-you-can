"use client";

import Link from "next/link";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="mx-auto max-w-xl py-16 text-center">
      <div className="eyebrow">Service error</div>
      <h1 className="mt-2 text-[34px] leading-tight text-ink">The evidence service did not answer</h1>
      <p className="mt-2 text-[13.5px] leading-relaxed text-muted">
        Start the FastAPI backend, then retry. The page never substitutes invented data for a failed
        request.
      </p>
      <p className="mono mt-3 break-words text-[11px] text-crimson">{error.message}</p>
      <div className="mt-5 flex justify-center gap-2">
        <button onClick={reset} className="btn btn-primary">
          Retry
        </button>
        <Link href="/" className="btn btn-ghost">
          Dashboard
        </Link>
      </div>
    </div>
  );
}

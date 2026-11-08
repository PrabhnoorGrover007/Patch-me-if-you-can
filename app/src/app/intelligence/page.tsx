import IntelligenceView from "@/components/IntelligenceView";

export const dynamic = "force-dynamic";

export default async function IntelligencePage({
  searchParams,
}: {
  searchParams: Promise<{ cve?: string }>;
}) {
  const { cve } = await searchParams;
  return <IntelligenceView initialCve={cve ?? null} />;
}

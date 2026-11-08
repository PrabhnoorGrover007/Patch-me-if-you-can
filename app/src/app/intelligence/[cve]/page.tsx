import IntelligenceView from "@/components/IntelligenceView";

export const dynamic = "force-dynamic";

export default async function IntelligenceCvePage({
  params,
}: {
  params: Promise<{ cve: string }>;
}) {
  const { cve } = await params;
  return <IntelligenceView initialCve={cve} />;
}

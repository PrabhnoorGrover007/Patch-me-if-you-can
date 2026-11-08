import UploadInspector from "@/components/UploadInspector";
import { getBriefs } from "@/lib/data";

export const dynamic = "force-dynamic";

export default async function UploadPage() {
  return <UploadInspector known={await getBriefs()} />;
}

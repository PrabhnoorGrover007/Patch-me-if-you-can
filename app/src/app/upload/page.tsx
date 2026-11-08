import UploadInspector from "@/components/UploadInspector";
import { getBriefs } from "@/lib/data";

export default function UploadPage() {
  return <UploadInspector known={getBriefs()} />;
}

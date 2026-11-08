import ChatWorkspace from "@/components/ChatWorkspace";
import { getBriefs } from "@/lib/data";

export const dynamic = "force-dynamic";

export default async function ChatPage() {
  return <ChatWorkspace briefs={await getBriefs()} />;
}

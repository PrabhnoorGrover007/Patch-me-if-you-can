import ChatWorkspace from "@/components/ChatWorkspace";
import { getBriefs } from "@/lib/data";

export default function ChatPage() {
  return <ChatWorkspace briefs={getBriefs()} />;
}

// ONE DOOR for an inbound chat turn (PLAN §1, I3/I5).
//
// Slack's turns arrive over HTTP (the Worker relays them to `/sessions/:id/threads/:key/messages`)
// and Buzz's arrive here, from a relay socket this process holds. They must not become two paths:
// the thread, the bridge, the view the browser can open and the reply's journey back are all the
// same, and the only difference is who was holding the message a moment earlier.
//
// So this is the shared tail — find or scaffold the agent's view for the thread, run the turn, and
// post the reply back through the connector.
import { connectorTurn } from "./acpview.js";
import { getSessionRecord } from "./sessions.js";
import { listAgents } from "./agents.js";
import { viewsForSandbox } from "./views.js";
import { bindingForThread, postToChannel, type ChatEnvelope } from "./channels.js";

const log = (...a: unknown[]) => console.log("[channel]", ...a);

/**
 * Run one inbound message as a turn and deliver the answer back to the chat. Never throws: the
 * caller is a relay socket or a fire-and-forget HTTP handler, and there is nobody left to tell.
 */
export async function deliverChannelTurn(sessionId: string, threadKey: string, agentId: string, text: string, envelope: ChatEnvelope): Promise<void> {
  const s = getSessionRecord(sessionId);
  if (!s?.sandboxId) return log(`${sessionId}: gone — dropping a ${envelope.connector} message`);

  let view = viewsForSandbox(s.sandboxId).find((v) => v.type === "agent" && v.specKey === threadKey);
  if (!view) {
    // First contact from this chat: the thread's view is created now, unplaced, which is also what
    // makes the conversation openable in the browser.
    const rec = listAgents(sessionId).find((a) => a.def.id === agentId);
    if (!rec) return log(`${sessionId}: no agent ${agentId} — dropping a ${envelope.connector} message`);
    const { scaffoldView } = await import("./launch.js");
    view = await scaffoldView(s.sandboxId, { type: "agent", specKey: threadKey, agentId: rec.def.id, label: rec.def.name });
    if (!view) return log(`${sessionId}: could not open a thread for ${rec.def.name}`);
  }

  const from = `${envelope.connector}:${envelope.senderName ?? envelope.sender ?? "someone"}`;
  const out = await connectorTurn(view, text, from);
  if ("error" in out) return log(`${sessionId}/${threadKey}: turn failed — ${out.error}`);
  if (!out.reply.text.trim()) return;

  const binding = bindingForThread(sessionId, threadKey);
  if (!binding) return log(`${sessionId}/${threadKey}: answered, but no chat is bound — the reply was dropped`);
  await postToChannel(binding.id, { text: out.reply.text, ...(envelope.thread ? { thread: envelope.thread } : {}), asAgent: agentId }).catch((e: Error) =>
    log(`${sessionId}/${threadKey}: could not deliver the reply — ${e?.message ?? e}`),
  );
}

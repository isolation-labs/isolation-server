// CHANNELS — a chat conversation bound to a running session (PLAN §1, I3b).
//
// A channel in Slack, in Buzz, or in anything that comes next is bound to ONE session and carries
// N of its agents. A mention or a direct message reaches the agent in a thread of its own — an
// agent view keyed by (chat, agent) — so the agent keeps that conversation's context across turns
// and sessions, and the browser can open the same thread and read it.
//
// Everything here is CONNECTOR-AGNOSTIC on purpose (owner call, 2026-09-08). The connector is a
// field, never a different code path: Slack's bot token lives on the Worker and Buzz's relay client
// lives on this host, but both deliver the same envelope to the same thread route and both post
// back through the same call. An agent asking "who said this, and what came before it" gets one
// answer shape whichever app the person is in.
//
// This module owns the binding records and the OUTBOUND half (reaching the chat). Inbound arrives
// as an ordinary thread turn carrying an envelope; the pump (toolpump.ts) exposes the agent-facing
// tools. Nothing chat-shaped is stored on this host beyond the binding: the transcript is the
// agent's own thread, under the workspace tree.
import { randomBytes } from "node:crypto";
import { getPairing } from "./config.js";
import { getSessionRecord } from "./sessions.js";

const log = (...a: unknown[]) => console.log("[channels]", ...a);

/** Where a message came from. The same shape for every connector — that is the point. */
export interface ChatEnvelope {
  connector: string; // "slack" | "buzz" | …
  channel: string; // the connector's own id for the chat
  channelName?: string;
  /** true when this is a direct message rather than a channel. */
  direct?: boolean;
  sender?: string; // the connector's id for the person
  senderName?: string;
  messageId?: string;
  /** The thread/root this message belongs to, when the connector has threads. */
  thread?: string;
}

export interface ChannelBinding {
  id: string;
  sessionId: string;
  connector: string;
  channel: string;
  channelName?: string;
  /** Roster agent ids reachable in this chat. */
  agents: string[];
  createdAt: number;
  /** A binding outlives its session (owner call): it ends, it is not deleted. */
  status: "live" | "ended";
}

const bindings = new Map<string, ChannelBinding>(); // id → binding
/**
 * The envelope of the turn currently being handled, per (session, thread key) — what `chat_context`
 * answers. Keyed by SESSION as well as thread: a thread key is deterministic (the same chat and
 * agent produce the same one), so two sessions of the same channel — two different members — would
 * otherwise read and erase each other's "who said this to me".
 */
const envelopes = new Map<string, ChatEnvelope>();
const envelopeKey = (sessionId: string, threadKey: string) => `${sessionId}\u0000${threadKey}`;

const mintId = () => `ch-${randomBytes(6).toString("hex")}`;
// A channel id comes from OUTSIDE and ends up in a thread key, which ends up in a filename. Dots
// are dropped along with everything else that is not a letter, a digit, a dash or an underscore:
// no connector needs them, and a key that cannot contain `..` is one less thing to reason about.
const safe = (s: string) => s.replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 40);

/**
 * The thread a (chat, agent) pair talks in. Stable across sessions of the workspace, because the
 * key IS the thread — so an agent re-attached to the same channel next week picks the conversation
 * up where it left it.
 */
export const channelThreadKey = (connector: string, channel: string, agentId: string): string => `chan-${safe(connector)}-${safe(channel)}-${safe(agentId)}`;

export function attachChannel(input: { sessionId: string; connector: string; channel: string; channelName?: string; agents: string[] }): ChannelBinding {
  // Re-attaching the same chat to the same session is the SAME binding, not a second one: a
  // connector that retries (or a person who runs the command twice) must not double-deliver.
  const existing = [...bindings.values()].find((b) => b.sessionId === input.sessionId && b.connector === input.connector && b.channel === input.channel);
  const b: ChannelBinding = existing
    ? { ...existing, channelName: input.channelName ?? existing.channelName, agents: input.agents, status: "live" }
    : {
        id: mintId(),
        sessionId: input.sessionId,
        connector: input.connector,
        channel: input.channel,
        ...(input.channelName ? { channelName: input.channelName } : {}),
        agents: input.agents,
        createdAt: Date.now(),
        status: "live",
      };
  bindings.set(b.id, b);
  log(`${b.id}: ${b.connector} ${b.channelName ?? b.channel} → ${b.sessionId} (${b.agents.length} agent(s))`);
  return b;
}

export function detachChannel(id: string): boolean {
  const b = bindings.get(id);
  if (!b) return false;
  if (isLocal(b.connector)) void import("./buzz.js").then((m) => m.detachBuzz(id));
  bindings.delete(id);
  log(`${id}: detached`);
  return true;
}

export const channelBinding = (id: string): ChannelBinding | undefined => bindings.get(id);
export const channelsForSession = (sessionId: string): ChannelBinding[] => [...bindings.values()].filter((b) => b.sessionId === sessionId);

/** Find the binding a thread key belongs to, so a tool call can be answered in the right chat. */
export function bindingForThread(sessionId: string, threadKey: string): ChannelBinding | undefined {
  return channelsForSession(sessionId).find((b) => b.agents.some((a) => channelThreadKey(b.connector, b.channel, a) === threadKey));
}

/**
 * A session is over. The channel STAYS (owner call 2026-09-08) — it is the record of what happened
 * — but it says so and its agents stop answering. A new launch re-attaches to the same chat.
 */
export async function endChannelsFor(sessionId: string): Promise<void> {
  await Promise.all(
    channelsForSession(sessionId).map(async (b) => {
      if (b.status === "ended") return;
      bindings.set(b.id, { ...b, status: "ended" });
      await postToChannel(b.id, { text: "This session has ended. Ask again to start a new one." }).catch(() => undefined);
    }),
  );
}

export function rememberEnvelope(sessionId: string, threadKey: string, envelope: ChatEnvelope | undefined): void {
  if (envelope) envelopes.set(envelopeKey(sessionId, threadKey), envelope);
}
export const envelopeFor = (sessionId: string, threadKey: string): ChatEnvelope | undefined => envelopes.get(envelopeKey(sessionId, threadKey));
/** Every envelope of a session, whether or not its binding is still attached. */
export function forgetEnvelopesFor(sessionId: string): void {
  const prefix = envelopeKey(sessionId, "");
  for (const k of envelopes.keys()) if (k.startsWith(prefix)) envelopes.delete(k);
}

// ── Reaching the chat ──────────────────────────────────────────────────────────────────────────
// Every connector's outbound goes through the CLOUD, which holds the app's credential (a Slack bot
// token) and knows how to talk to it. The one exception will be Buzz (I5), whose relay client runs
// on this host because posting there means signing with the agent's own key — the interface stays
// the same, only the implementation branches, and it branches once.

interface CloudCall {
  op: "post" | "history" | "members" | "notify";
  bindingId: string;
  [k: string]: unknown;
}

async function cloud(call: CloudCall): Promise<Record<string, unknown>> {
  const p = getPairing();
  if (!p) throw new Error("this server is not paired with a cloud, so it cannot reach the chat");
  const r = await fetch(`${p.backendUrl.replace(/\/+$/, "")}/api/pair/channel`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // The pairing secret is this server's identity to the cloud — the same credential the
    // heartbeat and the boot log use. A binding id is meaningless without it.
    body: JSON.stringify({ connectionId: p.connectionId, secret: p.secret, ...call }),
    signal: AbortSignal.timeout(20_000),
  });
  const body = (await r.json().catch(() => ({}))) as Record<string, unknown>;
  if (!r.ok) throw new Error(String(body.error ?? `the cloud answered HTTP ${r.status}`));
  return body;
}

/**
 * WHICH implementation serves a connector. Every one goes through the cloud, because that is where
 * a chat app's credential lives — except Buzz, whose relay socket and signing key are HERE (I5).
 * The branch is this one line; every caller above and every agent-facing tool is unchanged, which
 * is the whole point of one contract (docs/channels-plan.md).
 */
const isLocal = (connector: string): boolean => connector === "buzz";

/** Say something in the chat this binding names. `thread` replies inside a thread when given. */
export async function postToChannel(bindingId: string, o: { text: string; thread?: string; asAgent?: string }): Promise<{ posted: boolean }> {
  const b = bindings.get(bindingId);
  if (!b) throw new Error("that chat is not connected to this session any more");
  const text = o.text.slice(0, 8_000);
  if (isLocal(b.connector)) await (await import("./buzz.js")).buzzPost(bindingId, { ...o, text });
  else await cloud({ op: "post", bindingId, connector: b.connector, channel: b.channel, text, ...(o.thread ? { thread: o.thread } : {}), ...(o.asAgent ? { asAgent: o.asAgent } : {}) });
  return { posted: true };
}

/** The last messages of the chat, oldest first. Read on demand — never injected into a turn. */
export async function channelHistory(bindingId: string, limit = 30): Promise<unknown[]> {
  const b = bindings.get(bindingId);
  if (!b) throw new Error("that chat is not connected to this session any more");
  const n = Math.min(Math.max(limit, 1), 100);
  if (isLocal(b.connector)) return (await import("./buzz.js")).buzzHistory(bindingId, n);
  const out = await cloud({ op: "history", bindingId, connector: b.connector, channel: b.channel, limit: n });
  return Array.isArray(out.messages) ? out.messages : [];
}

export async function channelMembers(bindingId: string): Promise<unknown[]> {
  const b = bindings.get(bindingId);
  if (!b) throw new Error("that chat is not connected to this session any more");
  if (isLocal(b.connector)) return (await import("./buzz.js")).buzzMembers(bindingId);
  const out = await cloud({ op: "members", bindingId, connector: b.connector, channel: b.channel });
  return Array.isArray(out.members) ? out.members : [];
}

/**
 * Reach the person who launched this session, wherever they are — a direct message in the
 * connector, resolved by the cloud from that member's own chat identity. This is what makes an
 * agent able to report something nobody asked it for.
 */
export async function notifyOwner(sessionId: string, text: string, connector?: string): Promise<{ sent: boolean; via?: string }> {
  const s = getSessionRecord(sessionId);
  if (!s?.owner) throw new Error("this session has no recorded owner to reach");
  const live = channelsForSession(sessionId).find((b) => b.status === "live");
  const which = connector ?? live?.connector ?? "";
  // Buzz has no direct messages here (NIP-17 gift wraps are out of scope), so the honest answer is
  // the channel the person is already in — and the answer says which it was.
  if (isLocal(which) && live) return (await import("./buzz.js")).buzzNotifyOwner(live.id, text.slice(0, 4_000));
  const out = await cloud({ op: "notify", bindingId: live?.id ?? "", sessionId, member: s.owner, connector: which, text: text.slice(0, 4_000) });
  return { sent: out.sent === true, ...(typeof out.via === "string" ? { via: out.via } : {}) };
}

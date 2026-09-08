// BUZZ — the second chat connector, and the one that runs HERE (PLAN §1, I5).
//
// Slack lives on the Worker because Slack is an HTTP API with a bot token. Buzz is a Nostr relay:
// reading a channel means holding a WebSocket subscription open, and posting means signing with the
// AGENT'S OWN KEY. Neither fits a Worker request, and the key must not travel further than it has
// to — so this connector is a process on the server, beside the sandbox it speaks for.
//
// That is the only asymmetry. Inbound still becomes an ordinary thread turn carrying the same
// envelope Slack produces, and outbound still goes through `channels.ts` — which routes `buzz`
// here instead of to the cloud. An agent's chat tools cannot tell the difference, which is the
// whole point of the contract (docs/channels-plan.md).
//
// Scope, deliberately: CHANNELS. Direct messages are NIP-17 gift wraps, which need a second and
// much larger piece of cryptography (NIP-44 + NIP-59); "add an agent to a channel the way you add a
// person" is what Buzz's own pitch is about, and it is what this does.
import { getPairing } from "./config.js";
import { channelThreadKey, rememberEnvelope, type ChannelBinding, type ChatEnvelope } from "./channels.js";
import { getSessionRecord } from "./sessions.js";
import {
  AUTH_KIND,
  MESSAGE_KINDS,
  authEvent,
  channelMessage,
  npubOf,
  profileEvent,
  publicKeyHex,
  secretKeyBytes,
  signEvent,
  tagValue,
  tagValues,
  threadRoot,
  verifyEvent,
  type NostrEvent,
} from "./nostr.js";

const log = (...a: unknown[]) => console.log("[buzz]", ...a);

/** How long to wait before redialing a relay that dropped. Backs off, then settles. */
const RECONNECT_MS = [1_000, 2_000, 5_000, 10_000, 30_000];
const REQUEST_TIMEOUT_MS = 15_000;

interface AgentKey {
  agentId: string;
  name: string;
  sk: Uint8Array;
  pubkey: string;
}

interface Conn {
  relay: string;
  ws: WebSocket;
  /** Bindings served by this relay connection, by binding id. */
  bindings: Map<string, { binding: ChannelBinding; agents: AgentKey[] }>;
  /** Pending one-shot queries (history), by subscription id. */
  queries: Map<string, { events: NostrEvent[]; done: (e: NostrEvent[]) => void; timer: ReturnType<typeof setTimeout> }>;
  authed: boolean;
  closed: boolean;
  attempts: number;
}

const conns = new Map<string, Conn>(); // relay url → connection

/** Everything this connector knows, so `channels.ts` can ask whether Buzz can serve a binding. */
export const buzzKnows = (bindingId: string): boolean => [...conns.values()].some((c) => c.bindings.has(bindingId));

// ── Attaching ──────────────────────────────────────────────────────────────────────────────────

export interface BuzzAttach {
  relay: string;
  /** The agents' own keys, sealed to this server at attach and never written to disk. */
  keys: { agentId: string; name: string; nsec: string }[];
}

/**
 * Serve a binding: connect to its relay if we are not already, subscribe for the channel's messages
 * addressed to these agents, and publish each agent's profile once so it appears as a name rather
 * than a bare key.
 */
export async function attachBuzz(binding: ChannelBinding, input: BuzzAttach): Promise<{ npubs: Record<string, string> }> {
  if (typeof WebSocket !== "function") throw new Error("this Node build has no WebSocket — Buzz needs Node 22 or newer");
  const relay = normalizeRelay(input.relay);
  const agents: AgentKey[] = [];
  for (const k of input.keys) {
    if (!binding.agents.includes(k.agentId)) continue; // a key for an agent this chat does not carry
    const sk = secretKeyBytes(k.nsec);
    agents.push({ agentId: k.agentId, name: k.name, sk, pubkey: publicKeyHex(sk) });
  }
  if (!agents.length) throw new Error("no keys were supplied for the agents in this chat");

  const conn = await connect(relay);
  conn.bindings.set(binding.id, { binding, agents });
  resubscribe(conn);
  // A profile is published once per attach: it is a replaceable event, so re-publishing is how a
  // renamed agent is renamed in the room, and cheap enough not to be worth remembering.
  for (const a of agents) await publish(conn, await signEvent(a.sk, profileEvent(a.name, "An Isolation agent."))).catch(() => undefined);
  log(`${binding.id}: ${relay} ${binding.channelName ?? binding.channel} — ${agents.map((a) => a.name).join(", ")}`);
  return { npubs: Object.fromEntries(agents.map((a) => [a.agentId, npubOf(a.pubkey)])) };
}

export function detachBuzz(bindingId: string): void {
  for (const c of conns.values()) {
    if (!c.bindings.delete(bindingId)) continue;
    if (c.bindings.size === 0) close(c);
    else resubscribe(c);
  }
}

/** Every binding this server was serving on Buzz, dropped — teardown, or a session that ended. */
export function detachBuzzFor(sessionId: string): void {
  for (const c of [...conns.values()]) {
    for (const [id, e] of [...c.bindings]) if (e.binding.sessionId === sessionId) c.bindings.delete(id);
    if (c.bindings.size === 0) close(c);
    else resubscribe(c);
  }
}

// ── The relay connection ───────────────────────────────────────────────────────────────────────

function normalizeRelay(raw: string): string {
  const u = new URL(raw.trim());
  if (u.protocol === "http:") u.protocol = "ws:";
  if (u.protocol === "https:") u.protocol = "wss:";
  if (u.protocol !== "ws:" && u.protocol !== "wss:") throw new Error(`a relay is a ws:// or wss:// address, not ${u.protocol}`);
  return u.toString().replace(/\/+$/, "");
}

async function connect(relay: string): Promise<Conn> {
  const existing = conns.get(relay);
  if (existing && !existing.closed) return existing;
  const ws = new WebSocket(relay);
  const conn: Conn = { relay, ws, bindings: existing?.bindings ?? new Map(), queries: new Map(), authed: false, closed: false, attempts: existing?.attempts ?? 0 };
  conns.set(relay, conn);

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${relay} did not answer`)), REQUEST_TIMEOUT_MS);
    ws.addEventListener("open", () => {
      clearTimeout(timer);
      conn.attempts = 0;
      resolve();
    }, { once: true });
    ws.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error(`could not reach ${relay}`));
    }, { once: true });
  });

  ws.addEventListener("message", (ev) => void onMessage(conn, String((ev as MessageEvent).data)).catch((e) => log(`${relay}: ${String((e as Error)?.message ?? e)}`)));
  ws.addEventListener("close", () => {
    conn.closed = true;
    // Only redial while something still wants this relay; a detach closes it on purpose.
    if (conn.bindings.size) redial(conn);
  });
  return conn;
}

function redial(conn: Conn): void {
  const wait = RECONNECT_MS[Math.min(conn.attempts++, RECONNECT_MS.length - 1)];
  log(`${conn.relay}: connection lost — retrying in ${wait / 1000}s`);
  setTimeout(() => {
    if (!conn.bindings.size) return;
    void connect(conn.relay)
      .then((c) => resubscribe(c))
      .catch(() => redial(conn));
  }, wait);
}

function close(conn: Conn): void {
  conn.closed = true;
  conns.delete(conn.relay);
  try {
    conn.ws.close();
  } catch {
    /* already gone */
  }
}

const send = (conn: Conn, msg: unknown): void => {
  if (conn.ws.readyState === 1) conn.ws.send(JSON.stringify(msg));
};

/**
 * One subscription per connection, covering every channel it serves. Filtered to the message kinds
 * AND to the agents' own keys (`#p`) — a relay that sent us everything in a busy channel would have
 * us verify and discard the lot, and Buzz's own relay refuses a `#p` filter naming anyone else.
 */
function resubscribe(conn: Conn): void {
  send(conn, ["CLOSE", "iso"]);
  const channels = [...new Set([...conn.bindings.values()].map((b) => b.binding.channel))];
  const pubkeys = [...new Set([...conn.bindings.values()].flatMap((b) => b.agents.map((a) => a.pubkey)))];
  if (!channels.length || !pubkeys.length) return;
  // `since` now: history is read on demand (chat_history), never replayed as new mentions — a
  // reconnect must not answer a week of messages at once.
  send(conn, ["REQ", "iso", { kinds: MESSAGE_KINDS, "#h": channels, "#p": pubkeys, since: Math.floor(Date.now() / 1000) }]);
}

async function onMessage(conn: Conn, raw: string): Promise<void> {
  let msg: unknown[];
  try {
    msg = JSON.parse(raw) as unknown[];
  } catch {
    return;
  }
  const [type] = msg as [string, ...unknown[]];

  if (type === "AUTH") {
    // NIP-42: prove we hold each agent's key. One challenge, one answer per agent — the relay
    // associates the connection with whoever answered.
    const challenge = String(msg[1] ?? "");
    for (const b of conn.bindings.values()) for (const a of b.agents) send(conn, ["AUTH", await authEvent(a.sk, conn.relay, challenge)]);
    conn.authed = true;
    // A relay that challenges usually rejects the subscription that preceded it; ask again.
    resubscribe(conn);
    return;
  }

  if (type === "EOSE") {
    const q = conn.queries.get(String(msg[1] ?? ""));
    if (q) finishQuery(conn, String(msg[1]), q.events);
    return;
  }

  if (type === "NOTICE") return log(`${conn.relay}: ${String(msg[1] ?? "")}`);
  if (type === "OK" && msg[2] === false) return log(`${conn.relay}: rejected an event — ${String(msg[3] ?? "")}`);
  if (type !== "EVENT") return;

  const subId = String(msg[1] ?? "");
  const event = msg[2] as NostrEvent;
  if (!event?.id || !(await verifyEvent(event))) return; // a relay is not a trusted narrator

  const q = conn.queries.get(subId);
  if (q) {
    q.events.push(event);
    return;
  }
  if (subId !== "iso") return;
  await onChannelMessage(conn, event).catch((e) => log(`inbound: ${String((e as Error)?.message ?? e)}`));
}

// ── Inbound: a mention becomes a turn ──────────────────────────────────────────────────────────

async function onChannelMessage(conn: Conn, e: NostrEvent): Promise<void> {
  const channel = tagValue(e, "h");
  if (!channel || !e.content.trim()) return;
  const entry = [...conn.bindings.values()].find((b) => b.binding.channel === channel);
  if (!entry) return;
  const { binding } = entry;

  // Never answer ourselves: an agent's own message comes back on its own subscription, and
  // answering it is a loop that costs a turn every time round.
  if (entry.agents.some((a) => a.pubkey === e.pubkey)) return;

  const mentioned = new Set(tagValues(e, "p"));
  // Addressed by key when the sender mentioned one; otherwise the chat's single agent takes it.
  // Never fan out — that is N turns for one message.
  const target = entry.agents.find((a) => mentioned.has(a.pubkey)) ?? (entry.agents.length === 1 ? entry.agents[0] : undefined);
  if (!target) return;

  const s = getSessionRecord(binding.sessionId);
  if (!s?.sandboxId) return;

  const envelope: ChatEnvelope = {
    connector: "buzz",
    channel,
    ...(binding.channelName ? { channelName: binding.channelName } : {}),
    sender: e.pubkey,
    senderName: npubOf(e.pubkey).slice(0, 12), // a relay knows keys; a name is a profile lookup
    messageId: e.id,
    // NIP-10: answer inside the thread it was said in, or start one on this message.
    thread: threadRoot(e) ?? e.id,
  };
  const key = channelThreadKey("buzz", channel, target.agentId);
  rememberEnvelope(binding.sessionId, key, envelope);

  // The turn runs through the same door Slack's does — the server's own thread route — so the
  // bridge, the thread file and the agent's view are all identical either way.
  const { deliverChannelTurn } = await import("./channelturn.js");
  await deliverChannelTurn(binding.sessionId, key, target.agentId, e.content, envelope);
}

// ── Outbound ───────────────────────────────────────────────────────────────────────────────────

function connFor(bindingId: string): { conn: Conn; entry: { binding: ChannelBinding; agents: AgentKey[] } } {
  for (const conn of conns.values()) {
    const entry = conn.bindings.get(bindingId);
    if (entry) return { conn, entry };
  }
  throw new Error("this chat is not connected on this server any more");
}

/** Say something in the channel, signed by the agent that is saying it. */
export async function buzzPost(bindingId: string, o: { text: string; thread?: string; asAgent?: string }): Promise<void> {
  const { conn, entry } = connFor(bindingId);
  const agent = entry.agents.find((a) => a.agentId === o.asAgent) ?? entry.agents[0];
  if (!agent) throw new Error("no agent key for this chat");
  const ev = await signEvent(agent.sk, channelMessage(entry.binding.channel, o.text, o.thread ? { root: o.thread, replyTo: o.thread } : {}));
  await publish(conn, ev);
}

function publish(conn: Conn, ev: NostrEvent): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      conn.ws.removeEventListener("message", onOk);
      reject(new Error("the relay did not confirm the message"));
    }, REQUEST_TIMEOUT_MS);
    function onOk(m: Event) {
      let parsed: unknown[];
      try {
        parsed = JSON.parse(String((m as MessageEvent).data)) as unknown[];
      } catch {
        return;
      }
      if (parsed[0] !== "OK" || parsed[1] !== ev.id) return;
      clearTimeout(timer);
      conn.ws.removeEventListener("message", onOk);
      // The relay's own verdict — a missing membership or a rejected kind arrives here, and an
      // agent should hear the reason rather than a silence it cannot act on.
      parsed[2] === true ? resolve() : reject(new Error(String(parsed[3] ?? "the relay refused the message")));
    }
    conn.ws.addEventListener("message", onOk);
    send(conn, ["EVENT", ev]);
  });
}

/** The last messages of the channel, oldest first — read on demand, never injected into a turn. */
export async function buzzHistory(bindingId: string, limit: number): Promise<unknown[]> {
  const { conn, entry } = connFor(bindingId);
  const events = await query(conn, { kinds: MESSAGE_KINDS, "#h": [entry.binding.channel], limit });
  return events
    .sort((a, b) => a.created_at - b.created_at)
    .map((e) => ({
      id: e.id,
      from: e.pubkey,
      name: entry.agents.find((a) => a.pubkey === e.pubkey)?.name ?? npubOf(e.pubkey).slice(0, 12),
      text: e.content,
      at: new Date(e.created_at * 1000).toISOString(),
      thread: threadRoot(e) ?? null,
    }));
}

/**
 * Who is in the channel. A relay has no membership API of its own here, so this is who has SPOKEN
 * recently — honest, and said so in the answer rather than presented as a roster.
 */
export async function buzzMembers(bindingId: string): Promise<unknown[]> {
  const { conn, entry } = connFor(bindingId);
  const events = await query(conn, { kinds: MESSAGE_KINDS, "#h": [entry.binding.channel], limit: 100 });
  const seen = new Map<string, { id: string; name: string | null; kind: string }>();
  for (const e of events) {
    const agent = entry.agents.find((a) => a.pubkey === e.pubkey);
    if (!seen.has(e.pubkey)) seen.set(e.pubkey, { id: npubOf(e.pubkey), name: agent?.name ?? null, kind: agent ? "agent" : "person" });
  }
  return [...seen.values()];
}

function query(conn: Conn, filter: Record<string, unknown>): Promise<NostrEvent[]> {
  return new Promise((resolve) => {
    const id = `q${Math.random().toString(36).slice(2, 10)}`;
    const timer = setTimeout(() => finishQuery(conn, id, conn.queries.get(id)?.events ?? []), REQUEST_TIMEOUT_MS);
    conn.queries.set(id, { events: [], done: resolve, timer });
    send(conn, ["REQ", id, filter]);
  });
}

function finishQuery(conn: Conn, id: string, events: NostrEvent[]): void {
  const q = conn.queries.get(id);
  if (!q) return;
  clearTimeout(q.timer);
  conn.queries.delete(id);
  send(conn, ["CLOSE", id]);
  q.done(events);
}

/**
 * Reaching a session's owner on Buzz. A relay has no way to DM without NIP-17 gift wraps (out of
 * scope), so the honest answer is the channel: the person is in it, and being named there is how
 * they hear about it. `notify` on Slack is a real DM; here it is a mention, and the answer says so.
 */
export async function buzzNotifyOwner(bindingId: string, text: string): Promise<{ sent: boolean; via?: string }> {
  const { entry } = connFor(bindingId);
  await buzzPost(bindingId, { text });
  void entry;
  void getPairing();
  return { sent: true, via: "buzz (in the channel — Buzz direct messages are not supported yet)" };
}

export const buzzAuthKind = AUTH_KIND; // re-exported so a test can assert the handshake shape

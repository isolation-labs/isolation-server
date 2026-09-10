// THE CONTROL CHANNEL, host side (PLAN §1, I3).
//
// An agent inside a sandbox can reach loopback and nothing else — that is the shape of the runtime,
// and it is why `iso-mcp` has only ever been able to read files and dial other agents on
// 127.0.0.1. But what an agent is actually asked for in a chat ("open the preview", "send me the
// link", "how do I ssh in", "what do the logs say") is known only to THIS process, and the answer
// to "can the sandbox call the server?" is no (no host.docker.internal on Linux, no unix socket on
// Docker Desktop — the finding that shaped the retired daemon's tool pump).
//
// So the direction is inverted. The server LONG-POLLS each agent bridge for parked tool calls,
// runs them here, and posts the answers back. Both legs are requests the server makes, which is
// the only direction that works — and it needs no WebSocket client, no framing, no reconnect state
// machine: a failed poll is simply the next poll.
//
// A handler does NOT re-implement anything. What an agent asks for that a person could also ask for
// is an ACTION, and it is FORWARDED to the cloud (`op: "action"` on the pairing channel), which runs
// the one body every other door runs — so every ownership rule, every refusal and every future
// change applies to an agent's tool call exactly as it does to the browser's click. What is left
// here is the agent's own work plane: the chat it was spoken to in, which has no meaning outside
// this session. The tool map below is the entire surface an agent can reach, and each entry is
// pinned to the CALLING view's own session: an argument never names another one.
import { endpointFor } from "./opensandbox.js";
import { sessionForSandbox } from "./sessions.js";
import { getView, viewsForSandbox, type View } from "./views.js";
import { agentForView, threadKeyOf } from "./agents.js";
import { bindingForThread, channelHistory, channelMembers, channelsForSession, cloud, envelopeFor, notifyOwner, postToChannel } from "./channels.js";

const log = (...a: unknown[]) => console.log("[toolpump]", ...a);

const WAIT_MS = 25_000;
/** Consecutive poll failures before a pump gives up; whatever restarts the bridge restarts it. */
const MAX_FAILURES = 5;

export interface ToolCall {
  id: string;
  tool: string;
  args: Record<string, unknown>;
}

const pumps = new Map<string, { stop: () => void }>();

export const pumpRunning = (viewId: string): boolean => pumps.has(viewId);

/**
 * Poll a view's bridge for tool calls. Idempotent — the launch, the doorman's heal and a resume all
 * call it, and "one pump per view" is the invariant that matters.
 */
export function startToolPump(view: View): void {
  if (pumps.has(view.id) || view.type !== "agent" || !view.port) return;
  let stopped = false;
  // Only ever remove OUR OWN entry: a pump stopped mid-poll can still fall out of its request a
  // moment after a replacement was armed, and deleting the map entry blindly would orphan the new
  // pump (and let a third one start alongside it).
  const forget = () => {
    if (pumps.get(view.id) === self) pumps.delete(view.id);
  };
  const self = {
    stop: () => {
      stopped = true;
      forget();
    },
  };
  pumps.set(view.id, self);
  void (async () => {
    let failures = 0;
    while (!stopped) {
      // The view can go out from under a pump (DELETE /views/<id>, a spec change the SPA makes by
      // delete-then-recreate). View ports are RECYCLED — nextFree only avoids LIVE views — so a
      // pump still polling a dropped view's port can be handed the NEXT view's parked tool calls
      // and answer them against the WRONG thread (`threadKeyOf(view)` is the old view's). The
      // view registry is the authority on whether this pump still has a subject.
      if (!getView(view.id)) {
        forget();
        return;
      }
      let call: ToolCall | undefined;
      try {
        const ep = await endpointFor(view.sandboxId, view.port);
        const r = await fetch(`http://${ep.host}${ep.basePath}/iso-tool/next?wait=${WAIT_MS}`, { signal: AbortSignal.timeout(WAIT_MS + 10_000) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        call = ((await r.json()) as { call?: ToolCall }).call;
        failures = 0;
      } catch (e) {
        // A restarting bridge, a paused sandbox, a poll the proxy timed out: back off and ask
        // again. Only a persistent failure gives up — the bridge is then gone or being replaced.
        if (++failures >= MAX_FAILURES) {
          log(`${view.id}: bridge unreachable (${String((e as Error)?.message ?? e)}) — pump stopped`);
          forget();
          return;
        }
        await new Promise((r) => setTimeout(r, 1_000 * failures));
        continue;
      }
      if (!call) continue;
      // Same check once more: the poll parks for 25s, and the view can have been dropped (and its
      // port re-issued) while it was waiting. Better the caller's 60s timeout than an answer built
      // from a stale view's session and thread.
      if (stopped || !getView(view.id)) {
        forget();
        return;
      }
      let payload: { result?: unknown; error?: string };
      try {
        payload = { result: await runTool(view, call) };
      } catch (e) {
        payload = { error: String((e as Error)?.message ?? e).slice(0, 500) };
      }
      try {
        const ep = await endpointFor(view.sandboxId, view.port);
        await fetch(`http://${ep.host}${ep.basePath}/iso-tool/result`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ id: call.id, ...payload }),
          signal: AbortSignal.timeout(10_000),
        });
      } catch (e) {
        log(`${view.id}: could not return ${call.tool} — ${String((e as Error)?.message ?? e)}`);
      }
    }
  })();
}

export function stopToolPump(viewId: string): void {
  pumps.get(viewId)?.stop();
}

/** Every pump for a sandbox — teardown, pause and resume all work at that granularity. */
export function stopToolPumpsFor(sandboxId: string): void {
  for (const v of viewsForSandbox(sandboxId)) stopToolPump(v.id);
}

/** A pump for every agent view of a sandbox (after a launch, a resume, or a view restore). */
export function startToolPumpsFor(sandboxId: string): void {
  for (const v of viewsForSandbox(sandboxId)) if (v.type === "agent" && v.port) startToolPump(v);
}

// ── The tools ──────────────────────────────────────────────────────────────────────────────────

const str = (v: unknown, max = 500): string | undefined => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : undefined);

async function cloudAction(view: View, sessionId: string, call: ToolCall): Promise<unknown> {
  const rec = agentForView(view);
  let name = call.tool;
  let args: Record<string, unknown> = { ...(call.args ?? {}) };
  // `ssh_command` IS `view_connect` on the session's TERMINAL — but that action names a window by
  // id, by the label a person gave it, or by an agent's name (catalog.ts resolveView); a TYPE is not
  // something it can resolve, so "terminal" would come back as "this session has no window called
  // terminal". Which window it means is known here, where the view registry is, so the tool names it
  // by id — and the answer for a session with no terminal stays the one that says what to do.
  if (call.tool === "ssh_command") {
    const term = viewsForSandbox(view.sandboxId).find((v) => v.type === "terminal");
    if (!term) throw new Error("this session has no terminal to attach to — create one with view_create first");
    name = "view_connect";
    args = { view: term.id };
  }
  const out = await cloud({
    op: "action",
    name,
    args,
    sessionId,
    agentId: view.agentId ?? rec?.def.id ?? "",
    viewId: view.id,
    harness: rec?.def.harness ?? "agent",
  });
  // The cloud answers `{ result }` for a success and `{ error }` for anything the agent can act on;
  // `cloud()` has already turned the second into a throw.
  return (out as { result?: unknown }).result;
}

async function runTool(view: View, call: ToolCall): Promise<unknown> {
  const s = sessionForSandbox(view.sandboxId);
  if (!s) throw new Error("this session is gone");
  const args = call.args ?? {};

  switch (call.tool) {
    // ── THE CONTROL PLANE, forwarded (docs/actions-plan.md A2) ─────────────────────────────────
    //
    // These are not this server's to answer. Each one is an ACTION — the same body a person reaches
    // from the website, from `/view` typed in Slack, and from an MCP tool — and until 2026-09-10
    // there was a second implementation of every one of them right here, with the same names and
    // subtly different arguments. Now the agent is simply a fifth actor: the cloud checks that this
    // server is running this session, pins the call to it, runs the one body and logs it.
    //
    // WHAT IS NOT FORWARDED, and never will be: everything below this block. `chat_*` is the
    // conversation this agent was summoned into, `memory_*` and `thread_send` are answered inside
    // the sandbox. That is the agent's WORK plane, it has no equivalent outside a session, and
    // giving it one would be inventing a door rather than sharing one.
    case "views_list":
    case "view_create":
    case "view_link":
    case "view_delete":
    case "ssh_command":
    case "session_logs":
    case "session_save":
      return cloudAction(view, s.id, call);

    // ── The chat this agent was spoken to in (PLAN §1 I3) ──────────────────────────────────────
    // Agnostic by construction: the connector is a field on the envelope, never a different tool.
    // Every one of these is scoped to the CALLING view's own thread, so an agent can only read and
    // answer the conversation it is part of.

    case "chat_context": {
      const key = threadKeyOf(view);
      const env = envelopeFor(s.id, key);
      const b = bindingForThread(s.id, key);
      if (!env && !b) return { inChat: false, note: "This conversation is not connected to a chat — you are being talked to from the Isolation session screen." };
      return {
        inChat: true,
        connector: env?.connector ?? b?.connector,
        channel: { id: env?.channel ?? b?.channel, name: env?.channelName ?? b?.channelName, direct: env?.direct ?? false },
        lastMessage: env ? { from: { id: env.sender, name: env.senderName }, messageId: env.messageId, thread: env.thread } : null,
        agentsHere: b?.agents ?? [],
      };
    }

    case "chat_history": {
      const b = bindingForThread(s.id, threadKeyOf(view));
      if (!b) throw new Error("this conversation is not connected to a chat");
      const limit = typeof args.limit === "number" ? args.limit : 30;
      return { messages: await channelHistory(b.id, limit) };
    }

    case "chat_members": {
      const b = bindingForThread(s.id, threadKeyOf(view));
      if (!b) throw new Error("this conversation is not connected to a chat");
      return { members: await channelMembers(b.id) };
    }

    // Answer in the same place the question came from — in-thread when the connector threads.
    case "chat_reply": {
      const key = threadKeyOf(view);
      const b = bindingForThread(s.id, key);
      if (!b) throw new Error("this conversation is not connected to a chat");
      const text = str(args.text, 8_000);
      if (!text) throw new Error("text is required");
      const env = envelopeFor(s.id, key);
      await postToChannel(b.id, { text, ...(env?.thread ? { thread: env.thread } : {}), asAgent: view.agentId });
      return { posted: true, in: b.channelName ?? b.channel };
    }

    // Say something nobody asked for — a build finished, a test broke.
    case "chat_post": {
      const b = bindingForThread(s.id, threadKeyOf(view));
      if (!b) throw new Error("this conversation is not connected to a chat");
      const text = str(args.text, 8_000);
      if (!text) throw new Error("text is required");
      await postToChannel(b.id, { text, asAgent: view.agentId });
      return { posted: true, in: b.channelName ?? b.channel };
    }

    // Reach the person who launched this session, wherever they are.
    case "chat_notify_owner": {
      const text = str(args.text, 4_000);
      if (!text) throw new Error("text is required");
      const b = bindingForThread(s.id, threadKeyOf(view)) ?? channelsForSession(s.id).find((x) => x.status === "live");
      return await notifyOwner(s.id, text, b?.connector);
    }

    default:
      throw new Error(`unknown tool: ${call.tool}`);
  }
}

/**
 * The tools the in-sandbox MCP offers over the pump. This list is LOAD-BEARING: a unit test reads
 * `sandbox/iso-mcp.mjs` and this file and fails if either drifts from it, because the three places
 * are edited at different times and a tool that is offered but unhandled reads to an agent as a
 * broken product rather than a missing feature.
 */
export const PUMP_TOOLS = [
  "views_list",
  "view_create",
  "view_link",
  "view_delete",
  "ssh_command",
  "session_logs",
  "session_save",
  "chat_context",
  "chat_history",
  "chat_members",
  "chat_reply",
  "chat_post",
  "chat_notify_owner",
] as const;

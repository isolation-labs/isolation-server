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
// A handler does NOT re-implement anything. It calls this server's own HTTP API over loopback with
// the master token and the session owner's actor headers — the same door the Worker's proxy comes
// through — so every ownership rule, every refusal and every future change applies to an agent's
// tool call exactly as it does to the browser's click. The tool map below is the entire surface an
// agent can reach, and each entry is pinned to the CALLING view's own session: an argument never
// names another one.
import { HOST, PORT, getToken } from "./config.js";
import { endpointFor } from "./opensandbox.js";
import { getSessionRecord, sessionForSandbox } from "./sessions.js";
import { getView, viewsForSandbox, type View } from "./views.js";
import { threadKeyOf } from "./agents.js";
import { bindingForThread, channelHistory, channelMembers, channelsForSession, envelopeFor, notifyOwner, postToChannel } from "./channels.js";

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

/** One call into this server's own API, as the session's owner. */
async function api(sessionId: string, path: string, init: { method?: string; body?: unknown } = {}): Promise<any> {
  const s = getSessionRecord(sessionId);
  const headers: Record<string, string> = { authorization: `Bearer ${getToken()}`, "content-type": "application/json" };
  // Act as the session's launcher — the same identity the Worker's proxy stamps. Without it the
  // server would treat the call as identity-less, which is a WIDER right, not a narrower one.
  if (s?.owner) {
    headers["x-isolation-actor"] = s.owner;
    headers["x-isolation-actor-role"] = "member";
  }
  const r = await fetch(`http://${HOST}:${PORT}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await r.text();
  let body: any;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!r.ok) throw new Error(String(body?.error ?? `the server answered HTTP ${r.status}`));
  return body;
}

/** A view as an agent should see it: what it is, and the address to hand a person. */
function brief(v: { id: string; type: string; label?: string | null; target?: { url?: string; appPort?: number } }): Record<string, unknown> {
  const url = v.target?.url;
  // Only a WEB view's url is an address someone else can open: it lives on the sandbox plane and
  // its random hostname IS the access secret. Judged on the HOST, not a prefix match: a server the
  // cloud has served no preview domain to falls back to `<slug>.localhost` (views.ts webUrl), which
  // resolves on this machine and nowhere else — telling an agent to hand that to a colleague is
  // handing out a dead link.
  let host = "";
  try {
    host = typeof url === "string" ? new URL(url).hostname.toLowerCase() : "";
  } catch {
    host = "";
  }
  const local = !host || host === "localhost" || host.endsWith(".localhost") || host.startsWith("127.") || host === "::1" || host === "[::1]";
  const shareable = v.type === "web" && !local;
  return {
    id: v.id,
    type: v.type,
    label: v.label ?? null,
    shareable,
    ...(shareable ? { publicUrl: url } : {}),
    // A web view that is NOT shareable still has an address — it just only works on the machine
    // running this server. Say so rather than answering as if the window had no link at all.
    ...(!shareable && v.type === "web" && url ? { localUrl: url } : {}),
    ...(v.target?.appPort ? { appPort: v.target.appPort } : {}),
  };
}

async function runTool(view: View, call: ToolCall): Promise<unknown> {
  const s = sessionForSandbox(view.sandboxId);
  if (!s) throw new Error("this session is gone");
  const id = encodeURIComponent(s.id);
  const args = call.args ?? {};

  switch (call.tool) {
    case "views_list": {
      const views = await api(s.id, `/sessions/${id}/views`);
      return { views: (Array.isArray(views) ? views : []).map(brief) };
    }

    // "Show me the preview." A web view publishes what the sandbox serves on a port at a public
    // address whose random hostname is the access secret — so creating one IS sharing it, and the
    // answer says so in the same breath rather than leaving the agent to guess.
    case "view_create": {
      const type = str(args.type, 20) ?? "";
      if (!["web", "terminal", "code", "directory"].includes(type)) throw new Error("type must be web, terminal, code or directory");
      if (type === "web" && !str(args.url)) throw new Error("a web view needs a url — what you serve inside the sandbox, e.g. http://localhost:3000/");
      const created = await api(s.id, `/sessions/${id}/views`, {
        method: "POST",
        body: {
          type,
          ...(str(args.url) ? { url: str(args.url) } : {}),
          ...(str(args.dir, 200) ? { dir: str(args.dir, 200) } : {}),
          ...(str(args.command) ? { command: str(args.command) } : {}),
          ...(str(args.label, 80) ? { label: str(args.label, 80) } : {}),
        },
      });
      const b = brief(created);
      return {
        ...b,
        note: b.shareable
          ? "Anyone with that link can open it — the random part of the hostname is the only thing protecting it."
          : b.localUrl
            ? "This server has no public preview domain yet, so that address only opens on the machine running it. The window is on the session screen either way."
            : "This window opens on the session screen, which needs a signed-in browser.",
      };
    }

    case "view_link": {
      const want = str(args.viewId, 60);
      const views = await api(s.id, `/sessions/${id}/views`);
      const v = (Array.isArray(views) ? views : []).find((x: { id: string }) => x.id === want);
      if (!v) throw new Error(`this session has no view "${want ?? ""}"`);
      return brief(v);
    }

    case "view_delete": {
      const want = str(args.viewId, 60);
      if (!want) throw new Error("viewId is required");
      if (want === view.id) throw new Error("that is your own window — closing it would end this conversation");
      const views = await api(s.id, `/sessions/${id}/views`);
      if (!(Array.isArray(views) ? views : []).some((x: { id: string }) => x.id === want)) throw new Error(`this session has no view "${want}"`);
      await api(s.id, `/views/${encodeURIComponent(want)}`, { method: "DELETE" });
      return { closed: true };
    }

    // The command a person types to get into this sandbox from their own terminal.
    case "ssh_command": {
      const views = await api(s.id, `/sessions/${id}/views`);
      const term = (Array.isArray(views) ? views : []).find((v: { type: string }) => v.type === "terminal");
      if (!term) throw new Error("this session has no terminal to attach to — create one with view_create first");
      const conn = await api(s.id, `/sessions/${id}/views/${encodeURIComponent(term.id)}/connect`, { method: "POST", body: {} });
      if (!conn?.command) throw new Error("this server has no ssh route configured");
      return {
        command: conn.command,
        host: conn.host,
        ...(conn.bastion ? { throughBastion: true } : { port: conn.port }),
        note: "The person's ssh public key must be on the Isolation account that launched this session.",
      };
    }

    // The sandbox's own boot/lifecycle output — the first thing to read when something is wrong.
    case "session_logs": {
      const tail = Math.min(Math.max(typeof args.tail === "number" ? args.tail : 100, 1), 500);
      const out = await api(s.id, `/sessions/${id}/logs?tail=${tail}`);
      // The route always answers with its own last-500 window (it ignores the query), so the
      // `tail` the agent asked for is applied HERE — otherwise every call floods the turn with 500
      // lines whatever it requested.
      return out?.available ? { available: true, lines: (out.lines ?? []).slice(-tail).map((l: { line: string }) => l.line) } : { available: false, note: "the container is gone — there is nothing left to read" };
    }

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

    // Commit the session's file tree back into the workspace, so the work survives the session.
    case "session_save": {
      const out = await api(s.id, `/sessions/${id}/save`, { method: "POST", body: {} });
      return out?.skipped ? { saved: false, reason: out.reason ?? "there was nothing to save" } : { saved: true };
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

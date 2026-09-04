// The ACP connection (PLAN §5d): the official SDK's client side over a WebSocket the doorman
// proxies to the in-sandbox bridge. The bridge owns initialize + the session; this side
// receives `_iso/hello` (state + replay), then prompts/cancels/sets modes through the SDK.
import { ClientSideConnection, type Client, type RequestPermissionRequest, type RequestPermissionResponse, type SessionNotification, type Stream } from "@agentclientprotocol/sdk";
import { addPermission, applyNotification, answerPermission, hydrate, resetConversation, setConnected, setPhase, setSession, setTurn, store, type Hello, type Phase } from "./store.js";

export interface Connection {
  prompt(text: string): Promise<{ stopReason: string }>;
  cancel(): Promise<void>;
  setMode(modeId: string): Promise<void>;
  setConfig(configId: string, value: string | boolean): Promise<void>;
  restart(): Promise<void>;
  close(): void;
}

let conn: ClientSideConnection | undefined;
let ws: WebSocket | undefined;
let closedByUs = false;
let backoff = 500;
let permSeq = 0;

function wsUrl(): string {
  const u = new URL("ws", location.href);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  u.search = "";
  return u.href;
}

function makeStream(sock: WebSocket): Stream {
  const writable = new WritableStream({
    write: (msg) => {
      if (sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify(msg));
    },
  });
  const readable = new ReadableStream({
    start: (controller) => {
      sock.onmessage = (e) => {
        try {
          controller.enqueue(JSON.parse(String(e.data)));
        } catch {
          /* ignore junk */
        }
      };
      sock.onclose = () => {
        try {
          controller.close();
        } catch {
          /* already closed */
        }
        onClosed();
      };
      sock.onerror = () => {
        /* onclose follows */
      };
    },
  });
  return { writable, readable } as Stream;
}

const client: Client = {
  sessionUpdate(n: SessionNotification) {
    applyNotification(n);
  },
  requestPermission(p: RequestPermissionRequest): Promise<RequestPermissionResponse> {
    const id = `p${++permSeq}`;
    return new Promise((resolve) => addPermission(p, resolve, id));
  },
  async extNotification(method: string, params: Record<string, unknown>) {
    switch (method) {
      case "_iso/hello":
        hydrate(params as unknown as Hello);
        return;
      case "_iso/status": {
        const p = params as { phase: Phase; error?: string };
        setPhase(p.phase, p.error);
        return;
      }
      case "_iso/session": {
        const p = params as { sessionId: string; session: Hello["session"] };
        setSession(p.sessionId, p.session);
        return;
      }
      case "_iso/turn":
        setTurn(params as { active: boolean; from?: string });
        return;
      case "_iso/reset":
        resetConversation();
        return;
      case "_iso/permission_done": {
        // Another window answered: drop our copy of the prompt (the bridge ignores late answers).
        const tool = lastToolCallOf(String((params as { id?: unknown }).id ?? ""));
        for (const p of store.getState().permissions) if (tool && p.request.toolCall.toolCallId === tool) answerPermission(p.id);
        return;
      }
      default:
        return;
    }
  },
};

// Permission requests arrive with the bridge's own ids (`a:<n>`); the SDK hides the id from
// the handler, so a "done" for id X is matched by tool call instead — good enough: a tool
// call has one open permission at a time.
const permissionIds = new Map<string, string>();
function lastToolCallOf(bridgeId: string): string | undefined {
  return permissionIds.get(bridgeId);
}

function onClosed(): void {
  setConnected(false);
  conn = undefined;
  ws = undefined;
  if (closedByUs) return;
  setTimeout(open, backoff);
  backoff = Math.min(backoff * 2, 10_000);
}

function open(): void {
  if (ws) return;
  const sock = new WebSocket(wsUrl());
  ws = sock;
  // Peek at raw frames for the permission id ↔ tool call mapping (see above) before the SDK
  // consumes them.
  const stream = makeStream(sock);
  const peeked = stream.readable.pipeThrough(
    new TransformStream({
      transform(msg, controller) {
        const m = msg as { id?: unknown; method?: string; params?: { toolCall?: { toolCallId?: string } } };
        if (m.method === "session/request_permission" && typeof m.id === "string" && m.params?.toolCall?.toolCallId) permissionIds.set(m.id, m.params.toolCall.toolCallId);
        controller.enqueue(msg);
      },
    }),
  );
  sock.onopen = () => {
    backoff = 500;
    setConnected(true);
  };
  conn = new ClientSideConnection(() => client, { writable: stream.writable, readable: peeked } as Stream);
}

const need = (): ClientSideConnection => {
  if (!conn) throw new Error("not connected");
  return conn;
};
const sid = (): string => {
  const s = store.getState().sessionId;
  if (!s) throw new Error("the agent is still starting");
  return s;
};

export function connect(): Connection {
  closedByUs = false;
  open();
  return {
    async prompt(text) {
      const r = await need().prompt({ sessionId: sid(), prompt: [{ type: "text", text }] });
      return { stopReason: r.stopReason };
    },
    async cancel() {
      await need().cancel({ sessionId: sid() });
    },
    async setMode(modeId) {
      await need().setSessionMode({ sessionId: sid(), modeId });
    },
    async setConfig(configId, value) {
      await need().setSessionConfigOption({ sessionId: sid(), configId, value } as never);
    },
    async restart() {
      await need().extMethod("_iso/restart", {});
    },
    close() {
      closedByUs = true;
      ws?.close();
    },
  };
}

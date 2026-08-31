// The agent view (PLAN V2) — a doorman-served chat window onto ONE agent, the same
// first-party pattern as the code view: the page + assets ship in dist/agent, and the
// API bridges to the agent supervisor. An agent has ONE conversation; every view of it
// (and the same view in N tabs) is a window onto that conversation — the page polls,
// so windows converge. Auth (view token / cookie) happened in the doorman.
import { readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";
import { agentJson, getAgent, listAgents, sendMessage, startAgent, stopAgent } from "./agents.js";
import { sessionForSandbox } from "./sessions.js";
import type { View } from "./views.js";

const AGENT_DIR = join(dirname(fileURLToPath(import.meta.url)), "agent");

const ASSET_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

// The view stores the roster DEFINITION id; the live record is resolved per request
// and SCOPED TO THE VIEW'S SESSION — def ids repeat across sessions of the same
// workspace, and a view must never read another session's conversation.
function resolveAgent(view: View): ReturnType<typeof getAgent> {
  const session = sessionForSandbox(view.sandboxId);
  if (!session || !view.agentId) return undefined;
  const rec = listAgents(session.id).find((a) => a.def.id === view.agentId || a.runtimeId === view.agentId);
  return rec;
}

export async function handleAgentView(req: IncomingMessage, res: ServerResponse, view: View, rest: string): Promise<void> {
  const method = req.method ?? "GET";

  if (rest.startsWith("/api/")) {
    const rec = resolveAgent(view);
    if (!rec) return json(res, 404, { error: "agent not running in this session (session restarted?)" });
    try {
      if (rest === "/api/agent" && method === "GET") {
        return json(res, 200, agentJson(rec));
      }
      if (rest === "/api/messages" && method === "GET") {
        // Full conversation + status; the page renders the tail it hasn't seen.
        return json(res, 200, { status: rec.status, messages: rec.conversation });
      }
      if (rest === "/api/messages" && method === "POST") {
        const chunks: Buffer[] = [];
        for await (const c of req) {
          chunks.push(c as Buffer);
          if (chunks.reduce((n, b) => n + b.length, 0) > 256 * 1024) return json(res, 413, { error: "message too large" });
        }
        let text = "";
        try {
          text = String((JSON.parse(Buffer.concat(chunks).toString("utf8")) as { text?: unknown }).text ?? "");
        } catch {
          return json(res, 400, { error: "bad json" });
        }
        if (!text.trim()) return json(res, 400, { error: "text required" });
        const out = await sendMessage(rec.runtimeId, text, "view");
        return "error" in out ? json(res, 502, out) : json(res, 200, out);
      }
      if (rest === "/api/start" && method === "POST") return json(res, 200, { ok: startAgent(rec.runtimeId) });
      if (rest === "/api/stop" && method === "POST") return json(res, 200, { ok: stopAgent(rec.runtimeId) });
      return json(res, 404, { error: "unknown api route" });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  // Static chat app: flat directory, extension-typed, no traversal.
  const name = rest === "/" || rest === "" ? "index.html" : rest.slice(1);
  const type = ASSET_TYPES[name.slice(name.lastIndexOf("."))];
  if (method !== "GET" || !type || name.includes("/") || name.includes("..")) {
    return json(res, 404, { error: "not found" });
  }
  try {
    const file = join(AGENT_DIR, name);
    const size = statSync(file).size;
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Length": size,
      "Cache-Control": name === "index.html" ? "no-cache" : "public, max-age=3600",
    });
    res.end(readFileSync(file));
  } catch {
    json(res, 404, { error: "not found" });
  }
}

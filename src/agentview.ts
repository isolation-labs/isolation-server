// The agent view (PLAN §5d) — the doorman-served ACP client page onto ONE thread of ONE agent.
// The page + assets ship in dist/agent; the conversation itself rides a WebSocket the doorman
// proxies to the in-sandbox bridge (acpview.ts). The only API here is the view's own
// description — who the agent is — for the page header. Auth (view token / cookie) happened in
// the doorman.
import { readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";
import { agentForView, agentJson } from "./agents.js";
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
// (agentForView scopes by the view's SANDBOX: def ids repeat across sessions of the same
// workspace, and a view must never read another session's agent.)

export async function handleAgentView(req: IncomingMessage, res: ServerResponse, view: View, rest: string): Promise<void> {
  const method = req.method ?? "GET";

  if (rest.startsWith("/api/")) {
    const rec = agentForView(view);
    if (!rec) return json(res, 404, { error: "agent not running in this session (session restarted?)" });
    if (rest === "/api/agent" && method === "GET") return json(res, 200, { ...agentJson(rec), viewId: view.id, threadKey: view.specKey ?? view.id, label: view.label ?? null });
    return json(res, 404, { error: "unknown api route" });
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

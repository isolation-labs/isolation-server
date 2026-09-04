// iso-mcp — the `isolation` MCP server every agent gets (PLAN §5d, AV3). Stdio, dependency-free,
// registered with the harness through ACP's `session/new … mcpServers`. It teaches the agent
// its environment as TOOLS rather than prose: who it is, which session and workspace it is in,
// the views (windows) of the session, its own memory note, and a way to hand a message to
// another agent's thread (the bridge's POST /prompt). Env, all set by isolation-server:
//   ISO_AGENT_ID ISO_AGENT_NAME ISO_HARNESS ISO_SESSION_ID ISO_WORKSPACE_ID ISO_VIEW_ID
//   ISO_MEMORY_PATH ISO_VIEWS_FILE
import fs from "node:fs";
import path from "node:path";
import http from "node:http";

const env = process.env;
const MEMORY_PATH = env.ISO_MEMORY_PATH || "/workspace/.isolation/agents/unknown/memory.md";
const VIEWS_FILE = env.ISO_VIEWS_FILE || "/tmp/.iso-views.json";
const MAX_MEMORY = 32 * 1024;

const readViews = () => {
  try {
    const v = JSON.parse(fs.readFileSync(VIEWS_FILE, "utf8"));
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
};

const TOOLS = [
  {
    name: "session_info",
    description: "Who you are and where you are running: your agent identity, the Isolation session and workspace ids, the working directory, and the harness you run on.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "views",
    description: "The views (windows) of this session: terminals, code editors, file browsers, web apps and agent chats. Agent views name the agent they belong to.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "memory_read",
    description: "Read your own memory note for this workspace — a short markdown file you keep across sessions (facts about the project, decisions, what you were doing).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "memory_write",
    description: "Replace your memory note for this workspace (markdown, keep it short — it is read at the start of every conversation). Use `append` to add instead of replacing.",
    inputSchema: { type: "object", properties: { content: { type: "string" }, append: { type: "boolean" } }, required: ["content"], additionalProperties: false },
  },
  {
    name: "thread_send",
    description: "Send a message to another agent's thread in this session and wait for its reply. Address it by agent name or agent view id (see `views`). Use this to delegate or ask; coordinate through the shared files otherwise.",
    inputSchema: { type: "object", properties: { to: { type: "string", description: "agent name or view id" }, text: { type: "string" } }, required: ["to", "text"], additionalProperties: false },
  },
];

const text = (t) => ({ content: [{ type: "text", text: t }] });
const fail = (t) => ({ content: [{ type: "text", text: t }], isError: true });

async function callTool(name, args) {
  switch (name) {
    case "session_info":
      return text(
        JSON.stringify(
          {
            agent: { id: env.ISO_AGENT_ID, name: env.ISO_AGENT_NAME, harness: env.ISO_HARNESS, viewId: env.ISO_VIEW_ID },
            session: { id: env.ISO_SESSION_ID, workspaceId: env.ISO_WORKSPACE_ID, cwd: "/workspace" },
            notes: [
              "You are one of several independent agents on this workspace; each conversation is separate.",
              "Coordinate through the shared files under /workspace (git) or thread_send — never assume another agent sees your chat.",
              "Your memory note persists across sessions; keep it short and current.",
            ],
          },
          null,
          2,
        ),
      );
    case "views":
      return text(JSON.stringify(readViews(), null, 2));
    case "memory_read": {
      try {
        return text(fs.readFileSync(MEMORY_PATH, "utf8").slice(0, MAX_MEMORY) || "(empty)");
      } catch {
        return text("(no memory yet)");
      }
    }
    case "memory_write": {
      const content = typeof args?.content === "string" ? args.content : "";
      fs.mkdirSync(path.dirname(MEMORY_PATH), { recursive: true });
      let next = content;
      if (args?.append) {
        let cur = "";
        try {
          cur = fs.readFileSync(MEMORY_PATH, "utf8");
        } catch {
          cur = "";
        }
        next = cur ? `${cur.replace(/\s+$/, "")}\n\n${content}` : content;
      }
      if (next.length > MAX_MEMORY) return fail(`memory note too long (${next.length} > ${MAX_MEMORY} chars) — condense it`);
      fs.writeFileSync(MEMORY_PATH, next, { mode: 0o600 });
      return text(`memory saved (${next.length} chars)`);
    }
    case "thread_send": {
      const to = String(args?.to ?? "").trim();
      const body = String(args?.text ?? "");
      if (!to || !body.trim()) return fail("to and text are required");
      const views = readViews().filter((v) => v.type === "agent" && v.port);
      const target = views.find((v) => v.id === to) ?? views.find((v) => (v.agentName ?? "").toLowerCase() === to.toLowerCase()) ?? views.find((v) => v.agentId === to);
      if (!target) return fail(`no agent thread "${to}" in this session (see views)`);
      if (target.id === env.ISO_VIEW_ID) return fail("that is your own thread");
      return await new Promise((resolve) => {
        const req = http.request({ host: "127.0.0.1", port: target.port, path: "/prompt", method: "POST", headers: { "Content-Type": "application/json" }, timeout: 20 * 60_000 }, (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const raw = Buffer.concat(chunks).toString("utf8");
            try {
              const j = JSON.parse(raw);
              resolve(res.statusCode === 200 ? text(j.text || "(no reply text)") : fail(j.error || `HTTP ${res.statusCode}`));
            } catch {
              resolve(fail(`bad reply from ${to}: ${raw.slice(0, 200)}`));
            }
          });
        });
        req.on("error", (e) => resolve(fail(`could not reach ${to}: ${e.message}`)));
        req.on("timeout", () => {
          req.destroy();
          resolve(fail(`${to} did not reply in time`));
        });
        req.end(JSON.stringify({ text: body, from: `agent:${env.ISO_AGENT_NAME ?? env.ISO_AGENT_ID ?? "?"}` }));
      });
    }
    default:
      return fail(`unknown tool ${name}`);
  }
}

// --- MCP over stdio (JSON-RPC, newline-delimited) ---------------------------------

const send = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);
let acc = "";
process.stdin.on("data", (d) => {
  acc += String(d);
  let i;
  while ((i = acc.indexOf("\n")) >= 0) {
    const line = acc.slice(0, i).trim();
    acc = acc.slice(i + 1);
    if (line) void onLine(line);
  }
});
process.stdin.on("end", () => process.exit(0));

async function onLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  const { id, method, params } = msg;
  const result = async (r) => send({ jsonrpc: "2.0", id, result: r });
  try {
    switch (method) {
      case "initialize":
        return result({ protocolVersion: params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "isolation", version: "1" } });
      case "notifications/initialized":
      case "notifications/cancelled":
        return;
      case "ping":
        return result({});
      case "tools/list":
        return result({ tools: TOOLS });
      case "tools/call":
        return result(await callTool(params?.name, params?.arguments ?? {}));
      case "prompts/list":
        return result({ prompts: [] });
      case "resources/list":
        return result({ resources: [] });
      default:
        if (id !== undefined) send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
    }
  } catch (e) {
    if (id !== undefined) send({ jsonrpc: "2.0", id, error: { code: -32000, message: String(e?.message ?? e) } });
  }
}

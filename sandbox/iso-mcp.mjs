// iso-mcp — the `isolation` MCP server every agent gets (PLAN §5d, AV3). Stdio, dependency-free,
// registered with the harness through ACP's `session/new … mcpServers`. It teaches the agent
// its environment as TOOLS rather than prose: who it is, which session and workspace it is in,
// the views (windows) of the session, its own memory note, and a way to hand a message to
// another agent's thread (the bridge's POST /prompt). Env, all set by isolation-server:
//   ISO_AGENT_ID ISO_AGENT_NAME ISO_HARNESS ISO_SESSION_ID ISO_WORKSPACE_ID ISO_VIEW_ID
//   ISO_MEMORY_PATH ISO_VIEWS_FILE ISO_BRIDGE_PORT
//
// Tools split in two by WHERE the answer lives. The first group is inside the sandbox (files, other
// agents' bridges on loopback). The second group — the session's windows, its public preview links,
// its ssh command, its logs — is known only to isolation-server, which the sandbox cannot dial. Those
// are parked on the bridge and answered by the server, which long-polls for them (PLAN §1 I3): the
// agent gets a plain tool call, and no credential or route out of the sandbox is created for it.
import fs from "node:fs";
import path from "node:path";
import http from "node:http";

const env = process.env;
const MEMORY_PATH = env.ISO_MEMORY_PATH || "/workspace/.isolation/agents/unknown/memory.md";
const BRIDGE_PORT = Number(env.ISO_BRIDGE_PORT || 0);
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
  // ── The session, from outside the sandbox (answered by isolation-server) ──────────────────────
  {
    name: "views_list",
    description: "The session's windows and their links: which are terminals, editors, file browsers or web previews, and which of them have a public address you can share.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "view_create",
    description:
      "Open a window on this session. A 'web' view with a url like http://localhost:3000 publishes what you are serving on that port at a PUBLIC address — this is how you show someone the preview of what you built. 'terminal' opens a shell (optionally running a command), 'code' an editor, 'directory' a file browser.",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", enum: ["web", "terminal", "code", "directory"] },
        url: { type: "string", description: "web only: what you serve inside the sandbox, e.g. http://localhost:3000/" },
        dir: { type: "string", description: "a directory under /workspace to start in" },
        command: { type: "string", description: "terminal only: a command to run in it" },
        label: { type: "string", description: "a name for the window" },
      },
      required: ["type"],
      additionalProperties: false,
    },
  },
  {
    name: "view_link",
    description: "The address of one window. A web view's link is public — anyone who has it can open it. Everything else opens only in a signed-in browser.",
    inputSchema: { type: "object", properties: { viewId: { type: "string" } }, required: ["viewId"], additionalProperties: false },
  },
  {
    name: "view_delete",
    description: "Close a window. The session keeps running; a web view's public address stops working.",
    inputSchema: { type: "object", properties: { viewId: { type: "string" } }, required: ["viewId"], additionalProperties: false },
  },
  {
    name: "ssh_command",
    description: "The command someone types to get into this sandbox from their own terminal. It only works for a person whose ssh public key is on the account that launched this session.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "session_logs",
    description: "This sandbox's own boot and lifecycle output — how it started, what the clone did, why something failed.",
    inputSchema: { type: "object", properties: { tail: { type: "number", description: "how many lines (default 100, max 500)" } }, additionalProperties: false },
  },
  {
    name: "session_save",
    description: "Commit and merge this session's files back into the workspace, so the work survives the session ending.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

// Tools whose answer lives on the host: forwarded verbatim over the control channel.
const SERVER_TOOLS = new Set(["views_list", "view_create", "view_link", "view_delete", "ssh_command", "session_logs", "session_save"]);

// One outward tool call: park it on the bridge, wait for the server's answer. The bridge fails it
// fast when no server is polling, so an agent is never left hanging on a session nobody is watching.
function viaServer(tool, args = {}) {
  return new Promise((resolve) => {
    if (!BRIDGE_PORT) return resolve(fail("this session's control channel is not available"));
    const payload = JSON.stringify({ tool, args });
    const req = http.request(
      { host: "127.0.0.1", port: BRIDGE_PORT, path: "/iso-tool", method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }, timeout: 90_000 },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let j;
          try {
            j = JSON.parse(raw);
          } catch {
            return resolve(fail(`${tool}: unreadable answer`));
          }
          if (j.error) return resolve(fail(j.error));
          resolve(text(JSON.stringify(j.result ?? {}, null, 2)));
        });
      },
    );
    req.on("error", (e) => resolve(fail(`${tool}: ${e.message}`)));
    req.on("timeout", () => {
      req.destroy();
      resolve(fail(`${tool}: the Isolation server did not answer in time`));
    });
    req.end(payload);
  });
}

const text = (t) => ({ content: [{ type: "text", text: t }] });
const fail = (t) => ({ content: [{ type: "text", text: t }], isError: true });

async function callTool(name, args) {
  if (SERVER_TOOLS.has(name)) return viaServer(name, args ?? {});
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

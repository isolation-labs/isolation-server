// iso-acp-bridge — the in-sandbox session holder behind an agent view (PLAN §5d).
//
// One bridge per thread. It owns ONE ACP agent process (claude-agent-acp / codex-acp /
// goose acp), runs `initialize` + `session/new|load` itself (both are once-per-process),
// keeps a replay buffer of every `session/update`, and fans the session out to N
// WebSocket clients (the doorman-served page, one JSON-RPC message per text frame). The
// server is one more client over plain HTTP (`POST /prompt`) for connector turns.
//
// Dependency-free by design: it is written into the sandbox by isolation-server and runs on
// the bundled Node (`iso-node`), so the WebSocket server is a small RFC 6455 implementation
// (text frames, fragmentation, ping/pong, close) rather than a package.
//
//   iso-node iso-acp-bridge.mjs <port> <config.json>
//
// config: { viewId, threadKey, agent:{id,name,harness,model}, command, args, env, unsetEnv?,
//           cwd, home, sessionId?, statePath, mcpServers, initialModeId?, idleMinutes? }
import http from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [portArg, cfgPath] = process.argv.slice(2);
const PORT = Number(portArg);
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
// stderr goes wherever execd's background mode sends it (nowhere useful) — keep a file too.
const LOG_PATH = `/tmp/.iso-acp-${cfg.viewId}.log`;
const log = (...a) => {
  const line = `${new Date().toISOString()} ${a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ")}`;
  console.error(`[iso-acp-bridge ${cfg.viewId}]`, ...a);
  try {
    fs.appendFileSync(LOG_PATH, `${line}\n`);
    const st = fs.statSync(LOG_PATH);
    if (st.size > 2 * 1024 * 1024) fs.truncateSync(LOG_PATH, 0);
  } catch {
    /* logging is best-effort */
  }
};
const IDLE_MS = Math.max(1, Number(cfg.idleMinutes ?? 15)) * 60_000;
const MAX_BUFFER_ITEMS = 5000;
const MAX_BUFFER_BYTES = 6 * 1024 * 1024;
const TURN_TIMEOUT_MS = 60 * 60_000;

// --- agent process (ACP client side) -------------------------------------------

let child;
let alive = false;
let ready; // Promise<void> while a start is in flight / once started
let initResult; // the agent's initialize response
let sessionResult = null; // { modes, configOptions }
let sessionId = typeof cfg.sessionId === "string" && cfg.sessionId ? cfg.sessionId : undefined;
let nextId = 1;
const pending = new Map(); // agent-side request id → { resolve, reject }
const agentRequests = new Map(); // agent → client request id → { answered }
let lastActivity = Date.now();
let phase = "idle"; // idle | starting | ready | stopped | error
let lastError = "";

const buffer = []; // replayed to late joiners: raw session/update notifications
let bufferBytes = 0;
let bufferTruncated = false;
function resetBuffer() {
  buffer.length = 0;
  bufferBytes = 0;
  bufferTruncated = false;
}
function bufferPush(msg) {
  const size = JSON.stringify(msg).length;
  buffer.push(msg);
  bufferBytes += size;
  while (buffer.length > MAX_BUFFER_ITEMS || bufferBytes > MAX_BUFFER_BYTES) {
    bufferBytes -= JSON.stringify(buffer.shift()).length;
    bufferTruncated = true;
  }
}

const notif = (method, params) => ({ jsonrpc: "2.0", method, params });

function sendToAgent(msg) {
  if (!alive || !child?.stdin?.writable) throw new Error("agent is not running");
  child.stdin.write(`${JSON.stringify(msg)}\n`);
}
function request(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    try {
      sendToAgent({ jsonrpc: "2.0", id, method, params });
    } catch (e) {
      pending.delete(id);
      reject(e);
    }
  });
}

function setPhase(p, extra = {}) {
  phase = p;
  broadcast(notif("_iso/status", { phase, error: lastError || undefined, ...extra }));
}

function ensureAgent() {
  if (alive && ready) return ready;
  ready = start().catch((e) => {
    lastError = String(e?.message ?? e).slice(0, 500);
    log("start failed:", lastError);
    setPhase("error");
    ready = undefined;
    throw e;
  });
  return ready;
}

async function start() {
  lastError = "";
  setPhase("starting");
  // The container's env carries the SESSION's credential. `unsetEnv` names the vars this
  // agent's own credential replaces but does not set — dropped from the INHERITED env before
  // the harness's own values land, so a leftover can never out-rank or redirect them.
  const env = { ...process.env };
  for (const k of Array.isArray(cfg.unsetEnv) ? cfg.unsetEnv : []) delete env[k];
  Object.assign(env, cfg.env ?? {}, { HOME: cfg.home });
  log(`spawning ${cfg.command} ${(cfg.args ?? []).join(" ")} (home ${cfg.home})`);
  child = spawn(cfg.command, cfg.args ?? [], { cwd: cfg.cwd ?? "/workspace", env, stdio: ["pipe", "pipe", "pipe"] });
  alive = true;
  const me = child;
  child.stderr.on("data", (d) => {
    const t = String(d).trim();
    if (t) log("agent:", t.slice(0, 600));
  });
  let acc = "";
  child.stdout.on("data", (d) => {
    acc += String(d);
    let i;
    while ((i = acc.indexOf("\n")) >= 0) {
      const line = acc.slice(0, i);
      acc = acc.slice(i + 1);
      if (line.trim()) onAgentLine(line);
    }
  });
  // Everything that has to happen when the adapter is gone, whatever killed it — every
  // pending request rejected above all, or the `initialize` that gates the whole start
  // would never settle and every window would sit at "starting" forever.
  const gone = (code, signal) => {
    if (child !== me || !alive) return;
    alive = false;
    ready = undefined;
    const why = lastError || `agent exited (${signal ?? code})`;
    for (const p of pending.values()) p.reject(new Error(why));
    pending.clear();
    agentRequests.clear();
    if (turn) finishTurn(new Error(why));
    if (phase !== "error") {
      lastError = code && code !== 0 ? `agent exited with code ${code}` : lastError;
      setPhase("stopped", { code, signal });
    }
    log(`agent exited (code ${code}, signal ${signal})`);
  };
  child.on("error", (e) => {
    lastError = `spawn failed: ${e.message}`;
    // A spawn failure (the adapter is not installed in this image) emits 'error' and 'close'
    // but NEVER 'exit' — without this the handshake below would hang for good. `pid` is
    // undefined exactly when the process never came up, so a later error can't fake a death.
    if (me.pid === undefined) gone(null, null);
  });
  child.on("exit", gone);

  // A started-but-mute adapter would wedge the same way, so the handshake is bounded; the
  // kill runs the teardown above, which is what fails the start with a message the page shows.
  let handshook = false;
  const initTimer = setTimeout(() => {
    if (handshook || child !== me || !alive) return;
    lastError = "the agent did not answer `initialize` within 60s";
    log(lastError);
    try {
      me.kill();
    } catch {
      /* already gone */
    }
  }, 60_000);
  try {
    initResult = await request("initialize", {
      protocolVersion: 1,
      clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
      clientInfo: { name: "isolation", title: "Isolation", version: "1" },
    });
  } finally {
    handshook = true;
    clearTimeout(initTimer);
  }
  const mcpServers = Array.isArray(cfg.mcpServers) ? cfg.mcpServers : [];
  const fresh = async () => {
    const r = await request("session/new", { cwd: cfg.cwd ?? "/workspace", mcpServers });
    sessionId = r.sessionId;
    sessionResult = { modes: r.modes ?? null, configOptions: r.configOptions ?? null };
  };
  if (sessionId && initResult?.agentCapabilities?.loadSession) {
    // The agent replays the whole conversation as session/update notifications during the
    // load — those refill the buffer; every attached page is told to start over first.
    resetBuffer();
    broadcast(notif("_iso/reset", {}));
    try {
      const r = await request("session/load", { sessionId, cwd: cfg.cwd ?? "/workspace", mcpServers });
      sessionResult = { modes: r.modes ?? null, configOptions: r.configOptions ?? null };
    } catch (e) {
      log(`session/load of ${sessionId} failed (${e?.message ?? e}) — starting a new session`);
      resetBuffer();
      broadcast(notif("_iso/reset", {}));
      await fresh();
    }
  } else {
    await fresh();
  }
  persistState();
  // The launch's initial mode (e.g. bypass permissions — the sandbox is the boundary), only
  // when the agent offers it; users switch modes from the page afterwards.
  const wanted = typeof cfg.initialModeId === "string" ? cfg.initialModeId : "";
  const modes = sessionResult?.modes;
  if (wanted && modes && modes.currentModeId !== wanted && (modes.availableModes ?? []).some((m) => m.id === wanted)) {
    try {
      await request("session/set_mode", { sessionId, modeId: wanted });
      modes.currentModeId = wanted;
    } catch (e) {
      log(`initial mode ${wanted} refused: ${e?.message ?? e}`);
    }
  }
  lastActivity = Date.now();
  broadcast(notif("_iso/session", { sessionId, session: sessionResult }));
  setPhase("ready");
}

// The thread file (isolation-server threads.ts shape): the harness's own session id is what
// survives a bridge restart, a server restart, or a resume — nothing else about the chat is ours.
function persistState() {
  if (!cfg.statePath) return;
  let cur = {};
  try {
    cur = JSON.parse(fs.readFileSync(cfg.statePath, "utf8"));
  } catch {
    cur = {};
  }
  const now = Date.now();
  const next = { key: cfg.threadKey, agentId: cfg.agent?.id, messages: [], ...cur, harnessSession: sessionId, harness: cfg.agent?.harness, createdAt: cur.createdAt ?? now, updatedAt: now };
  try {
    fs.mkdirSync(path.dirname(cfg.statePath), { recursive: true });
    fs.writeFileSync(cfg.statePath, JSON.stringify(next), { mode: 0o600 });
  } catch (e) {
    log(`state write failed: ${e.message}`);
  }
}

function onAgentLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    log("agent stdout (non-JSON):", line.slice(0, 200));
    return;
  }
  if (Array.isArray(msg)) {
    for (const m of msg) onAgentMessage(m);
    return;
  }
  onAgentMessage(msg);
}

function onAgentMessage(msg) {
  if (msg.id !== undefined && msg.method === undefined) {
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.error) {
      const err = new Error(msg.error.message ?? "agent error");
      err.code = msg.error.code;
      err.data = msg.error.data;
      p.reject(err);
    } else p.resolve(msg.result ?? {});
    return;
  }
  if (msg.id === undefined) {
    // Notification from the agent.
    if (msg.method === "session/update") {
      lastActivity = Date.now();
      const u = msg.params?.update;
      if (turn && u?.sessionUpdate === "agent_message_chunk" && u.content?.type === "text") turn.collected.push(u.content.text);
      bufferPush(msg);
    }
    broadcast(msg);
    return;
  }
  // Request from the agent to its client (permission, fs, terminal).
  if (msg.method === "session/request_permission") {
    const options = Array.isArray(msg.params?.options) ? msg.params.options : [];
    if (clients.size === 0) {
      // Nobody to ask (a connector turn with no page open): the sandbox is the boundary.
      const pick = options.find((o) => o.kind === "allow_once") ?? options.find((o) => o.kind === "allow_always") ?? options[0];
      log(`auto-answering permission "${msg.params?.toolCall?.title ?? ""}" → ${pick?.optionId ?? "cancelled"}`);
      sendToAgent({ jsonrpc: "2.0", id: msg.id, result: pick ? { outcome: { outcome: "selected", optionId: pick.optionId } } : { outcome: { outcome: "cancelled" } } });
      return;
    }
    agentRequests.set(msg.id, { answered: false });
    broadcast({ ...msg, id: `a:${msg.id}` });
    return;
  }
  sendToAgent({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `client method not supported: ${msg.method}` } });
}

// --- turns ---------------------------------------------------------------------

let turn = null; // { ownerId, from, startedAt, collected: string[], done(result|error) }

function turnInfo() {
  return turn ? { active: true, from: turn.from, startedAt: turn.startedAt } : { active: false };
}

async function runTurn(ownerId, from, params, onDone) {
  await ensureAgent();
  if (turn) throw Object.assign(new Error("A turn is already in progress"), { code: -32000 });
  const startedAt = Date.now();
  turn = { ownerId, from, startedAt, collected: [], done: onDone };
  lastActivity = startedAt;
  // Every window (the sender included) renders the prompt from the bridge's echo — one
  // source of truth; the agent itself never echoes a live prompt.
  for (const block of Array.isArray(params.prompt) ? params.prompt : []) {
    const n = notif("session/update", { sessionId, update: { sessionUpdate: "user_message_chunk", content: block }, _meta: { iso: { from, ts: startedAt } } });
    bufferPush(n);
    broadcast(n);
  }
  broadcast(notif("_iso/turn", turnInfo()));
  const timer = setTimeout(() => {
    try {
      sendToAgent(notif("session/cancel", { sessionId }));
    } catch {
      /* gone */
    }
  }, TURN_TIMEOUT_MS);
  try {
    const result = await request("session/prompt", { ...params, sessionId });
    clearTimeout(timer);
    finishTurn(undefined, result);
  } catch (e) {
    clearTimeout(timer);
    finishTurn(e);
  }
}

function finishTurn(err, result) {
  const t = turn;
  if (!t) return;
  turn = null;
  lastActivity = Date.now();
  for (const id of agentRequests.keys()) agentRequests.delete(id);
  broadcast(notif("_iso/turn", { active: false }));
  try {
    t.done(err, result, t.collected.join(""));
  } catch (e) {
    log(`turn callback failed: ${e.message}`);
  }
}

// --- clients (WebSocket) ---------------------------------------------------------

const clients = new Map(); // id → { id, sock, send }

function broadcast(msg, except) {
  const text = JSON.stringify(msg);
  for (const c of clients.values()) if (c.id !== except) c.sendText(text);
}

function reply(c, id, result) {
  c.send({ jsonrpc: "2.0", id, result });
}
function replyError(c, id, e) {
  c.send({ jsonrpc: "2.0", id, error: { code: typeof e?.code === "number" ? e.code : -32000, message: String(e?.message ?? e).slice(0, 1000), ...(e?.data !== undefined ? { data: e.data } : {}) } });
}

function hello(c) {
  c.send(
    notif("_iso/hello", {
      viewId: cfg.viewId,
      agent: cfg.agent ?? null,
      sessionId: sessionId ?? null,
      session: sessionResult,
      initialize: initResult ?? null,
      phase,
      error: lastError || undefined,
      turn: turnInfo(),
      truncated: bufferTruncated,
      updates: buffer,
    }),
  );
}

function attach(sock) {
  const id = randomUUID();
  const c = {
    id,
    sock,
    sendText: (text) => wsSend(sock, text),
    send: (msg) => wsSend(sock, JSON.stringify(msg)),
  };
  clients.set(id, c);
  lastActivity = Date.now();
  hello(c);
  ensureAgent().catch(() => undefined);
  sock.on("close", () => {
    clients.delete(id);
    lastActivity = Date.now();
  });
  sock.on("error", () => sock.destroy());
  return c;
}

async function onClientMessage(c, msg) {
  if (Array.isArray(msg)) {
    for (const m of msg) await onClientMessage(c, m);
    return;
  }
  if (!msg || typeof msg !== "object") return;
  // A response to an agent→client request we fanned out (permission): first answer wins.
  if (msg.method === undefined && msg.id !== undefined) {
    if (typeof msg.id === "string" && msg.id.startsWith("a:")) {
      const agentId = Number(msg.id.slice(2));
      const r = agentRequests.get(agentId);
      if (!r || r.answered) return;
      r.answered = true;
      agentRequests.delete(agentId);
      try {
        sendToAgent({ jsonrpc: "2.0", id: agentId, ...(msg.error ? { error: msg.error } : { result: msg.result ?? {} }) });
      } catch {
        /* agent gone; the turn will fail on its own */
      }
      broadcast(notif("_iso/permission_done", { id: msg.id, by: c.id }));
    }
    return;
  }
  const id = msg.id;
  const isRequest = id !== undefined;
  try {
    switch (msg.method) {
      case "initialize": {
        if (!initResult) await ensureAgent();
        return reply(c, id, initResult);
      }
      case "session/new":
      case "session/load": {
        await ensureAgent();
        return reply(c, id, { sessionId, ...(sessionResult ?? {}) });
      }
      case "session/prompt": {
        await runTurn(c.id, "view", msg.params ?? {}, (err, result) => {
          if (!clients.has(c.id)) return; // the window went away mid-turn; the turn still ran
          if (err) replyError(c, id, err);
          else reply(c, id, result);
        });
        return;
      }
      case "session/cancel": {
        if (alive) sendToAgent(notif("session/cancel", { sessionId }));
        return;
      }
      case "_iso/restart": {
        // The page asked for a fresh adapter process (after an error/stop): same session.
        if (alive) child.kill();
        setTimeout(() => ensureAgent().catch(() => undefined), 300);
        return isRequest ? reply(c, id, { ok: true }) : undefined;
      }
      default: {
        if (typeof msg.method !== "string") return;
        if (msg.method.startsWith("_iso/")) return isRequest ? replyError(c, id, { code: -32601, message: "unknown bridge method" }) : undefined;
        await ensureAgent();
        const params = msg.params && typeof msg.params === "object" ? { ...msg.params, sessionId } : msg.params;
        if (!isRequest) return sendToAgent({ jsonrpc: "2.0", method: msg.method, params });
        const result = await request(msg.method, params);
        // Mode/config changes: the agent answers the requester; every other window learns from
        // the agent's own notification when it sends one — and from us when it doesn't.
        if (msg.method === "session/set_mode" && sessionResult?.modes) {
          sessionResult.modes.currentModeId = params.modeId;
          broadcast(notif("session/update", { sessionId, update: { sessionUpdate: "current_mode_update", currentModeId: params.modeId } }), c.id);
        }
        if (msg.method === "session/set_config_option" && Array.isArray(result?.configOptions)) {
          sessionResult.configOptions = result.configOptions;
          broadcast(notif("session/update", { sessionId, update: { sessionUpdate: "config_option_update", configOptions: result.configOptions } }), c.id);
        }
        return reply(c, id, result);
      }
    }
  } catch (e) {
    if (isRequest) replyError(c, id, e);
    else log(`client ${msg.method} failed: ${e?.message ?? e}`);
  }
}

// --- HTTP + WebSocket server ------------------------------------------------------

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  const json = (status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
    return json(200, { ok: true, viewId: cfg.viewId, agent: cfg.agent, phase, error: lastError || undefined, sessionId: sessionId ?? null, alive, clients: clients.size, turn: turnInfo(), buffered: buffer.length });
  }
  if (req.method === "POST" && url.pathname === "/prompt") {
    // A connector turn (Slack, Buzz, another agent's thread_send): one prompt, the reply text.
    const chunks = [];
    for await (const ch of req) {
      chunks.push(ch);
      if (chunks.reduce((n, b) => n + b.length, 0) > 1024 * 1024) return json(413, { error: "prompt too large" });
    }
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    } catch {
      return json(400, { error: "bad json" });
    }
    const text = typeof body.text === "string" ? body.text : "";
    if (!text.trim()) return json(400, { error: "text required" });
    const from = typeof body.from === "string" && body.from ? body.from.slice(0, 64) : "connector";
    if (turn) return json(409, { error: "a turn is already in progress" });
    try {
      await new Promise((resolve, reject) => {
        runTurn(`connector:${randomUUID()}`, from, { prompt: [{ type: "text", text }] }, (err, result, collected) => {
          if (err) reject(err);
          else resolve(json(200, { text: collected, stopReason: result?.stopReason ?? "end_turn" }));
        }).catch(reject);
      });
    } catch (e) {
      json(e?.code === -32000 ? 409 : 502, { error: String(e?.message ?? e).slice(0, 500) });
    }
    return;
  }
  json(404, { error: "not found" });
});

server.on("upgrade", (req, sock, head) => {
  const key = req.headers["sec-websocket-key"];
  if (!key || !/websocket/i.test(String(req.headers.upgrade ?? ""))) {
    sock.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    sock.destroy();
    return;
  }
  const accept = createHash("sha1").update(`${key}${GUID}`).digest("base64");
  sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  sock.setNoDelay(true);
  const c = attach(sock);
  wsReader(sock, head, (text) => {
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    void onClientMessage(c, msg);
  });
});

// RFC 6455, server side: unmasked text frames out; masked frames in (the browser always
// masks). Fragmented messages are reassembled; ping → pong; close → close.
function wsSend(sock, text) {
  if (sock.destroyed || !sock.writable) return;
  const payload = Buffer.from(text, "utf8");
  const len = payload.length;
  let header;
  if (len < 126) header = Buffer.from([0x81, len]);
  else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  sock.write(Buffer.concat([header, payload]));
}

function wsReader(sock, head, onText) {
  let acc = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
  let frag = [];
  const control = (op, payload) => sock.write(Buffer.concat([Buffer.from([0x80 | op, payload.length]), payload]));
  sock.on("data", (d) => {
    acc = acc.length ? Buffer.concat([acc, d]) : d;
    for (;;) {
      if (acc.length < 2) return;
      const b0 = acc[0];
      const b1 = acc[1];
      const fin = (b0 & 0x80) !== 0;
      const op = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (acc.length < 4) return;
        len = acc.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (acc.length < 10) return;
        len = Number(acc.readBigUInt64BE(2));
        off = 10;
      }
      let mask;
      if (masked) {
        if (acc.length < off + 4) return;
        mask = acc.subarray(off, off + 4);
        off += 4;
      }
      if (acc.length < off + len) return;
      const payload = Buffer.from(acc.subarray(off, off + len));
      acc = acc.subarray(off + len);
      if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      if (op === 8) {
        try {
          control(8, Buffer.alloc(0));
        } catch {
          /* closing anyway */
        }
        sock.end();
        return;
      }
      if (op === 9) {
        control(10, payload.subarray(0, 125));
        continue;
      }
      if (op === 10) continue;
      if (op === 1 || op === 2 || op === 0) {
        frag.push(payload);
        if (fin) {
          const whole = Buffer.concat(frag);
          frag = [];
          onText(whole.toString("utf8"));
        }
      }
    }
  });
}

// --- idle reaping ---------------------------------------------------------------

// An idle adapter (no window attached, no turn) is stopped after IDLE_MS; the session lives
// on disk in the agent's HOME and the next attach reloads it. The bridge itself stays.
setInterval(() => {
  if (alive && !turn && clients.size === 0 && Date.now() - lastActivity > IDLE_MS) {
    log("idle — stopping the agent process (session kept)");
    child.kill();
  }
}, 30_000).unref();

process.on("SIGTERM", () => {
  if (alive) child.kill();
  process.exit(0);
});
process.on("uncaughtException", (e) => log("uncaught:", e?.stack ?? e));
process.on("unhandledRejection", (e) => log("unhandled rejection:", e?.stack ?? e));
process.on("exit", (code) => log(`exiting (${code})`));
process.on("SIGHUP", () => log("SIGHUP ignored"));

server.listen(PORT, "0.0.0.0", () => log(`listening on ${PORT} for ${cfg.agent?.name ?? "agent"} (${cfg.agent?.harness ?? "?"})`));

// The in-sandbox ACP bridge (sandbox/iso-acp-bridge.mjs) against a fake ACP agent: the hello
// handshake, a prompt echoed to every window, streamed chunks, the turn lock, the replay
// buffer for a late joiner, and the connector path (POST /prompt). Runs the real script on this
// host's Node — the same file the server writes into sandboxes.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";

const ROOT = new URL("..", import.meta.url).pathname;
const BRIDGE = join(ROOT, "sandbox", "iso-acp-bridge.mjs");

// A minimal ACP agent: initialize → loadSession capability; session/new → id + one mode; prompt →
// two text chunks + end_turn; session/load → replays one chunk. Everything over stdio ndjson.
const FAKE_AGENT = `
let acc = "";
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
process.stdin.on("data", (d) => { acc += d; let i; while ((i = acc.indexOf("\\n")) >= 0) { const l = acc.slice(0, i); acc = acc.slice(i + 1); if (l.trim()) on(JSON.parse(l)); } });
function on(m) {
  if (m.method === "initialize") return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: 1, agentCapabilities: { loadSession: true } } });
  if (m.method === "session/new") return send({ jsonrpc: "2.0", id: m.id, result: { sessionId: "sess-1", modes: { currentModeId: "ask", availableModes: [{ id: "ask", name: "Ask" }, { id: "yolo", name: "Yolo" }] } } });
  if (m.method === "session/load") { send({ jsonrpc: "2.0", method: "session/update", params: { sessionId: m.params.sessionId, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "replayed" } } } }); return send({ jsonrpc: "2.0", id: m.id, result: {} }); }
  if (m.method === "session/set_mode") return send({ jsonrpc: "2.0", id: m.id, result: {} });
  if (m.method === "session/prompt") {
    const text = m.params.prompt.map((b) => b.text).join("");
    if (text.startsWith("env:")) {
      const name = text.slice(4);
      send({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "sess-1", update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: name + "=" + (process.env[name] ?? "<unset>") } } } });
      return send({ jsonrpc: "2.0", id: m.id, result: { stopReason: "end_turn" } });
    }
    send({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "sess-1", update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "echo:" } } } });
    setTimeout(() => { send({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "sess-1", update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text } } } }); send({ jsonrpc: "2.0", id: m.id, result: { stopReason: "end_turn" } }); }, 150);
    return;
  }
  if (m.id !== undefined) send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "nope" } });
}
`;

const freePort = () =>
  new Promise((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

async function startBridge(extra = {}, procEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "iso-bridge-"));
  const agentPath = join(dir, "agent.mjs");
  writeFileSync(agentPath, FAKE_AGENT);
  const port = await freePort();
  const cfg = { viewId: "v-test", threadKey: "t1", agent: { id: "a1", name: "Fake", harness: "fake", model: null }, command: process.execPath, args: [agentPath], env: {}, cwd: dir, home: dir, statePath: join(dir, "thread.json"), mcpServers: [], initialModeId: "yolo", idleMinutes: 5, ...extra };
  const cfgPath = join(dir, "cfg.json");
  writeFileSync(cfgPath, JSON.stringify(cfg));
  const proc = spawn(process.execPath, [BRIDGE, String(port), cfgPath], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, ...procEnv } });
  let logs = "";
  proc.stderr.on("data", (d) => (logs += d));
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) break;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { port, dir, proc, logs: () => logs, stop: () => proc.kill() };
}

// A tiny WS client that collects JSON-RPC messages and answers requests by id.
function client(port) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  const got = [];
  const waiters = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    got.push(m);
    for (const w of [...waiters]) if (w.pred(m)) { waiters.splice(waiters.indexOf(w), 1); w.resolve(m); }
  };
  const until = (pred, ms = 5000) => {
    const hit = got.find(pred);
    if (hit) return Promise.resolve(hit);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`timeout waiting for message; got ${JSON.stringify(got).slice(0, 400)}`)), ms);
      waiters.push({ pred, resolve: (m) => { clearTimeout(t); resolve(m); } });
    });
  };
  const open = new Promise((resolve) => (ws.onopen = resolve));
  return { ws, got, until, open, send: (m) => ws.send(JSON.stringify(m)), close: () => ws.close() };
}

const chunks = (msgs) => msgs.filter((m) => m.method === "session/update" && m.params.update.sessionUpdate === "agent_message_chunk").map((m) => m.params.update.content.text);

test("bridge: hello, cached initialize, prompt echoed to every window, streamed reply, thread file", async () => {
  const b = await startBridge();
  try {
    const a = client(b.port);
    await a.open;
    const hello = await a.until((m) => m.method === "_iso/hello");
    assert.equal(hello.params.agent.name, "Fake");
    const ready = await a.until((m) => m.method === "_iso/session");
    assert.equal(ready.params.sessionId, "sess-1");
    assert.equal(ready.params.session.modes.currentModeId, "yolo", "the initial mode was selected");
    a.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: 1 } });
    const init = await a.until((m) => m.id === 1);
    assert.equal(init.result.agentCapabilities.loadSession, true);

    const second = client(b.port);
    await second.open;
    await second.until((m) => m.method === "_iso/hello");

    a.send({ jsonrpc: "2.0", id: 2, method: "session/prompt", params: { prompt: [{ type: "text", text: "hi" }] } });
    const done = await a.until((m) => m.id === 2);
    assert.equal(done.result.stopReason, "end_turn");
    const userEcho = a.got.find((m) => m.method === "session/update" && m.params.update.sessionUpdate === "user_message_chunk");
    assert.equal(userEcho.params.update.content.text, "hi", "the sender sees its own prompt from the bridge echo");
    assert.deepEqual(chunks(a.got), ["echo:", "hi"]);
    await second.until((m) => m.method === "_iso/turn" && m.params.active === false);
    assert.deepEqual(chunks(second.got), ["echo:", "hi"], "the other window streamed the same turn");
    assert.ok(second.got.some((m) => m.method === "session/update" && m.params.update.sessionUpdate === "user_message_chunk"));

    const state = JSON.parse(readFileSync(join(b.dir, "thread.json"), "utf8"));
    assert.equal(state.harnessSession, "sess-1");
    assert.equal(state.key, "t1");

    // A late joiner gets the whole conversation in its hello.
    const late = client(b.port);
    await late.open;
    const h2 = await late.until((m) => m.method === "_iso/hello");
    assert.deepEqual(chunks(h2.params.updates.map((u) => ({ method: u.method, params: u.params }))), ["echo:", "hi"]);
    a.close();
    second.close();
    late.close();
  } finally {
    b.stop();
  }
});

test("bridge: one turn in flight (409 for the rest), connector turns over POST /prompt", async () => {
  const b = await startBridge();
  try {
    const a = client(b.port);
    await a.open;
    await a.until((m) => m.method === "_iso/session");
    a.send({ jsonrpc: "2.0", id: 5, method: "session/prompt", params: { prompt: [{ type: "text", text: "slow" }] } });
    await a.until((m) => m.method === "_iso/turn" && m.params.active === true);
    const busy = await fetch(`http://127.0.0.1:${b.port}/prompt`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: "x", from: "slack" }) });
    assert.equal(busy.status, 409);
    await a.until((m) => m.id === 5);
    const r = await fetch(`http://127.0.0.1:${b.port}/prompt`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: "from slack", from: "slack" }) });
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.text, "echo:from slack");
    // The window saw the connector's prompt tagged with its source.
    const echo = a.got.filter((m) => m.method === "session/update" && m.params.update.sessionUpdate === "user_message_chunk").at(-1);
    assert.equal(echo.params._meta.iso.from, "slack");
    a.close();
  } finally {
    b.stop();
  }
});

test("bridge: a known session id is reloaded (session/load replay refills the buffer)", async () => {
  const b = await startBridge({ sessionId: "sess-1" });
  try {
    const a = client(b.port);
    await a.open;
    await a.until((m) => m.method === "_iso/session");
    await a.until((m) => m.method === "_iso/status" && m.params.phase === "ready");
    const late = client(b.port);
    await late.open;
    const h = await late.until((m) => m.method === "_iso/hello");
    assert.deepEqual(chunks(h.params.updates.map((u) => ({ method: u.method, params: u.params }))), ["replayed"]);
    a.close();
    late.close();
  } finally {
    b.stop();
  }
});

// The container's env carries the SESSION's credential; an agent with its own must not inherit
// the half of the pair its harness does not set, or the leftover out-ranks or redirects it
// (harness.ts `unsetFor`). The adapter is spawned by the bridge, so the bridge is where it lands.
test("bridge: unsetEnv strips the session's leftovers from the adapter's environment", async () => {
  const b = await startBridge({ env: { ANTHROPIC_API_KEY: "agent-key" }, unsetEnv: ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"] }, { CLAUDE_CODE_OAUTH_TOKEN: "session-oauth", ANTHROPIC_AUTH_TOKEN: "session-auth" });
  try {
    const a = client(b.port);
    await a.open;
    await a.until((m) => m.method === "_iso/session");
    const ask = async (name, id) => {
      a.send({ jsonrpc: "2.0", id, method: "session/prompt", params: { prompt: [{ type: "text", text: `env:${name}` }] } });
      await a.until((m) => m.id === id);
      return a.got.filter((m) => m.method === "session/update" && m.params.update.sessionUpdate === "agent_message_chunk").at(-1).params.update.content.text;
    };
    assert.equal(await ask("CLAUDE_CODE_OAUTH_TOKEN", 11), "CLAUDE_CODE_OAUTH_TOKEN=<unset>");
    assert.equal(await ask("ANTHROPIC_AUTH_TOKEN", 12), "ANTHROPIC_AUTH_TOKEN=<unset>");
    assert.equal(await ask("ANTHROPIC_API_KEY", 13), "ANTHROPIC_API_KEY=agent-key", "the harness's own value still lands");
    a.close();
  } finally {
    b.stop();
  }
});

// An adapter that isn't installed in the image: spawn emits 'error' and 'close' but never
// 'exit', so nothing would reject the `initialize` that gates the start — the window would sit
// at "starting" for good. The page must be told instead.
test("bridge: an adapter that cannot spawn fails the start instead of hanging", async () => {
  const b = await startBridge({ command: "iso-definitely-not-installed", args: [] });
  try {
    const a = client(b.port);
    await a.open;
    await a.until((m) => m.method === "_iso/hello");
    const err = await a.until((m) => m.method === "_iso/status" && m.params.phase === "error", 8000);
    assert.match(err.params.error, /spawn/i);
    const h = await (await fetch(`http://127.0.0.1:${b.port}/health`)).json();
    assert.equal(h.alive, false, "the bridge itself stays up so the view can report the failure");
    a.close();
  } finally {
    b.stop();
  }
});

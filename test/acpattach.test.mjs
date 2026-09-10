// THE ACP STDIO ATTACH (`sandbox/iso-acp-attach.mjs`) — the agent view's external door.
//
// This is a hand-written RFC 6455 CLIENT, and every part of it fails silently when it is wrong: an
// unmasked frame is dropped by a compliant server, a mishandled length reads the next frame's header
// as payload, and a fragmented message arrives as half a JSON document. None of that throws — the
// conversation simply stops making sense. So the test drives the real script against a real socket
// and checks the bytes.
//
// The fake server here is deliberately NOT the bridge: what is under test is the client half, and
// borrowing the bridge's framing to test the client would make one bug in a shared helper look like
// agreement.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import net from "node:net";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("../sandbox/iso-acp-attach.mjs", import.meta.url));
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** A WebSocket server that speaks only what the bridge speaks, and records what the client sends. */
function fakeBridge() {
  const received = [];
  let sock;
  let onFrame = () => {};
  // WHEN THE FAKE BRIDGE IS ACTUALLY SPEAKABLE-TO. `send` writes onto the client's socket, so a
  // test that guesses (a fixed sleep after `spawn`) either writes frames before the 101 — which the
  // client reads as HTTP headers — or dereferences a socket that does not exist yet, on whichever
  // loaded CI runner takes longer than the guess to start Node. The timeout keeps a child that
  // never connects a FAILURE rather than a hung suite.
  let markReady;
  const ready = new Promise((resolve, reject) => {
    markReady = resolve;
    setTimeout(() => reject(new Error("the attach never connected to the fake bridge")), 10_000).unref();
  });
  const server = net.createServer((s) => {
    sock = s;
    let buf = Buffer.alloc(0);
    let up = false;
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (!up) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        const head = buf.subarray(0, end).toString("latin1");
        buf = buf.subarray(end + 4);
        const key = /sec-websocket-key:\s*(\S+)/i.exec(head)?.[1] ?? "";
        const accept = createHash("sha1").update(key + GUID).digest("base64");
        s.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
        up = true;
        markReady();
      }
      // Read client frames. A CLIENT MUST MASK, so an unmasked one is a bug we want to see.
      for (;;) {
        if (buf.length < 2) return;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          off = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          len = Number(buf.readBigUInt64BE(2));
          off = 10;
        }
        assert.equal(masked, true, "a client frame must be masked");
        if (buf.length < off + 4 + len) return;
        const mask = buf.subarray(off, off + 4);
        const body = Buffer.from(buf.subarray(off + 4, off + 4 + len));
        for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4];
        buf = buf.subarray(off + 4 + len);
        received.push(body.toString("utf8"));
        onFrame(body.toString("utf8"));
      }
    });
  });
  return {
    server,
    received,
    ready,
    onFrame: (fn) => (onFrame = fn),
    /** Send one text message, optionally split across `parts` continuation frames. */
    send(text, parts = 1) {
      const payload = Buffer.from(text, "utf8");
      const size = Math.ceil(payload.length / parts);
      for (let i = 0; i < parts; i++) {
        const slice = payload.subarray(i * size, Math.min((i + 1) * size, payload.length));
        const fin = i === parts - 1;
        const opcode = i === 0 ? 0x1 : 0x0;
        const head = slice.length < 126 ? Buffer.alloc(2) : slice.length < 65536 ? Buffer.alloc(4) : Buffer.alloc(10);
        head[0] = (fin ? 0x80 : 0) | opcode;
        if (slice.length < 126) head[1] = slice.length;
        else if (slice.length < 65536) {
          head[1] = 126;
          head.writeUInt16BE(slice.length, 2);
        } else {
          head[1] = 127;
          head.writeBigUInt64BE(BigInt(slice.length), 2);
        }
        sock.write(Buffer.concat([head, slice]));
      }
    },
    close: () => sock?.destroy(),
  };
}

const listen = (server) => new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));

/**
 * The child's exit code, BOUNDED. Every ending pinned below is one the script has to reach on its
 * own — a closed bridge, a hung-up client, a refused handshake, a bridge that is not this view's —
 * so "it never exited" IS the regression. Awaiting it forever turns that into a suite that hangs
 * until CI gives up hours later (verified: drop the view-id check and the refusal test simply
 * stops), which is strictly worse than a failing assertion. The kill is what lets the runner leave.
 */
const exitCode = (child) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("the attach never exited on its own"));
    }, 15_000);
    t.unref();
    child.on("exit", (c) => {
      clearTimeout(t);
      resolve(c);
    });
  });

/**
 * Bridge + child for the tests that drive stdio by hand, with cleanup in a `finally`.
 *
 * WITHOUT THE `finally` A FAILED ASSERTION HANGS THE SUITE rather than reporting: the listening
 * server and the live child both hold the test file's event loop open, so the run never ends and CI
 * waits for its own hours-long limit. Verified by breaking the view-id check on purpose.
 */
async function withBridgeAndChild(args, fn) {
  const bridge = fakeBridge();
  const port = await listen(bridge.server);
  const child = spawn(process.execPath, [SCRIPT, String(port), ...args], { stdio: ["pipe", "pipe", "pipe"] });
  try {
    return await fn({ bridge, child });
  } finally {
    child.kill("SIGKILL");
    bridge.close();
    bridge.server.close();
  }
}

/** Run the attach script against a fake bridge, and give the test both ends. */
async function withAttach(fn) {
  const bridge = fakeBridge();
  const port = await listen(bridge.server);
  const child = spawn(process.execPath, [SCRIPT, String(port)], { stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  let out = "";
  child.stdout.on("data", (d) => {
    out += d.toString("utf8");
    for (;;) {
      const nl = out.indexOf("\n");
      if (nl === -1) break;
      lines.push(out.slice(0, nl));
      out = out.slice(nl + 1);
    }
  });
  const nextLine = async () => {
    for (let i = 0; i < 200 && !lines.length; i++) await new Promise((r) => setTimeout(r, 10));
    return lines.shift();
  };
  const nextFrame = () =>
    new Promise((resolve) => {
      bridge.onFrame((t) => resolve(t));
    });
  try {
    await bridge.ready;
    await fn({ bridge, child, nextLine, nextFrame, lines });
  } finally {
    child.kill("SIGKILL");
    bridge.server.close();
  }
}

test("the handshake completes, and a text frame becomes one line on stdout", async () => {
  await withAttach(async ({ bridge, nextLine }) => {
    bridge.send(JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { viewId: "v-1" } }));
    const line = await nextLine();
    assert.ok(line, "the client emitted a line");
    assert.equal(JSON.parse(line).method, "_iso/hello");
  });
});

test("a line on stdin becomes one MASKED frame — an unmasked one is dropped by a real server", async () => {
  await withAttach(async ({ child, nextFrame }) => {
    const waiting = nextFrame();
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "session/prompt", params: { prompt: [] } })}\n`);
    const got = await waiting;
    // The masking assertion lives in the fake server, which fails the test if a frame arrives raw.
    assert.equal(JSON.parse(got).method, "session/prompt");
  });
});

test("a message split across continuation frames arrives as ONE line", async () => {
  // `_iso/hello` carries the whole replay buffer, which for a real conversation is far past what any
  // server puts in a single frame. Reassembled wrong, a client gets half a JSON document.
  await withAttach(async ({ bridge, nextLine }) => {
    const big = { jsonrpc: "2.0", method: "_iso/hello", params: { updates: Array.from({ length: 400 }, (_, i) => ({ i, text: "x".repeat(200) })) } };
    const text = JSON.stringify(big);
    assert.ok(text.length > 65536, "the fixture is past a 16-bit length, which is the case that breaks");
    bridge.send(text, 7);
    const line = await nextLine();
    const parsed = JSON.parse(line);
    assert.equal(parsed.params.updates.length, 400, "every fragment landed, in order");
  });
});

test("a message the client sends that is past 64KB is framed with a 64-bit length", async () => {
  await withAttach(async ({ child, nextFrame }) => {
    const waiting = nextFrame();
    const text = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "session/prompt", params: { prompt: [{ type: "text", text: "y".repeat(70000) }] } });
    child.stdin.write(`${text}\n`);
    const got = await waiting;
    assert.equal(got.length, text.length, "the whole message arrived, masked, in one frame");
  });
});

test("a prompt split mid-character across stdin chunks arrives intact — a chunk boundary is not a character boundary", async () => {
  // stdin arrives in pipe-sized pieces, and any prompt outside ASCII will sooner or later be cut
  // through the middle of a multi-byte sequence. Decoded per-chunk, each half becomes U+FFFD and
  // the agent is quietly asked something other than what was typed — with nothing thrown anywhere.
  await withAttach(async ({ child, nextFrame }) => {
    const waiting = nextFrame();
    const text = JSON.stringify({ jsonrpc: "2.0", id: 3, method: "session/prompt", params: { prompt: [{ type: "text", text: "café 🚀 日本語" }] } });
    const bytes = Buffer.from(`${text}\n`, "utf8");
    // Cut inside the emoji: a 4-byte sequence, so the split lands between its continuation bytes.
    const cut = bytes.indexOf(Buffer.from("🚀", "utf8")) + 2;
    child.stdin.write(bytes.subarray(0, cut));
    await new Promise((r) => setTimeout(r, 30));
    child.stdin.write(bytes.subarray(cut));
    const got = await waiting;
    assert.equal(JSON.parse(got).params.prompt[0].text, "café 🚀 日本語", "every character survived the split");
  });
});

test("a bridge that closes ends the client cleanly — an ended session is not a failure", async () => {
  await withAttach(async ({ bridge, child }) => {
    const exited = exitCode(child);
    bridge.close();
    assert.equal(await exited, 0, "exit 0, so `ssh` does not report a failure when the view simply ended");
  });
});

test("a bridge that speaks and then closes is fully delivered — stdout is a pipe, and exit drops what is buffered", async () => {
  // THE FAILING SHAPE: the bridge hands a late joiner the whole replay buffer and the view is then
  // deleted. Our stdout is the ssh channel, so those writes are queued, not written — and a client
  // that reads at its own pace (any real one) had received NOTHING by the time the socket closed.
  // A reader that drains instantly hides this completely, so this test deliberately does not.
  await withBridgeAndChild([], async ({ bridge, child }) => {
    let out = "";
    child.stdout.pause(); // the slow client
    await bridge.ready;
    const text = JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { updates: Array.from({ length: 2000 }, (_, i) => ({ i, text: "x".repeat(200) })) } });
    assert.ok(text.length > 256 * 1024, "past anything a pipe buffers for us");
    bridge.send(text);
    const exited = exitCode(child);
    setTimeout(() => bridge.close(), 20);
    // Start reading only well after the bridge is gone: what survives is what the client really gets.
    await new Promise((r) => setTimeout(r, 300));
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.stdout.resume();
    assert.equal(await exited, 0);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(JSON.parse(out.trim()).params.updates.length, 2000, "every byte the bridge said arrived before we exited");
  });
});

test("a client that hangs up mid-replay ends the script cleanly — a broken pipe is a goodbye, not a crash", async () => {
  // OUR STDIO IS THE SSH CHANNEL, so a client that disconnects breaks the pipe under a write that is
  // still queued — and an EPIPE on `process.stdout` with no listener is an UNCAUGHT EXCEPTION: exit
  // 1 and a stack trace, for what is simply somebody closing their client. The `_iso/hello` replay
  // buffer makes this the common shape, not a corner: there is always something still queued.
  await withBridgeAndChild([], async ({ bridge, child }) => {
    let err = "";
    child.stderr.on("data", (d) => (err += d.toString("utf8")));
    child.stdout.pause(); // nothing is draining, so the write stays queued
    await bridge.ready;
    bridge.send(JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { updates: Array.from({ length: 5000 }, (_, i) => ({ i, text: "x".repeat(200) })) } }));
    const exited = exitCode(child);
    setTimeout(() => child.stdout.destroy(), 150); // the client hangs up
    assert.equal(await exited, 0, "a hung-up client is exit 0, not a crash");
    assert.ok(!/Unhandled 'error'|EPIPE/.test(err), `nothing was thrown at the user: ${err.slice(0, 200)}`);
  });
});

test("a server that is not a WebSocket is refused rather than half-spoken to — and its answer cannot drive the terminal", async () => {
  // The refusal QUOTES THE STATUS LINE, and this stderr is the PERSON'S TERMINAL: the renderer
  // inherits it into the ssh channel. Whatever answered on the port wrote that line, so an escape in
  // it would be an instruction and not text — on the very first thing a person sees on connecting.
  const server = net.createServer((s) => {
    s.on("data", () => s.write("HTTP/1.1 404 Not \u001b[2JFound\r\nContent-Length: 0\r\n\r\n"));
  });
  const port = await listen(server);
  const child = spawn(process.execPath, [SCRIPT, String(port)], { stdio: ["pipe", "pipe", "pipe"] });
  let err = "";
  child.stderr.on("data", (d) => (err += d.toString("utf8")));
  try {
    assert.equal(await exitCode(child), 1, "a non-101 answer is fatal, not something to keep writing frames into");
    assert.ok(!err.includes("\u001b[2J"), `an escape reached the terminal: ${JSON.stringify(err)}`);
    assert.match(err, /404 Not \[2JFound/, "…and the line still says what answered, minus the one byte that was not text");
  } finally {
    child.kill("SIGKILL");
    server.close();
  }
});

// A PORT IS NOT IDENTITY. View ports come from the free ones (launch.ts `nextFree` only avoids LIVE
// views) and a bridge orphaned by a deleted view is never killed — so the number in the route's
// command can be another agent's bridge, which answers happily. On the browser's path the doorman
// makes this check (`bridgeHealthy` requires the view's own id); an ssh client gets it here, and
// getting it wrong hands somebody another agent's whole transcript.

test("the attach refuses a bridge that names a different view — nothing of it reaches the client", async () => {
  await withBridgeAndChild(["v-mine"], async ({ bridge, child }) => {
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d.toString("utf8")));
    child.stderr.on("data", (d) => (err += d.toString("utf8")));
    await bridge.ready;
    // The stale bridge's own hello — a whole conversation, and not the one this route is for.
    // The id it CLAIMS is quoted back in the refusal, and that refusal lands on the person's terminal
    // (the renderer inherits this stderr into the ssh channel) — so whatever is squatting on the port
    // gets to write there. Its escapes come out; the name it claimed still reads.
    bridge.send(JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { viewId: "v-someone-\u001b[2Jelse", updates: [{ text: "another agent's transcript" }] } }));
    assert.equal(await exitCode(child), 1, "a bridge that is not this view's is fatal");
    assert.equal(out, "", "not one byte of the other conversation was forwarded");
    assert.match(err, /not v-mine's agent view/);
    assert.ok(!err.includes("\u001b[2J"), `an escape reached the terminal: ${JSON.stringify(err)}`);
    assert.match(err, /v-someone-/, "…and what it claimed to be still shows");
  });
});

test("the ROUTE'S ARGUMENTS decide which bridge is joined — the environment cannot redirect it", async () => {
  // The route's command carries the port AND the view id that port must answer to, and the pair is
  // the whole identity check. If the environment out-ranked it, whatever reaches that environment
  // (an env var on the workspace environment, an sshd accepting env requests, an edge that starts
  // forwarding them) would name the port and the id checked against it — i.e. name another agent's
  // bridge and the id that clears it. Arguments win, and they are read as a pair.
  const mine = fakeBridge();
  const other = fakeBridge();
  const minePort = await listen(mine.server);
  const otherPort = await listen(other.server);
  let otherConnections = 0;
  other.server.on("connection", () => otherConnections++);
  // NOTHING EVER DIALS `other` — that is the assertion — so its `ready` is a promise that only
  // rejects. Left unhandled it is an unhandled rejection the runner would eventually blame on
  // whichever test is still running, so say out loud that this one is expected to time out.
  other.ready.catch(() => {});
  const child = spawn(process.execPath, [SCRIPT, String(minePort), "v-mine"], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, ISO_ACP_PORT: String(otherPort), ISO_ACP_VIEW: "v-other" },
  });
  const lines = [];
  let out = "";
  child.stdout.on("data", (d) => {
    out += d.toString("utf8");
    for (;;) {
      const nl = out.indexOf("\n");
      if (nl === -1) break;
      lines.push(out.slice(0, nl));
      out = out.slice(nl + 1);
    }
  });
  try {
    await mine.ready; // it dialled the ARGUMENT'S port; the env's port is never touched
    mine.send(JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { viewId: "v-mine" } }));
    for (let i = 0; i < 100 && !lines.length; i++) await new Promise((r) => setTimeout(r, 10));
    assert.equal(JSON.parse(lines[0] ?? "{}").params?.viewId, "v-mine", "the argument's view id is the one accepted");
    assert.equal(otherConnections, 0, "the env's bridge was never dialled");
  } finally {
    child.kill("SIGKILL");
    mine.close();
    other.close();
    mine.server.close();
    other.server.close();
  }
});

test("the attach joins a bridge that names its view, and holds stdin until it has", async () => {
  await withBridgeAndChild(["v-mine"], async ({ bridge, child }) => {
    const lines = [];
    let out = "";
    child.stdout.on("data", (d) => {
      out += d.toString("utf8");
      for (;;) {
        const nl = out.indexOf("\n");
        if (nl === -1) break;
        lines.push(out.slice(0, nl));
        out = out.slice(nl + 1);
      }
    });
    await bridge.ready;
    // A client that types before the bridge has identified itself must not have its prompt sent to
    // whatever is on the port — it waits for the hello, then goes to the verified bridge.
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "session/prompt", params: { prompt: [] } })}\n`);
    // A REAL PAUSE, not a settled promise: the point of this assertion is that the line had every
    // chance to be forwarded and was not, which an immediate check would claim whether or not the
    // hold works. Long enough for the 25ms retry the attach parks the line behind to fire repeatedly.
    await new Promise((r) => setTimeout(r, 200));
    assert.deepEqual(bridge.received, [], "nothing was sent before the bridge named its view");
    bridge.send(JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { viewId: "v-mine" } }));
    for (let i = 0; i < 100 && !bridge.received.length; i++) await new Promise((r) => setTimeout(r, 10));
    assert.equal(JSON.parse(bridge.received[0]).method, "session/prompt", "the held prompt went to the verified bridge");
    assert.equal(JSON.parse(lines[0]).method, "_iso/hello", "and the hello itself reached the client");
  });
});
